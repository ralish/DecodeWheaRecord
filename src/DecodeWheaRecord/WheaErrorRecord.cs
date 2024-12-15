using System;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;

using DecodeWheaRecord.Errors;

using static DecodeWheaRecord.Utilities;


namespace DecodeWheaRecord {
    internal abstract class WheaErrorRecord : IWheaRecord {
        public abstract uint GetNativeSize();

        private static uint _nestingDepth;

        private bool _Finalized;
        private readonly uint _SectionOffset;
        private readonly uint _BytesMinimum;
        private readonly uint _BytesRemaining;

        protected readonly Type SectionType;
        protected readonly WHEA_ERROR_RECORD_SECTION_DESCRIPTOR SectionDsc;

        private static uint GetSectionOffset(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc) {
            if (sectionDsc == null) throw new ArgumentNullException(nameof(sectionDsc));
            return sectionDsc.SectionOffset;
        }

        protected WheaErrorRecord(Type sectionType, uint sectionOffset, uint bytesMinimum, uint bytesRemaining) {
            if (sectionType == null) throw new ArgumentNullException(nameof(sectionType));
            if (bytesMinimum == 0) throw new ArgumentOutOfRangeException(nameof(bytesMinimum));

            if (bytesRemaining < bytesMinimum) {
                var msg = $"Section requires {bytesMinimum} bytes but only {bytesRemaining} bytes remaining.";
                throw new ArgumentOutOfRangeException(nameof(bytesMinimum), msg);
            }

            DebugOutput($"{"Start offset",-12} : {sectionOffset,-7} | {"Remaining bytes",-12} : {bytesRemaining,-7}", $"+ {sectionType.Name}", _nestingDepth);
            _nestingDepth++;

            SectionType = sectionType;
            _SectionOffset = sectionOffset;
            _BytesMinimum = bytesMinimum;
            _BytesRemaining = bytesRemaining;
        }

        protected WheaErrorRecord(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, Type sectionType, uint bytesMinimum, uint bytesRemaining) :
            this(sectionType, GetSectionOffset(sectionDsc), bytesMinimum, bytesRemaining) {
            if (sectionDsc.SectionLength > bytesRemaining) {
                var msg = $"Descriptor {nameof(sectionDsc.SectionLength)} is {sectionDsc.SectionLength} bytes but only {bytesRemaining} bytes remaining.";
                throw new ArgumentOutOfRangeException(nameof(bytesRemaining), msg);
            }

            if (sectionDsc.SectionLength < bytesMinimum) {
                var msg = $"Section requires {bytesMinimum} bytes but descriptor {nameof(sectionDsc.SectionLength)} is {sectionDsc.SectionLength} bytes.";
                throw new ArgumentOutOfRangeException(nameof(bytesMinimum), msg);
            }

            SectionDsc = sectionDsc;
        }

        protected void FinalizeRecord(IntPtr recordAddr, uint bytesMarshalled) {
            if (_Finalized) {
                throw new InvalidDataContractException("Record is already finalized.");
            }

            _Finalized = true;
            _nestingDepth--;
            DebugOutput($"{"End offset",-12} : {_SectionOffset + bytesMarshalled,-7} | {"Structure length",-16} : {bytesMarshalled,-7}",
                        $"- {SectionType.Name}",
                        _nestingDepth);

            if (bytesMarshalled > _BytesRemaining) {
                var msg = $"Number of bytes marshalled exceeds bytes remaining: {bytesMarshalled} > {_BytesRemaining}";
                throw new ArgumentOutOfRangeException(nameof(bytesMarshalled), msg);
            }

            if (bytesMarshalled < _BytesMinimum) {
                var msg = $"Number of bytes marshalled less than required bytes for section: {bytesMarshalled} < {_BytesMinimum}";
                throw new ArgumentOutOfRangeException(nameof(bytesMarshalled), msg);
            }

            if (SectionDsc != null && bytesMarshalled != SectionDsc.SectionLength) {
                var sectionLength = SectionDsc.SectionLength;
                if (bytesMarshalled > sectionLength) {
                    var msg = $"Number of bytes marshalled exceeds descriptor {nameof(SectionDsc.SectionLength)}: {bytesMarshalled} > {sectionLength}";
                    throw new ArgumentOutOfRangeException(nameof(bytesMarshalled), msg);
                }

                // Check the remaining non-marshalled bytes in the section
                var nonZeroFound = false;
                var numTrailingBytes = sectionLength - bytesMarshalled;
                var trailingBytesOffset = recordAddr + (int)_SectionOffset + (int)bytesMarshalled;

                for (var offset = 0; offset < numTrailingBytes; offset++) {
                    if (Marshal.ReadByte(trailingBytesOffset, offset) == 0) continue;
                    nonZeroFound = true;
                    break;
                }

                if (nonZeroFound) {
                    var msg = $"{numTrailingBytes} bytes in the section were not deserialized, at least one of which is non-zero.";
                    WarnOutput(msg, $"- {SectionType.Name}", _nestingDepth);
                } else {
                    var msg = $"{numTrailingBytes} bytes in the section were not deserialized, but all bytes were set to zero.";
                    InfoOutput(msg, $"- {SectionType.Name}", _nestingDepth);
                }
            }
        }
    }
}
