using System;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;

using DecodeWheaRecord.Descriptors;

using static DecodeWheaRecord.Utilities;

/*
 * An abstract class for WHEA structures which implements debug output and
 * error checking during deserialization. It provides two entry points for
 * usage based on the "complexity" of the WHEA structure being deserialized.
 *
 * Static methods ("simple" structures)
 * These methods wrap Marshal.PtrToStructure() and so can only be used with
 * structures which have a static size. However, they in turn don't require
 * implementing a non-static class which inherits from this class.
 *
 * Class inheritance ("complex" structures)
 * Inheriting from the class significantly improves the error checking which it
 * performs. In addition to calling the constructor classes must also call the
 * FinalizeRecord(...) method after performing their deserialization work but
 * before exiting the constructor. The majority of the error checks occur on
 * calling this method (e.g. checking for out-of-bounds reads).
 *
 * A structure may be "complex" for many reasons, but the most common is that
 * it simply can't be marshalled with Marshal.PtrToStructure(). That's usually
 * because it has a non-static size (e.g. due to variable length arrays), but
 * can also occur even with some statically sized structures (e.g. due to the
 * presence of one or more unions with differing non-blittable types).
 */
namespace DecodeWheaRecord.Internal {
    internal abstract class WheaRecord : IWheaRecord {
        public abstract uint GetNativeSize();

        private static uint _nestingDepth;

        private bool _Finalized;
        private readonly uint _StructOffset;
        private readonly uint _BytesMinimum;
        private readonly uint _BytesRemaining;

        protected readonly Type StructType;

        // ReSharper disable once MemberCanBePrivate.Global
        protected readonly WHEA_ERROR_RECORD_SECTION_DESCRIPTOR SectionDsc;

        protected static T PtrToStructure<T>(IntPtr ptr) {
            DebugOutput($"{"Pointer",-12} : {ptr.ToHexString(true)}", $"+ {typeof(T).Name}", _nestingDepth);
            _nestingDepth++;

            var wheaStruct = Marshal.PtrToStructure<T>(ptr);

            _nestingDepth--;
            DebugOutput($"{"Length",-12} : {Marshal.SizeOf<T>()}", $"- {typeof(T).Name}", _nestingDepth);

            return wheaStruct;
        }

        protected static T PtrToStructure<T>(IntPtr ptr, uint bytesRemaining) {
            var structSize = Marshal.SizeOf<T>();
            if (bytesRemaining >= structSize) return PtrToStructure<T>(ptr);

            var msg = $"Structure requires {structSize} bytes but only {bytesRemaining} bytes remaining.";
            throw new ArgumentOutOfRangeException(nameof(T), msg);
        }

        protected WheaRecord(Type structType, uint structOffset, uint bytesMinimum, uint bytesRemaining) {
            if (structType == null) throw new ArgumentNullException(nameof(structType));

            if (bytesRemaining < bytesMinimum) {
                var msg = $"Structure requires {bytesMinimum} bytes but only {bytesRemaining} bytes remaining.";
                throw new ArgumentOutOfRangeException(nameof(bytesMinimum), msg);
            }

            DebugOutput($"Start offset : {structOffset,-5} | Remaining bytes : {bytesRemaining}", $"+ {structType.Name}", _nestingDepth);
            _nestingDepth++;

            StructType = structType;
            _StructOffset = structOffset;
            _BytesMinimum = bytesMinimum;
            _BytesRemaining = bytesRemaining;
        }

        protected WheaRecord(Type structType, WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, uint bytesMinimum, uint bytesRemaining) :
            this(structType, GetSectionOffset(sectionDsc), bytesMinimum, bytesRemaining) {
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
            DebugOutput($"{"End offset",-12} : {_StructOffset + bytesMarshalled,-5} | {"Length",-15} : {bytesMarshalled}",
                        $"- {StructType.Name}",
                        _nestingDepth);

            if (bytesMarshalled > _BytesRemaining) {
                var msg = $"Number of bytes marshalled exceeds bytes remaining: {bytesMarshalled} > {_BytesRemaining}";
                throw new ArgumentOutOfRangeException(nameof(bytesMarshalled), msg);
            }

            if (bytesMarshalled < _BytesMinimum) {
                var msg = $"Number of bytes marshalled less than required bytes for structure: {bytesMarshalled} < {_BytesMinimum}";
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
                var trailingBytesOffset = recordAddr + (int)_StructOffset + (int)bytesMarshalled;

                for (var offset = 0; offset < numTrailingBytes; offset++) {
                    if (Marshal.ReadByte(trailingBytesOffset, offset) == 0) continue;
                    nonZeroFound = true;
                    break;
                }

                if (nonZeroFound) {
                    var msg = $"{numTrailingBytes} bytes in the section were not deserialized, at least one of which is non-zero.";
                    WarnOutput(msg, $"- {StructType.Name}", _nestingDepth);
                } else {
                    var msg = $"{numTrailingBytes} bytes in the section were not deserialized, but all bytes were set to zero.";
                    InfoOutput(msg, $"- {StructType.Name}", _nestingDepth);
                }
            }
        }

        private static uint GetSectionOffset(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc) {
            if (sectionDsc == null) throw new ArgumentNullException(nameof(sectionDsc));
            return sectionDsc.SectionOffset;
        }
    }
}
