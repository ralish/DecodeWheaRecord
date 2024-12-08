#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Runtime.InteropServices;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.NativeMethods;
using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors {
    internal sealed class WHEA_ERROR_RECORD_SECTION_DESCRIPTOR : WheaErrorRecord {
        // Structure size is static
        private const uint _StructSize = 72;
        public override uint GetNativeSize() => _StructSize;

        /*
         * The header defines the revision as a single value but the structure
         * has two single byte fields, corresponding to the major and minor
         * version, requiring some trivial bit shifting during validation.
         */
        private const ushort WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_REVISION = 0x300; // v3.0

        /*
         * Offset of the error record section from the start of the error
         * record (i.e. beginning with the error record header).
         */
        [JsonProperty(Order = 1)]
        public uint SectionOffset;

        /*
         * Length of the error record section (i.e. the error record section
         * which is described by this descriptor).
         */
        [JsonProperty(Order = 2)]
        public uint SectionLength;

        private WHEA_REVISION _Revision;

        [JsonProperty(Order = 3)]
        public string Revision => _Revision.ToString();

        private WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS _ValidBits;

        [JsonProperty(Order = 4)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        [JsonProperty(Order = 5)]
        public byte Reserved;

        private WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS _Flags;

        [JsonProperty(Order = 6)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        private Guid _SectionType;

        // Used by WHEA_ERROR_RECORD when decoding sections
        internal Guid SectionTypeGuid => _SectionType;

        [JsonProperty(Order = 7)]
        public new string SectionType => SectionTypes.TryGetValue(_SectionType, out var SectionTypeValue) ? SectionTypeValue : _SectionType.ToString();

        [JsonProperty(Order = 8)]
        public Guid FRUId;

        private WHEA_ERROR_SEVERITY _SectionSeverity;

        [JsonProperty(Order = 9)]
        public string SectionSeverity => Enum.GetName(typeof(WHEA_ERROR_SEVERITY), _SectionSeverity);

        [JsonProperty(Order = 10)]
        public string FRUText;

        public WHEA_ERROR_RECORD_SECTION_DESCRIPTOR(IntPtr recordAddr, uint descriptorOffset, uint bytesRemaining) :
            base(typeof(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR), descriptorOffset, _StructSize, bytesRemaining) {
            var descriptorAddr = recordAddr + (int)descriptorOffset;
            var recordSize = descriptorOffset + bytesRemaining;

            SectionOffset = (uint)Marshal.ReadInt32(descriptorAddr);
            if (SectionOffset > recordSize) {
                var msg = $"{nameof(SectionOffset)} is beyond the record size: {SectionOffset} > {recordSize}";
                throw new InvalidDataException(msg);
            }

            SectionLength = (uint)Marshal.ReadInt32(descriptorAddr, 4);
            if (SectionOffset + SectionLength > recordSize) {
                var msg = $"{nameof(SectionLength)} is beyond the record size: {SectionOffset} + {SectionLength} > {recordSize}";
                throw new InvalidDataException(msg);
            }

            _Revision = Marshal.PtrToStructure<WHEA_REVISION>(descriptorAddr + 8);
            var offset = 8 + Marshal.SizeOf<WHEA_REVISION>();
            var hdrRevision = new Version(_Revision.MajorRevision, _Revision.MinorRevision);
            var maxRevision = new Version(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_REVISION >> 8, WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_REVISION & 0xFF);
            if (hdrRevision > maxRevision) {
                var msg = $"{nameof(Revision)} is greater than latest supported of {maxRevision.ToString(2)}: {hdrRevision.ToString(2)}";
                throw new InvalidDataException(msg);
            }

            _ValidBits = (WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS)Marshal.ReadByte(descriptorAddr, offset);
            Reserved = Marshal.ReadByte(descriptorAddr, offset + 1);
            _Flags = (WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS)Marshal.ReadInt32(descriptorAddr, offset + 2);
            offset += 6;

            _SectionType = Marshal.PtrToStructure<Guid>(descriptorAddr + offset);
            FRUId = Marshal.PtrToStructure<Guid>(descriptorAddr + offset);
            offset += 32;

            _SectionSeverity = (WHEA_ERROR_SEVERITY)Marshal.ReadInt32(descriptorAddr, offset);
            offset += 4;

            FRUText = Marshal.PtrToStringAnsi(descriptorAddr + offset, 20).Trim('\0');

            FinalizeRecord(recordAddr, _StructSize);
        }

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();

        [UsedImplicitly]
        public bool ShouldSerializeFRUId() =>
            (_ValidBits & WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS.FRUId) ==
            WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS.FRUId;

        [UsedImplicitly]
        public bool ShouldSerializeFRUText() =>
            (_ValidBits & WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS.FRUText) ==
            WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS.FRUText;
    }

    // @formatter:int_align_fields true

    // Also specified as preprocessor definitions
    [Flags]
    internal enum WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS : uint {
        Primary              = 0x1,
        ContainmentWarning   = 0x2,
        Reset                = 0x4,
        ThresholdExceeded    = 0x8,
        ResourceNotAvailable = 0x10,
        LatentError          = 0x20,
        Propagated           = 0x40,
        FruTextByPlugin      = 0x80
    }

    [Flags]
    internal enum WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS : byte {
        FRUId   = 0x1,
        FRUText = 0x2
    }

    // @formatter:int_align_fields false
}
