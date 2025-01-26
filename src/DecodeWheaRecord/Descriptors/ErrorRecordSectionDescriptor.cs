#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Descriptors {
    internal sealed class WHEA_ERROR_RECORD_SECTION_DESCRIPTOR : WheaRecord {
        internal const uint StructSize = 72;
        public override uint GetNativeSize() => StructSize;

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
        public string ValidBits => GetEnumFlagsAsString(_ValidBits);

        [JsonProperty(Order = 5)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved;

        private WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS _Flags;

        [JsonProperty(Order = 6)]
        public string Flags => GetEnumFlagsAsString(_Flags);

        private Guid _SectionType;

        // Used by WHEA_ERROR_RECORD when decoding sections
        internal Guid SectionTypeGuid => _SectionType;

        [JsonProperty(Order = 7)]
        public string SectionType => WheaGuids.SectionTypes.TryGetValue(_SectionType, out var sectionType) ? sectionType : _SectionType.ToString();

        [JsonProperty(Order = 8)]
        public Guid FRUId;

        private WHEA_ERROR_SEVERITY _SectionSeverity;

        [JsonProperty(Order = 9)]
        public string SectionSeverity => GetEnumValueAsString<WHEA_ERROR_SEVERITY>(_SectionSeverity);

        private string _FRUText;

        [JsonProperty(Order = 10)]
        public string FRUText => _FRUText.Trim('\0').Trim();

        public WHEA_ERROR_RECORD_SECTION_DESCRIPTOR(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;
            var recordSize = structOffset + bytesRemaining;

            SectionOffset = (uint)Marshal.ReadInt32(structAddr);

            if (SectionOffset > recordSize) {
                var checkCalc = $"{SectionOffset} > {recordSize}";
                throw new InvalidDataException($"{nameof(SectionOffset)} is beyond the record size: {checkCalc}");
            }

            SectionLength = (uint)Marshal.ReadInt32(structAddr, 4);

            if (SectionOffset + SectionLength > recordSize) {
                var checkCalc = $"{SectionOffset} + {SectionLength} > {recordSize}";
                throw new InvalidDataException($"{nameof(SectionLength)} is beyond the record size: {checkCalc}");
            }

            _Revision = PtrToStructure<WHEA_REVISION>(structAddr + 8);

            var hdrRevision = new Version(_Revision.MajorRevision, _Revision.MinorRevision);
            var supRevision = new Version(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_REVISION >> 8, WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_REVISION & 0xFF);

            if (hdrRevision.MajorRevision > supRevision.MajorRevision) {
                var checkCalc = $"{hdrRevision.ToString(1)} > {supRevision.ToString(1)}";
                throw new InvalidDataException($"{nameof(Revision)} major version is greater than latest supported: {checkCalc}");
            }

            if (hdrRevision > supRevision) {
                var checkCalc = $"{hdrRevision.ToString(2)} > {supRevision.ToString(2)}";
                WarnOutput($"{nameof(Revision)} minor version is greater than latest supported: {checkCalc}");
            }

            _ValidBits = (WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS)Marshal.ReadByte(structAddr, 10);
            Reserved = Marshal.ReadByte(structAddr, 11);
            _Flags = (WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS)Marshal.ReadInt32(structAddr, 11);
            _SectionType = Marshal.PtrToStructure<Guid>(structAddr + 16);
            FRUId = Marshal.PtrToStructure<Guid>(structAddr + 32);
            _SectionSeverity = (WHEA_ERROR_SEVERITY)Marshal.ReadInt32(structAddr, 48);
            _FRUText = Marshal.PtrToStringAnsi(structAddr + 52, 20);

            FinalizeRecord(recordAddr, StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;

        [UsedImplicitly]
        public bool ShouldSerializeFRUId() => (_ValidBits & WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS.FRUId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeFRUText() => (_ValidBits & WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS.FRUText) != 0;
    }

    // @formatter:int_align_fields true

    [Flags]
    internal enum WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS : byte {
        FRUId   = 0x1,
        FRUText = 0x2
    }

    // Also in WHEA_SECTION_DESCRIPTOR_FLAGS preprocessor definitions
    [Flags]
    internal enum WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS : uint {
        Primary              = 0x1,
        ContainmentWarning   = 0x2,
        Reset                = 0x4,
        ThresholdExceeded    = 0x8,
        ResourceNotAvailable = 0x10,
        LatentError          = 0x20,
        Propagated           = 0x40,

        /*
         * The UEFI Specification defines this as the Overflow bit, but it's
         * different in the Windows headers. We'll use the Windows definition
         * but it's odd, as why redefine what appears to be an important bit?
         */
        FruTextByPlugin = 0x80
    }

    // @formatter:int_align_fields false
}
