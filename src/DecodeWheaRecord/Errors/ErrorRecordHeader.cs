#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors {
    internal sealed class WHEA_ERROR_RECORD_HEADER : WheaRecord {
        internal const uint StructSize = 128;
        public override uint GetNativeSize() => StructSize;

        /*
         * Value is reversed from header definition as validation is performed
         * against the field as a string instead of an integer.
         */
        internal const string WHEA_ERROR_RECORD_SIGNATURE = "CPER";

        /*
         * The header defines the revision as a single value but the structure
         * has two single byte fields, corresponding to the major and minor
         * version, requiring some trivial bit shifting during validation.
         */
        private const ushort WHEA_ERROR_RECORD_REVISION = 0x210; // v2.16

        private const uint WHEA_ERROR_RECORD_SIGNATURE_END = uint.MaxValue; // 0xFFFFFFFF

        private uint _Signature;

        [JsonProperty(Order = 1)]
        public string Signature => _Signature.ToAsciiOrHexString();

        private WHEA_REVISION _Revision;

        [JsonProperty(Order = 2)]
        public string Revision => _Revision.ToString();

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint SignatureEnd;

        [JsonProperty(Order = 4)]
        public ushort SectionCount;

        private WHEA_ERROR_SEVERITY _Severity;

        [JsonProperty(Order = 5)]
        public string Severity => GetEnumValueAsString<WHEA_ERROR_SEVERITY>(_Severity);

        private WHEA_ERROR_RECORD_HEADER_VALIDBITS _ValidBits;

        [JsonProperty(Order = 6)]
        public string ValidBits => GetEnumFlagsAsString(_ValidBits);

        /*
         * Length of the error record in its entirety; i.e. the error record
         * header (this structure), error record section descriptors, and the
         * error record sections. Extra buffer space may also be included to
         * support dynamic addition of further error record sections and the
         * associated error record section descriptors.
         */
        [JsonProperty(Order = 7)]
        public uint Length;

        private WHEA_TIMESTAMP _Timestamp;

        [JsonProperty(Order = 8)]
        public string Timestamp => _Timestamp.ToString();

        [JsonProperty(Order = 9)]
        public Guid PlatformId;

        [JsonProperty(Order = 10)]
        public Guid PartitionId;

        private Guid _CreatorId;

        [JsonProperty(Order = 11)]
        public string CreatorId => WheaGuids.CreatorIds.TryGetValue(_CreatorId, out var creatorId) ? creatorId : _CreatorId.ToString();

        private Guid _NotifyType;

        [JsonProperty(Order = 12)]
        public string NotifyType => WheaGuids.NotifyTypes.TryGetValue(_NotifyType, out var notifyType) ? notifyType : _NotifyType.ToString();

        [JsonProperty(Order = 13)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong RecordId;

        private WHEA_ERROR_RECORD_HEADER_FLAGS _Flags;

        [JsonProperty(Order = 14)]
        public string Flags => GetEnumFlagsAsString(_Flags);

        [JsonProperty(Order = 15)]
        public WHEA_PERSISTENCE_INFO PersistenceInfo;

        /*
         * Only populated in Azure by a PSHED plugin (AzPshedPi)
         *
         * Microsoft is being a bit naughty here as the UEFI Specification is
         * explicit that these bytes must be zero.
         */
        [JsonProperty(Order = 16)]
        public uint OsBuildNumber;

        [JsonProperty(Order = 17)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] Reserved = new byte[8];

        public WHEA_ERROR_RECORD_HEADER(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_ERROR_RECORD_HEADER), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _Signature = (uint)Marshal.ReadInt32(structAddr);

            if (Signature != WHEA_ERROR_RECORD_SIGNATURE) {
                throw new InvalidDataException($"Expected {nameof(Signature)} to be \"{WHEA_ERROR_RECORD_SIGNATURE}\" but found: {Signature}");
            }

            _Revision = PtrToStructure<WHEA_REVISION>(structAddr + 4);

            var hdrRevision = new Version(_Revision.MajorRevision, _Revision.MinorRevision);
            var supRevision = new Version(WHEA_ERROR_RECORD_REVISION >> 8, WHEA_ERROR_RECORD_REVISION & 0xFF);

            if (hdrRevision.MajorRevision > supRevision.MajorRevision) {
                var checkCalc = $"{hdrRevision.ToString(1)} > {supRevision.ToString(1)}";
                throw new InvalidDataException($"{nameof(Revision)} major version is greater than latest supported: {checkCalc}");
            }

            if (hdrRevision > supRevision) {
                var checkCalc = $"{hdrRevision.ToString(2)} > {supRevision.ToString(2)}";
                WarnOutput($"{nameof(Revision)} minor version is greater than latest supported: {checkCalc}");
            }

            SignatureEnd = (uint)Marshal.ReadInt32(structAddr, 6);

            if (SignatureEnd != WHEA_ERROR_RECORD_SIGNATURE_END) {
                var hdrSigEnd = Convert.ToString(SignatureEnd, 16);
                var expSigEnd = Convert.ToString(WHEA_ERROR_RECORD_SIGNATURE_END, 16);
                throw new InvalidDataException($"Expected {nameof(SignatureEnd)} to be \"{expSigEnd}\" but found: {hdrSigEnd}");
            }

            SectionCount = (ushort)Marshal.ReadInt16(structAddr, 10);

            if (SectionCount == 0) {
                throw new InvalidDataException($"{nameof(SectionCount)} Expected at least one error section.");
            }

            _Severity = (WHEA_ERROR_SEVERITY)Marshal.ReadInt32(structAddr, 12);
            _ValidBits = (WHEA_ERROR_RECORD_HEADER_VALIDBITS)Marshal.ReadInt32(structAddr, 16);
            Length = (uint)Marshal.ReadInt32(structAddr, 20);

            if (Length != bytesRemaining) {
                var isGreater = Length > bytesRemaining;
                var checkCalc = $"{Length} {(isGreater ? ">" : "<")} {bytesRemaining}";
                var msg = $"{nameof(Length)} is {(isGreater ? "greater" : "less")} than bytes remaining: {checkCalc}";

                if (isGreater) {
                    throw new InvalidDataException(msg);
                }

                WarnOutput(msg, StructType.Name);
                WarnOutput("Error record may be corrupt or incorrectly and/or partially decoded.", StructType.Name);
            }

            _Timestamp = PtrToStructure<WHEA_TIMESTAMP>(structAddr + 24);
            PlatformId = Marshal.PtrToStructure<Guid>(structAddr + 32);
            PartitionId = Marshal.PtrToStructure<Guid>(structAddr + 48);
            _CreatorId = Marshal.PtrToStructure<Guid>(structAddr + 64);
            _NotifyType = Marshal.PtrToStructure<Guid>(structAddr + 80);
            RecordId = (ulong)Marshal.ReadInt64(structAddr, 96);
            _Flags = (WHEA_ERROR_RECORD_HEADER_FLAGS)Marshal.ReadInt32(structAddr, 104);
            PersistenceInfo = new WHEA_PERSISTENCE_INFO(structAddr, 108, bytesRemaining - 108);
            OsBuildNumber = (uint)Marshal.ReadInt32(structAddr, 112);
            Marshal.Copy(structAddr + 116, Reserved, 0, 8);

            FinalizeRecord(recordAddr, StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeTimestamp() => (_ValidBits & WHEA_ERROR_RECORD_HEADER_VALIDBITS.Timestamp) != 0;

        [UsedImplicitly]
        public bool ShouldSerializePlatformId() => (_ValidBits & WHEA_ERROR_RECORD_HEADER_VALIDBITS.PlatformId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializePartitionId() => (_ValidBits & WHEA_ERROR_RECORD_HEADER_VALIDBITS.PartitionId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializePersistenceInfo() => PersistenceInfo.HasNonZeroBytes();

        [UsedImplicitly]
        public bool ShouldSerializeOsBuildNumber() => OsBuildNumber != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved.Any(element => element != 0);
    }

    internal sealed class WHEA_PERSISTENCE_INFO : WheaRecord {
        private const uint StructSize = 8;
        public override uint GetNativeSize() => StructSize;

        /*
         * The signature value is not defined in the header but Microsoft's
         * documentation states it is "RE". It is reversed as validation is
         * performed against the field as a string instead of an integer.
         */
        private const string ExpectedSignature = "ER";

        private ulong _RawBits;

        [JsonProperty(Order = 1)]
        public string Signature => ((ushort)_RawBits).ToAsciiOrHexString(); // Bits 0-15

        // Length of the error record when stored in persistent storage
        [JsonProperty(Order = 2)]
        public uint Length => (uint)((_RawBits >> 16) & 0xFFFFFF); // Bits 16-39

        [JsonProperty(Order = 3)]
        public ushort Identifier => (ushort)(_RawBits >> 40); // Bits 40-55

        [JsonProperty(Order = 4)]
        public byte Attributes => (byte)((_RawBits >> 56) & 0x3); // Bits 56-57

        [JsonProperty(Order = 5)]
        public bool DoNotLog => ((_RawBits >> 58) & 0x1) == 1; // Bit 58

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved => (byte)(_RawBits >> 59); // Bits 59-63

        public WHEA_PERSISTENCE_INFO(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_PERSISTENCE_INFO), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _RawBits = (ulong)Marshal.ReadInt64(structAddr);

            /*
             * The signature is seemingly only set when the error record is
             * persisted even though the structure itself is always present.
             */
            if (string.IsNullOrEmpty(Signature)) {
                if (HasNonZeroBytes()) {
                    WarnOutput($"{nameof(Signature)} not present but structure has non-zero bytes.", StructType.Name);
                }
            } else if (Signature != ExpectedSignature) {
                throw new InvalidDataException($"Expected {nameof(Signature)} to be \"{ExpectedSignature}\" but found: {Signature}");
            }

            FinalizeRecord(recordAddr, StructSize);
        }

        internal bool HasNonZeroBytes() => _RawBits != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // @formatter:int_align_fields true

    // Also in WHEA_ERROR_RECORD_VALID preprocessor definitions
    [Flags]
    internal enum WHEA_ERROR_RECORD_HEADER_VALIDBITS : uint {
        PlatformId  = 0x1,
        Timestamp   = 0x2,
        PartitionId = 0x4
    }

    // Subset in WHEA_ERROR_RECORD_FLAGS preprocessor definitions
    [Flags]
    internal enum WHEA_ERROR_RECORD_HEADER_FLAGS : uint {
        Recovered     = 0x1,
        PreviousError = 0x2,
        Simulated     = 0x4,

        // Remaining bits are not in the UEFI Specification
        DeviceDriver       = 0x8,
        CriticalEvent      = 0x10,
        PersistPfn         = 0x20,
        SectionsTruncated  = 0x40,
        RecoveryInProgress = 0x80,
        Throttle           = 0x100
    }

    // @formatter:int_align_fields false
}
