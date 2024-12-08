#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.NativeMethods;
using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors {
    internal sealed class WHEA_ERROR_RECORD : WheaErrorRecord {
        // At least one descriptor must be present
        private const uint BaseStructSize = 72; // TODO

        private uint _NativeSize;
        public override uint GetNativeSize() => _NativeSize;

        [JsonProperty(Order = 1)]
        public WHEA_ERROR_RECORD_HEADER Header { get; private set; }

        [JsonProperty(Order = 2)]
        public List<WHEA_ERROR_RECORD_SECTION_DESCRIPTOR> SectionDescriptor { get; private set; }

        [JsonProperty(Order = 3)]
        public List<IWheaRecord> Section { get; private set; }

        public WHEA_ERROR_RECORD(IntPtr recordAddr, uint recordSize) :
            base(typeof(WHEA_ERROR_RECORD), 0, BaseStructSize, recordSize) {
            Header = new WHEA_ERROR_RECORD_HEADER(recordAddr, recordSize);
            var offset = Header.GetNativeSize();

            // Each descriptor has a 1:1 mapping with an error section
            SectionDescriptor = new List<WHEA_ERROR_RECORD_SECTION_DESCRIPTOR>();
            Section = new List<IWheaRecord>();

            // First deserialize all the descriptors
            for (var i = 0; i < Header.SectionCount; i++) {
                var sectionDsc = new WHEA_ERROR_RECORD_SECTION_DESCRIPTOR(recordAddr, offset, recordSize - offset);
                SectionDescriptor.Add(sectionDsc);
                offset += sectionDsc.GetNativeSize();
            }

            // Now the corresponding error sections
            var bytesProcessed = offset;
            for (var i = 0; i < Header.SectionCount; i++) {
                var section = DecodeSection(SectionDescriptor[i], recordAddr, recordSize);
                if (section == null) continue;
                bytesProcessed += section.GetNativeSize();
                Section.Add(section);
            }

            FinalizeRecord(recordAddr, bytesProcessed);
        }

        private static IWheaRecord DecodeSection(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint recordSize) {
            IWheaRecord section = null;

            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;
            var bytesRemaining = recordSize - sectionDsc.SectionOffset; // TODO: Naive, handle adjacent sections

            switch (sectionDsc.SectionTypeGuid) {
                case var sectionGuid when sectionGuid == ARM_PROCESSOR_ERROR_SECTION_GUID:
                    section = new WHEA_ARM_PROCESSOR_ERROR_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == FIRMWARE_ERROR_RECORD_REFERENCE_GUID:
                    section = new WHEA_FIRMWARE_ERROR_RECORD_REFERENCE(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == MU_TELEMETRY_SECTION_GUID:
                    section = Marshal.PtrToStructure<MU_TELEMETRY_SECTION>(sectionAddr);
                    break;
                case var sectionGuid when sectionGuid == WHEA_ERROR_PACKET_SECTION_GUID:
                    section = WHEA_ERROR_PACKET.CreateBySignature(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == RECOVERY_INFO_SECTION_GUID:
                    section = Marshal.PtrToStructure<WHEA_ERROR_RECOVERY_INFO_SECTION>(sectionAddr);
                    break;
                case var sectionGuid when sectionGuid == MEMORY_CORRECTABLE_ERROR_SUMMARY_SECTION_GUID:
                    section = new WHEA_MEMORY_CORRECTABLE_ERROR_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == MEMORY_ERROR_SECTION_GUID:
                    section = new WHEA_MEMORY_ERROR_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == IPMI_MSR_DUMP_SECTION_GUID:
                    section = new WHEA_MSR_DUMP_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == NMI_SECTION_GUID:
                    section = Marshal.PtrToStructure<WHEA_NMI_ERROR_SECTION>(sectionAddr);
                    break;
                case var sectionGuid when sectionGuid == PCIE_CORRECTABLE_ERROR_SUMMARY_SECTION_GUID:
                    section = new WHEA_PCIE_CORRECTABLE_ERROR_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == PCIEXPRESS_ERROR_SECTION_GUID:
                    section = new WHEA_PCIEXPRESS_ERROR_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == PCIXBUS_ERROR_SECTION_GUID:
                    section = Marshal.PtrToStructure<WHEA_PCIXBUS_ERROR_SECTION>(sectionAddr);
                    break;
                case var sectionGuid when sectionGuid == PCIXDEVICE_ERROR_SECTION_GUID:
                    section = new WHEA_PCIXDEVICE_ERROR_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == PMEM_ERROR_SECTION_GUID:
                    section = new WHEA_PMEM_ERROR_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == PROCESSOR_GENERIC_ERROR_SECTION_GUID:
                    section = new WHEA_PROCESSOR_GENERIC_ERROR_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == XPF_PROCESSOR_ERROR_SECTION_GUID:
                    section = new WHEA_XPF_PROCESSOR_ERROR_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == XPF_MCA_SECTION_GUID:
                    section = new WHEA_XPF_MCA_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                default:
                    var msg = $"Skipping decoding of unknown section GUID: {sectionDsc.SectionTypeGuid}";
                    WarnOutput(msg, nameof(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR));
                    break;
            }

            return section;
        }
    }

    internal sealed class WHEA_ERROR_RECORD_HEADER : WheaErrorRecord {
        // Structure size is static
        private const uint _StructSize = 128;
        public override uint GetNativeSize() => _StructSize;

        /*
         * Reversed from what is defined in the header as validation of the
         * field is done as an ASCII string instead of a ULONG integer.
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
        public string Signature {
            get {
                var bytes = BitConverter.GetBytes(_Signature);
                return Encoding.ASCII.GetString(bytes);
            }
        }

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
        public string Severity => Enum.GetName(typeof(WHEA_ERROR_SEVERITY), _Severity);

        private WHEA_ERROR_RECORD_HEADER_VALIDBITS _ValidBits;

        [JsonProperty(Order = 6)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        /*
         * Length of the error record in its entirety. This includes the error
         * record header (this structure), error record section descriptors,
         * and any error record sections.
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
        public string CreatorId => CreatorIds.TryGetValue(_CreatorId, out var CreatorIdValue) ? CreatorIdValue : _CreatorId.ToString();

        private Guid _NotifyType;

        [JsonProperty(Order = 12)]
        public string NotifyType => NotifyTypes.TryGetValue(_NotifyType, out var NotifyTypeValue) ? NotifyTypeValue : _NotifyType.ToString();

        [JsonProperty(Order = 13)]
        public ulong RecordId;

        private WHEA_ERROR_RECORD_HEADER_FLAGS _Flags;

        [JsonProperty(Order = 14)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        [JsonProperty(Order = 15)]
        public WHEA_PERSISTENCE_INFO PersistenceInfo;

        [JsonProperty(Order = 16)]
        public uint OsBuildNumber;

        [JsonProperty(Order = 17)]
        public byte[] Reserved;

        public WHEA_ERROR_RECORD_HEADER(IntPtr recordAddr, uint recordSize) :
            base(typeof(WHEA_ERROR_RECORD_HEADER), 0, _StructSize, recordSize) {
            const string logCat = nameof(WHEA_ERROR_RECORD_HEADER);

            _Signature = (uint)Marshal.ReadInt32(recordAddr);
            if (Signature != WHEA_ERROR_RECORD_SIGNATURE) {
                var msg = $"Expected {nameof(Signature)} to be \"{WHEA_ERROR_RECORD_SIGNATURE}\" but found: {Signature}";
                throw new InvalidDataException(msg);
            }

            _Revision = Marshal.PtrToStructure<WHEA_REVISION>(recordAddr + 4);
            var offset = 4 + Marshal.SizeOf<WHEA_REVISION>();
            var hdrRevision = new Version(_Revision.MajorRevision, _Revision.MinorRevision);
            var maxRevision = new Version(WHEA_ERROR_RECORD_REVISION >> 8, WHEA_ERROR_RECORD_REVISION & 0xFF);
            if (hdrRevision > maxRevision) {
                var msg = $"{nameof(Revision)} is greater than latest supported of {maxRevision.ToString(2)}: {hdrRevision.ToString(2)}";
                throw new InvalidDataException(msg);
            }

            SignatureEnd = (uint)Marshal.ReadInt32(recordAddr, offset);
            if (SignatureEnd != WHEA_ERROR_RECORD_SIGNATURE_END) {
                var hdrSigEnd = Convert.ToString(SignatureEnd, 16);
                var expSigEnd = Convert.ToString(WHEA_ERROR_RECORD_SIGNATURE_END, 16);
                var msg = $"Expected {nameof(SignatureEnd)} to be \"{expSigEnd}\" but found: {hdrSigEnd}";
                throw new InvalidDataException(msg);
            }

            SectionCount = (ushort)Marshal.ReadInt16(recordAddr, offset + 4);
            if (SectionCount == 0) {
                throw new InvalidDataException($"{nameof(SectionCount)} is zero (expected at least one error section).");
            }

            _Severity = (WHEA_ERROR_SEVERITY)Marshal.ReadInt32(recordAddr, offset + 6);
            _ValidBits = (WHEA_ERROR_RECORD_HEADER_VALIDBITS)Marshal.ReadInt32(recordAddr, offset + 10);
            Length = (uint)Marshal.ReadInt32(recordAddr, offset + 14);
            offset += 18;

            if (Length != recordSize) {
                var diffStr = Length > recordSize ? "greater" : "less";
                var diffSym = Length > recordSize ? ">" : "<";
                var msg = $"{nameof(Length)} in header is {diffStr} than record size: {Length} {diffSym} {recordSize}";

                if (Length > recordSize) {
                    throw new InvalidDataException(msg);
                }

                WarnOutput(msg, logCat);
                WarnOutput("Error record is likely to be partially and/or incorrectly decoded.", logCat);
            }

            _Timestamp = Marshal.PtrToStructure<WHEA_TIMESTAMP>(recordAddr + offset);
            offset += Marshal.SizeOf<WHEA_TIMESTAMP>();

            PlatformId = Marshal.PtrToStructure<Guid>(recordAddr + offset);
            PartitionId = Marshal.PtrToStructure<Guid>(recordAddr + offset + 16);
            _CreatorId = Marshal.PtrToStructure<Guid>(recordAddr + offset + 32);
            _NotifyType = Marshal.PtrToStructure<Guid>(recordAddr + offset + 48);
            offset += 64;

            RecordId = (ulong)Marshal.ReadInt64(recordAddr, offset);
            _Flags = (WHEA_ERROR_RECORD_HEADER_FLAGS)Marshal.ReadInt32(recordAddr, offset + 8);
            offset += 12;

            PersistenceInfo = new WHEA_PERSISTENCE_INFO(recordAddr, (uint)offset, recordSize - (uint)offset);
            offset += (int)PersistenceInfo.GetNativeSize();

            OsBuildNumber = (uint)Marshal.ReadInt32(recordAddr, offset);
            offset += 4;

            Reserved = new byte[8];
            Marshal.Copy(recordAddr + offset, Reserved, 0, 8);

            FinalizeRecord(recordAddr, _StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeTimestamp() =>
            (_ValidBits & WHEA_ERROR_RECORD_HEADER_VALIDBITS.Timestamp) ==
            WHEA_ERROR_RECORD_HEADER_VALIDBITS.Timestamp;

        [UsedImplicitly]
        public bool ShouldSerializePlatformId() =>
            (_ValidBits & WHEA_ERROR_RECORD_HEADER_VALIDBITS.PlatformId) ==
            WHEA_ERROR_RECORD_HEADER_VALIDBITS.PlatformId;

        [UsedImplicitly]
        public bool ShouldSerializePartitionId() =>
            (_ValidBits & WHEA_ERROR_RECORD_HEADER_VALIDBITS.PartitionId) ==
            WHEA_ERROR_RECORD_HEADER_VALIDBITS.PartitionId;

        // Absence of the signature means this structure is empty
        [UsedImplicitly]
        public bool ShouldSerializePersistenceInfo() => !string.IsNullOrEmpty(PersistenceInfo.Signature);

        // Only populated in Azure by a PSHED plugin (AzPshedPi)
        [UsedImplicitly]
        public bool ShouldSerializeOsBuildNumber() => OsBuildNumber != 0;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();
    }

    /*
     * Originally defined as a ULONGLONG bitfield. This structure has the same
     * in memory format but is simpler to interact with.
     */
    internal sealed class WHEA_PERSISTENCE_INFO : WheaErrorRecord {
        // Structure size is static
        private const uint _StructSize = 8;
        public override uint GetNativeSize() => _StructSize;

        /*
         * The signature value is not defined in the header but Microsoft's
         * documentation states it is "RE". It is reversed as validation of the
         * field is done as an ASCII string instead of a USHORT integer.
         */
        private const string WHEA_PERSISTENCE_INFO_SIGNATURE = "ER";

        private ushort _Signature;

        [JsonProperty(Order = 1)]
        public string Signature {
            get {
                var bytes = BitConverter.GetBytes(_Signature);
                return Encoding.ASCII.GetString(bytes).Trim('\0');
            }
        }

        // Length of the error record when stored in persistent storage
        private byte[] _Length;

        [JsonProperty(Order = 2)]
        public uint Length => (uint)(_Length[0] + (_Length[1] << 8) + (_Length[2] << 16));

        [JsonProperty(Order = 3)]
        public ushort Identifier;

        private WHEA_PERSISTENCE_INFO_FLAGS _Flags;

        [JsonProperty(Order = 4)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        public WHEA_PERSISTENCE_INFO(IntPtr recordAddr, uint persistenceInfoOffset, uint bytesRemaining) :
            base(typeof(WHEA_PERSISTENCE_INFO), persistenceInfoOffset, _StructSize, bytesRemaining) {
            const string logCat = nameof(WHEA_PERSISTENCE_INFO);
            var persistenceInfoAddr = recordAddr + (int)persistenceInfoOffset;

            _Signature = (ushort)Marshal.ReadInt16(persistenceInfoAddr);

            _Length = new byte[3];
            Marshal.Copy(persistenceInfoAddr + 2, _Length, 0, 3);

            Identifier = (ushort)Marshal.ReadInt16(persistenceInfoAddr, 5);
            _Flags = (WHEA_PERSISTENCE_INFO_FLAGS)Marshal.ReadByte(persistenceInfoAddr, 7);

            /*
             * The signature is seemingly only set when the error record is
             * persisted, even though the structure itself is always present.
             */
            if (string.IsNullOrEmpty(Signature)) {
                if (Length != 0 || Identifier != 0 || _Flags != 0) {
                    WarnOutput($"{nameof(Signature)} not present but at least one field is non-zero.", logCat);
                }
            } else if (Signature != WHEA_PERSISTENCE_INFO_SIGNATURE) {
                var msg = $"Expected {nameof(Signature)} to be \"{WHEA_PERSISTENCE_INFO_SIGNATURE}\" but found: {Signature}";
                throw new InvalidDataException(msg);
            }

            FinalizeRecord(recordAddr, _StructSize);
        }
    }

    // @formatter:int_align_fields true

    [Flags]
    internal enum WHEA_ERROR_RECORD_HEADER_FLAGS : uint {
        Recovered          = 0x1, // Also a preprocessor definition
        PreviousError      = 0x2, // Also a preprocessor definition
        Simulated          = 0x4, // Also a preprocessor definition
        DeviceDriver       = 0x8, // Also a preprocessor definition
        CriticalEvent      = 0x10,
        PersistPfn         = 0x20,
        SectionsTruncated  = 0x40,
        RecoveryInProgress = 0x80,
        Throttle           = 0x100
    }

    // Also specified as preprocessor definitions
    [Flags]
    internal enum WHEA_ERROR_RECORD_HEADER_VALIDBITS : uint {
        PlatformId  = 0x1,
        Timestamp   = 0x2,
        PartitionId = 0x4
    }

    // Originally defined directly in the WHEA_PERSISTENCE_INFO structure
    [Flags]
    internal enum WHEA_PERSISTENCE_INFO_FLAGS : byte {
        Attribute1 = 0x1, // Originally a 2-bit field with Attribute2
        Attribute2 = 0x2, // Originally a 2-bit field with Attribute1
        DoNotLog   = 0x4
    }

    // @formatter:int_align_fields false
}
