#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Descriptors;
using DecodeWheaRecord.Errors.UEFI;
using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

/*
 * Module       Version             Arch(s)         Function(s)
 * ntoskrnl     10.0.26100.2605     AMD64           WheapAddSectionFromGenericErrorData
 */
namespace DecodeWheaRecord.Errors.Microsoft {
    internal sealed class WHEA_GENERIC_ERROR : WheaRecord {
        private uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        // Size up to and including the ErrorSeverity field
        private const uint MinStructSize = 20;

        private uint _BlockStatus;

        [JsonProperty(Order = 1)]
        public string BlockStatus => GetEnumFlagsAsString((WHEA_GENERIC_ERROR_BLOCKSTATUS)(_BlockStatus & 0xC00F)); // Exclude bits 4-13

        // Number of WHEA_GENERIC_ERROR_DATA_ENTRY structures
        [JsonProperty(Order = 2)]
        public ushort ErrorDataEntryCount => (ushort)((_BlockStatus >> 10) & 0x3FF); // Bits 4-13

        [JsonProperty(Order = 3)]
        public uint RawDataOffset;

        [JsonProperty(Order = 4)]
        public uint RawDataLength;

        [JsonProperty(Order = 5)]
        public uint DataLength;

        private WHEA_ERROR_SEVERITY _ErrorSeverity;

        [JsonProperty(Order = 6)]
        public string ErrorSeverity => GetEnumValueAsString<WHEA_ERROR_SEVERITY>(_ErrorSeverity);

        /*
         * The original structure defines the Data field as a byte array which
         * contains WHEA_GENERIC_ERROR_DATA_ENTRY structures followed by raw
         * error data. Only the former are marshalled into this field with the
         * raw error data stored in a separate RawData field.
         */
        [JsonProperty(Order = 7)]
        public IWheaRecord[] Data = Array.Empty<IWheaRecord>();

        /*
         * Per above, this contains the raw error data at the end of the Data
         * buffer after the WHEA_GENERIC_ERROR_DATA_ENTRY structures.
         */
        [JsonProperty(Order = 8)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] RawData = Array.Empty<byte>();

        public WHEA_GENERIC_ERROR(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_GENERIC_ERROR), structOffset, MinStructSize, bytesRemaining) {
            WheaGenericError(recordAddr, structOffset, bytesRemaining);
        }

        public WHEA_GENERIC_ERROR(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(typeof(WHEA_GENERIC_ERROR), sectionDsc, MinStructSize, bytesRemaining) {
            WheaGenericError(recordAddr, sectionDsc.SectionOffset, sectionDsc.SectionLength);
        }

        private void WheaGenericError(IntPtr recordAddr, uint structOffset, uint bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _BlockStatus = (uint)Marshal.ReadInt32(structAddr);
            RawDataOffset = (uint)Marshal.ReadInt32(structAddr, 4);
            RawDataLength = (uint)Marshal.ReadInt32(structAddr, 8);
            DataLength = (uint)Marshal.ReadInt32(structAddr, 12);

            if (MinStructSize + DataLength > bytesRemaining) {
                var checkCalc = $"{MinStructSize} + {DataLength} > {bytesRemaining}";
                throw new InvalidDataException($"{nameof(DataLength)} results in size greater than bytes remaining: {checkCalc}");
            }

            /*
             * Assumes there's no padding bytes between the error data and the
             * raw error data.
             */
            if (RawDataOffset != MinStructSize + DataLength - RawDataLength) {
                var checkCalc = $"{RawDataOffset} != {MinStructSize + DataLength - RawDataLength}";
                throw new InvalidDataException($"{nameof(RawDataOffset)} does not equal the expected offset: {checkCalc}");
            }

            if (RawDataOffset + RawDataLength > MinStructSize + DataLength) {
                var checkCalc = $"{RawDataOffset} + {RawDataLength} > {MinStructSize} + {DataLength}";
                throw new InvalidDataException($"{nameof(RawDataLength)} is beyond the Data buffer: {checkCalc}");
            }

            _ErrorSeverity = (WHEA_ERROR_SEVERITY)Marshal.ReadInt32(structAddr, 16);

            if (ErrorDataEntryCount > 0) {
                // Offset of current WHEA_GENERIC_ERROR_DATA_ENTRY structure
                var dataStructOffset = structOffset + MinStructSize;

                // Remaining bytes for WHEA_GENERIC_ERROR_DATA_ENTRY structures
                var dataBytesRemaining = RawDataOffset - MinStructSize;

                Data = new IWheaRecord[ErrorDataEntryCount];
                for (var i = 0; i < ErrorDataEntryCount; i++) {
                    Data[i] = WHEA_GENERIC_ERROR_DATA_ENTRY.CreateByRevision(recordAddr, dataStructOffset, dataBytesRemaining);
                    dataStructOffset += Data[i].GetNativeSize();
                    dataBytesRemaining -= Data[i].GetNativeSize();
                }
            } else {
                WarnOutput($"{nameof(ErrorDataEntryCount)} Expected at least one error data entry.", StructType.Name);
            }

            if (RawDataLength > 0) {
                RawData = new byte[RawDataLength];
                Marshal.Copy(structAddr + (int)MinStructSize + (int)RawDataOffset, RawData, 0, (int)RawDataLength);
            }

            _StructSize = MinStructSize + DataLength;
            FinalizeRecord(recordAddr, _StructSize);
        }
    }

    internal static class WHEA_GENERIC_ERROR_DATA_ENTRY {
        // Revision is 2 bytes at offset 0x14 in both structure versions
        private const uint MinRevisionBytes = 22;

        /*
         * The header defines the revision as a single value but the structure
         * has two single byte fields, corresponding to the major and minor
         * version, requiring some trivial bit shifting during validation.
         *
         * Also, despite being the v2 structure the revision is indeed v3.0.
         */
        private const ushort WHEA_GENERIC_ENTRY_V2_VERSION = 0x300; // v3.0

        private static readonly Version WheaGenericEntryV2Revision = new Version(WHEA_GENERIC_ENTRY_V2_VERSION >> 8, WHEA_GENERIC_ENTRY_V2_VERSION & 0xFF);

        public static WheaRecord CreateByRevision(IntPtr recordAddr, uint structOffset, uint bytesRemaining) {
            var revision = GetRevision(recordAddr, structOffset, bytesRemaining);

            if (revision == WheaGenericEntryV2Revision) {
                return new WHEA_GENERIC_ERROR_DATA_ENTRY_V2(recordAddr, structOffset, bytesRemaining);
            }

            if (revision < WheaGenericEntryV2Revision) {
                return new WHEA_GENERIC_ERROR_DATA_ENTRY_V1(recordAddr, structOffset, bytesRemaining);
            }

            throw new InvalidDataException($"Unsupported revision: {revision}");
        }

        private static Version GetRevision(IntPtr recordAddr, uint structOffset, uint bytesRemaining) {
            if (bytesRemaining < MinRevisionBytes) {
                var msg = $"Expected at least {MinRevisionBytes} bytes for the structure revision.";
                throw new ArgumentOutOfRangeException(nameof(bytesRemaining), msg);
            }

            var revision = Marshal.PtrToStructure<WHEA_REVISION>(recordAddr + (int)structOffset + 20);
            return new Version(revision.MajorRevision, revision.MinorRevision);
        }
    }

    internal sealed class WHEA_GENERIC_ERROR_DATA_ENTRY_V1 : WHEA_GENERIC_ERROR_DATA_ENTRY_BASE {
        // Size up to and including the Data field
        private const uint MinStructSize = 64;

        public WHEA_GENERIC_ERROR_DATA_ENTRY_V1(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_GENERIC_ERROR_DATA_ENTRY_V1), recordAddr, structOffset, MinStructSize, bytesRemaining) { }
    }

    internal sealed class WHEA_GENERIC_ERROR_DATA_ENTRY_V2 : WHEA_GENERIC_ERROR_DATA_ENTRY_BASE {
        // Size up to and including the Data field
        private const uint MinStructSize = 68;

        public WHEA_GENERIC_ERROR_DATA_ENTRY_V2(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_GENERIC_ERROR_DATA_ENTRY_V2), recordAddr, structOffset, MinStructSize, bytesRemaining) { }
    }

    internal abstract class WHEA_GENERIC_ERROR_DATA_ENTRY_BASE : WheaRecord {
        private readonly uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        // Size of the FRUText character array
        private const int WHEA_GENERIC_ENTRY_TEXT_LEN = 20;

        private Guid _SectionType;

        [JsonProperty(Order = 1)]
        public string SectionType => WheaGuids.SectionTypes.TryGetValue(_SectionType, out var sectionType) ? sectionType : _SectionType.ToString();

        private WHEA_ERROR_SEVERITY _ErrorSeverity;

        [JsonProperty(Order = 2)]
        public string ErrorSeverity => GetEnumValueAsString<WHEA_ERROR_SEVERITY>(_ErrorSeverity);

        private WHEA_REVISION _Revision;

        [JsonProperty(Order = 3)]
        public string Revision => _Revision.ToString();

        private WHEA_GENERIC_ERROR_DATA_ENTRY_VALIDBITS _ValidBits;

        [JsonProperty(Order = 4)]
        public string ValidBits => GetEnumFlagsAsString(_ValidBits);

        private WHEA_GENERIC_ERROR_DATA_ENTRY_FLAGS _Flags;

        [JsonProperty(Order = 5)]
        public string Flags => GetEnumFlagsAsString(_Flags);

        [JsonProperty(Order = 6)]
        public uint ErrorDataLength;

        [JsonProperty(Order = 7)]
        public Guid FRUId;

        private string _FRUText;

        [JsonProperty(Order = 8)]
        public string FRUText => _FRUText.Trim('\0').Trim();

        // Only present in the v2 structure
        [JsonProperty(Order = 9)]
        public WHEA_TIMESTAMP Timestamp;

        [JsonProperty(Order = 10)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public IWheaRecord Data;

        /*
         * Stores the raw data bytes when the section type is unsupported or
         * unknown, and so cannot be marshalled to a specific structure type.
         */
        [JsonProperty(Order = 11)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] RawData;

        protected WHEA_GENERIC_ERROR_DATA_ENTRY_BASE(Type sectionType, IntPtr recordAddr, uint structOffset, uint bytesMinimum, uint bytesRemaining) :
            base(sectionType, structOffset, bytesMinimum, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _SectionType = Marshal.PtrToStructure<Guid>(structAddr);
            _ErrorSeverity = (WHEA_ERROR_SEVERITY)Marshal.ReadInt32(structAddr, 16);
            _Revision = PtrToStructure<WHEA_REVISION>(structAddr + 20);
            _ValidBits = (WHEA_GENERIC_ERROR_DATA_ENTRY_VALIDBITS)Marshal.ReadByte(structAddr, 22);
            _Flags = (WHEA_GENERIC_ERROR_DATA_ENTRY_FLAGS)Marshal.ReadByte(structAddr, 23);
            ErrorDataLength = (uint)Marshal.ReadInt32(structAddr, 24);

            if (bytesMinimum + ErrorDataLength > bytesRemaining) {
                var checkCalc = $"{bytesMinimum} + {ErrorDataLength} > {bytesRemaining}";
                throw new InvalidDataException($"{nameof(ErrorDataLength)} results in size greater than bytes remaining: {checkCalc}");
            }

            FRUId = Marshal.PtrToStructure<Guid>(structAddr + 28);
            _FRUText = Marshal.PtrToStringAnsi(structAddr + 44, WHEA_GENERIC_ENTRY_TEXT_LEN);

            if (sectionType == typeof(WHEA_GENERIC_ERROR_DATA_ENTRY_V2)) {
                Timestamp = PtrToStructure<WHEA_TIMESTAMP>(structAddr + 64);
            }

            var dataOffset = structOffset + bytesMinimum;
            switch (_SectionType) {
                /*
                 * Standard sections
                 */

                case var sectionGuid when sectionGuid == WheaGuids.ARM_PROCESSOR_ERROR_SECTION_GUID:
                    Data = new WHEA_ARM_PROCESSOR_ERROR_SECTION(recordAddr, dataOffset, ErrorDataLength);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.FIRMWARE_ERROR_RECORD_REFERENCE_GUID:
                    Data = new WHEA_FIRMWARE_ERROR_RECORD_REFERENCE(recordAddr, dataOffset, ErrorDataLength);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.MEMORY_ERROR_SECTION_GUID:
                    Data = new WHEA_MEMORY_ERROR_SECTION(recordAddr, dataOffset, ErrorDataLength);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.PCIEXPRESS_ERROR_SECTION_GUID:
                    Data = new WHEA_PCIEXPRESS_ERROR_SECTION(recordAddr, dataOffset, ErrorDataLength);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.PCIXBUS_ERROR_SECTION_GUID:
                    Data = new WHEA_PCIXBUS_ERROR_SECTION(recordAddr, structOffset, ErrorDataLength);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.PCIXDEVICE_ERROR_SECTION_GUID:
                    Data = new WHEA_PCIXDEVICE_ERROR_SECTION(recordAddr, dataOffset, ErrorDataLength);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.PROCESSOR_GENERIC_ERROR_SECTION_GUID:
                    Data = new WHEA_PROCESSOR_GENERIC_ERROR_SECTION(recordAddr, dataOffset, ErrorDataLength);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.XPF_PROCESSOR_ERROR_SECTION_GUID:
                    Data = new WHEA_XPF_PROCESSOR_ERROR_SECTION(recordAddr, dataOffset, ErrorDataLength);
                    break;

                /*
                 * Microsoft sections
                 */

                case var sectionGuid when sectionGuid == WheaGuids.ARM_RAS_NODE_SECTION_GUID:
                    Data = new WHEA_ARM_RAS_NODE_SECTION(recordAddr, dataOffset, ErrorDataLength);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.IPMI_MSR_DUMP_SECTION_GUID:
                    Data = new WHEA_MSR_DUMP_SECTION(recordAddr, dataOffset, ErrorDataLength);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.MEMORY_CORRECTABLE_ERROR_SUMMARY_SECTION_GUID:
                    Data = new WHEA_MEMORY_CORRECTABLE_ERROR_SECTION(recordAddr, dataOffset, ErrorDataLength);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.MEMORY_ERROR_EXT_SECTION_INTEL_GUID:
                    Data = new WHEA_MEMORY_ERROR_EXT_SECTION_INTEL(recordAddr, dataOffset, ErrorDataLength);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.MU_TELEMETRY_SECTION_GUID:
                    Data = new MU_TELEMETRY_SECTION(recordAddr, dataOffset, ErrorDataLength);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.NMI_SECTION_GUID:
                    Data = new WHEA_NMI_ERROR_SECTION(recordAddr, structOffset, ErrorDataLength);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.PCI_RECOVERY_SECTION_GUID:
                    Data = new WHEA_PCI_RECOVERY_SECTION(recordAddr, dataOffset, ErrorDataLength);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.PCIE_CORRECTABLE_ERROR_SUMMARY_SECTION_GUID:
                    Data = new WHEA_PCIE_CORRECTABLE_ERROR_SECTION(recordAddr, dataOffset, ErrorDataLength);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.PMEM_ERROR_SECTION_GUID:
                    Data = new WHEA_PMEM_ERROR_SECTION(recordAddr, dataOffset, ErrorDataLength);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.RECOVERY_INFO_SECTION_GUID:
                    Data = new WHEA_ERROR_RECOVERY_INFO_SECTION(recordAddr, dataOffset, ErrorDataLength);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.SEA_SECTION_GUID:
                    Data = new WHEA_SEA_SECTION(recordAddr, dataOffset, ErrorDataLength);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.SEI_SECTION_GUID:
                    Data = new WHEA_SEI_SECTION(recordAddr, dataOffset, ErrorDataLength);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.WHEA_DPC_CAPABILITY_SECTION_GUID:
                    Data = new WHEA_PCI_DPC_SECTION(recordAddr, dataOffset, ErrorDataLength);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.WHEA_ERROR_PACKET_SECTION_GUID:
                    Data = WHEA_ERROR_PACKET.CreateBySignature(recordAddr, dataOffset, ErrorDataLength);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.XPF_MCA_SECTION_GUID:
                    Data = new WHEA_XPF_MCA_SECTION(recordAddr, dataOffset, ErrorDataLength);
                    break;

                /*
                 * Unsupported section
                 */

                default:
                    WarnOutput($"Unsupported section: {SectionType}", StructType.Name);
                    RawData = new byte[ErrorDataLength];
                    Marshal.Copy(recordAddr + (int)dataOffset, RawData, 0, (int)ErrorDataLength);
                    break;
            }

            _StructSize = bytesMinimum + ErrorDataLength;
            FinalizeRecord(recordAddr, _StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeFRUId() => (_ValidBits & WHEA_GENERIC_ERROR_DATA_ENTRY_VALIDBITS.FRUId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeFRUText() => (_ValidBits & WHEA_GENERIC_ERROR_DATA_ENTRY_VALIDBITS.FRUText) != 0;
    }

    // @formatter:int_align_fields true

    /*
     * Bits 4-13 represent the ErrorDataEntryCount field and are decoded in the
     * parent WHEA_GENERIC_ERROR structure. The remaining bits are reserved.
     */
    [Flags]
    internal enum WHEA_GENERIC_ERROR_BLOCKSTATUS : uint {
        UncorrectableError          = 0x1,
        CorrectableError            = 0x2,
        MultipleUncorrectableErrors = 0x4,
        MultipleCorrectableErrors   = 0x8
    }

    /*
     * Identical to the WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS type.
     * Strangely, the flags are defined in the documentation but there's no
     * apparent definition in the headers.
     */
    [Flags]
    internal enum WHEA_GENERIC_ERROR_DATA_ENTRY_VALIDBITS : byte {
        FRUId   = 0x1,
        FRUText = 0x2
    }

    /*
     * Almost identical to the WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS type,
     * except the field is only 8-bits instead of 32-bits, and flags above 0x20
     * aren't defined. It's unclear if that's an omission in the documentation
     * or they really aren't present, as the two missing flags would still fit.
     */
    [Flags]
    internal enum WHEA_GENERIC_ERROR_DATA_ENTRY_FLAGS : uint {
        Primary              = 0x1,
        ContainmentWarning   = 0x2,
        Reset                = 0x4,
        ThresholdExceeded    = 0x8,
        ResourceNotAvailable = 0x10,
        LatentError          = 0x20
    }

    // @formatter:int_align_fields false
}
