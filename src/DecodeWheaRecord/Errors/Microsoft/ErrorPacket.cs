#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

using DecodeWheaRecord.Errors.Standard;
using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors.Microsoft {
    internal static class WHEA_ERROR_PACKET {
        /*
         * Values are reversed from header definitions as validation is
         * performed against the fields as a string instead of an integer.
         */
        private const string WHEA_ERROR_PACKET_V1_SIGNATURE = "ErPt";
        private const string WHEA_ERROR_PACKET_V2_SIGNATURE = "WHEA";

        public static WheaRecord CreateBySignature(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) {
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;
            var signatureBytes = BitConverter.GetBytes((uint)Marshal.ReadInt32(sectionAddr));
            var signature = Encoding.ASCII.GetString(signatureBytes);

            switch (signature) {
                case WHEA_ERROR_PACKET_V1_SIGNATURE:
                    return new WHEA_ERROR_PACKET_V1(sectionDsc, recordAddr, bytesRemaining);
                case WHEA_ERROR_PACKET_V2_SIGNATURE:
                    return new WHEA_ERROR_PACKET_V2(sectionDsc, recordAddr, bytesRemaining);
                default:
                    throw new InvalidDataException($"Unknown signature: {signature}");
            }
        }
    }

    // Windows Server 2008 & Windows Vista SP1+
    internal sealed class WHEA_ERROR_PACKET_V1 : WheaRecord {
        public override uint GetNativeSize() => Size;

        /*
         * Size up to and including the RawDataOffset field. The embedded
         * WHEA_*_ERROR_SECTION structures vary in size but occupy a union.
         */
        private const uint MinStructSize = 280;

        private const int WHEA_ERROR_PACKET_V1_VERSION = 2; // Not a typo

        private uint _Signature;

        [JsonProperty(Order = 1)]
        public string Signature {
            get {
                var bytes = BitConverter.GetBytes(_Signature);
                return Encoding.ASCII.GetString(bytes);
            }
        }

        private WHEA_ERROR_PACKET_FLAGS _Flags;

        [JsonProperty(Order = 2)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        /*
         * Size of the hardware error packet including the raw data (the
         * RawDataLength field).
         */
        [JsonProperty(Order = 3)]
        public uint Size;

        /*
         * Length of the raw hardware error information contained in the
         * RawData field.
         */
        [JsonProperty(Order = 4)]
        public uint RawDataLength;

        [JsonProperty(Order = 5)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Reserved1;

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Context;

        private WHEA_ERROR_TYPE _ErrorType;

        [JsonProperty(Order = 7)]
        public string ErrorType => Enum.GetName(typeof(WHEA_ERROR_TYPE), _ErrorType);

        private WHEA_ERROR_SEVERITY _ErrorSeverity;

        [JsonProperty(Order = 8)]
        public string ErrorSeverity => Enum.GetName(typeof(WHEA_ERROR_SEVERITY), _ErrorSeverity);

        [JsonProperty(Order = 9)]
        public uint ErrorSourceId;

        private WHEA_ERROR_SOURCE_TYPE _ErrorSourceType;

        [JsonProperty(Order = 10)]
        public string ErrorSourceType => Enum.GetName(typeof(WHEA_ERROR_SOURCE_TYPE), _ErrorSourceType);

        [JsonProperty(Order = 11)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Reserved2;

        [JsonProperty(Order = 12)]
        public uint Version;

        [JsonProperty(Order = 13)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Cpu;

        [JsonProperty(Order = 14)]
        public WHEA_PROCESSOR_GENERIC_ERROR_SECTION ProcessorError;

        [JsonProperty(Order = 14)]
        public WHEA_MEMORY_ERROR_SECTION MemoryError;

        [JsonProperty(Order = 14)]
        public WHEA_NMI_ERROR_SECTION NmiError;

        [JsonProperty(Order = 14)]
        public WHEA_PCIEXPRESS_ERROR_SECTION PciExpressError;

        [JsonProperty(Order = 14)]
        public WHEA_PCIXBUS_ERROR_SECTION PciXBusError;

        [JsonProperty(Order = 14)]
        public WHEA_PCIXDEVICE_ERROR_SECTION PciXDeviceError;

        [JsonProperty(Order = 14)]
        public WHEA_PMEM_ERROR_SECTION PmemError;

        private WHEA_RAW_DATA_FORMAT _RawDataFormat;

        [JsonProperty(Order = 15)]
        public string RawDataFormat => Enum.GetName(typeof(WHEA_RAW_DATA_FORMAT), _RawDataFormat);

        /*
         * Offset from the beginning of the RawData data buffer where a PSHED
         * plug-in can add supplementary platform-specific data. The amount of
         * data that can be added is limited by the Size field.
         */
        [JsonProperty(Order = 16)]
        public uint RawDataOffset;

        [JsonProperty(Order = 17)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] RawData; // TODO: Deserialize

        public WHEA_ERROR_PACKET_V1(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(WHEA_ERROR_PACKET_V1), MinStructSize, bytesRemaining) {
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            // Verified previously in CreateBySignature
            _Signature = (uint)Marshal.ReadInt32(sectionAddr);

            _Flags = (WHEA_ERROR_PACKET_FLAGS)Marshal.ReadInt32(sectionAddr, 4);
            Size = (uint)Marshal.ReadInt32(sectionAddr, 8);

            if (Size > sectionDsc.SectionLength) {
                var msg = $"{nameof(Size)} is greater than in section descriptor: {Size} > {sectionDsc.SectionLength}";
                throw new InvalidDataException(msg);
            }

            RawDataLength = (uint)Marshal.ReadInt32(sectionAddr, 12);

            if (MinStructSize + RawDataLength > Size) {
                var msg = $"Base structure size with {nameof(RawDataLength)} exceeds {nameof(Size)} value: {MinStructSize} + {RawDataLength} > {Size}";
                throw new InvalidDataException(msg);
            }

            Reserved1 = (ulong)Marshal.ReadInt64(sectionAddr, 16);
            Context = (ulong)Marshal.ReadInt64(sectionAddr, 24);
            _ErrorType = (WHEA_ERROR_TYPE)Marshal.ReadInt32(sectionAddr, 32);
            _ErrorSeverity = (WHEA_ERROR_SEVERITY)Marshal.ReadInt32(sectionAddr, 36);
            ErrorSourceId = (uint)Marshal.ReadInt32(sectionAddr, 40);
            _ErrorSourceType = (WHEA_ERROR_SOURCE_TYPE)Marshal.ReadInt32(sectionAddr, 44);
            Reserved2 = (uint)Marshal.ReadInt32(sectionAddr, 48);
            Version = (uint)Marshal.ReadInt32(sectionAddr, 52);

            if (Version != WHEA_ERROR_PACKET_V1_VERSION) {
                var msg = $"Expected {nameof(Version)} to be {WHEA_ERROR_PACKET_V1_VERSION} but found: {Version}";
                throw new InvalidDataException(msg);
            }

            Cpu = (ulong)Marshal.ReadInt64(sectionAddr, 56);

            bytesRemaining -= 64;
            const uint errorStructOffset = 64;
            var errorStructAddr = sectionAddr + (int)errorStructOffset;
            switch (_ErrorType) {
                case WHEA_ERROR_TYPE.Processor:
                    ProcessorError = new WHEA_PROCESSOR_GENERIC_ERROR_SECTION(errorStructAddr, errorStructOffset, bytesRemaining);
                    break;
                case WHEA_ERROR_TYPE.Memory:
                    MemoryError = new WHEA_MEMORY_ERROR_SECTION(sectionAddr + 64, errorStructOffset, bytesRemaining);
                    break;
                case WHEA_ERROR_TYPE.NMI:
                    NmiError = Marshal.PtrToStructure<WHEA_NMI_ERROR_SECTION>(errorStructAddr);
                    break;
                case WHEA_ERROR_TYPE.PCIExpress:
                    PciExpressError = new WHEA_PCIEXPRESS_ERROR_SECTION(errorStructAddr, errorStructOffset, bytesRemaining);
                    break;
                case WHEA_ERROR_TYPE.PCIXBus:
                    PciXBusError = Marshal.PtrToStructure<WHEA_PCIXBUS_ERROR_SECTION>(errorStructAddr);
                    break;
                case WHEA_ERROR_TYPE.PCIXDevice:
                    PciXDeviceError = new WHEA_PCIXDEVICE_ERROR_SECTION(errorStructAddr, errorStructOffset, bytesRemaining);
                    break;
                case WHEA_ERROR_TYPE.Pmem:
                    PmemError = new WHEA_PMEM_ERROR_SECTION(errorStructAddr, errorStructOffset, bytesRemaining);
                    break;
                case WHEA_ERROR_TYPE.Generic: // TODO: No associated error section?
                    break;
                default:
                    throw new InvalidDataException($"{nameof(ErrorType)} is unknown or invalid: {ErrorType}");
            }

            _RawDataFormat = (WHEA_RAW_DATA_FORMAT)Marshal.ReadInt32(sectionAddr, 272);
            RawDataOffset = (uint)Marshal.ReadInt32(sectionAddr, 276);

            if (RawDataOffset > RawDataLength) {
                var msg = $"{nameof(RawDataOffset)} is beyond the end of the {nameof(RawData)} buffer: {RawDataOffset} > {RawDataLength}";
                throw new InvalidDataException(msg);
            }

            if (RawDataLength > 0) {
                RawData = new byte[RawDataLength];
                Marshal.Copy(sectionAddr, RawData, (int)MinStructSize, (int)RawDataLength);
            }

            FinalizeRecord(recordAddr, Size);
        }

        [UsedImplicitly]
        public bool ShouldSerializeReserved1() => Reserved1 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved2() => Reserved2 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeProcessorError() => _ErrorType == WHEA_ERROR_TYPE.Processor;

        [UsedImplicitly]
        public bool ShouldSerializeMemoryError() => _ErrorType == WHEA_ERROR_TYPE.Memory;

        [UsedImplicitly]
        public bool ShouldSerializeNmiError() => _ErrorType == WHEA_ERROR_TYPE.NMI;

        [UsedImplicitly]
        public bool ShouldSerializePciExpressError() => _ErrorType == WHEA_ERROR_TYPE.PCIExpress;

        [UsedImplicitly]
        public bool ShouldSerializePciXBusError() => _ErrorType == WHEA_ERROR_TYPE.PCIXBus;

        [UsedImplicitly]
        public bool ShouldSerializePciXDeviceError() => _ErrorType == WHEA_ERROR_TYPE.PCIXDevice;

        [UsedImplicitly]
        public bool ShouldSerializePmemError() => _ErrorType == WHEA_ERROR_TYPE.Pmem;
    }

    // Windows Server 2008 R2, Windows 7, and later
    internal sealed class WHEA_ERROR_PACKET_V2 : WheaRecord {
        public override uint GetNativeSize() => Length;

        // Size up to and including the PshedDataLength field
        private const uint MinStructSize = 80;

        private const int WHEA_ERROR_PACKET_V2_VERSION = 3; // Not a typo

        private uint _Signature;

        [JsonProperty(Order = 1)]
        public string Signature {
            get {
                var bytes = BitConverter.GetBytes(_Signature);
                return Encoding.ASCII.GetString(bytes);
            }
        }

        [JsonProperty(Order = 2)]
        public uint Version;

        /*
         * Size of the hardware error packet including the data (the DataLength
         * field) and the PSHED data (the PshedDataLength field).
         */
        [JsonProperty(Order = 3)]
        public uint Length;

        private WHEA_ERROR_PACKET_FLAGS _Flags;

        [JsonProperty(Order = 4)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        private WHEA_ERROR_TYPE _ErrorType;

        [JsonProperty(Order = 5)]
        public string ErrorType => Enum.GetName(typeof(WHEA_ERROR_TYPE), _ErrorType);

        private WHEA_ERROR_SEVERITY _ErrorSeverity;

        [JsonProperty(Order = 6)]
        public string ErrorSeverity => Enum.GetName(typeof(WHEA_ERROR_SEVERITY), _ErrorSeverity);

        [JsonProperty(Order = 7)]
        public uint ErrorSourceId;

        private WHEA_ERROR_SOURCE_TYPE _ErrorSourceType;

        [JsonProperty(Order = 8)]
        public string ErrorSourceType => Enum.GetName(typeof(WHEA_ERROR_SOURCE_TYPE), _ErrorSourceType);

        private Guid _NotifyType;

        [JsonProperty(Order = 9)]
        public string NotifyType => WheaGuids.NotifyTypes.TryGetValue(_NotifyType, out var notifyType) ? notifyType : _NotifyType.ToString();

        [JsonProperty(Order = 10)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Context;

        private WHEA_ERROR_PACKET_DATA_FORMAT _DataFormat;

        [JsonProperty(Order = 11)]
        public string DataFormat => Enum.GetName(typeof(WHEA_ERROR_PACKET_DATA_FORMAT), _DataFormat);

        [JsonProperty(Order = 12)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Reserved1;

        // Offset of the Data buffer from the beginning of the structure
        [JsonProperty(Order = 13)]
        public uint DataOffset;

        // Length of the Data buffer
        [JsonProperty(Order = 14)]
        public uint DataLength;

        // Offset of the PshedData buffer from the beginning of the structure
        [JsonProperty(Order = 15)]
        public uint PshedDataOffset;

        // Length of the PshedData buffer
        [JsonProperty(Order = 16)]
        public uint PshedDataLength;

        [JsonProperty(Order = 17)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] Data; // TODO: Deserialize

        [JsonProperty(Order = 18)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] PshedData; // TODO: Deserialize

        public WHEA_ERROR_PACKET_V2(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(WHEA_ERROR_PACKET_V2), MinStructSize, bytesRemaining) {
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            // Verified previously in CreateBySignature
            _Signature = (uint)Marshal.ReadInt32(sectionAddr);

            Version = (uint)Marshal.ReadInt32(sectionAddr, 4);

            if (Version != WHEA_ERROR_PACKET_V2_VERSION) {
                var msg = $"Expected {nameof(Version)} to be {WHEA_ERROR_PACKET_V2_VERSION} but found: {Version}";
                throw new InvalidDataException(msg);
            }

            Length = (uint)Marshal.ReadInt32(sectionAddr, 8);

            if (Length > sectionDsc.SectionLength) {
                var msg = $"{nameof(Length)} is greater than in section descriptor: {Length} > {sectionDsc.SectionLength}";
                throw new InvalidDataException(msg);
            }

            _Flags = (WHEA_ERROR_PACKET_FLAGS)Marshal.ReadInt32(sectionAddr, 12);
            _ErrorType = (WHEA_ERROR_TYPE)Marshal.ReadInt32(sectionAddr, 16);
            _ErrorSeverity = (WHEA_ERROR_SEVERITY)Marshal.ReadInt32(sectionAddr, 20);
            ErrorSourceId = (uint)Marshal.ReadInt32(sectionAddr, 24);
            _ErrorSourceType = (WHEA_ERROR_SOURCE_TYPE)Marshal.ReadInt32(sectionAddr, 28);
            _NotifyType = Marshal.PtrToStructure<Guid>(sectionAddr + 32);
            Context = (ulong)Marshal.ReadInt64(sectionAddr, 48);
            _DataFormat = (WHEA_ERROR_PACKET_DATA_FORMAT)Marshal.ReadInt32(sectionAddr, 56);
            Reserved1 = (uint)Marshal.ReadInt32(sectionAddr, 60);
            DataOffset = (uint)Marshal.ReadInt32(sectionAddr, 64);
            DataLength = (uint)Marshal.ReadInt32(sectionAddr, 68);
            PshedDataOffset = (uint)Marshal.ReadInt32(sectionAddr, 72);
            PshedDataLength = (uint)Marshal.ReadInt32(sectionAddr, 76);

            if (MinStructSize + DataLength + PshedDataLength > Length) {
                var msg = $"Base structure size with {nameof(DataLength)} and {nameof(PshedDataLength)} exceeds {nameof(Length)} value: " +
                          $"{MinStructSize} + {DataLength} + {PshedDataLength} > {Length}";
                throw new InvalidDataException(msg);
            }

            if (DataOffset != MinStructSize) {
                var msg = $"{nameof(DataOffset)} does not equal the expected offset: {DataOffset} != {MinStructSize}";
                throw new InvalidDataException(msg);
            }

            if (PshedDataOffset != MinStructSize + DataLength) {
                var msg = $"{nameof(PshedDataOffset)} does not equal the expected offset: {PshedDataOffset} != {MinStructSize + DataLength}";
                throw new InvalidDataException(msg);
            }

            if (DataLength > 0) {
                Data = new byte[DataLength];
                Marshal.Copy(sectionAddr, Data, (int)DataOffset, (int)DataLength);
            }

            if (PshedDataLength > 0) {
                PshedData = new byte[PshedDataLength];
                Marshal.Copy(sectionAddr, PshedData, (int)PshedDataOffset, (int)PshedDataLength);
            }

            FinalizeRecord(recordAddr, Length);
        }

        [UsedImplicitly]
        public bool ShouldSerializeReserved1() => Reserved1 != 0;
    }

    // @formatter:int_align_fields true

    [Flags]
    internal enum WHEA_ERROR_PACKET_FLAGS : uint {
        PreviousError               = 0x1,
        CriticalEvent               = 0x2,
        HypervisorError             = 0x4,
        Simulated                   = 0x8,
        PlatformPfaControl          = 0x10,
        PlatformDirectedOffline     = 0x20,
        AddressTranslationRequired  = 0x40,
        AddressTranslationCompleted = 0x80,
        RecoveryOptional            = 0x100
    }

    internal enum WHEA_ERROR_TYPE : uint {
        Processor  = 0,
        Memory     = 1,
        PCIExpress = 2,
        NMI        = 3,
        PCIXBus    = 4,
        PCIXDevice = 5,
        Generic    = 6,
        Pmem       = 7
    }

    internal enum WHEA_RAW_DATA_FORMAT : uint {
        IPFSalRecord = 0,
        IA32MCA      = 1,
        Intel64MCA   = 2,
        AMD64MCA     = 3,
        Memory       = 4,
        PCIExpress   = 5,
        NMIPort      = 6,
        PCIXBus      = 7,
        PCIXDevice   = 8,
        Generic      = 9
    }

    internal enum WHEA_ERROR_PACKET_DATA_FORMAT : uint {
        IPFSalRecord = 0,
        XPFMCA       = 1,
        Memory       = 2,
        PCIExpress   = 3,
        NMIPort      = 4,
        PCIXBus      = 5,
        PCIXDevice   = 6,
        Generic      = 7
    }

    // @formatter:int_align_fields false
}
