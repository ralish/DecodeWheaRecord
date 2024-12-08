#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming
// ReSharper disable MemberCanBePrivate.Global

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.NativeMethods;
using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors {
    internal static class WHEA_ERROR_PACKET {
        /*
         * Reversed from what is defined in the header as validation of the
         * field is done as an ASCII string instead of a ULONG integer.
         */
        internal const string WHEA_ERROR_PACKET_V1_SIGNATURE = "ErPt";
        internal const string WHEA_ERROR_PACKET_V2_SIGNATURE = "WHEA";

        public static WheaErrorRecord CreateBySignature(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) {
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;
            var signatureBytes = BitConverter.GetBytes((uint)Marshal.ReadInt32(sectionAddr));
            var signature = Encoding.ASCII.GetString(signatureBytes);

            switch (signature) {
                case WHEA_ERROR_PACKET_V1_SIGNATURE:
                    return new WHEA_ERROR_PACKET_V1(sectionDsc, recordAddr, bytesRemaining);
                case WHEA_ERROR_PACKET_V2_SIGNATURE:
                    return new WHEA_ERROR_PACKET_V2(sectionDsc, recordAddr, bytesRemaining);
                default:
                    throw new InvalidDataException($"Unexpected signature: {signature}");
            }
        }
    }

    /*
     * Windows Server 2008 & Windows Vista SP1+
     *
     * Cannot be directly marshalled as a structure due to the usage of a
     * variable length array, resulting in a non-static structure size.
     */
    internal sealed class WHEA_ERROR_PACKET_V1 : WheaErrorRecord {
        /*
         * Size up to and including the RawDataOffset field. While the embedded
         * ERROR_SECTION structures vary in size they are part of a union.
         */
        private const uint BaseStructSize = 280;

        public override uint GetNativeSize() => Size;

        internal const int WHEA_ERROR_PACKET_V1_VERSION = 2; // Not a typo

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
        public ulong Reserved1;

        [JsonProperty(Order = 6)]
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
        public uint Reserved2;

        [JsonProperty(Order = 12)]
        public uint Version;

        [JsonProperty(Order = 13)]
        public ulong Cpu;

        [JsonProperty(Order = 14)]
        public WHEA_PROCESSOR_GENERIC_ERROR_SECTION ProcessorError;

        [JsonProperty(Order = 15)]
        public WHEA_MEMORY_ERROR_SECTION MemoryError;

        [JsonProperty(Order = 16)]
        public WHEA_NMI_ERROR_SECTION NmiError;

        [JsonProperty(Order = 17)]
        public WHEA_PCIEXPRESS_ERROR_SECTION PciExpressError;

        [JsonProperty(Order = 18)]
        public WHEA_PCIXBUS_ERROR_SECTION PciXBusError;

        [JsonProperty(Order = 19)]
        public WHEA_PCIXDEVICE_ERROR_SECTION PciXDeviceError;

        [JsonProperty(Order = 20)]
        public WHEA_PMEM_ERROR_SECTION PmemError;

        private WHEA_RAW_DATA_FORMAT _RawDataFormat;

        [JsonProperty(Order = 21)]
        public string RawDataFormat => Enum.GetName(typeof(WHEA_RAW_DATA_FORMAT), _RawDataFormat);

        /*
         * Offset from the beginning of the RawData data buffer where a PSHED
         * plug-in can add supplementary platform-specific data. The amount of
         * data that can be added is limited by the Size field.
         */
        [JsonProperty(Order = 22)]
        public uint RawDataOffset;

        [JsonProperty(Order = 23)]
        public byte[] RawData;

        public WHEA_ERROR_PACKET_V1(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(WHEA_ERROR_PACKET_V1), BaseStructSize, bytesRemaining) {
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            _Signature = (uint)Marshal.ReadInt32(sectionAddr);
            _Flags = (WHEA_ERROR_PACKET_FLAGS)Marshal.ReadInt32(sectionAddr, 4);

            Size = (uint)Marshal.ReadInt32(sectionAddr, 8);
            if (Size != sectionDsc.SectionLength) {
                var errMsg = $"{nameof(Size)} does not match section descriptor: {Size} != {sectionDsc.SectionLength}";
                throw new InvalidDataException(errMsg);
            }

            RawDataLength = (uint)Marshal.ReadInt32(sectionAddr, 12);
            if (BaseStructSize + RawDataLength != Size) {
                var errMsg = $"{nameof(RawDataLength)} inconsistent with expected structure size: {BaseStructSize} + {RawDataLength} != {Size}";
                throw new InvalidDataException(errMsg);
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
                var errMsg = $"Expected {nameof(Version)} to be {WHEA_ERROR_PACKET_V1_VERSION} but found: {Version}";
                throw new InvalidDataException(errMsg);
            }

            Cpu = (ulong)Marshal.ReadInt64(sectionAddr, 56);
            var offset = 64;

            bytesRemaining -= (uint)offset;
            switch (_ErrorType) {
                case WHEA_ERROR_TYPE.Processor:
                    ProcessorError = new WHEA_PROCESSOR_GENERIC_ERROR_SECTION(sectionAddr + offset, (uint)offset, bytesRemaining);
                    break;
                case WHEA_ERROR_TYPE.Memory:
                    MemoryError = new WHEA_MEMORY_ERROR_SECTION(sectionAddr + offset, (uint)offset, bytesRemaining);
                    break;
                case WHEA_ERROR_TYPE.NMI:
                    NmiError = Marshal.PtrToStructure<WHEA_NMI_ERROR_SECTION>(sectionAddr + offset);
                    break;
                case WHEA_ERROR_TYPE.PCIExpress:
                    PciExpressError = new WHEA_PCIEXPRESS_ERROR_SECTION(sectionAddr + offset, (uint)offset, bytesRemaining);
                    break;
                case WHEA_ERROR_TYPE.PCIXBus:
                    PciXBusError = Marshal.PtrToStructure<WHEA_PCIXBUS_ERROR_SECTION>(sectionAddr + offset);
                    break;
                case WHEA_ERROR_TYPE.PCIXDevice:
                    PciXDeviceError = new WHEA_PCIXDEVICE_ERROR_SECTION(sectionAddr + offset, (uint)offset, bytesRemaining);
                    break;
                case WHEA_ERROR_TYPE.Pmem:
                    PmemError = new WHEA_PMEM_ERROR_SECTION(sectionAddr + offset, (uint)offset, bytesRemaining);
                    break;
                default:
                    var errMsg = $"{nameof(ErrorType)} is invalid: {ErrorType}";
                    throw new InvalidDataException(errMsg);
            }

            // Maximum previous structure size is 208 bytes (offset is 272)
            offset += 208;

            _RawDataFormat = (WHEA_RAW_DATA_FORMAT)Marshal.ReadInt32(sectionAddr, offset);

            RawDataOffset = (uint)Marshal.ReadInt32(sectionAddr, offset + 4);
            if (BaseStructSize + RawDataOffset > Size) {
                var errMsg = $"{nameof(RawDataOffset)} is beyond the end of the {nameof(RawData)} buffer: {BaseStructSize} + {RawDataOffset} > {Size}";
                throw new InvalidDataException(errMsg);
            }

            if (RawDataLength > 0) {
                RawData = new byte[RawDataLength];
                Marshal.Copy(sectionAddr + (int)RawDataOffset, RawData, 0, (int)RawDataLength);
            }

            FinalizeRecord(recordAddr, Size);
        }

        [UsedImplicitly]
        public static bool ShouldSerializeReserved1() => IsDebugBuild();

        [UsedImplicitly]
        public static bool ShouldSerializeReserved2() => IsDebugBuild();

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

    /*
     * Windows Server 2008 R2, Windows 7, and later
     *
     * Cannot be directly marshalled as a structure due to the usage of
     * variable length arrays, resulting in a non-static structure size.
     */
    internal sealed class WHEA_ERROR_PACKET_V2 : WheaErrorRecord {
        // Size up to and including the PshedDataLength field
        private const uint BaseStructSize = 80;

        public override uint GetNativeSize() => Length;

        internal const int WHEA_ERROR_PACKET_V2_VERSION = 3; // Not a typo

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

        [JsonProperty(Order = 3)]
        public uint Length; // TODO: Description & validation

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
        public string NotifyType => SectionTypes.TryGetValue(_NotifyType, out var NotifyTypeValue) ? NotifyTypeValue : _NotifyType.ToString();

        [JsonProperty(Order = 10)]
        public ulong Context;

        private WHEA_ERROR_PACKET_DATA_FORMAT _DataFormat;

        [JsonProperty(Order = 11)]
        public string DataFormat => Enum.GetName(typeof(WHEA_ERROR_PACKET_DATA_FORMAT), _DataFormat);

        [JsonProperty(Order = 12)]
        public uint Reserved1;

        [JsonProperty(Order = 13)]
        public uint DataOffset; // TODO: Description & validation

        [JsonProperty(Order = 14)]
        public uint DataLength; // TODO: Description & validation

        [JsonProperty(Order = 15)]
        public uint PshedDataOffset; // TODO: Description & validation

        [JsonProperty(Order = 16)]
        public uint PshedDataLength; // TODO: Description & validation

        [JsonProperty(Order = 17)]
        public byte[] Data;

        [JsonProperty(Order = 18)]
        public byte[] PshedData;

        public WHEA_ERROR_PACKET_V2(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(WHEA_ERROR_PACKET_V2), BaseStructSize, bytesRemaining) {
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            _Signature = (uint)Marshal.ReadInt32(sectionAddr);

            Version = (uint)Marshal.ReadInt32(sectionAddr, 4);
            if (Version != WHEA_ERROR_PACKET_V2_VERSION) {
                var errMsg = $"Expected {nameof(Version)} to be {WHEA_ERROR_PACKET_V2_VERSION} but found: {Version}";
                throw new InvalidDataException(errMsg);
            }

            Length = (uint)Marshal.ReadInt32(sectionAddr, 8);
            _Flags = (WHEA_ERROR_PACKET_FLAGS)Marshal.ReadInt32(sectionAddr, 12);
            _ErrorType = (WHEA_ERROR_TYPE)Marshal.ReadInt32(sectionAddr, 16);
            _ErrorSeverity = (WHEA_ERROR_SEVERITY)Marshal.ReadInt32(sectionAddr, 20);
            ErrorSourceId = (uint)Marshal.ReadInt32(sectionAddr, 24);
            _ErrorSourceType = (WHEA_ERROR_SOURCE_TYPE)Marshal.ReadInt32(sectionAddr, 28);
            var offset = 32;

            _NotifyType = Marshal.PtrToStructure<Guid>(sectionAddr + offset);
            offset += Marshal.SizeOf<Guid>();

            Context = (ulong)Marshal.ReadInt64(sectionAddr, offset);
            _DataFormat = (WHEA_ERROR_PACKET_DATA_FORMAT)Marshal.ReadInt32(sectionAddr, offset + 8);
            Reserved1 = (uint)Marshal.ReadInt32(sectionAddr, offset + 12);
            DataOffset = (uint)Marshal.ReadInt32(sectionAddr, offset + 16);
            DataLength = (uint)Marshal.ReadInt32(sectionAddr, offset + 20);
            PshedDataOffset = (uint)Marshal.ReadInt32(sectionAddr, offset + 24);
            PshedDataLength = (uint)Marshal.ReadInt32(sectionAddr, offset + 28);

            if (DataLength > 0) {
                Data = new byte[DataLength];
                Marshal.Copy(sectionAddr + (int)DataOffset, Data, 0, (int)DataLength);
            }

            if (PshedDataLength > 0) {
                PshedData = new byte[PshedDataLength];
                Marshal.Copy(sectionAddr + (int)PshedDataOffset, PshedData, 0, (int)PshedDataLength);
            }

            FinalizeRecord(recordAddr, Length);
        }

        [UsedImplicitly]
        public static bool ShouldSerializeReserved1() => IsDebugBuild();
    }

    // @formatter:int_align_fields true

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

    // @formatter:int_align_fields false
}
