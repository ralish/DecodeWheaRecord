#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming
// ReSharper disable MemberCanBePrivate.Global

using System;
using System.Runtime.InteropServices;
using System.Text;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.NativeMethods;
using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors {
    internal static class WHEA_ERROR_PACKET {
        /*
         * Reversed from what is defined in the header as we perform validation
         * against the member as an ASCII string instead of a ULONG.
         */
        internal const string WHEA_ERROR_PACKET_V1_SIGNATURE = "ErPt";
        internal const string WHEA_ERROR_PACKET_V2_SIGNATURE = "WHEA";

        public static WheaRecord CreateBySignature(IntPtr recordAddr, WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc) {
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;
            var signatureBytes = BitConverter.GetBytes((uint)Marshal.ReadInt32(sectionAddr));
            var signature = Encoding.ASCII.GetString(signatureBytes);

            switch (signature) {
                case WHEA_ERROR_PACKET_V1_SIGNATURE:
                    return new WHEA_ERROR_PACKET_V1(recordAddr, sectionDsc);
                case WHEA_ERROR_PACKET_V2_SIGNATURE:
                    return new WHEA_ERROR_PACKET_V2(recordAddr, sectionDsc);
                default:
                    throw new ArgumentOutOfRangeException($"[{nameof(WHEA_ERROR_PACKET)}] Unexpected signature: {signature}");
            }
        }
    }

    /*
     * Windows Server 2008 & Windows Vista SP1+
     */
    internal sealed class WHEA_ERROR_PACKET_V1 : WheaRecord {
        /*
         * Reversed from what is defined in the header as we perform validation
         * against the member as an ASCII string instead of a ULONG.
         */
        internal const string WHEA_ERROR_PACKET_V1_SIGNATURE = "ErPt";

        internal const int WHEA_ERROR_PACKET_V1_VERSION = 2; // Not a typo

        internal override int GetNativeSize() => (int)Size;

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
         * Size of the hardware error packet (this structure), including
         * the raw data (see the RawDataLength member).
         */
        [JsonProperty(Order = 3)]
        public uint Size; // TODO: Validate

        /*
         * Length of the raw hardware error information contained in the
         * RawData member.
         */
        [JsonProperty(Order = 4)]
        public uint RawDataLength; // TODO: Validate

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
         * Offset from the beginning of the RawData data buffer where a
         * PSHED plug-in can add supplementary platform-specific data. The
         * amount of data that can be added is limited by the Size member.
         */
        [JsonProperty(Order = 22)]
        public uint RawDataOffset; // TODO: Validate

        [JsonProperty(Order = 23)]
        public byte[] RawData;

        public WHEA_ERROR_PACKET_V1(IntPtr recordAddr, WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc) {
            DebugOutputPre(typeof(WHEA_ERROR_PACKET_V1), sectionDsc);
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            _Signature = (uint)Marshal.ReadInt32(sectionAddr);
            if (Signature != WHEA_ERROR_PACKET_V1_SIGNATURE) {
                var msg = $"[{nameof(WHEA_ERROR_PACKET_V1)}] Expected signature \"{WHEA_ERROR_PACKET_V1_SIGNATURE}\" but Signature member is: {Signature}";
                ExitWithMessage(msg, 2);
            }

            _Flags = (WHEA_ERROR_PACKET_FLAGS)Marshal.ReadInt32(sectionAddr, 4);
            Size = (uint)Marshal.ReadInt32(sectionAddr, 8);
            RawDataLength = (uint)Marshal.ReadInt32(sectionAddr, 12);
            Reserved1 = (ulong)Marshal.ReadInt64(sectionAddr, 16);
            Context = (ulong)Marshal.ReadInt64(sectionAddr, 24);
            _ErrorType = (WHEA_ERROR_TYPE)Marshal.ReadInt32(sectionAddr, 32);
            _ErrorSeverity = (WHEA_ERROR_SEVERITY)Marshal.ReadInt32(sectionAddr, 36);
            ErrorSourceId = (uint)Marshal.ReadInt32(sectionAddr, 40);
            _ErrorSourceType = (WHEA_ERROR_SOURCE_TYPE)Marshal.ReadInt32(sectionAddr, 44);
            Reserved2 = (uint)Marshal.ReadInt32(sectionAddr, 48);

            Version = (uint)Marshal.ReadInt32(sectionAddr, 52);
            if (Version != WHEA_ERROR_PACKET_V1_VERSION) {
                var msg = $"[{nameof(WHEA_ERROR_PACKET_V1)}] Expected version {WHEA_ERROR_PACKET_V1_VERSION} but Version member is: {Version}";
                ExitWithMessage(msg, 2);
            }

            Cpu = (ulong)Marshal.ReadInt64(sectionAddr, 56);
            var offset = 64;

            switch (_ErrorType) {
                case WHEA_ERROR_TYPE.Processor:
                    ProcessorError = new WHEA_PROCESSOR_GENERIC_ERROR_SECTION(sectionAddr + offset);
                    break;
                case WHEA_ERROR_TYPE.Memory:
                    MemoryError = Marshal.PtrToStructure<WHEA_MEMORY_ERROR_SECTION>(sectionAddr + offset);
                    break;
                case WHEA_ERROR_TYPE.NMI:
                    NmiError = Marshal.PtrToStructure<WHEA_NMI_ERROR_SECTION>(sectionAddr + offset);
                    break;
                case WHEA_ERROR_TYPE.PCIExpress:
                    PciExpressError = new WHEA_PCIEXPRESS_ERROR_SECTION(sectionAddr + offset);
                    break;
                case WHEA_ERROR_TYPE.PCIXBus:
                    PciXBusError = Marshal.PtrToStructure<WHEA_PCIXBUS_ERROR_SECTION>(sectionAddr + offset);
                    break;
                case WHEA_ERROR_TYPE.PCIXDevice:
                    PciXDeviceError = new WHEA_PCIXDEVICE_ERROR_SECTION(sectionAddr + offset);
                    break;
                case WHEA_ERROR_TYPE.Pmem:
                    PmemError = new WHEA_PMEM_ERROR_SECTION(sectionAddr + offset);
                    break;
            }

            // Offset is always 272 (maximum size of previous structure)
            offset += 208;

            _RawDataFormat = (WHEA_RAW_DATA_FORMAT)Marshal.ReadInt32(sectionAddr, offset);
            RawDataOffset = (uint)Marshal.ReadInt32(sectionAddr, offset + 4);

            if (RawDataLength > 0) {
                RawData = new byte[RawDataLength];
                Marshal.Copy(sectionAddr + (int)RawDataOffset, RawData, 0, (int)RawDataLength);
            }

            DebugOutputPost(typeof(WHEA_ERROR_PACKET_V1), sectionDsc, (int)Size);
        }

        [UsedImplicitly]
        public static bool ShouldSerializeReserved1() => IsDebugBuild();

        [UsedImplicitly]
        public static bool ShouldSerializeReserved2() => IsDebugBuild();

        [UsedImplicitly]
        public bool ShouldSerializeProcessorError() {
            return _ErrorType == WHEA_ERROR_TYPE.Processor;
        }

        [UsedImplicitly]
        public bool ShouldSerializeMemoryError() {
            return _ErrorType == WHEA_ERROR_TYPE.Memory;
        }

        [UsedImplicitly]
        public bool ShouldSerializeNmiError() {
            return _ErrorType == WHEA_ERROR_TYPE.NMI;
        }

        [UsedImplicitly]
        public bool ShouldSerializePciExpressError() {
            return _ErrorType == WHEA_ERROR_TYPE.PCIExpress;
        }

        [UsedImplicitly]
        public bool ShouldSerializePciXBusError() {
            return _ErrorType == WHEA_ERROR_TYPE.PCIXBus;
        }

        [UsedImplicitly]
        public bool ShouldSerializePciXDeviceError() {
            return _ErrorType == WHEA_ERROR_TYPE.PCIXDevice;
        }

        [UsedImplicitly]
        public bool ShouldSerializePmemError() {
            return _ErrorType == WHEA_ERROR_TYPE.Pmem;
        }
    }

    /*
     * Windows Server 2008 R2, Windows Vista 7, and later
     */
    internal sealed class WHEA_ERROR_PACKET_V2 : WheaRecord {
        /*
         * Reversed from what is defined in the header as we perform validation
         * against the member as an ASCII string instead of a ULONG.
         */
        internal const string WHEA_ERROR_PACKET_V2_SIGNATURE = "WHEA";

        internal const int WHEA_ERROR_PACKET_V2_VERSION = 3; // Not a typo

        internal override int GetNativeSize() => (int)Length;

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

        // TODO: Description & validation
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
        public string NotifyType => SectionTypes.TryGetValue(_NotifyType, out var NotifyTypeValue) ? NotifyTypeValue : _NotifyType.ToString();

        [JsonProperty(Order = 10)]
        public ulong Context;

        private WHEA_ERROR_PACKET_DATA_FORMAT _DataFormat;

        [JsonProperty(Order = 11)]
        public string DataFormat => Enum.GetName(typeof(WHEA_ERROR_PACKET_DATA_FORMAT), _DataFormat);

        [JsonProperty(Order = 12)]
        public uint Reserved1;

        // TODO: Description & validation
        [JsonProperty(Order = 13)]
        public uint DataOffset;

        // TODO: Description & validation
        [JsonProperty(Order = 14)]
        public uint DataLength;

        // TODO: Description & validation
        [JsonProperty(Order = 15)]
        public uint PshedDataOffset;

        // TODO: Description & validation
        [JsonProperty(Order = 16)]
        public uint PshedDataLength;

        [JsonProperty(Order = 17)]
        public byte[] Data;

        [JsonProperty(Order = 18)]
        public byte[] PshedData;

        public WHEA_ERROR_PACKET_V2(IntPtr recordAddr, WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc) {
            DebugOutputPre(typeof(WHEA_ERROR_PACKET_V2), sectionDsc);
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            _Signature = (uint)Marshal.ReadInt32(sectionAddr);
            if (Signature != WHEA_ERROR_PACKET_V2_SIGNATURE) {
                var msg = $"[{nameof(WHEA_ERROR_PACKET_V2)}] Expected signature \"{WHEA_ERROR_PACKET_V2_SIGNATURE}\" but Signature member is: {Signature}";
                ExitWithMessage(msg, 2);
            }

            Version = (uint)Marshal.ReadInt32(sectionAddr, 4);
            if (Version != WHEA_ERROR_PACKET_V2_VERSION) {
                var msg = $"[{nameof(WHEA_ERROR_PACKET_V2)}] Expected version {WHEA_ERROR_PACKET_V2_VERSION} but Version member is: {Version}";
                ExitWithMessage(msg, 2);
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

            DebugOutputPost(typeof(WHEA_ERROR_PACKET_V2), sectionDsc, (int)Length);
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
