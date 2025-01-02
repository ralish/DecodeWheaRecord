#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Events {
    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogAddPcieDeviceFilterEvent
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_THROTTLE_PCIE_ADD_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_THROTTLE_PCIE_ADD_EVENT>(); // 25 bytes

        [JsonProperty(Order = 1)]
        public WHEA_PCIE_ADDRESS Address;

        [JsonProperty(Order = 2)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Mask;

        [JsonProperty(Order = 3)]
        [MarshalAs(UnmanagedType.U1)]
        public bool Updated;

        private NtStatus _Status;

        [JsonProperty(Order = 4)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogRemovePcieDeviceFilterEvent
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_THROTTLE_PCIE_REMOVE_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_THROTTLE_PCIE_REMOVE_EVENT>(); // 20 bytes

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Mask;
    }

    /*
     * Module:          pci.sys
     * Version:         10.0.26100.2161
     * Function(s):     ExpressRootPortRecoveryReset
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_DPC_ERROR_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_DPC_ERROR_EVENT>(); // 20 bytes

        private WHEAP_DPC_ERROR_EVENT_TYPE _ErrType;

        [JsonProperty(Order = 1)]
        public string ErrType => Enum.GetName(typeof(WHEAP_DPC_ERROR_EVENT_TYPE), _ErrType);

        [JsonProperty(Order = 2)]
        public uint Bus;

        [JsonProperty(Order = 3)]
        public uint Device;

        [JsonProperty(Order = 4)]
        public uint Function;

        [JsonProperty(Order = 5)]
        public ushort DeviceId;

        [JsonProperty(Order = 6)]
        public ushort VendorId;
    }

    /*
     * Module:          pci.sys
     * Version:         10.0.26100.2161
     * Function(s):     PciGetSystemWideHackFlagsFromRegistry
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_EDPC_ENABLED_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_EDPC_ENABLED_EVENT>(); // 2 bytes

        [MarshalAs(UnmanagedType.U1)]
        public bool eDPCEnabled;

        [MarshalAs(UnmanagedType.U1)]
        public bool eDPCRecovEnabled;
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipDoPcieConfig
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PCIE_CONFIG_INFO : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PCIE_CONFIG_INFO>(); // 36 bytes

        public uint Segment;
        public uint Bus;
        public uint Device;
        public uint Function;
        public uint Offset;
        public uint Length;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Value;

        [MarshalAs(UnmanagedType.U1)]
        public bool Succeeded; // Changed from byte

        [JsonConverter(typeof(HexStringJsonConverter))]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        public byte[] Reserved;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipReadPcieAerOverrides
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PCIE_OVERRIDE_INFO : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PCIE_OVERRIDE_INFO>(); // 36 bytes

        public uint Segment;
        public uint Bus;
        public uint Device;
        public uint Function;
        public byte ValidBits; // TODO: Where are these defined?

        [JsonConverter(typeof(HexStringJsonConverter))]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        public byte[] Reserved;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint UncorrectableErrorMask;

        public uint UncorrectableErrorSeverity;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint CorrectableErrorMask;

        public uint CapAndControl;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipReadPcieAerOverrides
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PCIE_READ_OVERRIDES_ERR : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PCIE_READ_OVERRIDES_ERR>(); // 8 bytes

        private PSHED_PI_ERR_READING_PCIE_OVERRIDES _FailureReason;

        [JsonProperty(Order = 1)]
        public string FailureReason => Enum.GetName(typeof(PSHED_PI_ERR_READING_PCIE_OVERRIDES), _FailureReason);

        private NtStatus _FailureStatus;

        [JsonProperty(Order = 2)]
        public string FailureStatus => Enum.GetName(typeof(NtStatus), _FailureStatus);
    }

    /*
     * Module:          pci.sys
     * Version:         10.0.26100.2161
     * Function(s):     PciPromoteAerError
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PROMOTED_AER_ERROR_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PROMOTED_AER_ERROR_EVENT>(); // 24 bytes

        private WHEA_ERROR_SEVERITY _ErrorSeverity;

        [JsonProperty(Order = 1)]
        public string ErrorSeverity => Enum.GetName(typeof(WHEA_ERROR_SEVERITY), _ErrorSeverity);

        [JsonProperty(Order = 2)]
        public uint ErrorHandlerType;

        [JsonProperty(Order = 3)]
        public uint ErrorSourceId;

        [JsonProperty(Order = 4)]
        public uint RootErrorCommand;

        [JsonProperty(Order = 5)]
        public uint RootErrorStatus;

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint DeviceAssociationBitmap;
    }

    /*
     * Module:          pci.sys
     * Version:         10.0.26100.2161
     * Function(s):     PciWheaReportSpuriousError
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_SPURIOUS_AER_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_SPURIOUS_AER_EVENT>(); // 24 bytes

        private WHEA_ERROR_SEVERITY _ErrorSeverity;

        [JsonProperty(Order = 1)]
        public string ErrorSeverity => Enum.GetName(typeof(WHEA_ERROR_SEVERITY), _ErrorSeverity);

        private WHEA_PCIEXPRESS_DEVICE_TYPE _ErrorHandlerType;

        [JsonProperty(Order = 2)]
        public string ErrorHandlerType => Enum.GetName(typeof(WHEA_PCIEXPRESS_DEVICE_TYPE), _ErrorHandlerType);

        [JsonProperty(Order = 3)]
        public uint SpuriousErrorSourceId;

        [JsonProperty(Order = 4)]
        public uint RootErrorCommand;

        [JsonProperty(Order = 5)]
        public uint RootErrorStatus;

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint DeviceAssociationBitmap;

        // TODO: Do this in a constructor?
        public override void Validate() {
            if (_ErrorHandlerType != WHEA_PCIEXPRESS_DEVICE_TYPE.RootPort &&
                _ErrorHandlerType != WHEA_PCIEXPRESS_DEVICE_TYPE.DownstreamSwitchPort &&
                _ErrorHandlerType != WHEA_PCIEXPRESS_DEVICE_TYPE.RootComplexEventCollector) {
                var cat = $"{nameof(WHEAP_SPURIOUS_AER_EVENT)}.{nameof(ErrorHandlerType)}";
                DebugOutput("Not RootPort, DownstreamSwitchPort, or RootComplexEventCollector.", cat);
            }
        }
    }

    // @formatter:int_align_fields true

    internal enum PSHED_PI_ERR_READING_PCIE_OVERRIDES : uint {
        NoErr        = 0,
        NoMemory     = 1,
        QueryErr     = 2,
        BadSize      = 3,
        BadSignature = 4,
        NoCapOffset  = 5,
        NotBinary    = 6
    }

    internal enum WHEAP_DPC_ERROR_EVENT_TYPE : uint {
        NoErr        = 0,
        BusNotFound  = 1,
        DpcedSubtree = 2,
        DeviceIdBad  = 3,
        ResetFailed  = 4,
        NoChildren   = 5
    }

    // @formatter:int_align_fields false
}
