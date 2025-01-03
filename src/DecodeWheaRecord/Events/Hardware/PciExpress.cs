#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Hardware;
using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using JetBrains.Annotations;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Events.Hardware {
    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogAddPcieDeviceFilterEvent
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_THROTTLE_PCIE_ADD_EVENT : WheaRecord {
        private const uint StructSize = 25;
        public override uint GetNativeSize() => StructSize;

        [JsonProperty(Order = 1)]
        public WHEA_PCIE_ADDRESS Address;

        [JsonProperty(Order = 2)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Mask;

        [JsonProperty(Order = 3)]
        public bool Updated;

        private readonly NtStatus _Status;

        [JsonProperty(Order = 4)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);

        public WHEA_THROTTLE_PCIE_ADD_EVENT(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_THROTTLE_PCIE_ADD_EVENT), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            Address = new WHEA_PCIE_ADDRESS(recordAddr, structOffset, bytesRemaining);
            Mask = (uint)Marshal.ReadInt32(structAddr, 16);
            Updated = Marshal.ReadByte(structAddr, 20) != 0;
            _Status = (NtStatus)Marshal.ReadInt32(structAddr, 21);

            FinalizeRecord(recordAddr, StructSize);
        }
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogRemovePcieDeviceFilterEvent
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_THROTTLE_PCIE_REMOVE_EVENT : WheaRecord {
        private const uint StructSize = 20;
        public override uint GetNativeSize() => StructSize;

        public WHEA_PCIE_ADDRESS Address;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Mask;

        public WHEA_THROTTLE_PCIE_REMOVE_EVENT(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_THROTTLE_PCIE_REMOVE_EVENT), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            Address = new WHEA_PCIE_ADDRESS(recordAddr, structOffset, bytesRemaining);
            Mask = (uint)Marshal.ReadInt32(structAddr, 16);

            FinalizeRecord(recordAddr, StructSize);
        }
    }

    /*
     * Module:          pci.sys
     * Version:         10.0.26100.2161
     * Function(s):     ExpressRootPortRecoveryReset
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_DPC_ERROR_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_DPC_ERROR_EVENT>(); // 20 bytes

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
    internal sealed class WHEAP_EDPC_ENABLED_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_EDPC_ENABLED_EVENT>(); // 2 bytes

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
    internal sealed class WHEAP_PCIE_CONFIG_INFO : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_PCIE_CONFIG_INFO>(); // 36 bytes

        public uint Segment;
        public uint Bus;
        public uint Device;
        public uint Function;
        public uint Offset;
        public uint Length;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Value;

        [MarshalAs(UnmanagedType.U1)]
        public bool Succeeded; // UINT8

        [JsonConverter(typeof(HexStringJsonConverter))]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        public byte[] Reserved;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved.Any(element => element != 0);
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipReadPcieAerOverrides
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PCIE_OVERRIDE_INFO : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_PCIE_OVERRIDE_INFO>(); // 36 bytes

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
        public bool ShouldSerializeReserved() => Reserved.Any(element => element != 0);
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipReadPcieAerOverrides
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PCIE_READ_OVERRIDES_ERR : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_PCIE_READ_OVERRIDES_ERR>(); // 8 bytes

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
    internal sealed class WHEAP_PROMOTED_AER_ERROR_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_PROMOTED_AER_ERROR_EVENT>(); // 24 bytes

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
    internal sealed class WHEAP_SPURIOUS_AER_EVENT : WheaRecord {
        private const uint StructSize = 24;
        public override uint GetNativeSize() => StructSize;

        private readonly WHEA_ERROR_SEVERITY _ErrorSeverity;

        [JsonProperty(Order = 1)]
        public string ErrorSeverity => Enum.GetName(typeof(WHEA_ERROR_SEVERITY), _ErrorSeverity);

        // Switched to an enumeration
        private readonly PCI_EXPRESS_DEVICE_TYPE _ErrorHandlerType; // WHEA_PCIEXPRESS_DEVICE_TYPE

        [JsonProperty(Order = 2)]
        public string ErrorHandlerType => Enum.GetName(typeof(PCI_EXPRESS_DEVICE_TYPE), _ErrorHandlerType);

        [JsonProperty(Order = 3)]
        public uint SpuriousErrorSourceId;

        [JsonProperty(Order = 4)]
        public uint RootErrorCommand;

        [JsonProperty(Order = 5)]
        public uint RootErrorStatus;

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint DeviceAssociationBitmap;

        public WHEAP_SPURIOUS_AER_EVENT(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEAP_SPURIOUS_AER_EVENT), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _ErrorSeverity = (WHEA_ERROR_SEVERITY)Marshal.ReadInt32(structAddr);
            _ErrorHandlerType = (PCI_EXPRESS_DEVICE_TYPE)Marshal.ReadInt32(structAddr, 4);

            if (_ErrorHandlerType != PCI_EXPRESS_DEVICE_TYPE.RootPort &&
                _ErrorHandlerType != PCI_EXPRESS_DEVICE_TYPE.DownstreamSwitchPort &&
                _ErrorHandlerType != PCI_EXPRESS_DEVICE_TYPE.RootComplexEventCollector) {
                var devTypeRp = Enum.GetName(typeof(PCI_EXPRESS_DEVICE_TYPE), PCI_EXPRESS_DEVICE_TYPE.RootPort);
                var devTypeDsp = Enum.GetName(typeof(PCI_EXPRESS_DEVICE_TYPE), PCI_EXPRESS_DEVICE_TYPE.DownstreamSwitchPort);
                var devTypeRcec = Enum.GetName(typeof(PCI_EXPRESS_DEVICE_TYPE), PCI_EXPRESS_DEVICE_TYPE.RootComplexEventCollector);
                var msg = $"{nameof(ErrorHandlerType)} is not valid for the event: {ErrorHandlerType} != ({devTypeRp} || {devTypeDsp} || {devTypeRcec})";
                throw new InvalidDataException(msg);
            }

            SpuriousErrorSourceId = (uint)Marshal.ReadInt32(structAddr, 8);
            RootErrorCommand = (uint)Marshal.ReadInt32(structAddr, 12);
            RootErrorStatus = (uint)Marshal.ReadInt32(structAddr, 16);
            DeviceAssociationBitmap = (uint)Marshal.ReadInt32(structAddr, 20);

            FinalizeRecord(recordAddr, StructSize);
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
