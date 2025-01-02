#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Errors.Microsoft {
    // Structure size: 3 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCI_RECOVERY_SECTION : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_PCI_RECOVERY_SECTION>();

        private WHEA_PCI_RECOVERY_SIGNAL _SignalType;

        [JsonProperty(Order = 1)]
        public string SignalType => Enum.GetName(typeof(WHEA_PCI_RECOVERY_SIGNAL), _SignalType);

        [JsonProperty(Order = 2)]
        [MarshalAs(UnmanagedType.U1)]
        public bool RecoveryAttempted;

        private WHEA_PCI_RECOVERY_STATUS _RecoveryStatus;

        [JsonProperty(Order = 3)]
        public string RecoveryStatus => Enum.GetName(typeof(WHEA_PCI_RECOVERY_STATUS), _RecoveryStatus);
    }

    // @formatter:int_align_fields true

    internal enum WHEA_PCI_RECOVERY_SIGNAL : byte {
        Unknown = 0,
        Aer     = 1,
        Dpc     = 2
    }

    internal enum WHEA_PCI_RECOVERY_STATUS : byte {
        Unknown              = 0,
        NoError              = 1,
        LinkDisableTimeout   = 2,
        LinkEnableTimeout    = 3,
        RpBusyTimeout        = 4,
        ComplexTree          = 5,
        BusNotFound          = 6,
        DeviceNotFound       = 7,
        DdaAerNotRecoverable = 8,
        FailedRecovery       = 9
    }

    // @formatter:int_align_fields false
}
