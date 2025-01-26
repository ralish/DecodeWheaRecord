#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable InconsistentNaming

using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Events.Software {
    /*
     * Entry ID:        KeyNotificationFailed
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogRegistryKeyNotificationFailedEvent
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_REGISTER_KEY_NOTIFICATION_FAILED_EVENT : IWheaRecord {
        public uint GetNativeSize() => 0;
    }

    /*
     * Entry ID:        RegError
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheapOpenPolicyRegistryKey
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_REGISTRY_ERROR_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_REGISTRY_ERROR_EVENT>(); // 8 bytes

        private WHEA_REGISTRY_ERRORS _RegErr;

        [JsonProperty(Order = 1)]
        public string RegErr => GetEnumValueAsString<WHEA_REGISTRY_ERRORS>(_RegErr);

        // Originally defined as a UINT32 but verified to be an NTSTATUS
        private NtStatus _Status;

        [JsonProperty(Order = 2)]
        public string Status => GetEnumValueAsString<NtStatus>(_Status);
    }

    /*
     * Entry ID:        RegNotifyPolicyChange
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheaRegChangeNotifyCallback
     */
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEA_REGNOTIFY_POLICY_CHANGE_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_REGNOTIFY_POLICY_CHANGE_EVENT>(); // 40 bytes

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WHEA_EVENT_LOG_ENTRY.WHEA_ERROR_TEXT_LEN)]
        public string PolicyName;

        public uint PolicyIndex;
        public uint PolicyValue;
    }

    /*
     * Entry ID:        ThrottleRegDataIgnored
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogThrottlingRegistryDataBeingIgnoredEvent
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_THROTTLE_REG_DATA_IGNORED_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_THROTTLE_REG_DATA_IGNORED_EVENT>(); // 4 bytes

        private WHEA_THROTTLE_TYPE _ThrottleType;

        [JsonProperty(Order = 1)]
        public string ThrottleType => GetEnumValueAsString<WHEA_THROTTLE_TYPE>(_ThrottleType);
    }

    /*
     * Entry ID:        ThrottleRegCorrupt
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogThrottlingRegistryCorruptEvent
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT>(); // 4 bytes

        private WHEA_THROTTLE_TYPE _ThrottleType;

        [JsonProperty(Order = 1)]
        public string ThrottleType => GetEnumValueAsString<WHEA_THROTTLE_TYPE>(_ThrottleType);
    }

    // @formatter:int_align_fields true

    internal enum WHEA_REGISTRY_ERRORS : uint {
        None            = 0,
        CreateWheaKey   = 1,
        CreatePolicyKey = 2,
        OpenHandle      = 3
    }

    internal enum WHEA_THROTTLE_TYPE : uint {
        Pcie   = 0,
        Memory = 1
    }

    // @formatter:int_align_fields false
}
