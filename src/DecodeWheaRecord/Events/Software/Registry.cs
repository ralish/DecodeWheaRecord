#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Events.Software {
    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogRegistryKeyNotificationFailedEvent
     * Notes:           No payload
     */
    // TODO
    internal sealed class WHEA_REGISTER_KEY_NOTIFICATION_FAILED_EVENT : IWheaRecord {
        public uint GetNativeSize() => 0;
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheapOpenPolicyRegistryKey
     */
    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_REGISTRY_ERROR_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_REGISTRY_ERROR_EVENT>(); // 8 bytes

        private WHEA_REGISTRY_ERRORS _RegErr;

        [JsonProperty(Order = 1)]
        public string RegErr => Enum.GetName(typeof(WHEA_REGISTRY_ERRORS), _RegErr);

        [JsonProperty(Order = 2)]
        public uint Status; // TODO: Probably NTSTATUS?
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheaRegChangeNotifyCallback
     */
    // TODO
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEA_REGNOTIFY_POLICY_CHANGE_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_REGNOTIFY_POLICY_CHANGE_EVENT>(); // 40 bytes

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        public string PolicyName;

        public uint PolicyIndex;
        public uint PolicyValue;
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogThrottlingRegistryDataBeingIgnoredEvent
     */
    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_THROTTLE_REG_DATA_IGNORED_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_THROTTLE_REG_DATA_IGNORED_EVENT>(); // 4 bytes

        private WHEA_THROTTLE_TYPE _ThrottleType;

        [JsonProperty(Order = 1)]
        public string ThrottleType => Enum.GetName(typeof(WHEA_THROTTLE_TYPE), _ThrottleType);
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogThrottlingRegistryCorruptEvent
     */
    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT>(); // 4 bytes

        private WHEA_THROTTLE_TYPE _ThrottleType;

        [JsonProperty(Order = 1)]
        public string ThrottleType => Enum.GetName(typeof(WHEA_THROTTLE_TYPE), _ThrottleType);
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
