#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Events {
    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogRegistryKeyNotificationFailedEvent
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_REGISTER_KEY_NOTIFICATION_FAILED_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_REGISTER_KEY_NOTIFICATION_FAILED_EVENT>(); // 0 bytes
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheapOpenPolicyRegistryKey
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_REGISTRY_ERROR_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_REGISTRY_ERROR_EVENT>(); // 8 bytes

        private WHEA_REGISTRY_ERRORS _RegErr;

        [JsonProperty(Order = 1)]
        public string RegErr => Enum.GetName(typeof(WHEA_REGISTRY_ERRORS), _RegErr);

        [JsonProperty(Order = 2)]
        public uint Status;
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheaRegChangeNotifyCallback
     */
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEA_REGNOTIFY_POLICY_CHANGE_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_REGNOTIFY_POLICY_CHANGE_EVENT>(); // 40 bytes

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
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_THROTTLE_REG_DATA_IGNORED_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_THROTTLE_REG_DATA_IGNORED_EVENT>(); // 4 bytes

        private WHEA_THROTTLE_TYPE _ThrottleType;

        [JsonProperty(Order = 1)]
        public string ThrottleType => Enum.GetName(typeof(WHEA_THROTTLE_TYPE), _ThrottleType);
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogThrottlingRegistryCorruptEvent
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT>(); // 4 bytes

        private WHEA_THROTTLE_TYPE _ThrottleType;

        [JsonProperty(Order = 1)]
        public string ThrottleType => Enum.GetName(typeof(WHEA_THROTTLE_TYPE), _ThrottleType);
    }
}
