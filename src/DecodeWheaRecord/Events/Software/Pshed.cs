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
     * Entry ID:        PshedPiTraceLog
     * Module:          Unknown
     * Version:         Unknown
     * Function(s):     Unknown
     * Notes:           Unable to locate the responsible function in Windows
     *                  Server 2025.
     */
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEA_PSHED_PI_TRACE_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_PSHED_PI_TRACE_EVENT>(); // 256 bytes

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        private string _Buffer;

        [JsonProperty(Order = 1)]
        public string Buffer => _Buffer.Trim('\0').Trim();
    }

    /*
     * Entry ID:        EnableKeyNotifFailed
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogEnableRegistryKeyNotifyFailedEvent
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_FAILED_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_FAILED_EVENT>(); // 4 bytes

        private WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_ERRORS _EnableError;

        [JsonProperty(Order = 1)]
        public string EnableError => GetEnumValueAsString<WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_ERRORS>(_EnableError);
    }

    /*
     * Entry ID:        WheaHeartbeat
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipHeartbeatDeferredRoutine
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PSHED_PLUGIN_HEARTBEAT : IWheaRecord {
        public uint GetNativeSize() => 0;
    }

    /*
     * Entry ID:        PshedPluginInitFailed
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogInitFailedEvent
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PSHED_PLUGIN_INIT_FAILED_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_PSHED_PLUGIN_INIT_FAILED_EVENT>(); // 4 bytes

        private NtStatus _Status;

        [JsonProperty(Order = 1)]
        public string Status => GetEnumValueAsString<NtStatus>(_Status);
    }

    /*
     * Entry ID:        PshedPluginLoad
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogLoadEvent
     */
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
    internal sealed class WHEA_PSHED_PLUGIN_LOAD_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_PSHED_PLUGIN_LOAD_EVENT>(); // 72 bytes

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WHEA_EVENT_LOG_ENTRY.WHEA_ERROR_TEXT_LEN)]
        private string _PluginName;

        [JsonProperty(Order = 1)]
        public string PluginName => _PluginName.Trim('\0').Trim();

        [JsonProperty(Order = 2)]
        public uint MajorVersion;

        [JsonProperty(Order = 3)]
        public uint MinorVersion;
    }

    /*
     * Entry ID:        PshedPluginSupported
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogPlatformSupportedEvent
     */
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
    internal sealed class WHEA_PSHED_PLUGIN_PLATFORM_SUPPORT_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_PSHED_PLUGIN_PLATFORM_SUPPORT_EVENT>(); // 65 bytes

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WHEA_EVENT_LOG_ENTRY.WHEA_ERROR_TEXT_LEN)]
        private string _PluginName;

        [JsonProperty(Order = 1)]
        public string PluginName => _PluginName.Trim('\0').Trim();

        [JsonProperty(Order = 2)]
        [MarshalAs(UnmanagedType.U1)]
        public bool Supported;
    }

    /*
     * Entry ID:        PshedPluginUnload
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogUnloadEvent
     */
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
    internal sealed class WHEA_PSHED_PLUGIN_UNLOAD_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_PSHED_PLUGIN_UNLOAD_EVENT>(); // 64 bytes

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WHEA_EVENT_LOG_ENTRY.WHEA_ERROR_TEXT_LEN)]
        private string _PluginName;

        [JsonProperty(Order = 1)]
        public string PluginName => _PluginName.Trim('\0').Trim();
    }

    /*
     * Entry ID:        PshedCallbackCollision
     * Module:          pshed.dll
     * Version:         10.0.26100.1150
     * Function(s):     PshedpLogRegistrationCollision
     * Notes:           Structure is not public
     */
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
    internal sealed class WHEAP_PSHED_PLUGIN_CALLBACK_COLLISION : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_PSHED_PLUGIN_CALLBACK_COLLISION>(); // 64 bytes

        // Name of the plugin which was not loaded due to callback collision
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WHEA_EVENT_LOG_ENTRY.WHEA_ERROR_TEXT_LEN)]
        private string _PluginName;

        [JsonProperty(Order = 1)]
        public string PluginName => _PluginName.Trim('\0').Trim();
    }

    /*
     * Entry ID:        PshedInjectError
     * Module:          pshed.dll
     * Version:         10.0.26100.1150
     * Function(s):     PshedInjectError
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PSHED_INJECT_ERROR : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_PSHED_INJECT_ERROR>(); // 42 bytes

        [JsonProperty(Order = 1)]
        public uint ErrorType;

        [JsonProperty(Order = 2)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Parameter1;

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Parameter2;

        [JsonProperty(Order = 4)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Parameter3;

        [JsonProperty(Order = 5)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Parameter4;

        private NtStatus _InjectionStatus;

        [JsonProperty(Order = 6)]
        public string InjectionStatus => GetEnumValueAsString<NtStatus>(_InjectionStatus);

        [JsonProperty(Order = 7)]
        [MarshalAs(UnmanagedType.U1)]
        public bool InjectionAttempted;

        [JsonProperty(Order = 8)]
        [MarshalAs(UnmanagedType.U1)]
        public bool InjectionByPlugin;
    }

    /*
     * Entry ID:        PshedPluginRegister
     * Module:          pshed.dll
     * Version:         10.0.26100.1150
     * Function(s):     PshedRegisterPlugin
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PSHED_PLUGIN_REGISTER : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_PSHED_PLUGIN_REGISTER>(); // 16 bytes

        /*
         * Version of the WHEA_PSHED_PLUGIN_REGISTRATION_PACKET structure used
         * to register the PSHED plugin (not the version of this structure).
         */
        [JsonProperty(Order = 1)]
        public uint Version;

        /*
         * Length of the WHEA_PSHED_PLUGIN_REGISTRATION_PACKET structure used
         * to register the PSHED plugin (not the length of this structure).
         */
        [JsonProperty(Order = 2)]
        public uint Length;

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint FunctionalAreaMask;

        private NtStatus _Status;

        [JsonProperty(Order = 4)]
        public string Status => GetEnumValueAsString<NtStatus>(_Status);
    }

    // @formatter:int_align_fields true

    internal enum WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_ERRORS : uint {
        CreateNotifyEvent  = 1,
        CreateSystemThread = 2
    }

    // @formatter:int_align_fields false
}
