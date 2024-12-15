#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Shared;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Events {
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT>();

        private NtStatus _Status;

        [JsonProperty(Order = 1)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PSHED_PI_CPUID : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_PSHED_PI_CPUID>();

        public uint CpuVendor;
        public uint CpuFamily;
        public uint CpuModel;
        public uint CpuStepping;
        public uint NumBanks;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEA_PSHED_PI_TRACE_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_PSHED_PI_TRACE_EVENT>();

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string Buffer;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PSHED_PLUGIN_DIMM_MISMATCH : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_PSHED_PLUGIN_DIMM_MISMATCH>();

        public ushort FirmwareBank;
        public ushort FirmwareCol;
        public ushort FirmwareRow;
        public ushort RetryRdBank;
        public ushort RetryRdCol;
        public ushort RetryRdRow;
        public ushort TaBank;
        public ushort TaCol;
        public ushort TaRow;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_FAILED_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_FAILED_EVENT>();

        private WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_ERRORS _EnableError;

        [JsonProperty(Order = 1)]
        public string EnableError => Enum.GetName(typeof(WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_ERRORS), _EnableError);
    }

    // Deliberately empty (no payload)
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PSHED_PLUGIN_HEARTBEAT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_PSHED_PLUGIN_HEARTBEAT>();
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PSHED_PLUGIN_INIT_FAILED_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_PSHED_PLUGIN_INIT_FAILED_EVENT>();

        private NtStatus _Status;

        [JsonProperty(Order = 1)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
    internal sealed class WHEA_PSHED_PLUGIN_LOAD_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_PSHED_PLUGIN_LOAD_EVENT>();

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        public string PluginName;

        public uint MajorVersion;
        public uint MinorVersion;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
    internal sealed class WHEA_PSHED_PLUGIN_PLATFORM_SUPPORT_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_PSHED_PLUGIN_PLATFORM_SUPPORT_EVENT>();

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        public string PluginName;

        [MarshalAs(UnmanagedType.U1)]
        public bool Supported;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
    internal sealed class WHEA_PSHED_PLUGIN_UNLOAD_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_PSHED_PLUGIN_UNLOAD_EVENT>();

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        public string PluginName;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PSHED_INJECT_ERROR : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PSHED_INJECT_ERROR>();

        [JsonProperty(Order = 1)]
        public uint ErrorType;

        [JsonProperty(Order = 2)]
        public ulong Parameter1;

        [JsonProperty(Order = 3)]
        public ulong Parameter2;

        [JsonProperty(Order = 4)]
        public ulong Parameter3;

        [JsonProperty(Order = 5)]
        public ulong Parameter4;

        private NtStatus _InjectionStatus;

        [JsonProperty(Order = 6)]
        public string InjectionStatus => Enum.GetName(typeof(NtStatus), _InjectionStatus);

        [JsonProperty(Order = 7)]
        [MarshalAs(UnmanagedType.U1)]
        public bool InjectionAttempted;

        [JsonProperty(Order = 8)]
        [MarshalAs(UnmanagedType.U1)]
        public bool InjectionByPlugin;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PSHED_PLUGIN_REGISTER : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PSHED_PLUGIN_REGISTER>();

        [JsonProperty(Order = 1)]
        public uint Version; // TODO: Validate

        [JsonProperty(Order = 2)]
        public uint Length; // TODO: Description & validation

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint FunctionalAreaMask;

        private NtStatus _Status;

        [JsonProperty(Order = 4)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);
    }

    // @formatter:int_align_fields true

    internal enum WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_ERRORS : uint {
        CreateNotifyEvent  = 1,
        CreateSystemThread = 2
    }

    // @formatter:int_align_fields false
}
