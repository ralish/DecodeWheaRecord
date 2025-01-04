#pragma warning disable CS0649 // Field is never assigned to

// ReSharper disable InconsistentNaming

using System;
using System.Linq;
using System.Runtime.InteropServices;
using DecodeWheaRecord.Events.Hardware;
using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;
using JetBrains.Annotations;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Events.Software {
    /*
     * Module:          crashdmp.sys
     * Version:         10.0.26100.1882
     * Function(s):     CrashdmpLogSELCheckpoint_ULONG1
     */
    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_CRASHDUMP_EVENT_LOG_ENTRY_ULONG1 : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_GAS_ERROR_EVENT>(); // 4 bytes

        public uint Value;
    }

    /*
     * Module:          crashdmp.sys
     * Version:         10.0.26100.1882
     * Function(s):     CrashdmpLogSELError
     */
    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_CRASHDUMP_EVENT_LOG_ENTRY_WITH_STATUS : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_GAS_ERROR_EVENT>(); // 8 bytes

        [JsonProperty(Order = 1)]
        public uint SourceLocationId;

        private NtStatus _Status;

        [JsonProperty(Order = 2)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     IoSaveBugCheckProgress
     */
    // TODO
    // TODO: Not certain about above function
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_SEL_BUGCHECK_PROGRESS : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_SEL_BUGCHECK_PROGRESS>(); // 8 bytes

        public uint BugCheckCode;
        public uint BugCheckProgressSummary;
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     IoSaveBugCheckProgress
     */
    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_SEL_BUGCHECK_RECOVERY_STATUS_MULTIPLE_BUGCHECK_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_SEL_BUGCHECK_PROGRESS>(); // 3 bytes

        [MarshalAs(UnmanagedType.U1)]
        public bool IsBugcheckOwner;

        public byte RecursionCount;

        [MarshalAs(UnmanagedType.U1)]
        public bool IsBugcheckRecoveryOwner;
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     IoSaveBugCheckProgress
     */
    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE1_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_SEL_BUGCHECK_PROGRESS>(); // 8 bytes

        private const uint WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE1_VERSION = 1;

        [MarshalAs(UnmanagedType.U1)]
        public bool Success;

        public byte Version; // TODO: Should always be 1
        public ushort EntryCount;

        /*
         * Version 1 information
         */

        public byte DumpPolicy;

        [JsonConverter(typeof(HexStringJsonConverter))]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        public byte[] Reserved;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved.Any(element => element != 0);
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     IoSaveBugCheckProgress
     */
    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE2_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_SEL_BUGCHECK_PROGRESS>(); // 5 bytes

        public uint BootId;

        [MarshalAs(UnmanagedType.U1)]
        public bool Success;
    }

    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_SEL_BUGCHECK_RECOVERY_STATUS_START_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_SEL_BUGCHECK_RECOVERY_STATUS_START_EVENT>(); // 1 byte

        public byte StartingIrql; // KIRQL
    }
}
