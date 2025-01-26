#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable InconsistentNaming

using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Events.Hardware {
    /*
     * Entry ID:        CpuBusesInitFailed
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogCpuBusesInitFailedEvent
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT>(); // 4 bytes

        private NtStatus _Status;

        [JsonProperty(Order = 1)]
        public string Status => GetEnumValueAsString<NtStatus>(_Status);
    }

    /*
     * Entry ID:        PshedPiCpuid
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipIsRunningInGuest
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PSHED_PI_CPUID : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_PSHED_PI_CPUID>(); // 20 bytes

        public uint CpuVendor;
        public uint CpuFamily;
        public uint CpuModel;
        public uint CpuStepping;
        public uint NumBanks;
    }

    /*
     * Entry ID:        CmcPollingTimeout
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     HalpCmcLogPollingTimeoutEvent
     * Notes:           Structure is not public
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_CMC_POLLING_TIMEOUT_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_CMC_POLLING_TIMEOUT_EVENT>(); // 24 bytes

        /*
         * Next five fields are equivalent to a KDPC_WATCHDOG_INFORMATION
         * structure.
         */

        public uint DpcTimeLimit;
        public uint DpcTimeCount;
        public uint DpcWatchdogLimit;
        public uint DpcWatchdogCount;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Reserved;

        public uint CmcPollCount;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    /*
     * Entry ID:        CmcSwitchToPolling
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     HalpCmciHandler
     * Notes:           Structure is not public
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_CMC_SWITCH_TO_POLLING_EVENT : IWheaRecord {
        public uint GetNativeSize() => 0;
    }

    /*
     * Entry ID:        CmciImplPresent
     * Module:          Unknown
     * Version:         Unknown
     * Function(s):     Unknown
     * Notes:           Unable to locate the responsible function in Windows
     *                  Server 2025.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_CMCI_IMPLEMENTED_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_CMCI_IMPLEMENTED_EVENT>(); // 1 byte

        [MarshalAs(UnmanagedType.U1)]
        public bool CmciAvailable;
    }

    /*
     * Entry ID:        CmciInitError
     * Module:          Unknown
     * Version:         Unknown
     * Function(s):     Unknown
     * Notes:           Unable to locate the responsible function in Windows
     *                  Server 2025.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_CMCI_INITERR_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_CMCI_INITERR_EVENT>(); // 20 bytes

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Msr;

        public uint Type;
        public uint Bank;
        public uint EpIndex;
    }

    /*
     * Entry ID:        CmciRestart & CmciFinalRestart
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     HalpCmcWorkerRoutine
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_CMCI_RESTART_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_CMCI_RESTART_EVENT>(); // 16 bytes

        public uint CmciRestoreAttempts;
        public uint MaxCmciRestoreLimit;
        public uint MaxCorrectedErrorsFound;
        public uint MaxCorrectedErrorLimit;
    }

    /*
     * Entry ID:        DroppedCorrectedError
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheaReportHwError
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_DROPPED_CORRECTED_ERROR_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_DROPPED_CORRECTED_ERROR_EVENT>(); // 8 bytes

        private WHEA_ERROR_SOURCE_TYPE _ErrorSourceType;

        [JsonProperty(Order = 1)]
        public string ErrorSourceType => GetEnumValueAsString<WHEA_ERROR_SOURCE_TYPE>(_ErrorSourceType);

        [JsonProperty(Order = 2)]
        public uint ErrorSourceId;
    }

    /*
     * Entry ID:        McaErrorCleared
     * Module:          Unknown
     * Version:         Unknown
     * Function(s):     Unknown
     * Notes:           Unable to locate the responsible function in Windows
     *                  Server 2025.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_ERROR_CLEARED_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_ERROR_CLEARED_EVENT>(); // 8 bytes

        public uint EpIndex;
        public uint Bank;
    }

    /*
     * Entry ID:        McaFoundErrorInBank
     * Module:          Unknown
     * Version:         Unknown
     * Function(s):     Unknown
     * Notes:           Unable to locate the responsible function in Windows
     *                  Server 2025.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_FOUND_ERROR_IN_BANK_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_FOUND_ERROR_IN_BANK_EVENT>(); // 20 bytes

        public uint EpIndex;
        public uint Bank;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MciStatus;

        public uint ErrorType; // TODO: Where are these defined?
    }

    /*
     * Entry ID:        McaStuckErrorCheck
     * Module:          Unknown
     * Version:         Unknown
     * Function(s):     Unknown
     * Notes:           Unable to locate the responsible function in Windows
     *                  Server 2025.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_STUCK_ERROR_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_STUCK_ERROR_EVENT>(); // 16 bytes

        public uint EpIndex;
        public uint Bank;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MciStatus;
    }
}
