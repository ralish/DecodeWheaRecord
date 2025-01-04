#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Errors;
using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Events {
    /*
     * HalpCmciHandler -> CmcSwitchToPolling (0 bytes)
     * KiBugCheckProgressCpusFrozen -> CpusFrozen (0 bytes)
     * WheaRemoveErrorSourceDeviceDriver -> DrvHandleBusy (32 bytes)
     * WheaReportHwError -> EarlyError (0 bytes)
     * WheapTrackPendingPage -> PageOfflinePendMax (0 bytes)
     *
     * TODO -> hal (now krnl)
     * HalpCmcLogPollingTimeoutEvent -> CmcPollingTimeout (24 bytes)
     * HalpCmcWorkerRoutine
     *
     * TODO -> krnl
     * PspVsmLogBugCheckCallback -> SELBugCheckStackDump (256 bytes)
     * WheapCreateRecordFromGenericErrorData -> CreateGenericRecord
     * WheaPersistentBadPageToRegistry -> BadPageLimitReached
     * WheapExecuteRowFailureCheck -> SrasTableEntries
     * WheapInitErrorReportDeviceDriver -> DrvErrSrcInvalid, DrvHandleBusy
     * WheapLogInitEvent -> WheaInit
     *
     * AzPshedPi.sys
     * PshedPipReportAllPcieErrorSummary -> PcieSummaryFailed (25 bytes)
     * PshedPipWriteSelEvent -> ??? (16 bytes)
     */


    internal static class Shared {
        internal const int WHEA_ERROR_TEXT_LEN = 32;
    }

    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_FOUND_ERROR_IN_BANK_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_FOUND_ERROR_IN_BANK_EVENT>(); // 20 bytes

        public uint EpIndex;
        public uint Bank;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MciStatus;

        public uint ErrorType;
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     KiMcheckAlternateReturn
     */
    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_SRAR_DETAIL_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_SRAR_DETAIL_EVENT>(); // 17 bytes

        [JsonProperty(Order = 1)]
        public uint RecoveryContextFlags;

        [JsonProperty(Order = 2)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong RecoveryContextPa;

        private NtStatus _PageOfflineStatus;

        [JsonProperty(Order = 3)]
        public string PageOfflineStatus => Enum.GetName(typeof(NtStatus), _PageOfflineStatus);

        [JsonProperty(Order = 4)]
        [MarshalAs(UnmanagedType.U1)]
        public bool KernelConsumerError;
    }

    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_CMCI_IMPLEMENTED_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_CMCI_IMPLEMENTED_EVENT>(); // 1 byte

        [MarshalAs(UnmanagedType.U1)]
        public bool CmciAvailable;
    }

    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_CMCI_INITERR_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_CMCI_INITERR_EVENT>(); // 20 bytes

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Msr;

        public uint Type;
        public uint Bank;
        public uint EpIndex;
    }

    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_CMCI_RESTART_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_CMCI_RESTART_EVENT>(); // 16 bytes

        public uint CmciRestoreAttempts;
        public uint MaxCmciRestoreLimit;
        public uint MaxCorrectedErrorsFound;
        public uint MaxCorrectedErrorLimit;
    }

    // TODO
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEAP_CREATE_GENERIC_RECORD_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_CREATE_GENERIC_RECORD_EVENT>(); // 40 bytes

        [JsonProperty(Order = 1)]
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        public string Error;

        [JsonProperty(Order = 2)]
        public uint EntryCount;

        private NtStatus _Status;

        [JsonProperty(Order = 3)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipWriteDeviceDriverSelEntry
     */
    // TODO
    // TODO: Missing 4 bytes?
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEAP_DEVICE_DRV_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_DEVICE_DRV_EVENT>(); // 32 bytes

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        public string Function;
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheaReportHwError
     */
    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_DROPPED_CORRECTED_ERROR_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_DROPPED_CORRECTED_ERROR_EVENT>(); // 8 bytes

        private WHEA_ERROR_SOURCE_TYPE _ErrorSourceType;

        [JsonProperty(Order = 1)]
        public string ErrorSourceType => Enum.GetName(typeof(WHEA_ERROR_SOURCE_TYPE), _ErrorSourceType);

        [JsonProperty(Order = 2)]
        public uint ErrorSourceId;
    }

    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_ERROR_CLEARED_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_ERROR_CLEARED_EVENT>(); // 8 bytes

        public uint EpIndex;
        public uint Bank;
    }

    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_ERROR_RECORD_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_ERROR_RECORD_EVENT>();

        /*
         * TODO
         * How is this a pointer to an error record in the context of a
         * hex-encoded serialized record? Need a sample record to inspect.
         */
        public IntPtr Record; // PWHEA_ERROR_RECORD
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     HalpInitGenericErrorSourceEntry
     *                  HalpInitGenericErrorSourceEntryV2
     */
    // TODO
    // TODO: Alongside MCE, CMC, and NMI (processor?)
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEAP_GENERIC_ERR_MEM_MAP_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_GENERIC_ERR_MEM_MAP_EVENT>(); // 48 bytes

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        public string MapReason;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong PhysicalAddress;

        public ulong Length;
    }

    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_STARTED_REPORT_HW_ERROR : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_STARTED_REPORT_HW_ERROR>();

        /*
         * TODO
         * How is this a pointer to an error record in the context of a
         * hex-encoded serialized record? Need a sample record to inspect.
         */
        public IntPtr ErrorPacket; // PWHEA_ERROR_PACKET
    }

    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_STUCK_ERROR_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_STUCK_ERROR_EVENT>(); // 16 bytes

        public uint EpIndex;
        public uint Bank;
        public ulong MciStatus;
    }
}
