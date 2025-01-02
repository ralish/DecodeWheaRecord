#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Events {
    /*
     * Module:          pshed.dll
     * Version:         10.0.26100.1150
     * Function(s):     PshedAddToDefectList
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_FAILED_ADD_DEFECT_LIST_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_FAILED_ADD_DEFECT_LIST_EVENT>(); // 0 bytes
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipReportAllMemoryErrorSummary
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT>(); // 4 bytes

        private NtStatus _Status;

        [JsonProperty(Order = 1)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheapProcessOfflineList
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_OFFLINE_DONE_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_OFFLINE_DONE_EVENT>(); // 8 bytes

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Address;
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheapCallInUsePageNotificationCallbacks
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PFA_MEMORY_OFFLINED_NOTIFY_CALLBACK_ACTION : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PFA_MEMORY_OFFLINED_NOTIFY_CALLBACK_ACTION>(); // 24 bytes

        [JsonProperty(Order = 1)]
        public uint Page;

        [JsonProperty(Order = 2)]
        public uint ComponentTag;

        private NtStatus _Status;

        [JsonProperty(Order = 3)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);

        private WHEA_RECOVERY_CONTEXT_ACTION_TAKEN _ActionTaken;

        [JsonProperty(Order = 4)]
        public string ActionTaken => Enum.GetName(typeof(WHEA_RECOVERY_CONTEXT_ACTION_TAKEN), _ActionTaken);

        private WHEA_RECOVERY_CONTEXT_ACTION_TAKEN_ADDITIONAL_INFO _ActionTakenAdditionalInfo;

        [JsonProperty(Order = 5)]
        public string ActionTakenAdditionalInfo => Enum.GetName(typeof(WHEA_RECOVERY_CONTEXT_ACTION_TAKEN_ADDITIONAL_INFO), _ActionTakenAdditionalInfo);
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPIHsxFinalizeErrorRec
     *                  PshedPiIcxFinalizeErrorRec
     *                  PshedPISkxFinalizeErrorRec
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PSHED_PLUGIN_DIMM_MISMATCH : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_PSHED_PLUGIN_DIMM_MISMATCH>(); // 18 bytes

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

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogAddMemoryDeviceFilterEvent
     *                  PshedPipLogRemoveMemoryDeviceFilterEvent
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT>(); // 12 bytes

        public uint SocketId;
        public uint ChannelId;
        public uint DimmSlot;
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheapClearPoison
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_CLEARED_POISON_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_CLEARED_POISON_EVENT>(); // 8 bytes

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong PhysicalAddress;
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheaAttemptRowOffline
     *                  WheapAttemptPhysicalPageOffline
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PFA_MEMORY_OFFLINED : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PFA_MEMORY_OFFLINED>(); // 10 bytes

        private WHEAP_PFA_OFFLINE_DECISION_TYPE _DecisionType;

        [JsonProperty(Order = 1)]
        public string DecisionType => Enum.GetName(typeof(WHEAP_PFA_OFFLINE_DECISION_TYPE), _DecisionType);

        [JsonProperty(Order = 2)]
        [MarshalAs(UnmanagedType.U1)]
        public bool ImmediateSuccess;

        [JsonProperty(Order = 3)]
        public uint Page;

        [JsonProperty(Order = 4)]
        [MarshalAs(UnmanagedType.U1)]
        public bool NotifyVid;
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     XXX
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PFA_MEMORY_POLICY : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PFA_MEMORY_POLICY>(); // TODO bytes

        public uint RegistryKeysPresent;

        [MarshalAs(UnmanagedType.U1)]
        public bool DisableOffline;

        [MarshalAs(UnmanagedType.U1)]
        public bool PersistOffline;

        [MarshalAs(UnmanagedType.U1)]
        public bool PfaDisabled;

        public uint PageCount;
        public uint ErrorThreshold;
        public uint TimeOut;
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheapPfaLogPageMonitorRemoval
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PFA_MEMORY_REMOVE_MONITOR : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PFA_MEMORY_REMOVE_MONITOR>(); // 16 bytes

        private WHEA_PFA_REMOVE_TRIGGER _RemoveTrigger;

        [JsonProperty(Order = 1)]
        public string RemoveTrigger => Enum.GetName(typeof(WHEA_PFA_REMOVE_TRIGGER), _RemoveTrigger);

        [JsonProperty(Order = 2)]
        public uint TimeInList;

        [JsonProperty(Order = 3)]
        public uint ErrorCount;

        [JsonProperty(Order = 4)]
        public uint Page;
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogDefectListCorrupt
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PLUGIN_DEFECT_LIST_CORRUPT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PLUGIN_DEFECT_LIST_CORRUPT>(); // 0 bytes
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogDefectListFull
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PLUGIN_DEFECT_LIST_FULL_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PLUGIN_DEFECT_LIST_FULL_EVENT>(); // 0 bytes
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogDefectListUEFIVarFailed
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PLUGIN_DEFECT_LIST_UEFI_VAR_FAILED : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PLUGIN_DEFECT_LIST_UEFI_VAR_FAILED>(); // 0 bytes
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_ROW_FAILURE_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_ROW_FAILURE_EVENT>(); // Variable bytes

        public uint LowOrderPage;  // TODO: PFN_NUMBER
        public uint HighOrderPage; // TODO: PFN_NUMBER
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheapOfflinePage
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_BIT_OFFLINE_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_ROW_FAILURE_EVENT>(); // Variable bytes

        [JsonProperty(Order = 1)]
        public uint Page; // TODO: PFN_NUMBER

        private NtStatus _Status;

        [JsonProperty(Order = 2)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);

        private WHEA_OFFLINE_ERRS _ErrorReason;

        [JsonProperty(Order = 3)]
        public string ErrorReason => Enum.GetName(typeof(WHEA_OFFLINE_ERRS), _ErrorReason);
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheapOfflineRow
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_ROW_OFFLINE_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_ROW_FAILURE_EVENT>(); // Variable bytes

        [JsonProperty(Order = 1)]
        public uint FirstPage; // TODO: PFN_NUMBER

        [JsonProperty(Order = 2)]
        public uint LastPage; // TODO: PFN_NUMBER

        [JsonProperty(Order = 3)]
        public uint Range;

        private NtStatus _Status;

        [JsonProperty(Order = 4)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);

        private WHEA_OFFLINE_ERRS _ErrorReason;

        [JsonProperty(Order = 5)]
        public string ErrorReason => Enum.GetName(typeof(WHEA_OFFLINE_ERRS), _ErrorReason);
    }

    // @formatter:int_align_fields true

    internal enum WHEA_OFFLINE_ERRS : uint {
        NoError               = 0,
        GetMemoryDetailsErr   = 1,
        RatFailure            = 2,
        RatFailureFirstCol    = 3,
        RatFailureLastCol     = 4,
        ClosedPage            = 5,
        BadPageRange          = 6,
        InvalidData           = 7,
        NotDdr                = 8,
        UnsupportedDdrVersion = 9,
        IncorrectDdrVersion   = 10,
        NoMemoryForWrapper    = 11
    }

    internal enum WHEA_PFA_REMOVE_TRIGGER : uint {
        ErrorThreshold = 1,
        Timeout        = 2,
        Capacity       = 3
    }

    internal enum WHEA_RECOVERY_CONTEXT_ACTION_TAKEN : uint {
        None            = 0,
        OfflineDemotion = 1,
        PageNotReplaced = 2,
        PageReplaced    = 3
    }

    // All bits are reserved
    internal enum WHEA_RECOVERY_CONTEXT_ACTION_TAKEN_ADDITIONAL_INFO : ulong { }

    internal enum WHEAP_PFA_OFFLINE_DECISION_TYPE : uint {
        PredictiveFailure = 1,
        UncorrectedError  = 2
    }

    // @formatter:int_align_fields false
}
