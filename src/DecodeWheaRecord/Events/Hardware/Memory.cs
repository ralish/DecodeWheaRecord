#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Events.Hardware {
    /*
     * Module:          pshed.dll
     * Version:         10.0.26100.1150
     * Function(s):     PshedAddToDefectList
     * Notes:           No payload
     */
    // TODO
    internal sealed class WHEA_FAILED_ADD_DEFECT_LIST_EVENT : IWheaRecord {
        public uint GetNativeSize() => 0;
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipReportAllMemoryErrorSummary
     */
    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT>(); // 4 bytes

        private NtStatus _Status;

        [JsonProperty(Order = 1)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheapProcessOfflineList
     */
    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_OFFLINE_DONE_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_OFFLINE_DONE_EVENT>(); // 8 bytes

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Address;
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPIHsxFinalizeErrorRec
     *                  PshedPiIcxFinalizeErrorRec
     *                  PshedPISkxFinalizeErrorRec
     */
    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PSHED_PLUGIN_DIMM_MISMATCH : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_PSHED_PLUGIN_DIMM_MISMATCH>(); // 18 bytes

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
    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT>(); // 12 bytes

        public uint SocketId;
        public uint ChannelId;
        public uint DimmSlot;
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheapOfflinePage
     */
    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_BIT_OFFLINE_EVENT : WheaRecord {
        private uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        // Structure size with 32-bit pointers
        private const uint StructSizePtr32 = 12;

        // Structure size with 64-bit pointers
        private const uint StructSizePtr64 = 16;

        [JsonProperty(Order = 1)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public IntPtr Page; // PFN_NUMBER

        private NtStatus _Status;

        [JsonProperty(Order = 2)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);

        private WHEA_OFFLINE_ERRS _ErrorReason;

        [JsonProperty(Order = 3)]
        public string ErrorReason => Enum.GetName(typeof(WHEA_OFFLINE_ERRS), _ErrorReason);

        public WHEAP_BIT_OFFLINE_EVENT(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEAP_BIT_OFFLINE_EVENT), structOffset, GetStructSize(), bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;
            var isPtrSize64 = IntPtr.Size == 8;

            Page = Marshal.ReadIntPtr(structAddr);
            _Status = (NtStatus)Marshal.ReadInt32(structAddr, isPtrSize64 ? 8 : 4);
            _ErrorReason = (WHEA_OFFLINE_ERRS)Marshal.ReadInt32(structAddr, isPtrSize64 ? 12 : 8);

            _StructSize = GetStructSize();
            FinalizeRecord(recordAddr, _StructSize);
        }

        private static uint GetStructSize() => IntPtr.Size == 8 ? StructSizePtr64 : StructSizePtr32;
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheapClearPoison
     */
    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_CLEARED_POISON_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_CLEARED_POISON_EVENT>(); // 8 bytes

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong PhysicalAddress;
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheaAttemptRowOffline
     *                  WheapAttemptPhysicalPageOffline
     */
    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PFA_MEMORY_OFFLINED : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_PFA_MEMORY_OFFLINED>(); // 10 bytes

        private WHEAP_PFA_OFFLINE_DECISION_TYPE _DecisionType;

        [JsonProperty(Order = 1)]
        public string DecisionType => Enum.GetName(typeof(WHEAP_PFA_OFFLINE_DECISION_TYPE), _DecisionType);

        [JsonProperty(Order = 2)]
        [MarshalAs(UnmanagedType.U1)]
        public bool ImmediateSuccess;

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Page;

        [JsonProperty(Order = 4)]
        [MarshalAs(UnmanagedType.U1)]
        public bool NotifyVid;
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheapCallInUsePageNotificationCallbacks
     */
    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PFA_MEMORY_OFFLINED_NOTIFY_CALLBACK_ACTION : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_PFA_MEMORY_OFFLINED_NOTIFY_CALLBACK_ACTION>(); // 24 bytes

        [JsonProperty(Order = 1)]
        [JsonConverter(typeof(HexStringJsonConverter))]
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
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     TODO
     */
    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PFA_MEMORY_POLICY : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_PFA_MEMORY_POLICY>(); // 19 bytes

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
    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PFA_MEMORY_REMOVE_MONITOR : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_PFA_MEMORY_REMOVE_MONITOR>(); // 16 bytes

        private WHEA_PFA_REMOVE_TRIGGER _RemoveTrigger;

        [JsonProperty(Order = 1)]
        public string RemoveTrigger => Enum.GetName(typeof(WHEA_PFA_REMOVE_TRIGGER), _RemoveTrigger);

        [JsonProperty(Order = 2)]
        public uint TimeInList;

        [JsonProperty(Order = 3)]
        public uint ErrorCount;

        [JsonProperty(Order = 4)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Page;
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogDefectListCorrupt
     * Notes:           No payload
     */
    // TODO
    internal sealed class WHEAP_PLUGIN_DEFECT_LIST_CORRUPT : IWheaRecord {
        public uint GetNativeSize() => 0;
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogDefectListFull
     * Notes:           No payload
     */
    // TODO
    internal sealed class WHEAP_PLUGIN_DEFECT_LIST_FULL_EVENT : IWheaRecord {
        public uint GetNativeSize() => 0;
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogDefectListUEFIVarFailed
     * Notes:           No payload
     */
    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PLUGIN_DEFECT_LIST_UEFI_VAR_FAILED : IWheaRecord {
        public uint GetNativeSize() => 0;
    }

    // TODO
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PLUGIN_PFA_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_PLUGIN_PFA_EVENT>(); // 1 byte

        [MarshalAs(UnmanagedType.U1)]
        public bool NoFurtherPfa;
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheapExecuteRowFailureCheck
     */
    // TODO
    internal sealed class WHEAP_ROW_FAILURE_EVENT : WheaRecord {
        private uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        // Structure size with 32-bit pointers
        private const uint StructSizePtr32 = 8;

        // Structure size with 64-bit pointers
        private const uint StructSizePtr64 = 16;

        [JsonProperty(Order = 1)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public IntPtr LowOrderPage; // PFN_NUMBER

        [JsonProperty(Order = 2)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public IntPtr HighOrderPage; // PFN_NUMBER

        public WHEAP_ROW_FAILURE_EVENT(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEAP_ROW_FAILURE_EVENT), structOffset, GetStructSize(), bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;
            var isPtrSize64 = IntPtr.Size == 8;

            LowOrderPage = Marshal.ReadIntPtr(structAddr);
            HighOrderPage = Marshal.ReadIntPtr(structAddr, isPtrSize64 ? 8 : 4);

            _StructSize = GetStructSize();
            FinalizeRecord(recordAddr, _StructSize);
        }

        private static uint GetStructSize() => IntPtr.Size == 8 ? StructSizePtr64 : StructSizePtr32;
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheapOfflineRow
     */
    // TODO
    internal sealed class WHEAP_ROW_OFFLINE_EVENT : WheaRecord {
        private uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        // Structure size with 32-bit pointers
        private const uint StructSizePtr32 = 20;

        // Structure size with 64-bit pointers
        private const uint StructSizePtr64 = 28;

        [JsonProperty(Order = 1)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public IntPtr FirstPage; // PFN_NUMBER

        [JsonProperty(Order = 2)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public IntPtr LastPage; // PFN_NUMBER

        [JsonProperty(Order = 3)]
        public uint Range;

        private NtStatus _Status;

        [JsonProperty(Order = 4)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);

        private WHEA_OFFLINE_ERRS _ErrorReason;

        [JsonProperty(Order = 5)]
        public string ErrorReason => Enum.GetName(typeof(WHEA_OFFLINE_ERRS), _ErrorReason);

        public WHEAP_ROW_OFFLINE_EVENT(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEAP_ROW_OFFLINE_EVENT), structOffset, GetStructSize(), bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;
            var isPtrSize64 = IntPtr.Size == 8;

            FirstPage = Marshal.ReadIntPtr(structAddr);
            LastPage = Marshal.ReadIntPtr(structAddr, isPtrSize64 ? 8 : 4);
            Range = (uint)Marshal.ReadInt32(structAddr, isPtrSize64 ? 16 : 8);
            _Status = (NtStatus)Marshal.ReadInt32(structAddr, isPtrSize64 ? 20 : 12);
            _ErrorReason = (WHEA_OFFLINE_ERRS)Marshal.ReadInt32(structAddr, isPtrSize64 ? 24 : 16);

            _StructSize = GetStructSize();
            FinalizeRecord(recordAddr, _StructSize);
        }

        private static uint GetStructSize() => IntPtr.Size == 8 ? StructSizePtr64 : StructSizePtr32;
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
