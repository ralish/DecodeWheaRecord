#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;
using System.Text;

using DecodeWheaRecord.Events.Hardware;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Events {
    internal sealed class WHEA_EVENT_LOG_ENTRY : WheaStruct {
        internal override int GetNativeSize() => _bytesProcessed;

        // Byte array of the entire event log entry
        private byte[] _entryBytes;

        // Pinned GC handle to the event log entry
        private GCHandle _entryHandle;

        // Total bytes that have been processed
        private int _bytesProcessed;

        [JsonProperty(Order = 1)]
        public WHEA_EVENT_LOG_ENTRY_HEADER Header { get; private set; }

        [JsonProperty(Order = 2)]
        public WheaStruct Entry { get; private set; }

        public WHEA_EVENT_LOG_ENTRY(byte[] eventBytes) {
            DebugBeforeDecode(typeof(WHEA_EVENT_LOG_ENTRY), 0);

            _entryBytes = eventBytes;
            _entryHandle = GCHandle.Alloc(_entryBytes, GCHandleType.Pinned);

            Header = new WHEA_EVENT_LOG_ENTRY_HEADER(_entryHandle.AddrOfPinnedObject(), _entryBytes.Length);
            _bytesProcessed = Header.GetNativeSize();

            DecodeEntry();

            DebugAfterDecode(typeof(WHEA_EVENT_LOG_ENTRY), _bytesProcessed, _bytesProcessed);
        }

        ~WHEA_EVENT_LOG_ENTRY() {
            _entryHandle.Free();
        }

        private void DecodeEntry() {
            WheaStruct entry = null;

            var entryAddr = _entryHandle.AddrOfPinnedObject() + Header.GetNativeSize();

            switch (Header.Id) {
                case "CmcPollingTimeout":
                    ExitUnsupportedEvent(Header.Id);
                    break;
                case "WheaInit":
                    ExitUnsupportedEvent(Header.Id);
                    break;
                case "CmcSwitchToPolling":
                    ExitUnsupportedEvent(Header.Id);
                    break;
                case "DroppedCorrectedError":
                    entry = Marshal.PtrToStructure<WHEAP_DROPPED_CORRECTED_ERROR_EVENT>(entryAddr);
                    break;
                case "StartedReportHwError":
                    ExitUnsupportedEvent(Header.Id);
                    break;
                case "PFAMemoryOfflined":
                    entry = Marshal.PtrToStructure<WHEAP_PFA_MEMORY_OFFLINED>(entryAddr);
                    break;
                case "PFAMemoryRemoveMonitor":
                    entry = Marshal.PtrToStructure<WHEAP_PFA_MEMORY_REMOVE_MONITOR>(entryAddr);
                    break;
                case "PFAMemoryPolicy":
                    entry = Marshal.PtrToStructure<WHEAP_PFA_MEMORY_POLICY>(entryAddr);
                    break;
                case "PshedInjectError":
                    entry = Marshal.PtrToStructure<WHEAP_PSHED_INJECT_ERROR>(entryAddr);
                    break;
                case "OscCapabilities":
                    entry = Marshal.PtrToStructure<WHEAP_OSC_IMPLEMENTED>(entryAddr);
                    break;
                case "PshedPluginRegister":
                    entry = Marshal.PtrToStructure<WHEAP_PSHED_PLUGIN_REGISTER>(entryAddr);
                    break;
                case "AddRemoveErrorSource":
                    entry = new WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT(entryAddr, 0); // todo
                    break;
                case "WorkQueueItem":
                    ExitUnsupportedEvent(Header.Id);
                    break;
                case "AttemptErrorRecovery":
                    entry = Marshal.PtrToStructure<WHEAP_ATTEMPT_RECOVERY_EVENT>(entryAddr);
                    break;
                case "McaFoundErrorInBank":
                    entry = Marshal.PtrToStructure<WHEAP_FOUND_ERROR_IN_BANK_EVENT>(entryAddr);
                    break;
                case "McaStuckErrorCheck":
                    entry = Marshal.PtrToStructure<WHEAP_STUCK_ERROR_EVENT>(entryAddr);
                    break;
                case "McaErrorCleared":
                    entry = Marshal.PtrToStructure<WHEAP_ERROR_CLEARED_EVENT>(entryAddr);
                    break;
                case "ClearedPoison":
                    entry = Marshal.PtrToStructure<WHEAP_CLEARED_POISON_EVENT>(entryAddr);
                    break;
                case "ProcessEINJ":
                    entry = Marshal.PtrToStructure<WHEAP_PROCESS_EINJ_EVENT>(entryAddr);
                    break;
                case "ProcessHEST":
                    entry = Marshal.PtrToStructure<WHEAP_PROCESS_HEST_EVENT>(entryAddr);
                    break;
                case "CreateGenericRecord":
                    entry = Marshal.PtrToStructure<WHEAP_CREATE_GENERIC_RECORD_EVENT>(entryAddr);
                    break;
                case "ErrorRecord":
                    ExitUnsupportedEvent(Header.Id);
                    break;
                case "ErrorRecordLimit":
                    ExitUnsupportedEvent(Header.Id);
                    break;
                case "AerNotGrantedToOs":
                    // No payload (verified)
                    break;
                case "ErrSrcArrayInvalid":
                    entry = Marshal.PtrToStructure<WHEAP_ERR_SRC_ARRAY_INVALID_EVENT>(entryAddr);
                    break;
                case "AcpiTimeOut":
                    entry = Marshal.PtrToStructure<WHEAP_ACPI_TIMEOUT_EVENT>(entryAddr);
                    break;
                case "CmciRestart":
                    entry = Marshal.PtrToStructure<WHEAP_CMCI_RESTART_EVENT>(entryAddr);
                    break;
                case "CmciFinalRestart":
                    ExitUnsupportedEvent(Header.Id);
                    break;
                case "EtwOverFlow":
                    entry = Marshal.PtrToStructure<WHEA_ETW_OVERFLOW_EVENT>(entryAddr);
                    break;
                case "AzccRootBusSearchErr":
                    entry = Marshal.PtrToStructure<WHEA_AZCC_ROOT_BUS_ERR_EVENT>(entryAddr);
                    break;
                case "AzccRootBusList":
                    entry = Marshal.PtrToStructure<WHEA_AZCC_ROOT_BUS_LIST_EVENT>(entryAddr);
                    break;
                case "ErrSrcInvalid":
                    entry = new WHEAP_ERR_SRC_INVALID_EVENT(entryAddr, 0); // TODO
                    break;
                case "GenericErrMemMap":
                    entry = Marshal.PtrToStructure<WHEAP_GENERIC_ERR_MEM_MAP_EVENT>(entryAddr);
                    break;
                case "PshedCallbackCollision":
                    ExitUnsupportedEvent(Header.Id);
                    break;
                case "SELBugCheckProgress":
                    entry = Marshal.PtrToStructure<WHEA_SEL_BUGCHECK_PROGRESS>(entryAddr);
                    break;
                case "PshedPluginLoad":
                    entry = Marshal.PtrToStructure<WHEA_PSHED_PLUGIN_LOAD_EVENT>(entryAddr);
                    break;
                case "PshedPluginUnload":
                    entry = Marshal.PtrToStructure<WHEA_PSHED_PLUGIN_UNLOAD_EVENT>(entryAddr);
                    break;
                case "PshedPluginSupported":
                    entry = Marshal.PtrToStructure<WHEA_PSHED_PLUGIN_PLATFORM_SUPPORT_EVENT>(entryAddr);
                    break;
                case "DeviceDriver":
                    entry = Marshal.PtrToStructure<WHEAP_DEVICE_DRV_EVENT>(entryAddr);
                    break;
                case "CmciImplPresent":
                    entry = Marshal.PtrToStructure<WHEAP_CMCI_IMPLEMENTED_EVENT>(entryAddr);
                    break;
                case "CmciInitError":
                    entry = Marshal.PtrToStructure<WHEAP_CMCI_INITERR_EVENT>(entryAddr);
                    break;
                case "SELBugCheckRecovery":
                    ExitUnsupportedEvent(Header.Id);
                    break;
                case "DrvErrSrcInvalid":
                    ExitUnsupportedEvent(Header.Id);
                    break;
                case "DrvHandleBusy":
                    ExitUnsupportedEvent(Header.Id);
                    break;
                case "WheaHeartbeat":
                    entry = Marshal.PtrToStructure<WHEA_PSHED_PLUGIN_HEARTBEAT>(entryAddr);
                    break;
                case "AzccRootBusPoisonSet":
                    entry = Marshal.PtrToStructure<WHEA_AZCC_SET_POISON_EVENT>(entryAddr);
                    break;
                case "SELBugCheckInfo":
                    ExitUnsupportedEvent(Header.Id);
                    break;
                case "ErrDimmInfoMismatch":
                    entry = Marshal.PtrToStructure<WHEA_PSHED_PLUGIN_DIMM_MISMATCH>(entryAddr);
                    break;
                case "eDpcEnabled":
                    entry = Marshal.PtrToStructure<WHEAP_EDPC_ENABLED_EVENT>(entryAddr);
                    break;
                case "PageOfflineDone":
                    entry = Marshal.PtrToStructure<WHEA_OFFLINE_DONE_EVENT>(entryAddr);
                    break;
                case "PageOfflinePendMax":
                    ExitUnsupportedEvent(Header.Id);
                    break;
                case "BadPageLimitReached":
                    ExitUnsupportedEvent(Header.Id);
                    break;
                case "SrarDetail":
                    entry = Marshal.PtrToStructure<WHEA_SRAR_DETAIL_EVENT>(entryAddr);
                    break;
                case "EarlyError":
                    ExitUnsupportedEvent(Header.Id);
                    break;
                case "PcieOverrideInfo":
                    entry = Marshal.PtrToStructure<WHEAP_PCIE_OVERRIDE_INFO>(entryAddr);
                    break;
                case "ReadPcieOverridesErr":
                    entry = Marshal.PtrToStructure<WHEAP_PCIE_READ_OVERRIDES_ERR>(entryAddr);
                    break;
                case "PcieConfigInfo":
                    entry = Marshal.PtrToStructure<WHEAP_PCIE_CONFIG_INFO>(entryAddr);
                    break;
                case "PcieSummaryFailed":
                    ExitUnsupportedEvent(Header.Id);
                    break;
                case "ThrottleRegCorrupt":
                    entry = Marshal.PtrToStructure<WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT>(entryAddr);
                    break;
                case "ThrottleAddErrSrcFailed":
                    entry = Marshal.PtrToStructure<WHEA_THROTTLE_ADD_ERR_SRC_FAILED_EVENT>(entryAddr);
                    break;
                case "ThrottleRegDataIgnored":
                    entry = Marshal.PtrToStructure<WHEA_THROTTLE_REG_DATA_IGNORED_EVENT>(entryAddr);
                    break;
                case "EnableKeyNotifFailed":
                    entry = Marshal.PtrToStructure<WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_FAILED_EVENT>(entryAddr);
                    break;
                case "KeyNotificationFailed":
                    entry = Marshal.PtrToStructure<WHEA_REGISTER_KEY_NOTIFICATION_FAILED_EVENT>(entryAddr);
                    break;
                case "PcieRemoveDevice":
                    entry = Marshal.PtrToStructure<WHEA_THROTTLE_PCIE_REMOVE_EVENT>(entryAddr);
                    break;
                case "PcieAddDevice":
                    entry = Marshal.PtrToStructure<WHEA_THROTTLE_PCIE_ADD_EVENT>(entryAddr);
                    break;
                case "PcieSpuriousErrSource":
                    entry = Marshal.PtrToStructure<WHEAP_SPURIOUS_AER_EVENT>(entryAddr);
                    break;
                case "MemoryAddDevice":
                case "MemoryRemoveDevice":
                    entry = Marshal.PtrToStructure<WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT>(entryAddr);
                    break;
                case "MemorySummaryFailed":
                    entry = Marshal.PtrToStructure<WHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT>(entryAddr);
                    break;
                case "PcieDpcError":
                    entry = Marshal.PtrToStructure<WHEAP_DPC_ERROR_EVENT>(entryAddr);
                    break;
                case "CpuBusesInitFailed":
                    entry = Marshal.PtrToStructure<WHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT>(entryAddr);
                    break;
                case "PshedPluginInitFailed":
                    entry = Marshal.PtrToStructure<WHEA_PSHED_PLUGIN_INIT_FAILED_EVENT>(entryAddr);
                    break;
                case "FailedAddToDefectList":
                    entry = Marshal.PtrToStructure<WHEA_FAILED_ADD_DEFECT_LIST_EVENT>(entryAddr);
                    break;
                case "DefectListFull":
                    entry = Marshal.PtrToStructure<WHEAP_PLUGIN_DEFECT_LIST_FULL_EVENT>(entryAddr);
                    break;
                case "DefectListUEFIVarFailed":
                    entry = Marshal.PtrToStructure<WHEAP_PLUGIN_DEFECT_LIST_UEFI_VAR_FAILED>(entryAddr);
                    break;
                case "DefectListCorrupt":
                    entry = Marshal.PtrToStructure<WHEAP_PLUGIN_DEFECT_LIST_CORRUPT>(entryAddr);
                    break;
                case "BadHestNotifyData":
                    entry = Marshal.PtrToStructure<WHEAP_BAD_HEST_NOTIFY_DATA_EVENT>(entryAddr);
                    break;
                case "RowFailure":
                    entry = Marshal.PtrToStructure<WHEAP_ROW_FAILURE_EVENT>(entryAddr);
                    break;
                case "SrasTableNotFound":
                    entry = Marshal.PtrToStructure<WHEA_SRAS_TABLE_NOT_FOUND>(entryAddr);
                    break;
                case "SrasTableError":
                    entry = Marshal.PtrToStructure<WHEA_SRAS_TABLE_ERROR>(entryAddr);
                    break;
                case "SrasTableEntries":
                    entry = new WHEA_SRAS_TABLE_ENTRIES_EVENT(entryAddr);
                    break;
                case "PFANotifyCallbackAction":
                    // TODO
                    break;
                case "SELBugCheckCpusQuiesced":
                    // TODO
                    break;
                case "PshedPiCpuid":
                    entry = Marshal.PtrToStructure<WHEA_PSHED_PI_CPUID>(entryAddr);
                    break;
                case "SrasTableBadData":
                    // TODO
                    break;
                case "DriFsStatus":
                    // TODO
                    break;
                case "CpusFrozen":
                    ExitUnsupportedEvent(Header.Id);
                    break;
                case "CpusFrozenNoCrashDump":
                    ExitUnsupportedEvent(Header.Id);
                    break;
                case "RegNotifyPolicyChange":
                    entry = Marshal.PtrToStructure<WHEA_REGNOTIFY_POLICY_CHANGE_EVENT>(entryAddr);
                    break;
                case "RegError":
                    entry = Marshal.PtrToStructure<WHEA_REGISTRY_ERROR_EVENT>(entryAddr);
                    break;
                case "RowOfflineEvent":
                    // TODO
                    break;
                case "BitOfflineEvent":
                    // TODO
                    break;
                case "BadGasFields":
                    entry = Marshal.PtrToStructure<WHEA_GAS_ERROR_EVENT>(entryAddr);
                    break;
                case "CrashDumpError":
                    entry = Marshal.PtrToStructure<WHEA_CRASHDUMP_EVENT_LOG_ENTRY_WITH_STATUS>(entryAddr);
                    break;
                case "CrashDumpCheckpoint":
                    // TODO
                    break;
                case "CrashDumpProgressPercent":
                    entry = Marshal.PtrToStructure<WHEA_CRASHDUMP_EVENT_LOG_ENTRY_ULONG1>(entryAddr);
                    break;
                case "PreviousCrashBugCheckProgress":
                    // TODO
                    break;
                case "SELBugCheckStackDump":
                    // TODO
                    break;
                case "PciePromotedAerErr":
                    entry = Marshal.PtrToStructure<WHEAP_PROMOTED_AER_ERROR_EVENT>(entryAddr);
                    break;
                case "PshedPiTraceLog":
                    entry = Marshal.PtrToStructure<WHEA_PSHED_PI_TRACE_EVENT>(entryAddr);
                    break;
                default:
                    ExitWithMessage($"Unknown WHEA event log entry type: {Header.Id}", code: 2);
                    break;
            }

            // TODO: Validate marshalled size matches descriptor SectionLength
            if (entry != null) {
                _bytesProcessed += entry.GetNativeSize();
                Entry = entry;
            }
        }
    }

    internal sealed class WHEA_EVENT_LOG_ENTRY_HEADER : WheaStruct {
        // Structure is always 32 bytes
        private const int _NativeSize = 32;
        internal override int GetNativeSize() => _NativeSize;

        /*
         * Reversed from what is defined in the header as validation of the
         * member is done as an ASCII string instead of a ULONG integer.
         */
        internal const string WHEA_ERROR_LOG_ENTRY_SIGNATURE = "WhLg";

        private const int WHEA_ERROR_LOG_ENTRY_VERSION = 1;

        private uint _Signature;

        [JsonProperty(Order = 1)]
        public string Signature {
            get {
                var bytes = BitConverter.GetBytes(_Signature);
                return Encoding.ASCII.GetString(bytes);
            }
        }

        [JsonProperty(Order = 2)]
        public uint Version;

        // TODO: Description
        [JsonProperty(Order = 3)]
        public uint Length; // TODO: Validate against Type and PayloadLength

        private WHEA_EVENT_LOG_ENTRY_TYPE _Type;

        [JsonProperty(Order = 4)]
        public string Type => Enum.GetName(typeof(WHEA_EVENT_LOG_ENTRY_TYPE), _Type);

        [JsonProperty(Order = 5)]
        public uint OwnerTag; // TODO: String (like Signature)?

        private WHEA_EVENT_LOG_ENTRY_ID _Id;

        [JsonProperty(Order = 6)]
        public string Id => Enum.GetName(typeof(WHEA_EVENT_LOG_ENTRY_ID), _Id);

        private WHEA_EVENT_LOG_ENTRY_FLAGS _Flags;

        [JsonProperty(Order = 7)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        // TODO: Description
        [JsonProperty(Order = 8)]
        public uint PayloadLength; // TODO: Validate against Type and PayloadLength

        public WHEA_EVENT_LOG_ENTRY_HEADER(IntPtr recordAddr, int recordSize) {
            if (recordSize < _NativeSize) {
                var msg = $"Header is {_NativeSize} bytes but only {recordSize} bytes provided.";
                ExitWithMessage(msg, nameof(WHEA_EVENT_LOG_ENTRY_HEADER), 1);
            }

            _Signature = (uint)Marshal.ReadInt32(recordAddr);
            if (Signature != WHEA_ERROR_LOG_ENTRY_SIGNATURE) {
                var cat = $"{nameof(WHEA_EVENT_LOG_ENTRY_HEADER)}.{nameof(Signature)}";
                var msg = $"Expected \"{WHEA_ERROR_LOG_ENTRY_SIGNATURE}\" but found: {Signature}";
                ExitWithMessage(msg, cat, 2);
            }

            Version = (uint)Marshal.ReadInt32(recordAddr, 4);
            if (Version != WHEA_ERROR_LOG_ENTRY_VERSION) {
                var cat = $"{nameof(WHEA_EVENT_LOG_ENTRY_HEADER)}.{nameof(Version)}";
                var msg = $"Expected version {WHEA_ERROR_LOG_ENTRY_VERSION} but found: {Version}";
                ExitWithMessage(msg, cat, 2);
            }

            Length = (uint)Marshal.ReadInt32(recordAddr, 8);
            _Type = (WHEA_EVENT_LOG_ENTRY_TYPE)Marshal.ReadInt32(recordAddr, 12);
            OwnerTag = (uint)Marshal.ReadInt32(recordAddr, 16);
            _Id = (WHEA_EVENT_LOG_ENTRY_ID)Marshal.ReadInt32(recordAddr, 20);
            _Flags = (WHEA_EVENT_LOG_ENTRY_FLAGS)Marshal.ReadInt32(recordAddr, 24);
            PayloadLength = (uint)Marshal.ReadInt32(recordAddr, 28);
        }
    }

    // @formatter:int_align_fields true

    internal enum WHEA_EVENT_LOG_ENTRY_TYPE : uint {
        Informational = 0,
        Warning       = 1,
        Error         = 2
    }

    internal enum WHEA_EVENT_LOG_ENTRY_ID : uint {
        CmcPollingTimeout             = 0x80000001,
        WheaInit                      = 0x80000002,
        CmcSwitchToPolling            = 0x80000003,
        DroppedCorrectedError         = 0x80000004,
        StartedReportHwError          = 0x80000005,
        PFAMemoryOfflined             = 0x80000006,
        PFAMemoryRemoveMonitor        = 0x80000007,
        PFAMemoryPolicy               = 0x80000008,
        PshedInjectError              = 0x80000009,
        OscCapabilities               = 0x8000000a,
        PshedPluginRegister           = 0x8000000b,
        AddRemoveErrorSource          = 0x8000000c,
        WorkQueueItem                 = 0x8000000d,
        AttemptErrorRecovery          = 0x8000000e,
        McaFoundErrorInBank           = 0x8000000f,
        McaStuckErrorCheck            = 0x80000010,
        McaErrorCleared               = 0x80000011,
        ClearedPoison                 = 0x80000012,
        ProcessEINJ                   = 0x80000013,
        ProcessHEST                   = 0x80000014,
        CreateGenericRecord           = 0x80000015,
        ErrorRecord                   = 0x80000016,
        ErrorRecordLimit              = 0x80000017,
        AerNotGrantedToOs             = 0x80000018,
        ErrSrcArrayInvalid            = 0x80000019,
        AcpiTimeOut                   = 0x8000001a,
        CmciRestart                   = 0x8000001b,
        CmciFinalRestart              = 0x8000001c,
        EtwOverFlow                   = 0x8000001d,
        AzccRootBusSearchErr          = 0x8000001e,
        AzccRootBusList               = 0x8000001f,
        ErrSrcInvalid                 = 0x80000020,
        GenericErrMemMap              = 0x80000021,
        PshedCallbackCollision        = 0x80000022,
        SELBugCheckProgress           = 0x80000023,
        PshedPluginLoad               = 0x80000024,
        PshedPluginUnload             = 0x80000025,
        PshedPluginSupported          = 0x80000026,
        DeviceDriver                  = 0x80000027,
        CmciImplPresent               = 0x80000028,
        CmciInitError                 = 0x80000029,
        SELBugCheckRecovery           = 0x8000002a,
        DrvErrSrcInvalid              = 0x8000002b,
        DrvHandleBusy                 = 0x8000002c,
        WheaHeartbeat                 = 0x8000002d,
        AzccRootBusPoisonSet          = 0x8000002e,
        SELBugCheckInfo               = 0x8000002f,
        ErrDimmInfoMismatch           = 0x80000030,
        eDpcEnabled                   = 0x80000031,
        PageOfflineDone               = 0x80000032,
        PageOfflinePendMax            = 0x80000033,
        BadPageLimitReached           = 0x80000034,
        SrarDetail                    = 0x80000035,
        EarlyError                    = 0x80000036,
        PcieOverrideInfo              = 0x80000037,
        ReadPcieOverridesErr          = 0x80000038,
        PcieConfigInfo                = 0x80000039,
        PcieSummaryFailed             = 0x80000040,
        ThrottleRegCorrupt            = 0x80000041,
        ThrottleAddErrSrcFailed       = 0x80000042,
        ThrottleRegDataIgnored        = 0x80000043,
        EnableKeyNotifFailed          = 0x80000044,
        KeyNotificationFailed         = 0x80000045,
        PcieRemoveDevice              = 0x80000046,
        PcieAddDevice                 = 0x80000047,
        PcieSpuriousErrSource         = 0x80000048,
        MemoryAddDevice               = 0x80000049,
        MemoryRemoveDevice            = 0x8000004a,
        MemorySummaryFailed           = 0x8000004b,
        PcieDpcError                  = 0x8000004c,
        CpuBusesInitFailed            = 0x8000004d,
        PshedPluginInitFailed         = 0x8000004e,
        FailedAddToDefectList         = 0x8000004f,
        DefectListFull                = 0x80000050,
        DefectListUEFIVarFailed       = 0x80000051,
        DefectListCorrupt             = 0x80000052,
        BadHestNotifyData             = 0x80000053,
        RowFailure                    = 0x80000054,
        SrasTableNotFound             = 0x80000055,
        SrasTableError                = 0x80000056,
        SrasTableEntries              = 0x80000057,
        PFANotifyCallbackAction       = 0x80000058,
        SELBugCheckCpusQuiesced       = 0x80000059,
        PshedPiCpuid                  = 0x8000005a,
        SrasTableBadData              = 0x8000005b,
        DriFsStatus                   = 0x8000005c,
        CpusFrozen                    = 0x80000060,
        CpusFrozenNoCrashDump         = 0x80000061,
        RegNotifyPolicyChange         = 0x80000062,
        RegError                      = 0x80000063,
        RowOfflineEvent               = 0x80000064,
        BitOfflineEvent               = 0x80000065,
        BadGasFields                  = 0x80000066,
        CrashDumpError                = 0x80000067,
        CrashDumpCheckpoint           = 0x80000068,
        CrashDumpProgressPercent      = 0x80000069,
        PreviousCrashBugCheckProgress = 0x8000006a,
        SELBugCheckStackDump          = 0x8000006b,
        PciePromotedAerErr            = 0x8000006c,
        PshedPiTraceLog               = 0x80040010

        /*
        CmcPollingTimeout             = 0x80000001, // TODO
        WheaInit                      = 0x80000002, // TODO
        CmcSwitchToPolling            = 0x80000003, // TODO
        DroppedCorrectedError         = 0x80000004, // WHEAP_DROPPED_CORRECTED_ERROR_EVENT
        StartedReportHwError          = 0x80000005, // WHEAP_STARTED_REPORT_HW_ERROR (SEL only)
        PFAMemoryOfflined             = 0x80000006, // WHEAP_PFA_MEMORY_OFFLINED
        PFAMemoryRemoveMonitor        = 0x80000007, // WHEAP_PFA_MEMORY_REMOVE_MONITOR
        PFAMemoryPolicy               = 0x80000008, // WHEAP_PFA_MEMORY_POLICY
        PshedInjectError              = 0x80000009, // WHEAP_PSHED_INJECT_ERROR
        OscCapabilities               = 0x8000000a, // WHEAP_OSC_IMPLEMENTED
        PshedPluginRegister           = 0x8000000b, // WHEAP_PSHED_PLUGIN_REGISTER
        AddRemoveErrorSource          = 0x8000000c, // WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT
        WorkQueueItem                 = 0x8000000d, // TODO
        AttemptErrorRecovery          = 0x8000000e, // WHEAP_ATTEMPT_RECOVERY_EVENT
        McaFoundErrorInBank           = 0x8000000f, // WHEAP_FOUND_ERROR_IN_BANK_EVENT
        McaStuckErrorCheck            = 0x80000010, // WHEAP_STUCK_ERROR_EVENT
        McaErrorCleared               = 0x80000011, // WHEAP_ERROR_CLEARED_EVENT
        ClearedPoison                 = 0x80000012, // WHEAP_CLEARED_POISON_EVENT
        ProcessEINJ                   = 0x80000013, // WHEAP_PROCESS_EINJ_EVENT
        ProcessHEST                   = 0x80000014, // WHEAP_PROCESS_HEST_EVENT
        CreateGenericRecord           = 0x80000015, // WHEAP_CREATE_GENERIC_RECORD_EVENT
        ErrorRecord                   = 0x80000016, // WHEAP_ERROR_RECORD_EVENT
        ErrorRecordLimit              = 0x80000017, // TODO
        AerNotGrantedToOs             = 0x80000018, // No payload
        ErrSrcArrayInvalid            = 0x80000019, // WHEAP_ERR_SRC_ARRAY_INVALID_EVENT
        AcpiTimeOut                   = 0x8000001a, // WHEAP_ACPI_TIMEOUT_EVENT
        CmciRestart                   = 0x8000001b, // WHEAP_CMCI_RESTART_EVENT
        CmciFinalRestart              = 0x8000001c, // TODO
        EtwOverFlow                   = 0x8000001d, // WHEA_ETW_OVERFLOW_EVENT
        AzccRootBusSearchErr          = 0x8000001e, // WHEA_AZCC_ROOT_BUS_ERR_EVENT
        AzccRootBusList               = 0x8000001f, // WHEA_AZCC_ROOT_BUS_LIST_EVENT
        ErrSrcInvalid                 = 0x80000020, // WHEAP_ERR_SRC_INVALID_EVENT
        GenericErrMemMap              = 0x80000021, // WHEAP_GENERIC_ERR_MEM_MAP_EVENT
        PshedCallbackCollision        = 0x80000022, // TODO
        SELBugCheckProgress           = 0x80000023, // WHEA_SEL_BUGCHECK_PROGRESS
        PshedPluginLoad               = 0x80000024, // WHEA_PSHED_PLUGIN_LOAD_EVENT
        PshedPluginUnload             = 0x80000025, // WHEA_PSHED_PLUGIN_UNLOAD_EVENT
        PshedPluginSupported          = 0x80000026, // WHEA_PSHED_PLUGIN_PLATFORM_SUPPORT_EVENT
        DeviceDriver                  = 0x80000027, // WHEAP_DEVICE_DRV_EVENT
        CmciImplPresent               = 0x80000028, // WHEAP_CMCI_IMPLEMENTED_EVENT
        CmciInitError                 = 0x80000029, // WHEAP_CMCI_INITERR_EVENT
        SELBugCheckRecovery           = 0x8000002a, // TODO
        DrvErrSrcInvalid              = 0x8000002b, // TODO
        DrvHandleBusy                 = 0x8000002c, // TODO
        WheaHeartbeat                 = 0x8000002d, // WHEA_PSHED_PLUGIN_HEARTBEAT (no payload)
        AzccRootBusPoisonSet          = 0x8000002e, // WHEA_AZCC_SET_POISON_EVENT
        SELBugCheckInfo               = 0x8000002f, // TODO
        ErrDimmInfoMismatch           = 0x80000030, // WHEA_PSHED_PLUGIN_DIMM_MISMATCH
        eDpcEnabled                   = 0x80000031, // WHEAP_EDPC_ENABLED_EVENT
        PageOfflineDone               = 0x80000032, // WHEA_OFFLINE_DONE_EVENT
        PageOfflinePendMax            = 0x80000033, // TODO
        BadPageLimitReached           = 0x80000034, // TODO
        SrarDetail                    = 0x80000035, // WHEA_SRAR_DETAIL_EVENT
        EarlyError                    = 0x80000036, // TODO
        PcieOverrideInfo              = 0x80000037, // WHEAP_PCIE_OVERRIDE_INFO
        ReadPcieOverridesErr          = 0x80000038, // WHEAP_PCIE_READ_OVERRIDES_ERR
        PcieConfigInfo                = 0x80000039, // WHEAP_PCIE_CONFIG_INFO
        PcieSummaryFailed             = 0x80000040, // TODO
        ThrottleRegCorrupt            = 0x80000041, // WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT
        ThrottleAddErrSrcFailed       = 0x80000042, // WHEA_THROTTLE_ADD_ERR_SRC_FAILED_EVENT (no payload)
        ThrottleRegDataIgnored        = 0x80000043, // WHEA_THROTTLE_REG_DATA_IGNORED_EVENT
        EnableKeyNotifFailed          = 0x80000044, // WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_FAILED_EVENT
        KeyNotificationFailed         = 0x80000045, // WHEA_REGISTER_KEY_NOTIFICATION_FAILED_EVENT (no payload)
        PcieRemoveDevice              = 0x80000046, // WHEA_THROTTLE_PCIE_REMOVE_EVENT
        PcieAddDevice                 = 0x80000047, // WHEA_THROTTLE_PCIE_ADD_EVENT
        PcieSpuriousErrSource         = 0x80000048, // WHEAP_SPURIOUS_AER_EVENT
        MemoryAddDevice               = 0x80000049, // WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT
        MemoryRemoveDevice            = 0x8000004a, // WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT
        MemorySummaryFailed           = 0x8000004b, // WHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT
        PcieDpcError                  = 0x8000004c, // WHEAP_DPC_ERROR_EVENT
        CpuBusesInitFailed            = 0x8000004d, // WHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT
        PshedPluginInitFailed         = 0x8000004e, // WHEA_PSHED_PLUGIN_INIT_FAILED_EVENT
        FailedAddToDefectList         = 0x8000004f, // WHEA_FAILED_ADD_DEFECT_LIST_EVENT (no payload)
        DefectListFull                = 0x80000050, // WHEAP_PLUGIN_DEFECT_LIST_FULL_EVENT (no payload)
        DefectListUEFIVarFailed       = 0x80000051, // WHEAP_PLUGIN_DEFECT_LIST_UEFI_VAR_FAILED (no payload)
        DefectListCorrupt             = 0x80000052, // WHEAP_PLUGIN_DEFECT_LIST_CORRUPT (no payload)
        BadHestNotifyData             = 0x80000053, // WHEAP_BAD_HEST_NOTIFY_DATA_EVENT
        RowFailure                    = 0x80000054, // WHEAP_ROW_FAILURE_EVENT
        SrasTableNotFound             = 0x80000055, // WHEA_SRAS_TABLE_NOT_FOUND (no payload)
        SrasTableError                = 0x80000056, // WHEA_SRAS_TABLE_ERROR (no payload)
        SrasTableEntries              = 0x80000057, // WHEA_SRAS_TABLE_ENTRIES_EVENT
        PFANotifyCallbackAction       = 0x80000058, // TODO (new)
        SELBugCheckCpusQuiesced       = 0x80000059, // TODO (new)
        PshedPiCpuid                  = 0x8000005a, // WHEA_PSHED_PI_CPUID
        SrasTableBadData              = 0x8000005b, // TODO (new)
        DriFsStatus                   = 0x8000005c, // TODO (new)
        CpusFrozen                    = 0x80000060, // No payload
        CpusFrozenNoCrashDump         = 0x80000061, // TODO
        RegNotifyPolicyChange         = 0x80000062, // WHEA_REGNOTIFY_POLICY_CHANGE_EVENT
        RegError                      = 0x80000063, // WHEA_REGISTRY_ERROR_EVENT
        RowOfflineEvent               = 0x80000064, // TODO (new)
        BitOfflineEvent               = 0x80000065, // TODO (new)
        BadGasFields                  = 0x80000066, // WHEA_GAS_ERROR_EVENT
        CrashDumpError                = 0x80000067, // TODO (new)
        CrashDumpCheckpoint           = 0x80000068, // TODO (new)
        CrashDumpProgressPercent      = 0x80000069, // TODO (new)
        PreviousCrashBugCheckProgress = 0x8000006a, // TODO (new)
        SELBugCheckStackDump          = 0x8000006b, // TODO (new)
        PciePromotedAerErr            = 0x8000006c, // WHEAP_PROMOTED_AER_ERROR_EVENT
        PshedPiTraceLog               = 0x80040010  // WHEA_PSHED_PI_TRACE_EVENT
        */
    }

    [Flags]
    internal enum WHEA_EVENT_LOG_ENTRY_FLAGS : uint {
        Reserved       = 0x1,
        LogInternalEtw = 0x2,
        LogBlackbox    = 0x4,
        LogSel         = 0x8,
        RawSel         = 0x10,
        NoFormat       = 0x20,
        Driver         = 0x40
    }

    // @formatter:int_align_fields false
}
