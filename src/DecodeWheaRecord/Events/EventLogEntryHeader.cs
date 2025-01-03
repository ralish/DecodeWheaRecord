#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Events {
    internal sealed class WHEA_EVENT_LOG_ENTRY_HEADER : WheaRecord {
        internal const uint StructSize = 32;
        public override uint GetNativeSize() => StructSize;

        /*
         * Value is reversed from header definition as validation is performed
         * against the field as a string instead of an integer.
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

        /*
         * Length of the event log entry in its entirety; i.e. the entry
         * header (this structure) and the entry itself (the payload).
         */
        [JsonProperty(Order = 3)]
        public uint Length;

        private WHEA_EVENT_LOG_ENTRY_TYPE _Type;

        [JsonProperty(Order = 4)]
        public string Type => Enum.GetName(typeof(WHEA_EVENT_LOG_ENTRY_TYPE), _Type);

        // TODO: Document known owners
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
        public uint PayloadLength;

        public WHEA_EVENT_LOG_ENTRY_HEADER(IntPtr recordAddr, uint recordSize) :
            base(typeof(WHEA_EVENT_LOG_ENTRY_HEADER), 0, StructSize, recordSize) {
            _Signature = (uint)Marshal.ReadInt32(recordAddr);

            if (Signature != WHEA_ERROR_LOG_ENTRY_SIGNATURE) {
                throw new InvalidDataException($"Expected {nameof(Signature)} to be \"{WHEA_ERROR_LOG_ENTRY_SIGNATURE}\" but found: {Signature}");
            }

            Version = (uint)Marshal.ReadInt32(recordAddr, 4);

            if (Version != WHEA_ERROR_LOG_ENTRY_VERSION) {
                throw new InvalidDataException($"Expected {nameof(Version)} to be {WHEA_ERROR_LOG_ENTRY_VERSION} but found: {Version}");
            }

            Length = (uint)Marshal.ReadInt32(recordAddr, 8);

            if (Length < StructSize) {
                throw new InvalidDataException($"Expected {nameof(Length)} to be at least {StructSize} bytes: {Length} < {StructSize}");
            }

            _Type = (WHEA_EVENT_LOG_ENTRY_TYPE)Marshal.ReadInt32(recordAddr, 12);
            OwnerTag = (uint)Marshal.ReadInt32(recordAddr, 16);
            _Id = (WHEA_EVENT_LOG_ENTRY_ID)Marshal.ReadInt32(recordAddr, 20);
            _Flags = (WHEA_EVENT_LOG_ENTRY_FLAGS)Marshal.ReadInt32(recordAddr, 24);
            PayloadLength = (uint)Marshal.ReadInt32(recordAddr, 28);

            if (StructSize + PayloadLength > Length) {
                throw new InvalidDataException($"{nameof(PayloadLength)} exceeds total event log entry size: {StructSize} + {PayloadLength} > {Length}");
            }

            if (StructSize + PayloadLength < Length) {
                var msg = $"{nameof(PayloadLength)} is less than the total size of the event log entry structure: {StructSize} + {PayloadLength} < {Length}";
                WarnOutput(msg, SectionType.Name);
                WarnOutput("Event log entry may be corrupt or incorrectly and/or partially decoded.", SectionType.Name);
            }

            FinalizeRecord(recordAddr, StructSize);
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
        DroppedCorrectedError         = 0x80000004, // WHEAP_DROPPED_CORRECTED_ERROR_EVENT
        StartedReportHwError          = 0x80000005, // WHEAP_STARTED_REPORT_HW_ERROR (SEL only)
        PFAMemoryOfflined             = 0x80000006, // WHEAP_PFA_MEMORY_OFFLINED
        PFAMemoryRemoveMonitor        = 0x80000007, // WHEAP_PFA_MEMORY_REMOVE_MONITOR
        PFAMemoryPolicy               = 0x80000008, // WHEAP_PFA_MEMORY_POLICY
        PshedInjectError              = 0x80000009, // WHEAP_PSHED_INJECT_ERROR
        OscCapabilities               = 0x8000000a, // WHEAP_OSC_IMPLEMENTED
        PshedPluginRegister           = 0x8000000b, // WHEAP_PSHED_PLUGIN_REGISTER
        AddRemoveErrorSource          = 0x8000000c, // WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT
        WorkQueueItem                 = 0x8000000d,
        AttemptErrorRecovery          = 0x8000000e, // WHEAP_ATTEMPT_RECOVERY_EVENT
        McaFoundErrorInBank           = 0x8000000f, // WHEAP_FOUND_ERROR_IN_BANK_EVENT
        McaStuckErrorCheck            = 0x80000010, // WHEAP_STUCK_ERROR_EVENT
        McaErrorCleared               = 0x80000011, // WHEAP_ERROR_CLEARED_EVENT
        ClearedPoison                 = 0x80000012, // WHEAP_CLEARED_POISON_EVENT
        ProcessEINJ                   = 0x80000013, // WHEAP_PROCESS_EINJ_EVENT
        ProcessHEST                   = 0x80000014, // WHEAP_PROCESS_HEST_EVENT
        CreateGenericRecord           = 0x80000015, // WHEAP_CREATE_GENERIC_RECORD_EVENT
        ErrorRecord                   = 0x80000016, // WHEAP_ERROR_RECORD_EVENT
        ErrorRecordLimit              = 0x80000017,
        AerNotGrantedToOs             = 0x80000018,
        ErrSrcArrayInvalid            = 0x80000019, // WHEAP_ERR_SRC_ARRAY_INVALID_EVENT
        AcpiTimeOut                   = 0x8000001a, // WHEAP_ACPI_TIMEOUT_EVENT
        CmciRestart                   = 0x8000001b, // WHEAP_CMCI_RESTART_EVENT
        CmciFinalRestart              = 0x8000001c,
        EtwOverFlow                   = 0x8000001d, // WHEA_ETW_OVERFLOW_EVENT
        AzccRootBusSearchErr          = 0x8000001e, // WHEA_AZCC_ROOT_BUS_ERR_EVENT
        AzccRootBusList               = 0x8000001f, // WHEA_AZCC_ROOT_BUS_LIST_EVENT
        ErrSrcInvalid                 = 0x80000020, // WHEAP_ERR_SRC_INVALID_EVENT
        GenericErrMemMap              = 0x80000021, // WHEAP_GENERIC_ERR_MEM_MAP_EVENT
        PshedCallbackCollision        = 0x80000022,
        SELBugCheckProgress           = 0x80000023, // WHEA_SEL_BUGCHECK_PROGRESS
        PshedPluginLoad               = 0x80000024, // WHEA_PSHED_PLUGIN_LOAD_EVENT
        PshedPluginUnload             = 0x80000025, // WHEA_PSHED_PLUGIN_UNLOAD_EVENT
        PshedPluginSupported          = 0x80000026, // WHEA_PSHED_PLUGIN_PLATFORM_SUPPORT_EVENT
        DeviceDriver                  = 0x80000027, // WHEAP_DEVICE_DRV_EVENT
        CmciImplPresent               = 0x80000028, // WHEAP_CMCI_IMPLEMENTED_EVENT
        CmciInitError                 = 0x80000029, // WHEAP_CMCI_INITERR_EVENT
        SELBugCheckRecovery           = 0x8000002a,
        DrvErrSrcInvalid              = 0x8000002b,
        DrvHandleBusy                 = 0x8000002c,
        WheaHeartbeat                 = 0x8000002d, // WHEA_PSHED_PLUGIN_HEARTBEAT
        AzccRootBusPoisonSet          = 0x8000002e, // WHEA_AZCC_SET_POISON_EVENT
        SELBugCheckInfo               = 0x8000002f,
        ErrDimmInfoMismatch           = 0x80000030, // WHEA_PSHED_PLUGIN_DIMM_MISMATCH
        eDpcEnabled                   = 0x80000031, // WHEAP_EDPC_ENABLED_EVENT
        PageOfflineDone               = 0x80000032, // WHEA_OFFLINE_DONE_EVENT
        PageOfflinePendMax            = 0x80000033,
        BadPageLimitReached           = 0x80000034,
        SrarDetail                    = 0x80000035, // WHEA_SRAR_DETAIL_EVENT
        EarlyError                    = 0x80000036,
        PcieOverrideInfo              = 0x80000037, // WHEAP_PCIE_OVERRIDE_INFO
        ReadPcieOverridesErr          = 0x80000038, // WHEAP_PCIE_READ_OVERRIDES_ERR
        PcieConfigInfo                = 0x80000039, // WHEAP_PCIE_CONFIG_INFO
        PcieSummaryFailed             = 0x80000040,
        ThrottleRegCorrupt            = 0x80000041, // WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT
        ThrottleAddErrSrcFailed       = 0x80000042, // WHEA_THROTTLE_ADD_ERR_SRC_FAILED_EVENT
        ThrottleRegDataIgnored        = 0x80000043, // WHEA_THROTTLE_REG_DATA_IGNORED_EVENT
        EnableKeyNotifFailed          = 0x80000044, // WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_FAILED_EVENT
        KeyNotificationFailed         = 0x80000045, // WHEA_REGISTER_KEY_NOTIFICATION_FAILED_EVENT
        PcieRemoveDevice              = 0x80000046, // WHEA_THROTTLE_PCIE_REMOVE_EVENT
        PcieAddDevice                 = 0x80000047, // WHEA_THROTTLE_PCIE_ADD_EVENT
        PcieSpuriousErrSource         = 0x80000048, // WHEAP_SPURIOUS_AER_EVENT
        MemoryAddDevice               = 0x80000049, // WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT
        MemoryRemoveDevice            = 0x8000004a, // WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT
        MemorySummaryFailed           = 0x8000004b, // WHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT
        PcieDpcError                  = 0x8000004c, // WHEAP_DPC_ERROR_EVENT
        CpuBusesInitFailed            = 0x8000004d, // WHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT
        PshedPluginInitFailed         = 0x8000004e, // WHEA_PSHED_PLUGIN_INIT_FAILED_EVENT
        FailedAddToDefectList         = 0x8000004f, // WHEA_FAILED_ADD_DEFECT_LIST_EVENT
        DefectListFull                = 0x80000050, // WHEAP_PLUGIN_DEFECT_LIST_FULL_EVENT
        DefectListUEFIVarFailed       = 0x80000051, // WHEAP_PLUGIN_DEFECT_LIST_UEFI_VAR_FAILED
        DefectListCorrupt             = 0x80000052, // WHEAP_PLUGIN_DEFECT_LIST_CORRUPT
        BadHestNotifyData             = 0x80000053, // WHEAP_BAD_HEST_NOTIFY_DATA_EVENT
        RowFailure                    = 0x80000054, // WHEAP_ROW_FAILURE_EVENT
        SrasTableNotFound             = 0x80000055, // WHEA_SRAS_TABLE_NOT_FOUND
        SrasTableError                = 0x80000056, // WHEA_SRAS_TABLE_ERROR
        SrasTableEntries              = 0x80000057, // WHEA_SRAS_TABLE_ENTRIES_EVENT
        PFANotifyCallbackAction       = 0x80000058, // WHEAP_PFA_MEMORY_OFFLINED_NOTIFY_CALLBACK_ACTION
        SELBugCheckCpusQuiesced       = 0x80000059,
        PshedPiCpuid                  = 0x8000005a, // WHEA_PSHED_PI_CPUID
        SrasTableBadData              = 0x8000005b, // WHEA_SRAS_TABLE_BAD_DATA
        DriFsStatus                   = 0x8000005c,
        CpusFrozen                    = 0x80000060,
        CpusFrozenNoCrashDump         = 0x80000061,
        RegNotifyPolicyChange         = 0x80000062, // WHEA_REGNOTIFY_POLICY_CHANGE_EVENT
        RegError                      = 0x80000063, // WHEA_REGISTRY_ERROR_EVENT
        RowOfflineEvent               = 0x80000064, // WHEAP_ROW_OFFLINE_EVENT
        BitOfflineEvent               = 0x80000065, // WHEAP_BIT_OFFLINE_EVENT
        BadGasFields                  = 0x80000066, // WHEA_GAS_ERROR_EVENT
        CrashDumpError                = 0x80000067,
        CrashDumpCheckpoint           = 0x80000068,
        CrashDumpProgressPercent      = 0x80000069,
        PreviousCrashBugCheckProgress = 0x8000006a,
        SELBugCheckStackDump          = 0x8000006b,
        PciePromotedAerErr            = 0x8000006c, // WHEAP_PROMOTED_AER_ERROR_EVENT
        PshedPiTraceLog               = 0x80040010  // WHEA_PSHED_PI_TRACE_EVENT

        /*
        CmcPollingTimeout             = 0x80000001, // TODO
        WheaInit                      = 0x80000002, // TODO
        CmcSwitchToPolling            = 0x80000003, // TODO
        WorkQueueItem                 = 0x8000000d, // TODO
        ErrorRecordLimit              = 0x80000017, // TODO
        AerNotGrantedToOs             = 0x80000018, // No payload
        CmciFinalRestart              = 0x8000001c, // TODO
        PshedCallbackCollision        = 0x80000022, // TODO
        SELBugCheckRecovery           = 0x8000002a, // TODO
        DrvErrSrcInvalid              = 0x8000002b, // TODO
        DrvHandleBusy                 = 0x8000002c, // TODO
        SELBugCheckInfo               = 0x8000002f, // TODO
        PageOfflinePendMax            = 0x80000033, // TODO
        BadPageLimitReached           = 0x80000034, // TODO
        EarlyError                    = 0x80000036, // TODO
        PcieSummaryFailed             = 0x80000040, // TODO
        SELBugCheckCpusQuiesced       = 0x80000059, // TODO (new)
        DriFsStatus                   = 0x8000005c, // TODO (new)
        CpusFrozen                    = 0x80000060, // No payload
        CpusFrozenNoCrashDump         = 0x80000061, // TODO
        CrashDumpError                = 0x80000067, // TODO (new)
        CrashDumpCheckpoint           = 0x80000068, // TODO (new)
        CrashDumpProgressPercent      = 0x80000069, // TODO (new)
        PreviousCrashBugCheckProgress = 0x8000006a, // TODO (new)
        SELBugCheckStackDump          = 0x8000006b, // TODO (new)
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
