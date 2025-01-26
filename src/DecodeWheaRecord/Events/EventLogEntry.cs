#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;

using DecodeWheaRecord.Events.Hardware;
using DecodeWheaRecord.Events.Software;
using DecodeWheaRecord.Internal;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Events {
    internal sealed class WHEA_EVENT_LOG_ENTRY : WheaRecord {
        private uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        // Size of character array used in many event log entry structures
        internal const int WHEA_ERROR_TEXT_LEN = 32;

        // At least the header
        private const uint MinStructSize = WHEA_EVENT_LOG_ENTRY_HEADER.StructSize;

        [JsonProperty(Order = 1)]
        public WHEA_EVENT_LOG_ENTRY_HEADER Header { get; private set; }

        [JsonProperty(Order = 2)]
        public IWheaRecord Entry { get; private set; }

        public WHEA_EVENT_LOG_ENTRY(IntPtr recordAddr, uint recordSize) :
            base(typeof(WHEA_EVENT_LOG_ENTRY), 0, MinStructSize, recordSize) {
            // Deserialize the header
            Header = new WHEA_EVENT_LOG_ENTRY_HEADER(recordAddr, recordSize);
            var offset = Header.GetNativeSize();

            // Deserialize the payload
            Entry = DecodeEvent(Header, recordAddr);
            if (Entry != null) {
                offset += Entry.GetNativeSize();
            }

            _StructSize = offset;
            FinalizeRecord(recordAddr, _StructSize);
        }

        private static IWheaRecord DecodeEvent(WHEA_EVENT_LOG_ENTRY_HEADER eventHeader, IntPtr recordAddr) {
            IWheaRecord eventEntry = null;

            var headerSize = eventHeader.GetNativeSize();
            var eventAddr = recordAddr + (int)headerSize;

            switch (eventHeader.Id) {
                case "CmcPollingTimeout":
                    eventEntry = PtrToStructureHelper<WHEAP_CMC_POLLING_TIMEOUT_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "WheaInit":
                    eventEntry = new WHEAP_INIT_EVENT(recordAddr, headerSize, eventHeader.PayloadLength);
                    break;
                case "CmcSwitchToPolling":
                    eventEntry = PtrToStructureHelper<WHEAP_CMC_SWITCH_TO_POLLING_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "DroppedCorrectedError":
                    eventEntry = PtrToStructureHelper<WHEAP_DROPPED_CORRECTED_ERROR_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "StartedReportHwError":
                    eventEntry = PtrToStructureHelper<WHEAP_STARTED_REPORT_HW_ERROR>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "PFAMemoryOfflined":
                    eventEntry = PtrToStructureHelper<WHEAP_PFA_MEMORY_OFFLINED>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "PFAMemoryRemoveMonitor":
                    eventEntry = PtrToStructureHelper<WHEAP_PFA_MEMORY_REMOVE_MONITOR>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "PFAMemoryPolicy":
                    eventEntry = PtrToStructureHelper<WHEAP_PFA_MEMORY_POLICY>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "PshedInjectError":
                    eventEntry = PtrToStructureHelper<WHEAP_PSHED_INJECT_ERROR>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "OscCapabilities":
                    eventEntry = PtrToStructureHelper<WHEAP_OSC_IMPLEMENTED>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "PshedPluginRegister":
                    eventEntry = PtrToStructureHelper<WHEAP_PSHED_PLUGIN_REGISTER>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "AddRemoveErrorSource":
                    eventEntry = new WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT(recordAddr, headerSize, eventHeader.PayloadLength);
                    break;
                case "WorkQueueItem":
                    break;
                case "AttemptErrorRecovery":
                    eventEntry = new WHEAP_ATTEMPT_RECOVERY_EVENT(recordAddr, headerSize, eventHeader.PayloadLength);
                    break;
                case "McaFoundErrorInBank":
                    eventEntry = PtrToStructureHelper<WHEAP_FOUND_ERROR_IN_BANK_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "McaStuckErrorCheck":
                    eventEntry = PtrToStructureHelper<WHEAP_STUCK_ERROR_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "McaErrorCleared":
                    eventEntry = PtrToStructureHelper<WHEAP_ERROR_CLEARED_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "ClearedPoison":
                    eventEntry = PtrToStructureHelper<WHEAP_CLEARED_POISON_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "ProcessEINJ":
                    eventEntry = PtrToStructureHelper<WHEAP_PROCESS_EINJ_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "ProcessHEST":
                    eventEntry = PtrToStructureHelper<WHEAP_PROCESS_HEST_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "CreateGenericRecord":
                    eventEntry = PtrToStructureHelper<WHEAP_CREATE_GENERIC_RECORD_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "ErrorRecord":
                    eventEntry = PtrToStructureHelper<WHEAP_ERROR_RECORD_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "ErrorRecordLimit":
                    break;
                case "AerNotGrantedToOs":
                    eventEntry = PtrToStructureHelper<WHEAP_AER_NOT_GRANTED_TO_OS>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "ErrSrcArrayInvalid":
                    eventEntry = PtrToStructureHelper<WHEAP_ERR_SRC_ARRAY_INVALID_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "AcpiTimeOut":
                    eventEntry = PtrToStructureHelper<WHEAP_ACPI_TIMEOUT_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "CmciRestart":
                case "CmciFinalRestart":
                    eventEntry = PtrToStructureHelper<WHEAP_CMCI_RESTART_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "EtwOverFlow":
                    eventEntry = PtrToStructureHelper<WHEA_ETW_OVERFLOW_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "AzccRootBusSearchErr":
                    eventEntry = PtrToStructureHelper<WHEA_AZCC_ROOT_BUS_ERR_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "AzccRootBusList":
                    eventEntry = PtrToStructureHelper<WHEA_AZCC_ROOT_BUS_LIST_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "ErrSrcInvalid":
                    eventEntry = new WHEAP_ERR_SRC_INVALID_EVENT(recordAddr, headerSize, eventHeader.PayloadLength);
                    break;
                case "GenericErrMemMap":
                    eventEntry = PtrToStructureHelper<WHEAP_GENERIC_ERR_MEM_MAP_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "PshedCallbackCollision":
                    eventEntry = PtrToStructureHelper<WHEAP_PSHED_PLUGIN_CALLBACK_COLLISION>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "SELBugCheckProgress":
                    eventEntry = PtrToStructureHelper<WHEA_SEL_BUGCHECK_PROGRESS>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "PshedPluginLoad":
                    eventEntry = PtrToStructureHelper<WHEA_PSHED_PLUGIN_LOAD_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "PshedPluginUnload":
                    eventEntry = PtrToStructureHelper<WHEA_PSHED_PLUGIN_UNLOAD_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "PshedPluginSupported":
                    eventEntry = PtrToStructureHelper<WHEA_PSHED_PLUGIN_PLATFORM_SUPPORT_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "DeviceDriver":
                    break;
                case "CmciImplPresent":
                    eventEntry = PtrToStructureHelper<WHEAP_CMCI_IMPLEMENTED_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "CmciInitError":
                    eventEntry = PtrToStructureHelper<WHEAP_CMCI_INITERR_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "SELBugCheckRecovery":
                    switch (eventHeader.PayloadLength) {
                        case 1:
                            eventEntry = PtrToStructureHelper<WHEA_SEL_BUGCHECK_RECOVERY_STATUS_START_EVENT>(eventAddr, eventHeader.PayloadLength);
                            break;
                        case 3:
                            eventEntry = PtrToStructureHelper<WHEA_SEL_BUGCHECK_RECOVERY_STATUS_MULTIPLE_BUGCHECK_EVENT>(eventAddr, eventHeader.PayloadLength);
                            break;
                        case 5:
                            eventEntry = PtrToStructureHelper<WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE2_EVENT>(eventAddr, eventHeader.PayloadLength);
                            break;
                        case 8:
                            eventEntry = new WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE1_EVENT(recordAddr, headerSize, eventHeader.PayloadLength);
                            break;
                    }
                    break;
                case "DrvErrSrcInvalid":
                case "DrvHandleBusy":
                    eventEntry = PtrToStructureHelper<WHEAP_DEVICE_DRV_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "WheaHeartbeat":
                    eventEntry = PtrToStructureHelper<WHEA_PSHED_PLUGIN_HEARTBEAT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "AzccRootBusPoisonSet":
                    eventEntry = PtrToStructureHelper<WHEA_AZCC_SET_POISON_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "SELBugCheckInfo":
                    break;
                case "ErrDimmInfoMismatch":
                    eventEntry = PtrToStructureHelper<WHEA_PSHED_PLUGIN_DIMM_MISMATCH>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "eDpcEnabled":
                    eventEntry = PtrToStructureHelper<WHEAP_EDPC_ENABLED_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "PageOfflineDone":
                    eventEntry = PtrToStructureHelper<WHEA_OFFLINE_DONE_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "PageOfflinePendMax":
                    eventEntry = PtrToStructureHelper<WHEAP_OFFLINE_PENDING_MAX>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "BadPageLimitReached":
                    eventEntry = PtrToStructureHelper<WHEAP_BAD_PAGE_LIMIT_REACHED>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "SrarDetail":
                    eventEntry = PtrToStructureHelper<WHEA_SRAR_DETAIL_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "EarlyError":
                    eventEntry = PtrToStructureHelper<WHEAP_EARLY_ERROR>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "PcieOverrideInfo":
                    eventEntry = PtrToStructureHelper<WHEAP_PCIE_OVERRIDE_INFO>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "ReadPcieOverridesErr":
                    eventEntry = PtrToStructureHelper<WHEAP_PCIE_READ_OVERRIDES_ERR>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "PcieConfigInfo":
                    eventEntry = PtrToStructureHelper<WHEAP_PCIE_CONFIG_INFO>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "PcieSummaryFailed":
                    eventEntry = PtrToStructureHelper<WHEA_THROTTLE_PCIE_ADD_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "ThrottleRegCorrupt":
                    eventEntry = PtrToStructureHelper<WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "ThrottleAddErrSrcFailed":
                    eventEntry = PtrToStructureHelper<WHEA_THROTTLE_ADD_ERR_SRC_FAILED_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "ThrottleRegDataIgnored":
                    eventEntry = PtrToStructureHelper<WHEA_THROTTLE_REG_DATA_IGNORED_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "EnableKeyNotifFailed":
                    eventEntry = PtrToStructureHelper<WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_FAILED_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "KeyNotificationFailed":
                    eventEntry = PtrToStructureHelper<WHEA_REGISTER_KEY_NOTIFICATION_FAILED_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "PcieRemoveDevice":
                    eventEntry = new WHEA_THROTTLE_PCIE_REMOVE_EVENT(recordAddr, headerSize, eventHeader.PayloadLength);
                    break;
                case "PcieAddDevice":
                    eventEntry = new WHEA_THROTTLE_PCIE_ADD_EVENT(recordAddr, headerSize, eventHeader.PayloadLength);
                    break;
                case "PcieSpuriousErrSource":
                    eventEntry = new WHEAP_SPURIOUS_AER_EVENT(recordAddr, headerSize, eventHeader.PayloadLength);
                    break;
                case "MemoryAddDevice":
                case "MemoryRemoveDevice":
                    eventEntry = PtrToStructureHelper<WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "MemorySummaryFailed":
                    eventEntry = PtrToStructureHelper<WHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "PcieDpcError":
                    eventEntry = PtrToStructureHelper<WHEAP_DPC_ERROR_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "CpuBusesInitFailed":
                    eventEntry = PtrToStructureHelper<WHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "PshedPluginInitFailed":
                    eventEntry = PtrToStructureHelper<WHEA_PSHED_PLUGIN_INIT_FAILED_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "FailedAddToDefectList":
                    eventEntry = PtrToStructureHelper<WHEA_FAILED_ADD_DEFECT_LIST_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "DefectListFull":
                    eventEntry = PtrToStructureHelper<WHEAP_PLUGIN_DEFECT_LIST_FULL_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "DefectListUEFIVarFailed":
                    eventEntry = PtrToStructureHelper<WHEAP_PLUGIN_DEFECT_LIST_UEFI_VAR_FAILED>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "DefectListCorrupt":
                    eventEntry = PtrToStructureHelper<WHEAP_PLUGIN_DEFECT_LIST_CORRUPT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "BadHestNotifyData":
                    eventEntry = PtrToStructureHelper<WHEAP_BAD_HEST_NOTIFY_DATA_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "RowFailure":
                    eventEntry = new WHEAP_ROW_FAILURE_EVENT(recordAddr, headerSize, eventHeader.PayloadLength);
                    break;
                case "SrasTableNotFound":
                    eventEntry = PtrToStructureHelper<WHEA_SRAS_TABLE_NOT_FOUND>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "SrasTableError":
                    eventEntry = PtrToStructureHelper<WHEA_SRAS_TABLE_ERROR>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "SrasTableEntries":
                    eventEntry = new WHEA_SRAS_TABLE_ENTRIES_EVENT(recordAddr, headerSize, eventHeader.PayloadLength);
                    break;
                case "PFANotifyCallbackAction":
                    eventEntry = PtrToStructureHelper<WHEAP_PFA_MEMORY_OFFLINED_NOTIFY_CALLBACK_ACTION>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "SELBugCheckCpusQuiesced":
                    break;
                case "PshedPiCpuid":
                    eventEntry = PtrToStructureHelper<WHEA_PSHED_PI_CPUID>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "SrasTableBadData":
                    eventEntry = PtrToStructureHelper<WHEAP_SRAS_TABLE_BAD_DATA>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "DriFsStatus":
                    break;
                case "CpusFrozen":
                    eventEntry = PtrToStructureHelper<WHEAP_BUGCHECK_CPUS_FROZEN_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "CpusFrozenNoCrashDump":
                    break;
                case "RegNotifyPolicyChange":
                    eventEntry = PtrToStructureHelper<WHEA_REGNOTIFY_POLICY_CHANGE_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "RegError":
                    eventEntry = PtrToStructureHelper<WHEA_REGISTRY_ERROR_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "RowOfflineEvent":
                    eventEntry = new WHEAP_ROW_OFFLINE_EVENT(recordAddr, headerSize, eventHeader.PayloadLength);
                    break;
                case "BitOfflineEvent":
                    eventEntry = new WHEAP_BIT_OFFLINE_EVENT(recordAddr, headerSize, eventHeader.PayloadLength);
                    break;
                case "BadGasFields":
                    eventEntry = PtrToStructureHelper<WHEA_GAS_ERROR_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "CrashDumpError":
                    eventEntry = PtrToStructureHelper<WHEA_CRASHDUMP_EVENT_LOG_ENTRY_WITH_STATUS>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "CrashDumpCheckpoint":
                    break;
                case "CrashDumpProgressPercent":
                    eventEntry = PtrToStructureHelper<WHEA_CRASHDUMP_EVENT_LOG_ENTRY_ULONG1>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "PreviousCrashBugCheckProgress":
                    break;
                case "SELBugCheckStackDump":
                    eventEntry = PtrToStructureHelper<WHEA_SEL_RAW_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "PciePromotedAerErr":
                    eventEntry = PtrToStructureHelper<WHEAP_PROMOTED_AER_ERROR_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
                case "PshedPiTraceLog":
                    eventEntry = PtrToStructureHelper<WHEA_PSHED_PI_TRACE_EVENT>(eventAddr, eventHeader.PayloadLength);
                    break;
            }

            return eventEntry ?? new UnsupportedEvent(recordAddr, headerSize, eventHeader.PayloadLength);
        }

        private static IWheaRecord PtrToStructureHelper<T>(IntPtr eventAddr, uint payloadLength) {
            /*
             * HACK HACK HACK
             *
             * Marshal.SizeOf<T>() returns 1 for empty structures?! Just for
             * the marshalling of event records, of which several are empty
             * structures, override the payload length to 1 if it's zero.
             *
             * This is obviously wrong and should be fixed properly.
             */
            payloadLength = payloadLength == 0 ? 1 : payloadLength;
            return (IWheaRecord)PtrToStructure<T>(eventAddr, payloadLength);
        }
    }
}
