#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;
using System.Text;

using DecodeWheaRecord.Events.Todo;
using DecodeWheaRecord.Events.Hardware;
using DecodeWheaRecord.Events.Software;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;
using DecodeWheaRecord.Errors;

namespace DecodeWheaRecord.Events {
    internal sealed class WHEA_EVENT_LOG_ENTRY : WheaRecord {
        private uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

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
            Entry = DecodeEvent(Header, recordAddr, recordSize - offset);
        }

        private static IWheaRecord DecodeEvent(WHEA_EVENT_LOG_ENTRY_HEADER eventHeader, IntPtr recordAddr, uint recordSize) {
            IWheaRecord eventEntry = null;

            var headerSize = eventHeader.GetNativeSize();
            var eventAddr = recordAddr + (int)headerSize;
            var bytesRemaining = recordSize - headerSize;

            // TODO: Pre/post marshalling debug output for PtrToStructure calls
            switch (eventHeader.Id) {
                case "CmcPollingTimeout":
                    break;
                case "WheaInit":
                    break;
                case "CmcSwitchToPolling":
                    break;
                case "DroppedCorrectedError":
                    break;
                case "StartedReportHwError":
                    break;
                case "PFAMemoryOfflined":
                    eventEntry = Marshal.PtrToStructure<WHEAP_PFA_MEMORY_OFFLINED>(eventAddr);
                    break;
                case "PFAMemoryRemoveMonitor":
                    eventEntry = Marshal.PtrToStructure<WHEAP_PFA_MEMORY_REMOVE_MONITOR>(eventAddr);
                    break;
                case "PFAMemoryPolicy":
                    eventEntry = Marshal.PtrToStructure<WHEAP_PFA_MEMORY_POLICY>(eventAddr);
                    break;
                case "PshedInjectError":
                    break;
                case "OscCapabilities":
                    eventEntry = Marshal.PtrToStructure<WHEAP_OSC_IMPLEMENTED>(eventAddr);
                    break;
                case "PshedPluginRegister":
                    break;
                case "AddRemoveErrorSource":
                    eventEntry = new WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT(recordAddr, headerSize, bytesRemaining);
                    break;
                case "WorkQueueItem":
                    break;
                case "AttemptErrorRecovery":
                    eventEntry = new WHEAP_ATTEMPT_RECOVERY_EVENT(recordAddr, headerSize, bytesRemaining);
                    break;
                case "McaFoundErrorInBank":
                    break;
                case "McaStuckErrorCheck":
                    break;
                case "McaErrorCleared":
                    break;
                case "ClearedPoison":
                    eventEntry = Marshal.PtrToStructure<WHEAP_CLEARED_POISON_EVENT>(eventAddr);
                    break;
                case "ProcessEINJ":
                    eventEntry = Marshal.PtrToStructure<WHEAP_PROCESS_EINJ_EVENT>(eventAddr);
                    break;
                case "ProcessHEST":
                    eventEntry = Marshal.PtrToStructure<WHEAP_PROCESS_HEST_EVENT>(eventAddr);
                    break;
                case "CreateGenericRecord":
                    break;
                case "ErrorRecord":
                    break;
                case "ErrorRecordLimit":
                    break;
                case "AerNotGrantedToOs":
                    break;
                case "ErrSrcArrayInvalid":
                    eventEntry = Marshal.PtrToStructure<WHEAP_ERR_SRC_ARRAY_INVALID_EVENT>(eventAddr);
                    break;
                case "AcpiTimeOut":
                    eventEntry = Marshal.PtrToStructure<WHEAP_ACPI_TIMEOUT_EVENT>(eventAddr);
                    break;
                case "CmciRestart":
                    break;
                case "CmciFinalRestart":
                    break;
                case "EtwOverFlow":
                    eventEntry = Marshal.PtrToStructure<WHEA_ETW_OVERFLOW_EVENT>(eventAddr);
                    break;
                case "AzccRootBusSearchErr":
                    eventEntry = Marshal.PtrToStructure<WHEA_AZCC_ROOT_BUS_ERR_EVENT>(eventAddr);
                    break;
                case "AzccRootBusList":
                    eventEntry = Marshal.PtrToStructure<WHEA_AZCC_ROOT_BUS_LIST_EVENT>(eventAddr);
                    break;
                case "ErrSrcInvalid":
                    eventEntry = new WHEAP_ERR_SRC_INVALID_EVENT(recordAddr, headerSize, bytesRemaining);
                    break;
                case "GenericErrMemMap":
                    break;
                case "PshedCallbackCollision":
                    break;
                case "SELBugCheckProgress":
                    break;
                case "PshedPluginLoad":
                    break;
                case "PshedPluginUnload":
                    break;
                case "PshedPluginSupported":
                    break;
                case "DeviceDriver":
                    break;
                case "CmciImplPresent":
                    break;
                case "CmciInitError":
                    break;
                case "SELBugCheckRecovery":
                    break;
                case "DrvErrSrcInvalid":
                    break;
                case "DrvHandleBusy":
                    break;
                case "WheaHeartbeat":
                    break;
                case "AzccRootBusPoisonSet":
                    eventEntry = Marshal.PtrToStructure<WHEA_AZCC_SET_POISON_EVENT>(eventAddr);
                    break;
                case "SELBugCheckInfo":
                    break;
                case "ErrDimmInfoMismatch":
                    eventEntry = Marshal.PtrToStructure<WHEA_PSHED_PLUGIN_DIMM_MISMATCH>(eventAddr);
                    break;
                case "eDpcEnabled":
                    eventEntry = Marshal.PtrToStructure<WHEAP_EDPC_ENABLED_EVENT>(eventAddr);
                    break;
                case "PageOfflineDone":
                    eventEntry = Marshal.PtrToStructure<WHEA_OFFLINE_DONE_EVENT>(eventAddr);
                    break;
                case "PageOfflinePendMax":
                    break;
                case "BadPageLimitReached":
                    break;
                case "SrarDetail":
                    break;
                case "EarlyError":
                    break;
                case "PcieOverrideInfo":
                    eventEntry = Marshal.PtrToStructure<WHEAP_PCIE_OVERRIDE_INFO>(eventAddr);
                    break;
                case "ReadPcieOverridesErr":
                    eventEntry = Marshal.PtrToStructure<WHEAP_PCIE_READ_OVERRIDES_ERR>(eventAddr);
                    break;
                case "PcieConfigInfo":
                    eventEntry = Marshal.PtrToStructure<WHEAP_PCIE_CONFIG_INFO>(eventAddr);
                    break;
                case "PcieSummaryFailed":
                    break;
                case "ThrottleRegCorrupt":
                    eventEntry = Marshal.PtrToStructure<WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT>(eventAddr);
                    break;
                case "ThrottleAddErrSrcFailed":
                    eventEntry = Marshal.PtrToStructure<WHEA_THROTTLE_ADD_ERR_SRC_FAILED_EVENT>(eventAddr);
                    break;
                case "ThrottleRegDataIgnored":
                    eventEntry = Marshal.PtrToStructure<WHEA_THROTTLE_REG_DATA_IGNORED_EVENT>(eventAddr);
                    break;
                case "EnableKeyNotifFailed":
                    break;
                case "KeyNotificationFailed":
                    eventEntry = Marshal.PtrToStructure<WHEA_REGISTER_KEY_NOTIFICATION_FAILED_EVENT>(eventAddr);
                    break;
                case "PcieRemoveDevice":
                    eventEntry = new WHEA_THROTTLE_PCIE_REMOVE_EVENT(recordAddr, headerSize, bytesRemaining);
                    break;
                case "PcieAddDevice":
                    eventEntry = new WHEA_THROTTLE_PCIE_ADD_EVENT(recordAddr, headerSize, bytesRemaining);
                    break;
                case "PcieSpuriousErrSource":
                    eventEntry = new WHEAP_SPURIOUS_AER_EVENT(recordAddr, headerSize, bytesRemaining);
                    break;
                case "MemoryAddDevice":
                case "MemoryRemoveDevice":
                    eventEntry = Marshal.PtrToStructure<WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT>(eventAddr);
                    break;
                case "MemorySummaryFailed":
                    eventEntry = Marshal.PtrToStructure<WHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT>(eventAddr);
                    break;
                case "PcieDpcError":
                    eventEntry = Marshal.PtrToStructure<WHEAP_DPC_ERROR_EVENT>(eventAddr);
                    break;
                case "CpuBusesInitFailed":
                    eventEntry = Marshal.PtrToStructure<WHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT>(eventAddr);
                    break;
                case "PshedPluginInitFailed":
                    break;
                case "FailedAddToDefectList":
                    eventEntry = Marshal.PtrToStructure<WHEA_FAILED_ADD_DEFECT_LIST_EVENT>(eventAddr);
                    break;
                case "DefectListFull":
                    eventEntry = Marshal.PtrToStructure<WHEAP_PLUGIN_DEFECT_LIST_FULL_EVENT>(eventAddr);
                    break;
                case "DefectListUEFIVarFailed":
                    eventEntry = Marshal.PtrToStructure<WHEAP_PLUGIN_DEFECT_LIST_UEFI_VAR_FAILED>(eventAddr);
                    break;
                case "DefectListCorrupt":
                    eventEntry = Marshal.PtrToStructure<WHEAP_PLUGIN_DEFECT_LIST_CORRUPT>(eventAddr);
                    break;
                case "BadHestNotifyData":
                    eventEntry = Marshal.PtrToStructure<WHEAP_BAD_HEST_NOTIFY_DATA_EVENT>(eventAddr);
                    break;
                case "RowFailure":
                    eventEntry = new WHEAP_ROW_FAILURE_EVENT(recordAddr, headerSize, bytesRemaining);
                    break;
                case "SrasTableNotFound":
                    eventEntry = Marshal.PtrToStructure<WHEA_SRAS_TABLE_NOT_FOUND>(eventAddr);
                    break;
                case "SrasTableError":
                    eventEntry = Marshal.PtrToStructure<WHEA_SRAS_TABLE_ERROR>(eventAddr);
                    break;
                case "SrasTableEntries":
                    eventEntry = new WHEA_SRAS_TABLE_ENTRIES_EVENT(recordAddr, headerSize, bytesRemaining);
                    break;
                case "PFANotifyCallbackAction":
                    eventEntry = Marshal.PtrToStructure<WHEAP_PFA_MEMORY_OFFLINED_NOTIFY_CALLBACK_ACTION>(eventAddr);
                    break;
                case "SELBugCheckCpusQuiesced":
                    break;
                case "PshedPiCpuid":
                    eventEntry = Marshal.PtrToStructure<WHEA_PSHED_PI_CPUID>(eventAddr);
                    break;
                case "SrasTableBadData":
                    eventEntry = Marshal.PtrToStructure<WHEA_SRAS_TABLE_BAD_DATA>(eventAddr);
                    break;
                case "DriFsStatus":
                    break;
                case "CpusFrozen":
                    break;
                case "CpusFrozenNoCrashDump":
                    break;
                case "RegNotifyPolicyChange":
                    eventEntry = Marshal.PtrToStructure<WHEA_REGNOTIFY_POLICY_CHANGE_EVENT>(eventAddr);
                    break;
                case "RegError":
                    eventEntry = Marshal.PtrToStructure<WHEA_REGISTRY_ERROR_EVENT>(eventAddr);
                    break;
                case "RowOfflineEvent":
                    eventEntry = new WHEAP_ROW_OFFLINE_EVENT(recordAddr, headerSize, bytesRemaining);
                    break;
                case "BitOfflineEvent":
                    eventEntry = new WHEAP_BIT_OFFLINE_EVENT(recordAddr, headerSize, bytesRemaining);
                    break;
                case "BadGasFields":
                    eventEntry = Marshal.PtrToStructure<WHEA_GAS_ERROR_EVENT>(eventAddr);
                    break;
                case "CrashDumpError":
                    break;
                case "CrashDumpCheckpoint":
                    break;
                case "CrashDumpProgressPercent":
                    break;
                case "PreviousCrashBugCheckProgress":
                    break;
                case "SELBugCheckStackDump":
                    break;
                case "PciePromotedAerErr":
                    eventEntry = Marshal.PtrToStructure<WHEAP_PROMOTED_AER_ERROR_EVENT>(eventAddr);
                    break;
                case "PshedPiTraceLog":
                    break;
                default:
                    ExitWithMessage($"Unknown WHEA event log entry type: {eventHeader.Id}", code: 2);
                    break;
            }

            return eventEntry;
        }
    }
}
