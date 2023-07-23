using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

using Newtonsoft.Json;

using static DecodeWheaRecord.NativeMethods;
using static DecodeWheaRecord.Utilities;


// Mark assembly as not CLS compliant
[assembly: CLSCompliant(false)]


namespace DecodeWheaRecord {
    public static class Program {
        private static byte[] _recordBytes;
        private static int _recordOffset;

        internal static bool TestMode;

        [SuppressMessage("Design", "CA1062:Validate arguments of public methods")]
        public static void Main(string[] args) {
            if (args.Length == 0)
                ExitWithMessage($"Usage: {Assembly.GetExecutingAssembly().GetName().Name} <WheaHexRecord>");
            else if (args.Length > 1)
                ExitWithMessage($"Expected a hex encoded WHEA record but received {args.Length} arguments.", 1);
            else if (args[0].Length < 8)
                ExitWithMessage("Expected at least 8 hex characters for the 4 byte WHEA record signature.", 2);

            _recordBytes = ConvertHexToBytes(args[0]);
            byte[] signatureBytes = { _recordBytes[0], _recordBytes[1], _recordBytes[2], _recordBytes[3] };
            var signature = Encoding.ASCII.GetString(signatureBytes);

            switch (signature) {
                case WHEA_ERROR_LOG_ENTRY_SIGNATURE: {
                    var header = DecodeWheaEventLogEntryHeader();
                    DecodeWheaEventLogEntryPayload(header);
                    break;
                }
                case WHEA_ERROR_RECORD_SIGNATURE:
                    DecodeWheaErrorRecord();
                    break;
                default:
                    ExitWithMessage($"Unknown WHEA record signature: {signature}", 2);
                    break;
            }

            var remainingBytes = _recordBytes.Length - _recordOffset;
            if (remainingBytes == 0) return;

            var allBytesZero = true;
            for (var i = _recordOffset; i < _recordBytes.Length; i++) {
                if (_recordBytes[i] == 0) continue;

                allBytesZero = false;
                break;
            }

            Console.Error.WriteLine(allBytesZero
                                        ? $"Ignoring remaining {remainingBytes} bytes (all zero)."
                                        : $"{remainingBytes} remaining bytes were not processed.");
        }

        public static void MainTest(string[] args) {
            /*
             * Throw an ArgumentException instead of calling Environment.Exit()
             * when ExitWithMessage() is called.
             */
            TestMode = true;

            /*
             * Reset the record offset to 0 as we are being invoked multiple
             * times within a single process.
             */
            _recordOffset = 0;

            Main(args);
        }

        private static void DecodeWheaErrorRecord() {
            var header = MarshalWheaRecord(typeof(WHEA_ERROR_RECORD_HEADER)) as WHEA_ERROR_RECORD_HEADER;
            Debug.Assert(header != null, nameof(header) + " != null");

            var headerJson = JsonConvert.SerializeObject(header, Formatting.Indented);
            Console.Out.WriteLine(headerJson);

            for (var sectionIndex = 0; sectionIndex < header.SectionCount; sectionIndex++) {
                var sectionDsc =
                    MarshalWheaRecord(typeof(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR)) as
                        WHEA_ERROR_RECORD_SECTION_DESCRIPTOR;
                Debug.Assert(sectionDsc != null, nameof(sectionDsc) + " != null");

                var sectionDscJson = JsonConvert.SerializeObject(sectionDsc, Formatting.Indented);
                Console.Out.WriteLine(sectionDscJson);

                if (sectionDsc.SectionType == "Firmware Error Record Reference") {
                    var fwRecordRef =
                        MarshalWheaRecord(typeof(WHEA_FIRMWARE_ERROR_RECORD_REFERENCE)) as
                            WHEA_FIRMWARE_ERROR_RECORD_REFERENCE;
                    var fwRecordRefJson = JsonConvert.SerializeObject(fwRecordRef, Formatting.Indented);
                    Console.Out.WriteLine(fwRecordRefJson);
                }
            }
        }

        private static WHEA_EVENT_LOG_ENTRY_HEADER DecodeWheaEventLogEntryHeader() {
            var header = MarshalWheaRecord(typeof(WHEA_EVENT_LOG_ENTRY_HEADER)) as WHEA_EVENT_LOG_ENTRY_HEADER;
            Debug.Assert(header != null, nameof(header) + " != null");

            var headerJson = JsonConvert.SerializeObject(header, Formatting.Indented);
            Console.Out.WriteLine(headerJson);

            return header;
        }

        private static void DecodeWheaEventLogEntryPayload(WHEA_EVENT_LOG_ENTRY_HEADER header) {
            var payloadJson = string.Empty;

            switch (header.Id) {
                case "CmcPollingTimeout":
                    ExitUnsupportedEvent(header.Id);
                    break;
                case "WheaInit":
                    ExitUnsupportedEvent(header.Id);
                    break;
                case "CmcSwitchToPolling":
                    ExitUnsupportedEvent(header.Id);
                    break;
                case "DroppedCorrectedError":
                    var droppedCorrectedError = MarshalWheaRecord(typeof(WHEAP_DROPPED_CORRECTED_ERROR_EVENT)) as WHEAP_DROPPED_CORRECTED_ERROR_EVENT;
                    payloadJson = JsonConvert.SerializeObject(droppedCorrectedError, Formatting.Indented);
                    break;
                case "StartedReportHwError":
                    ExitUnsupportedEvent(header.Id);
                    break;
                case "PFAMemoryOfflined":
                    var pfaMemoryOfflined = MarshalWheaRecord(typeof(WHEAP_PFA_MEMORY_OFFLINED)) as WHEAP_PFA_MEMORY_OFFLINED;
                    payloadJson = JsonConvert.SerializeObject(pfaMemoryOfflined, Formatting.Indented);
                    break;
                case "PFAMemoryRemoveMonitor":
                    var pfaMemoryRemoveMonitor = MarshalWheaRecord(typeof(WHEAP_PFA_MEMORY_REMOVE_MONITOR)) as WHEAP_PFA_MEMORY_REMOVE_MONITOR;
                    payloadJson = JsonConvert.SerializeObject(pfaMemoryRemoveMonitor, Formatting.Indented);
                    break;
                case "PFAMemoryPolicy":
                    var pfaMemoryPolicy = MarshalWheaRecord(typeof(WHEAP_PFA_MEMORY_POLICY)) as WHEAP_PFA_MEMORY_POLICY;
                    payloadJson = JsonConvert.SerializeObject(pfaMemoryPolicy, Formatting.Indented);
                    break;
                case "PshedInjectError":
                    var PshedInjectError = MarshalWheaRecord(typeof(WHEAP_PSHED_INJECT_ERROR)) as WHEAP_PSHED_INJECT_ERROR;
                    payloadJson = JsonConvert.SerializeObject(PshedInjectError, Formatting.Indented);
                    break;
                case "OscCapabilities":
                    var oscCapabilities = MarshalWheaRecord(typeof(WHEAP_OSC_IMPLEMENTED)) as WHEAP_OSC_IMPLEMENTED;
                    payloadJson = JsonConvert.SerializeObject(oscCapabilities, Formatting.Indented);
                    break;
                case "PshedPluginRegister":
                    var pshedPluginRegister = MarshalWheaRecord(typeof(WHEAP_PSHED_PLUGIN_REGISTER)) as WHEAP_PSHED_PLUGIN_REGISTER;
                    payloadJson = JsonConvert.SerializeObject(pshedPluginRegister, Formatting.Indented);
                    break;
                case "AddRemoveErrorSource":
                    var addRemoveErrorSource = MarshalWheaRecord(typeof(WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT)) as WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT;
                    payloadJson = JsonConvert.SerializeObject(addRemoveErrorSource, Formatting.Indented);
                    break;
                case "WorkQueueItem":
                    ExitUnsupportedEvent(header.Id);
                    break;
                case "AttemptErrorRecovery":
                    var attemptErrorRecovery = MarshalWheaRecord(typeof(WHEAP_ATTEMPT_RECOVERY_EVENT)) as WHEAP_ATTEMPT_RECOVERY_EVENT;
                    payloadJson = JsonConvert.SerializeObject(attemptErrorRecovery, Formatting.Indented);
                    break;
                case "McaFoundErrorInBank":
                    var mcaFoundErrorInBank = MarshalWheaRecord(typeof(WHEAP_FOUND_ERROR_IN_BANK_EVENT)) as WHEAP_FOUND_ERROR_IN_BANK_EVENT;
                    payloadJson = JsonConvert.SerializeObject(mcaFoundErrorInBank, Formatting.Indented);
                    break;
                case "McaStuckErrorCheck":
                    var mcaStuckErrorCheck = MarshalWheaRecord(typeof(WHEAP_STUCK_ERROR_EVENT)) as WHEAP_STUCK_ERROR_EVENT;
                    payloadJson = JsonConvert.SerializeObject(mcaStuckErrorCheck, Formatting.Indented);
                    break;
                case "McaErrorCleared":
                    var mcaErrorCleared = MarshalWheaRecord(typeof(WHEAP_ERROR_CLEARED_EVENT)) as WHEAP_ERROR_CLEARED_EVENT;
                    payloadJson = JsonConvert.SerializeObject(mcaErrorCleared, Formatting.Indented);
                    break;
                case "ClearedPoison":
                    var clearedPoison = MarshalWheaRecord(typeof(WHEAP_CLEARED_POISON_EVENT)) as WHEAP_CLEARED_POISON_EVENT;
                    payloadJson = JsonConvert.SerializeObject(clearedPoison, Formatting.Indented);
                    break;
                case "ProcessEINJ":
                    var processEINJ = MarshalWheaRecord(typeof(WHEAP_PROCESS_EINJ_EVENT)) as WHEAP_PROCESS_EINJ_EVENT;
                    payloadJson = JsonConvert.SerializeObject(processEINJ, Formatting.Indented);
                    break;
                case "ProcessHEST":
                    var processHEST = MarshalWheaRecord(typeof(WHEAP_PROCESS_HEST_EVENT)) as WHEAP_PROCESS_HEST_EVENT;
                    payloadJson = JsonConvert.SerializeObject(processHEST, Formatting.Indented);
                    break;
                case "CreateGenericRecord":
                    var createGenericRecord = MarshalWheaRecord(typeof(WHEAP_CREATE_GENERIC_RECORD_EVENT)) as WHEAP_CREATE_GENERIC_RECORD_EVENT;
                    payloadJson = JsonConvert.SerializeObject(createGenericRecord, Formatting.Indented);
                    break;
                case "ErrorRecord":
                    ExitUnsupportedEvent(header.Id);
                    break;
                case "ErrorRecordLimit":
                    ExitUnsupportedEvent(header.Id);
                    break;
                case "AerNotGrantedToOs":
                    // No payload
                    break;
                case "ErrSrcArrayInvalid":
                    var errSrcArrayInvalid = MarshalWheaRecord(typeof(WHEAP_ERR_SRC_ARRAY_INVALID_EVENT)) as WHEAP_ERR_SRC_ARRAY_INVALID_EVENT;
                    payloadJson = JsonConvert.SerializeObject(errSrcArrayInvalid, Formatting.Indented);
                    break;
                case "AcpiTimeOut":
                    var acpiTimeOut = MarshalWheaRecord(typeof(WHEAP_ACPI_TIMEOUT_EVENT)) as WHEAP_ACPI_TIMEOUT_EVENT;
                    payloadJson = JsonConvert.SerializeObject(acpiTimeOut, Formatting.Indented);
                    break;
                case "CmciRestart":
                    var cmciRestart = MarshalWheaRecord(typeof(WHEAP_CMCI_RESTART_EVENT)) as WHEAP_CMCI_RESTART_EVENT;
                    payloadJson = JsonConvert.SerializeObject(cmciRestart, Formatting.Indented);
                    break;
                case "CmciFinalRestart":
                    ExitUnsupportedEvent(header.Id);
                    break;
                case "EntryEtwOverFlow":
                    var entryEtwOverFlow = MarshalWheaRecord(typeof(WHEA_ETW_OVERFLOW_EVENT)) as WHEA_ETW_OVERFLOW_EVENT;
                    payloadJson = JsonConvert.SerializeObject(entryEtwOverFlow, Formatting.Indented);
                    break;
                case "AzccRootBusSearchErr":
                    var azccRootBusSearchErr = MarshalWheaRecord(typeof(WHEA_AZCC_ROOT_BUS_ERR_EVENT)) as WHEA_AZCC_ROOT_BUS_ERR_EVENT;
                    payloadJson = JsonConvert.SerializeObject(azccRootBusSearchErr, Formatting.Indented);
                    break;
                case "AzccRootBusList":
                    var azccRootBusList = MarshalWheaRecord(typeof(WHEA_AZCC_ROOT_BUS_LIST_EVENT)) as WHEA_AZCC_ROOT_BUS_LIST_EVENT;
                    payloadJson = JsonConvert.SerializeObject(azccRootBusList, Formatting.Indented);
                    break;
                case "ErrSrcInvalid":
                    var errSrcInvalid = MarshalWheaRecord(typeof(WHEAP_ERR_SRC_INVALID_EVENT)) as WHEAP_ERR_SRC_INVALID_EVENT;
                    payloadJson = JsonConvert.SerializeObject(errSrcInvalid, Formatting.Indented);
                    break;
                case "GenericErrMemMap":
                    var genericErrMemMap = MarshalWheaRecord(typeof(WHEAP_GENERIC_ERR_MEM_MAP_EVENT)) as WHEAP_GENERIC_ERR_MEM_MAP_EVENT;
                    payloadJson = JsonConvert.SerializeObject(genericErrMemMap, Formatting.Indented);
                    break;
                case "PshedCallbackCollision":
                    ExitUnsupportedEvent(header.Id);
                    break;
                case "SELBugCheckProgress":
                    var selBugCheckProgress = MarshalWheaRecord(typeof(WHEA_SEL_BUGCHECK_PROGRESS)) as WHEA_SEL_BUGCHECK_PROGRESS;
                    payloadJson = JsonConvert.SerializeObject(selBugCheckProgress, Formatting.Indented);
                    break;
                case "PshedPluginLoad":
                    var pshedPluginLoad = MarshalWheaRecord(typeof(WHEA_PSHED_PLUGIN_LOAD_EVENT)) as WHEA_PSHED_PLUGIN_LOAD_EVENT;
                    payloadJson = JsonConvert.SerializeObject(pshedPluginLoad, Formatting.Indented);
                    break;
                case "PshedPluginUnload":
                    var pshedPluginUnload = MarshalWheaRecord(typeof(WHEA_PSHED_PLUGIN_UNLOAD_EVENT)) as WHEA_PSHED_PLUGIN_UNLOAD_EVENT;
                    payloadJson = JsonConvert.SerializeObject(pshedPluginUnload, Formatting.Indented);
                    break;
                case "PshedPluginSupported":
                    var pshedPluginSupported = MarshalWheaRecord(typeof(WHEA_PSHED_PLUGIN_PLATFORM_SUPPORT_EVENT)) as WHEA_PSHED_PLUGIN_PLATFORM_SUPPORT_EVENT;
                    payloadJson = JsonConvert.SerializeObject(pshedPluginSupported, Formatting.Indented);
                    break;
                case "DeviceDriver":
                    var deviceDriver = MarshalWheaRecord(typeof(WHEAP_DEVICE_DRV_EVENT)) as WHEAP_DEVICE_DRV_EVENT;
                    payloadJson = JsonConvert.SerializeObject(deviceDriver, Formatting.Indented);
                    break;
                case "CmciImplPresent":
                    var cmciImplPresent = MarshalWheaRecord(typeof(WHEAP_CMCI_IMPLEMENTED_EVENT)) as WHEAP_CMCI_IMPLEMENTED_EVENT;
                    payloadJson = JsonConvert.SerializeObject(cmciImplPresent, Formatting.Indented);
                    break;
                case "CmciInitError":
                    var cmciInitError = MarshalWheaRecord(typeof(WHEAP_CMCI_INITERR_EVENT)) as WHEAP_CMCI_INITERR_EVENT;
                    payloadJson = JsonConvert.SerializeObject(cmciInitError, Formatting.Indented);
                    break;
                case "SELBugCheckRecovery":
                    ExitUnsupportedEvent(header.Id);
                    break;
                case "DrvErrSrcInvalid":
                    ExitUnsupportedEvent(header.Id);
                    break;
                case "DrvHandleBusy":
                    ExitUnsupportedEvent(header.Id);
                    break;
                case "WheaHeartbeat":
                    // No payload
                    break;
                case "AzccRootBusPoisonSet":
                    var azccRootBusPoisonSet = MarshalWheaRecord(typeof(WHEA_AZCC_SET_POISON_EVENT)) as WHEA_AZCC_SET_POISON_EVENT;
                    payloadJson = JsonConvert.SerializeObject(azccRootBusPoisonSet, Formatting.Indented);
                    break;
                case "SELBugCheckInfo":
                    ExitUnsupportedEvent(header.Id);
                    break;
                case "ErrDimmInfoMismatch":
                    var errDimmInfoMismatch = MarshalWheaRecord(typeof(WHEA_PSHED_PLUGIN_DIMM_MISMATCH)) as WHEA_PSHED_PLUGIN_DIMM_MISMATCH;
                    payloadJson = JsonConvert.SerializeObject(errDimmInfoMismatch, Formatting.Indented);
                    break;
                case "eDpcEnabled":
                    var eDpcEnabled = MarshalWheaRecord(typeof(WHEAP_EDPC_ENABLED_EVENT)) as WHEAP_EDPC_ENABLED_EVENT;
                    payloadJson = JsonConvert.SerializeObject(eDpcEnabled, Formatting.Indented);
                    break;
                case "PageOfflineDone":
                    var pageOfflineDone = MarshalWheaRecord(typeof(WHEA_OFFLINE_DONE_EVENT)) as WHEA_OFFLINE_DONE_EVENT;
                    payloadJson = JsonConvert.SerializeObject(pageOfflineDone, Formatting.Indented);
                    break;
                case "PageOfflinePendMax":
                    ExitUnsupportedEvent(header.Id);
                    break;
                case "BadPageLimitReached":
                    ExitUnsupportedEvent(header.Id);
                    break;
                case "SrarDetail":
                    var srarDetail = MarshalWheaRecord(typeof(WHEA_SRAR_DETAIL_EVENT)) as WHEA_SRAR_DETAIL_EVENT;
                    payloadJson = JsonConvert.SerializeObject(srarDetail, Formatting.Indented);
                    break;
                case "EarlyError":
                    ExitUnsupportedEvent(header.Id);
                    break;
                case "PcieOverrideInfo":
                    var pcieOverrideInfo = MarshalWheaRecord(typeof(WHEAP_PCIE_OVERRIDE_INFO)) as WHEAP_PCIE_OVERRIDE_INFO;
                    payloadJson = JsonConvert.SerializeObject(pcieOverrideInfo, Formatting.Indented);
                    break;
                case "ReadPcieOverridesErr":
                    var readPcieOverridesErr = MarshalWheaRecord(typeof(WHEAP_PCIE_READ_OVERRIDES_ERR)) as WHEAP_PCIE_READ_OVERRIDES_ERR;
                    payloadJson = JsonConvert.SerializeObject(readPcieOverridesErr, Formatting.Indented);
                    break;
                case "PcieConfigInfo":
                    var pcieConfigInfo = MarshalWheaRecord(typeof(WHEAP_PCIE_CONFIG_INFO)) as WHEAP_PCIE_CONFIG_INFO;
                    payloadJson = JsonConvert.SerializeObject(pcieConfigInfo, Formatting.Indented);
                    break;
                case "PcieSummaryFailed":
                    ExitUnsupportedEvent(header.Id);
                    break;
                case "ThrottleRegCorrupt":
                    var throttleRegCorrupt = MarshalWheaRecord(typeof(WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT)) as WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT;
                    payloadJson = JsonConvert.SerializeObject(throttleRegCorrupt, Formatting.Indented);
                    break;
                case "ThrottleAddErrSrcFailed":
                    // No payload
                    break;
                case "ThrottleRegDataIgnored":
                    var throttleRegDataIgnored = MarshalWheaRecord(typeof(WHEA_THROTTLE_REG_DATA_IGNORED_EVENT)) as WHEA_THROTTLE_REG_DATA_IGNORED_EVENT;
                    payloadJson = JsonConvert.SerializeObject(throttleRegDataIgnored, Formatting.Indented);
                    break;
                case "EnableKeyNotifFailed":
                    var enableKeyNotifFailed =
                        MarshalWheaRecord(typeof(WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_FAILED_EVENT)) as WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_FAILED_EVENT;
                    payloadJson = JsonConvert.SerializeObject(enableKeyNotifFailed, Formatting.Indented);
                    break;
                case "KeyNotificationFailed":
                    // No payload
                    break;
                case "PcieRemoveDevice":
                    var pcieRemoveDevice = MarshalWheaRecord(typeof(WHEA_THROTTLE_PCIE_REMOVE_EVENT)) as WHEA_THROTTLE_PCIE_REMOVE_EVENT;
                    payloadJson = JsonConvert.SerializeObject(pcieRemoveDevice, Formatting.Indented);
                    break;
                case "PcieAddDevice":
                    var pcieAddDevice = MarshalWheaRecord(typeof(WHEA_THROTTLE_PCIE_ADD_EVENT)) as WHEA_THROTTLE_PCIE_ADD_EVENT;
                    payloadJson = JsonConvert.SerializeObject(pcieAddDevice, Formatting.Indented);
                    break;
                case "PcieSpuriousErrSource":
                    var pcieSpuriousErrSource = MarshalWheaRecord(typeof(WHEAP_SPURIOUS_AER_EVENT)) as WHEAP_SPURIOUS_AER_EVENT;
                    payloadJson = JsonConvert.SerializeObject(pcieSpuriousErrSource, Formatting.Indented);
                    break;
                case "MemoryAddDevice":
                case "MemoryRemoveDevice":
                    var memoryAddOrRemoveDevice =
                        MarshalWheaRecord(typeof(WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT)) as WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT;
                    payloadJson = JsonConvert.SerializeObject(memoryAddOrRemoveDevice, Formatting.Indented);
                    break;
                case "MemorySummaryFailed":
                    var memorySummaryFailed = MarshalWheaRecord(typeof(WHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT)) as WHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT;
                    payloadJson = JsonConvert.SerializeObject(memorySummaryFailed, Formatting.Indented);
                    break;
                case "PcieDpcError":
                    var pcieDpcError = MarshalWheaRecord(typeof(WHEAP_DPC_ERROR_EVENT)) as WHEAP_DPC_ERROR_EVENT;
                    payloadJson = JsonConvert.SerializeObject(pcieDpcError, Formatting.Indented);
                    break;
                case "CpuBusesInitFailed":
                    var cpuBusesInitFailed = MarshalWheaRecord(typeof(WHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT)) as WHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT;
                    payloadJson = JsonConvert.SerializeObject(cpuBusesInitFailed, Formatting.Indented);
                    break;
                case "PshedPluginInitFailed":
                    var pshedPluginInitFailed = MarshalWheaRecord(typeof(WHEA_PSHED_PLUGIN_INIT_FAILED_EVENT)) as WHEA_PSHED_PLUGIN_INIT_FAILED_EVENT;
                    payloadJson = JsonConvert.SerializeObject(pshedPluginInitFailed, Formatting.Indented);
                    break;
                case "FailedAddToDefectList":
                    // No payload
                    break;
                case "DefectListFull":
                    // No payload
                    break;
                case "DefectListUEFIVarFailed":
                    // No payload
                    break;
                case "DefectListCorrupt":
                    // No payload
                    break;
                case "BadHestNotifyData":
                    var badHestNotifyData = MarshalWheaRecord(typeof(WHEAP_BAD_HEST_NOTIFY_DATA_EVENT)) as WHEAP_BAD_HEST_NOTIFY_DATA_EVENT;
                    payloadJson = JsonConvert.SerializeObject(badHestNotifyData, Formatting.Indented);
                    break;
                case "SrasTableNotFound":
                    // No payload
                    break;
                case "SrasTableError":
                    // No payload
                    break;
                case "SrasTableEntries":
                    var srasTableEntries = MarshalWheaRecord(typeof(WHEAP_SRAS_TABLE_ENTRIES_EVENT)) as WHEAP_SRAS_TABLE_ENTRIES_EVENT;
                    payloadJson = JsonConvert.SerializeObject(srasTableEntries, Formatting.Indented);
                    break;
                case "RowFailure":
                    var rowFailure = MarshalWheaRecord(typeof(WHEAP_ROW_FAILURE_EVENT)) as WHEAP_ROW_FAILURE_EVENT;
                    payloadJson = JsonConvert.SerializeObject(rowFailure, Formatting.Indented);
                    break;
                case "CpusFrozen":
                    ExitUnsupportedEvent(header.Id);
                    break;
                case "CpusFrozenNoCrashDump":
                    ExitUnsupportedEvent(header.Id);
                    break;
                case "PshedPiTraceLog":
                    var pshedPiTraceLog = MarshalWheaRecord(typeof(WHEA_PSHED_PI_TRACE_EVENT)) as WHEA_PSHED_PI_TRACE_EVENT;
                    payloadJson = JsonConvert.SerializeObject(pshedPiTraceLog, Formatting.Indented);
                    break;
                default:
                    ExitWithMessage($"Unknown WHEA event log entry type: {header.Id}", 2);
                    break;
            }

            if (!string.IsNullOrEmpty(payloadJson))
                Console.Out.WriteLine(payloadJson);
        }

        private static WheaRecord MarshalWheaRecord(Type recordType) {
            var recordSize = Marshal.SizeOf(recordType);
#if DEBUG
            Console.Error.WriteLine($"Expected size of {recordType.Name} record: {recordSize}");
#endif

            var remainingBytes = _recordBytes.Length - _recordOffset;
            if (remainingBytes < recordSize)
                ExitWithMessage($"[{nameof(recordType)}] Provided record is too small: {remainingBytes} bytes", 2);

            var recordBytes = new byte[recordSize];
            for (var i = 0; i < recordBytes.Length; i++) recordBytes[i] = _recordBytes[_recordOffset + i];

            WheaRecord record;
            var hRecord = GCHandle.Alloc(recordBytes, GCHandleType.Pinned);
            try {
                record = Marshal.PtrToStructure(hRecord.AddrOfPinnedObject(), recordType) as WheaRecord;
                Debug.Assert(record != null, nameof(record) + " != null");
                record.Validate();
            } finally {
                hRecord.Free();
            }

            _recordOffset += recordSize;
            return record;
        }
    }
}
