using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

using DecodeWheaRecord.Errors;

using Newtonsoft.Json;

using static DecodeWheaRecord.NativeMethods;
using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord {
    internal static class Decoder {
        private interface IWheaDecoder {
            bool Decode();
            bool Validate();
        }

        /*
         * Implements the WHEA_ERROR_RECORD structure. This structure can't be
         * directly marshalled due to its usage of a variably sized array for
         * holding the error record section descriptors. There's no field for
         * the error record sections themselves, but they are also implicitly
         * part of the structure. Note that while each error record section
         * must have a corresponding error record section descriptor, it's
         * entirely valid to have a descriptor with no error record section.
         */
        internal sealed class WheaErrorRecord : IWheaDecoder {
            public const string StructureName = "WHEA_ERROR_RECORD";

            // Byte array of the entire error record
            private byte[] _recordBytes;

            // Offset in the byte array for an operation
            private uint _recordOffset;

            // Total bytes that have been processed
            private uint _bytesProcessed;

            // Total bytes that have been marshalled
            private uint _bytesMarshalled;

            [JsonProperty(Order = 1)]
            public WHEA_ERROR_RECORD_HEADER Header { get; private set; }

            [JsonProperty(Order = 2)]
            public List<WHEA_ERROR_RECORD_SECTION_DESCRIPTOR> SectionDescriptor { get; private set; }

            [JsonProperty(Order = 3)]
            public List<WheaRecord> Section { get; private set; }

            public WheaErrorRecord(byte[] recordBytes) {
                _recordBytes = recordBytes;
                _recordOffset = 0;

                _bytesProcessed = 0;
                _bytesMarshalled = 0;

                SectionDescriptor = new List<WHEA_ERROR_RECORD_SECTION_DESCRIPTOR>();
                Section = new List<WheaRecord>();
            }

            public bool Decode() {
                var hRecord = GCHandle.Alloc(_recordBytes, GCHandleType.Pinned);
                var recordAddr = hRecord.AddrOfPinnedObject();

                var header =
                    MarshalWheaRecord(typeof(WHEA_ERROR_RECORD_HEADER), ref _recordBytes, ref _recordOffset, out var bytesMarshalled) as
                        WHEA_ERROR_RECORD_HEADER;
                Debug.Assert(header != null, nameof(header) + " != null");

                if (header.Length != _recordBytes.Length) {
                    Console.Error.Write($"Provided {_recordBytes.Length} bytes but expected {header.Length} bytes.");
                    Environment.Exit(1);
                }

                _bytesProcessed += bytesMarshalled;
                _bytesMarshalled += bytesMarshalled;
                Header = header;

                for (var sectionIdx = 0; sectionIdx < Header.SectionCount; sectionIdx++) {
                    var sectionDsc =
                        MarshalWheaRecord(typeof(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR), ref _recordBytes, ref _recordOffset, out bytesMarshalled) as
                            WHEA_ERROR_RECORD_SECTION_DESCRIPTOR;
                    Debug.Assert(sectionDsc != null, nameof(sectionDsc) + " != null");

                    _bytesProcessed += bytesMarshalled;
                    _bytesMarshalled += bytesMarshalled;
                    SectionDescriptor.Add(sectionDsc);
                }

                foreach (var sectionDsc in SectionDescriptor) {
                    WheaRecord section = null;

                    switch (sectionDsc.SectionTypeGuid) {
                        case var sectionGuid when sectionGuid == ARM_PROCESSOR_ERROR_SECTION_GUID:
                            section = new WHEA_ARM_PROCESSOR_ERROR_SECTION(recordAddr, sectionDsc);
                            _recordOffset += (uint)section.GetNativeSize();
                            break;
                        case var sectionGuid when sectionGuid == FIRMWARE_ERROR_RECORD_REFERENCE_GUID:
                            section = new WHEA_FIRMWARE_ERROR_RECORD_REFERENCE(recordAddr, sectionDsc);
                            _recordOffset += (uint)section.GetNativeSize();
                            break;
                        case var sectionGuid when sectionGuid == MU_TELEMETRY_SECTION_GUID:
                            section = MarshalWheaRecord(typeof(MU_TELEMETRY_SECTION), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                            break;
                        case var sectionGuid when sectionGuid == WHEA_ERROR_PACKET_SECTION_GUID:
                            section = WHEA_ERROR_PACKET.CreateBySignature(recordAddr, sectionDsc);
                            _recordOffset += (uint)section.GetNativeSize();
                            break;
                        case var sectionGuid when sectionGuid == RECOVERY_INFO_SECTION_GUID:
                            section = MarshalWheaRecord(typeof(WHEA_ERROR_RECOVERY_INFO_SECTION), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                            break;
                        case var sectionGuid when sectionGuid == MEMORY_CORRECTABLE_ERROR_SUMMARY_SECTION_GUID:
                            section = new WHEA_MEMORY_CORRECTABLE_ERROR_SECTION(recordAddr, sectionDsc);
                            _recordOffset += (uint)section.GetNativeSize();
                            break;
                        case var sectionGuid when sectionGuid == MEMORY_ERROR_SECTION_GUID:
                            section = MarshalWheaRecord(typeof(WHEA_MEMORY_ERROR_SECTION), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                            break;
                        case var sectionGuid when sectionGuid == IPMI_MSR_DUMP_SECTION_GUID:
                            section = new WHEA_MSR_DUMP_SECTION(recordAddr, sectionDsc);
                            _recordOffset += (uint)section.GetNativeSize();
                            break;
                        case var sectionGuid when sectionGuid == NMI_SECTION_GUID:
                            section = MarshalWheaRecord(typeof(WHEA_NMI_ERROR_SECTION), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                            break;
                        case var sectionGuid when sectionGuid == PCIE_CORRECTABLE_ERROR_SUMMARY_SECTION_GUID:
                            section = new WHEA_PCIE_CORRECTABLE_ERROR_SECTION(recordAddr, sectionDsc);
                            _recordOffset += (uint)section.GetNativeSize();
                            break;
                        case var sectionGuid when sectionGuid == PCIEXPRESS_ERROR_SECTION_GUID:
                            section = new WHEA_PCIEXPRESS_ERROR_SECTION(recordAddr, sectionDsc);
                            _recordOffset += (uint)section.GetNativeSize();
                            break;
                        case var sectionGuid when sectionGuid == PCIXBUS_ERROR_SECTION_GUID:
                            section = MarshalWheaRecord(typeof(WHEA_PCIXBUS_ERROR_SECTION), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                            break;
                        case var sectionGuid when sectionGuid == PCIXDEVICE_ERROR_SECTION_GUID:
                            section = new WHEA_PCIXDEVICE_ERROR_SECTION(recordAddr, sectionDsc);
                            _recordOffset += (uint)section.GetNativeSize();
                            break;
                        case var sectionGuid when sectionGuid == PMEM_ERROR_SECTION_GUID:
                            section = new WHEA_PMEM_ERROR_SECTION(recordAddr, sectionDsc);
                            _recordOffset += (uint)section.GetNativeSize();
                            break;
                        case var sectionGuid when sectionGuid == PROCESSOR_GENERIC_ERROR_SECTION_GUID:
                            section = new WHEA_PROCESSOR_GENERIC_ERROR_SECTION(recordAddr, sectionDsc);
                            _recordOffset += (uint)section.GetNativeSize();
                            break;
                        case var sectionGuid when sectionGuid == XPF_PROCESSOR_ERROR_SECTION_GUID:
                            section = new WHEA_XPF_PROCESSOR_ERROR_SECTION(recordAddr, sectionDsc);
                            _recordOffset += (uint)section.GetNativeSize();
                            break;
                        case var sectionGuid when sectionGuid == XPF_MCA_SECTION_GUID:
                            section = new WHEA_XPF_MCA_SECTION(recordAddr, sectionDsc);
                            _recordOffset += (uint)section.GetNativeSize();
                            break;
                        default:
                            // TODO
                            bytesMarshalled = 0;
                            break;
                    }

                    _bytesProcessed += sectionDsc.SectionLength;
                    _bytesMarshalled += bytesMarshalled;
                    if (section != null) Section.Add(section);
                }

                return true;
            }

            public bool Validate() {
                if (Header.Length != _bytesProcessed) {
                    var msg = $"[{StructureName}] Header indicates error record contains {Header.Length} bytes but processed {_bytesProcessed} bytes.";
                    Console.Error.WriteLine(msg);
                }

                if (Header.Length != _bytesMarshalled) {
                    var msg = $"[{StructureName}] Header indicates error record contains {Header.Length} bytes but marshalled {_bytesMarshalled} bytes.";
                    Console.Error.WriteLine(msg);
                }

                return true;
            }
        }

        /*
         * Implements the WHEA_EVENT_LOG_ENTRY structure. This structure can't
         * be directly marshalled due to its usage of a variably sized byte
         * array for holding the event data.
         */
        internal sealed class WheaEventRecord : IWheaDecoder {
            public const string StructureName = "WHEA_EVENT_LOG_ENTRY";

            // Byte array of the entire error record
            private byte[] _recordBytes;

            // Offset in the byte array for an operation
            private uint _recordOffset;

            // Total bytes that have been processed
            private uint _bytesProcessed;

            // Total bytes that have been marshalled
            private uint _bytesMarshalled;

            [JsonProperty(Order = 1)]
            public WHEA_EVENT_LOG_ENTRY_HEADER Header { get; private set; }

            [JsonProperty(Order = 2)]
            public WheaRecord Event { get; private set; }

            public WheaEventRecord(byte[] recordBytes) {
                _recordBytes = recordBytes;
                _recordOffset = 0;

                _bytesProcessed = 0;
                _bytesMarshalled = 0;
            }

            public bool Decode() {
                var header =
                    MarshalWheaRecord(typeof(WHEA_EVENT_LOG_ENTRY_HEADER), ref _recordBytes, ref _recordOffset, out var bytesMarshalled) as
                        WHEA_EVENT_LOG_ENTRY_HEADER;
                Debug.Assert(header != null, nameof(header) + " != null");

                _bytesProcessed += bytesMarshalled;
                _bytesMarshalled += bytesMarshalled;
                Header = header;

                WheaRecord record = null;

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
                        record = MarshalWheaRecord(typeof(WHEAP_DROPPED_CORRECTED_ERROR_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "StartedReportHwError":
                        ExitUnsupportedEvent(header.Id);
                        break;
                    case "PFAMemoryOfflined":
                        record = MarshalWheaRecord(typeof(WHEAP_PFA_MEMORY_OFFLINED), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "PFAMemoryRemoveMonitor":
                        record = MarshalWheaRecord(typeof(WHEAP_PFA_MEMORY_REMOVE_MONITOR), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "PFAMemoryPolicy":
                        record = MarshalWheaRecord(typeof(WHEAP_PFA_MEMORY_POLICY), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "PshedInjectError":
                        record = MarshalWheaRecord(typeof(WHEAP_PSHED_INJECT_ERROR), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "OscCapabilities":
                        record = MarshalWheaRecord(typeof(WHEAP_OSC_IMPLEMENTED), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "PshedPluginRegister":
                        record = MarshalWheaRecord(typeof(WHEAP_PSHED_PLUGIN_REGISTER), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "AddRemoveErrorSource":
                        record = MarshalWheaRecord(typeof(WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "WorkQueueItem":
                        ExitUnsupportedEvent(header.Id);
                        break;
                    case "AttemptErrorRecovery":
                        record = MarshalWheaRecord(typeof(WHEAP_ATTEMPT_RECOVERY_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "McaFoundErrorInBank":
                        record = MarshalWheaRecord(typeof(WHEAP_FOUND_ERROR_IN_BANK_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "McaStuckErrorCheck":
                        record = MarshalWheaRecord(typeof(WHEAP_STUCK_ERROR_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "McaErrorCleared":
                        record = MarshalWheaRecord(typeof(WHEAP_ERROR_CLEARED_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "ClearedPoison":
                        record = MarshalWheaRecord(typeof(WHEAP_CLEARED_POISON_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "ProcessEINJ":
                        record = MarshalWheaRecord(typeof(WHEAP_PROCESS_EINJ_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "ProcessHEST":
                        record = MarshalWheaRecord(typeof(WHEAP_PROCESS_HEST_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "CreateGenericRecord":
                        record = MarshalWheaRecord(typeof(WHEAP_CREATE_GENERIC_RECORD_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
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
                        record = MarshalWheaRecord(typeof(WHEAP_ERR_SRC_ARRAY_INVALID_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "AcpiTimeOut":
                        record = MarshalWheaRecord(typeof(WHEAP_ACPI_TIMEOUT_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "CmciRestart":
                        record = MarshalWheaRecord(typeof(WHEAP_CMCI_RESTART_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "CmciFinalRestart":
                        ExitUnsupportedEvent(header.Id);
                        break;
                    case "EntryEtwOverFlow":
                        record = MarshalWheaRecord(typeof(WHEA_ETW_OVERFLOW_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "AzccRootBusSearchErr":
                        record = MarshalWheaRecord(typeof(WHEA_AZCC_ROOT_BUS_ERR_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "AzccRootBusList":
                        record = MarshalWheaRecord(typeof(WHEA_AZCC_ROOT_BUS_LIST_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "ErrSrcInvalid":
                        record = MarshalWheaRecord(typeof(WHEAP_ERR_SRC_INVALID_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "GenericErrMemMap":
                        record = MarshalWheaRecord(typeof(WHEAP_GENERIC_ERR_MEM_MAP_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "PshedCallbackCollision":
                        ExitUnsupportedEvent(header.Id);
                        break;
                    case "SELBugCheckProgress":
                        record = MarshalWheaRecord(typeof(WHEA_SEL_BUGCHECK_PROGRESS), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "PshedPluginLoad":
                        record = MarshalWheaRecord(typeof(WHEA_PSHED_PLUGIN_LOAD_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "PshedPluginUnload":
                        record = MarshalWheaRecord(typeof(WHEA_PSHED_PLUGIN_UNLOAD_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "PshedPluginSupported":
                        record = MarshalWheaRecord(typeof(WHEA_PSHED_PLUGIN_PLATFORM_SUPPORT_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "DeviceDriver":
                        record = MarshalWheaRecord(typeof(WHEAP_DEVICE_DRV_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "CmciImplPresent":
                        record = MarshalWheaRecord(typeof(WHEAP_CMCI_IMPLEMENTED_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "CmciInitError":
                        record = MarshalWheaRecord(typeof(WHEAP_CMCI_INITERR_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
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
                        record = MarshalWheaRecord(typeof(WHEA_AZCC_SET_POISON_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "SELBugCheckInfo":
                        ExitUnsupportedEvent(header.Id);
                        break;
                    case "ErrDimmInfoMismatch":
                        record = MarshalWheaRecord(typeof(WHEA_PSHED_PLUGIN_DIMM_MISMATCH), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "eDpcEnabled":
                        record = MarshalWheaRecord(typeof(WHEAP_EDPC_ENABLED_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "PageOfflineDone":
                        record = MarshalWheaRecord(typeof(WHEA_OFFLINE_DONE_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "PageOfflinePendMax":
                        ExitUnsupportedEvent(header.Id);
                        break;
                    case "BadPageLimitReached":
                        ExitUnsupportedEvent(header.Id);
                        break;
                    case "SrarDetail":
                        record = MarshalWheaRecord(typeof(WHEA_SRAR_DETAIL_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "EarlyError":
                        ExitUnsupportedEvent(header.Id);
                        break;
                    case "PcieOverrideInfo":
                        record = MarshalWheaRecord(typeof(WHEAP_PCIE_OVERRIDE_INFO), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "ReadPcieOverridesErr":
                        record = MarshalWheaRecord(typeof(WHEAP_PCIE_READ_OVERRIDES_ERR), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "PcieConfigInfo":
                        record = MarshalWheaRecord(typeof(WHEAP_PCIE_CONFIG_INFO), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "PcieSummaryFailed":
                        ExitUnsupportedEvent(header.Id);
                        break;
                    case "ThrottleRegCorrupt":
                        record = MarshalWheaRecord(typeof(WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "ThrottleAddErrSrcFailed":
                        // No payload
                        break;
                    case "ThrottleRegDataIgnored":
                        record = MarshalWheaRecord(typeof(WHEA_THROTTLE_REG_DATA_IGNORED_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "EnableKeyNotifFailed":
                        record = MarshalWheaRecord(typeof(WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_FAILED_EVENT), ref _recordBytes, ref _recordOffset,
                                                   out bytesMarshalled);
                        break;
                    case "KeyNotificationFailed":
                        // No payload
                        break;
                    case "PcieRemoveDevice":
                        record = MarshalWheaRecord(typeof(WHEA_THROTTLE_PCIE_REMOVE_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "PcieAddDevice":
                        record = MarshalWheaRecord(typeof(WHEA_THROTTLE_PCIE_ADD_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "PcieSpuriousErrSource":
                        record = MarshalWheaRecord(typeof(WHEAP_SPURIOUS_AER_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "MemoryAddDevice":
                    case "MemoryRemoveDevice":
                        record = MarshalWheaRecord(typeof(WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "MemorySummaryFailed":
                        record = MarshalWheaRecord(typeof(WHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "PcieDpcError":
                        record = MarshalWheaRecord(typeof(WHEAP_DPC_ERROR_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "CpuBusesInitFailed":
                        record = MarshalWheaRecord(typeof(WHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "PshedPluginInitFailed":
                        record = MarshalWheaRecord(typeof(WHEA_PSHED_PLUGIN_INIT_FAILED_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
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
                        record = MarshalWheaRecord(typeof(WHEAP_BAD_HEST_NOTIFY_DATA_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "SrasTableNotFound":
                        // No payload
                        break;
                    case "SrasTableError":
                        // No payload
                        break;
                    case "SrasTableEntries":
                        record = MarshalWheaRecord(typeof(WHEA_SRAS_TABLE_ENTRIES_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "RowFailure":
                        record = MarshalWheaRecord(typeof(WHEAP_ROW_FAILURE_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    case "CpusFrozen":
                        ExitUnsupportedEvent(header.Id);
                        break;
                    case "CpusFrozenNoCrashDump":
                        ExitUnsupportedEvent(header.Id);
                        break;
                    case "PshedPiTraceLog":
                        record = MarshalWheaRecord(typeof(WHEA_PSHED_PI_TRACE_EVENT), ref _recordBytes, ref _recordOffset, out bytesMarshalled);
                        break;
                    default:
                        ExitWithMessage($"Unknown WHEA event log entry type: {header.Id}", 2);
                        break;
                }

                _bytesProcessed += bytesMarshalled; // TODO
                _bytesMarshalled += bytesMarshalled;
                if (record != null) Event = record;

                return true;
            }

            public bool Validate() {
                if (Header.Length != _bytesProcessed) {
                    var msg = $"[{StructureName}] Header indicates error record contains {Header.Length} bytes but processed {_bytesProcessed} bytes.";
                    Console.Error.WriteLine(msg);
                }

                if (Header.Length != _bytesMarshalled) {
                    var msg = $"[{StructureName}] Header indicates error record contains {Header.Length} bytes but marshalled {_bytesMarshalled} bytes.";
                    Console.Error.WriteLine(msg);
                }

                return true;
            }
        }

        private static WheaRecord MarshalWheaRecord(Type recordType, ref byte[] recordBytes, ref uint recordOffset, out uint bytesMarshalled) {
            var recordSize = (uint)Marshal.SizeOf(recordType);
#if DEBUG
            Console.Error.WriteLine($"[{recordType.Name}] Expected size: {recordSize} | Current offset: {recordOffset}");
#endif

            var remainingBytes = recordBytes.Length - recordOffset;
            if (remainingBytes < recordSize) ExitWithMessage($"[{nameof(recordType)}] Provided record is too small: {remainingBytes} bytes", 2);

            var marshalBytes = new byte[recordSize];
            for (var i = 0; i < marshalBytes.Length; i++) marshalBytes[i] = recordBytes[recordOffset + i];

            WheaRecord record;
            var hRecord = GCHandle.Alloc(marshalBytes, GCHandleType.Pinned);
            try {
                record = Marshal.PtrToStructure(hRecord.AddrOfPinnedObject(), recordType) as WheaRecord;
                Debug.Assert(record != null, nameof(record) + " != null");
                record.Validate();
            } finally {
                hRecord.Free();
            }

            recordOffset += recordSize;
            bytesMarshalled = recordSize;

            return record;
        }
    }
}
