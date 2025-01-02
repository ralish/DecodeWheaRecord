DecodeWheaRecord
================

[![azure devops](https://dev.azure.com/nexiom/DecodeWheaRecord/_apis/build/status/DecodeWheaRecord)](https://dev.azure.com/nexiom/DecodeWheaRecord/_build/latest?definitionId=1)
[![license](https://img.shields.io/github/license/ralish/DecodeWheaRecord)](https://choosealicense.com/licenses/mit/)

A work-in-progress utility to decode hex-encoded Windows Hardware Event Architecture (WHEA) records.

- [Requirements](#requirements)
- [Support status](#support-status)
  - [WHEA errors](#whea-errors)
  - [WHEA events](#whea-events)
- [Glossary](#glossary)
  - [Buses](#buses)
  - [Memory](#memory)
  - [Microsoft](#microsoft)
  - [Processors](#processors)
  - [Specifications](#specifications)
  - [Miscellaneous](#miscellaneous)
  - [TODO](#todo)
- [License](#license)

Requirements
------------

- .NET Framework 4.6.2 (or newer)  
  *Built-in since Windows 10 1607 and Server 2016*

Support status
--------------

The `Microsoft-Windows-Kernel-WHEA` provider outputs errors and events to the `Microsoft-Windows-Kernel-WHEA/Errors` and `Microsoft-Windows-Kernel-WHEA/Operational` event log channels respectively. You can view these events using standard Windows tools such as the *Event Viewer* application and `Get-WinEvent` PowerShell command. The events are not parsed, with only the "*raw data*" provided in the form of a hex-encoded string. To parse the WHEA error or event the value of the `RawData` field should be provided to `DecodeWheaRecord` as the input argument. For example:

```plain
DecodeWheaRecord.exe 57684C6701000000200000000000000050434920180000800200000000000000
Expected size of WHEA_EVENT_LOG_ENTRY_HEADER record: 32
{
  "Signature": "WhLg",
  "Version": 1,
  "Length": 32,
  "Type": "Informational",
  "OwnerTag": 541672272,
  "Id": "AerNotGrantedToOs",
  "Flags": "LogInternalEtw",
  "PayloadLength": 0
}
```

Support for the majority of errors and events is present, current as of Windows 11 22H2 and Windows Server 2022, but few have been tested against real data. Adding support for the unsupported errors and events would greatly benefit by having real data to test against. If you're using this utility to parse an event which doesn't have a test case, as per the table below, please consider submitting it via a [GitHub issue](https://github.com/ralish/DecodeWheaRecord/issues) to help us verify the correctness of the implementation and improve support.

### WHEA errors

| Name                             | Implemented? | Owner      | GUID                                   | WHEA structure                          | UEFI section | MSFT documentation |
| -------------------------------- | ------------ | ---------- | -------------------------------------- | --------------------------------------- | ------------ | ------------------ |
| ARM Processor Error              | Complete     | UEFI       | `e19e3d16-bc11-11e4-9caa-c2051d5d46b0` | `WHEA_ARM_PROCESSOR_ERROR_SECTION`      | N.2.4.4      | Undocumented |
| ARM RAS Node Error               | Complete     | Microsoft  | `e3ebf4a2-df50-4708-b2d7-0b29ec2f7aa9` | `WHEA_ARM_RAS_NODE_SECTION`             | N/A          | Undocumented |
| ARM SEA Exception                | Complete     | Microsoft  | `f5fe48a6-84ce-4c1e-aa64-20c9a53099f1` | `WHEA_SEA_SECTION`                      | N/A          | [Partial](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-whea_sea_section) |
| ARM SEI Exception                | Complete     | Microsoft  | `f2a4a152-9c6d-4020-aecf-7695b389251b` | `WHEA_SEI_SECTION`                      | N/A          | [Partial](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-whea_sei_section) |
| Correctable Memory Error Summary | Complete     | Microsoft  | `0e36c93e-ca15-4a83-ba8a-cbe80f7f0017` | `WHEA_MEMORY_CORRECTABLE_ERROR_SECTION` | N/A          | [Partial](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-whea_memory_correctable_error_section) |
| Correctable PCIe Error Summary   | Partial      | Microsoft  | `e96eca99-53e2-4f52-9be7-d2dbe9508ed0` | `WHEA_PCIE_CORRECTABLE_ERROR_SECTION`   | N/A          | [Partial](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-whea_pcie_correctable_error_section_header) |
| Error Recovery Information       | Complete     | Microsoft  | `c34832a1-02c3-4c52-a9f1-9f1d5d7723fc` | `WHEA_ERROR_RECOVERY_INFO_SECTION`      | N/A          | Undocumented |
| Firmware Error Record Reference  | Complete     | UEFI       | `81212a96-09ed-4996-9471-8d729c8e69ed` | `WHEA_FIRMWARE_ERROR_RECORD_REFERENCE`  | N.2.10       | [Yes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_firmware_error_record_reference) |
| Generic Processor Error          | Complete     | UEFI       | `9876ccad-47b4-4bdb-b65e-16f193c4f3db` | `WHEA_PROCESSOR_GENERIC_ERROR_SECTION`  | N.2.4.1      | [Yes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_processor_generic_error_section) |
| Hardware Error Packet (v1)       | Partial      | Microsoft  | `e71254e9-c1b9-4940-ab76-909703a4320f` | `WHEA_ERROR_PACKET_V1`                  | N/A          | [Yes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_error_packet_v1) |
| Hardware Error Packet (v2)       | Partial      | Microsoft  | `e71254e9-c1b9-4940-ab76-909703a4320f` | `WHEA_ERROR_PACKET_V2`                  | N/A          | [Partial](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_error_packet_v2) |
| IA32/AMD64 Machine Check Error   | Partial      | Microsoft  | `8a1e1d01-42f9-4557-9c33-565e5cc3f7e8` | `WHEA_XPF_MCA_SECTION`                  | N/A          | [Partial](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_xpf_mca_section) |
| IA32/AMD64 Processor Error       | Complete     | UEFI       | `dc3ea0b0-a144-4797-b95b-53fa242b6e1d` | `WHEA_XPF_PROCESSOR_ERROR_SECTION`      | N.2.4.2      | [Yes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_xpf_processor_error_section) |
| IA64 Processor Error             | Unsupported  | UEFI       | `e429faf1-3cb7-11d4-bca7-0080c73c8881` | None?                                   | N.2.4.3      | N/A |
| IA64 SAL Record                  | Unsupported  | Microsoft  | `6f3380d1-6eb0-497f-a578-4d4c65a71617` | None?                                   | N/A          | N/A |
| IPMI MSR Dump                    | Partial      | Microsoft  | `1c15b445-9b06-4667-ac25-33c056b88803` | `WHEA_MSR_DUMP_SECTION`                 | N/A          | [Partial](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-whea_msr_dump_section) |
| Memory Error                     | Complete     | UEFI       | `a5bc1114-6f64-4ede-b863-3e83ed7c83b1` | `WHEA_MEMORY_ERROR_SECTION`             | N.2.5        | [Yes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_memory_error_section) |
| NMI Error                        | Complete     | Microsoft  | `e71254e7-c1b9-4940-ab76-909703a4320f` | `WHEA_NMI_ERROR_SECTION`                | N/A          | [Yes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_nmi_error_section) |
| PCI Express DPC Capability       | Complete     | Microsoft  | `ec49534b-30e7-4358-972f-eca6958fae3b` | `PCI_EXPRESS_DPC_CAPABILITY`            | N/A          | [Partial](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-pci_express_dpc_capability) |
| PCI Express Error                | Complete     | UEFI       | `d995e954-bbc1-430f-ad91-b44dcb3c6f35` | `WHEA_PCIEXPRESS_ERROR_SECTION`         | N.2.7        | [Yes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_pciexpress_error_section) |
| PCI Recovery                     | Complete     | Microsoft  | `dd060800-f6e1-4204-ac27-c4bca9568402` | `WHEA_PCI_RECOVERY_SECTION`             | N/A          | [Partial](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-whea_pci_recovery_section) |
| PCI/PCI-X Bus Error              | Complete     | UEFI       | `c5753963-3b84-4095-bf78-eddad3f9c9dd` | `WHEA_PCIXBUS_ERROR_SECTION`            | N.2.8        | [Yes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_pcixbus_error_section) |
| PCI/PCI-X Device Error           | Complete     | UEFI       | `eb5e4685-ca66-4769-b6a2-26068b001326` | `WHEA_PCIXDEVICE_ERROR_SECTION`         | M.2.9        | [Yes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_pcixdevice_error_section) |
| Persistent Memory Error          | Partial      | Microsoft  | `81687003-dbfd-4728-9ffd-f0904f97597d` | `WHEA_PMEM_ERROR_SECTION`               | N/A          | [Partial](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-whea_pmem_error_section) |
| Project Mu Telemetry             | Complete     | Microsoft  | `85183a8b-9c41-429c-939c-5c3c087ca280` | `MU_TELEMETRY_SECTION`                  | N/A          | Undocumented |

### WHEA events

| Entry ID     | Symbolic name                   | Status      | WHEA structure                                              | Test case | Notes           |
| ------------ | ------------------------------- | ----------- | ----------------------------------------------------------- | --------- | --------------- |







| `0x80000004` | `DroppedCorrectedError`         | Done        | `WHEAP_DROPPED_CORRECTED_ERROR_EVENT`                       | No        |                 |
| `0x80000006` | `PFAMemoryOfflined`             | Done        | `WHEAP_PFA_MEMORY_OFFLINED`                                 |           |                 |
| `0x80000007` | `PFAMemoryRemoveMonitor`        | Done        | `WHEAP_PFA_MEMORY_REMOVE_MONITOR`                           |           |                 |
*| `0x80000008` | `PFAMemoryPolicy`               | Done        | `WHEAP_PFA_MEMORY_POLICY`                                   |           |                 |
| `0x80000009` | `PshedInjectError`              | Done        | `WHEAP_PSHED_INJECT_ERROR`                                  |           |                 |
| `0x8000000a` | `OscCapabilities`               | Done        | `WHEAP_OSC_IMPLEMENTED`                                     |           |                 |
| `0x8000000b` | `PshedPluginRegister`           | WiP         | `WHEAP_PSHED_PLUGIN_REGISTER`                               |           |                 |
| `0x80000012` | `ClearedPoison`                 | Done        | `WHEAP_CLEARED_POISON_EVENT`                                |           |                 |
| `0x80000013` | `ProcessEINJ`                   | Done        | `WHEAP_PROCESS_EINJ_EVENT`                                  |           |                 |
| `0x80000014` | `ProcessHEST`                   | Done        | `WHEAP_PROCESS_HEST_EVENT`                                  |           |                 |
| `0x80000019` | `ErrSrcArrayInvalid`            | Done        | `WHEAP_ERR_SRC_ARRAY_INVALID_EVENT`                         |           |                 |
| `0x8000001a` | `AcpiTimeOut`                   | Done        | `WHEAP_ACPI_TIMEOUT_EVENT`                                  |           |                 |
| `0x80000020` | `ErrSrcInvalid`                 | WiP         | `WHEAP_ERR_SRC_INVALID_EVENT`                               |           |                 |
*| `0x8000001d` | `EtwOverFlow`                   | Done        | `WHEA_ETW_OVERFLOW_EVENT`                                   |           |                 |
| `0x8000001f` | `AzccRootBusList`               | Done        | `WHEA_AZCC_ROOT_BUS_LIST_EVENT`                             |           |                 |
| `0x80000023` | `SELBugCheckProgress`           | Done        | `WHEA_SEL_BUGCHECK_PROGRESS`                                |           |                 |
| `0x80000024` | `PshedPluginLoad`               | Done        | `WHEA_PSHED_PLUGIN_LOAD_EVENT`                              |           |                 |
| `0x80000025` | `PshedPluginUnload`             | Done        | `WHEA_PSHED_PLUGIN_UNLOAD_EVENT`                            |           |                 |
| `0x80000026` | `PshedPluginSupported`          | Done        | `WHEA_PSHED_PLUGIN_PLATFORM_SUPPORT_EVENT`                  |           |                 |
| `0x8000002a` | `SELBugCheckRecovery`           | WiP         | `WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE1_EVENT`            |           |                 |
|              |                                 | WiP         | `WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE2_EVENT`            |           |                 |
|              |                                 | WiP         | `WHEA_SEL_BUGCHECK_RECOVERY_STATUS_MULTIPLE_BUGCHECK_EVENT` |           |                 |
| `0x8000002d` | `WheaHeartbeat`                 | Done        | `WHEA_PSHED_PLUGIN_HEARTBEAT`                               |           | Empty event     |
| `0x8000002e` | `AzccRootBusPoisonSet`          | Done        | `WHEA_AZCC_SET_POISON_EVENT`                                | o         |                 |
| `0x80000030` | `ErrDimmInfoMismatch`           | Done        | `WHEA_PSHED_PLUGIN_DIMM_MISMATCH`                           |           |                 |
| `0x80000031` | `eDpcEnabled`                   | Done        | `WHEAP_EDPC_ENABLED_EVENT`                                  |           |                 |
| `0x80000032` | `PageOfflineDone`               | Done        | `WHEA_OFFLINE_DONE_EVENT`                                   |           |                 |
| `0x80000037` | `PcieOverrideInfo`              | WiP         | `WHEAP_PCIE_OVERRIDE_INFO`                                  |           |                 |
| `0x80000038` | `ReadPcieOverridesErr`          | Done        | `WHEAP_PCIE_READ_OVERRIDES_ERR`                             |           |                 |
| `0x80000039` | `PcieConfigInfo`                | Done        | `WHEAP_PCIE_CONFIG_INFO`                                    |           |                 |
| `0x80000041` | `ThrottleRegCorrupt`            | Done        | `WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT`                      |           |                 |
| `0x80000043` | `ThrottleRegDataIgnored`        | Done        | `WHEA_THROTTLE_REG_DATA_IGNORED_EVENT`                      |           |                 |
| `0x80000044` | `EnableKeyNotifFailed`          | Done        | `WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_FAILED_EVENT`              |           |                 |
| `0x80000046` | `PcieRemoveDevice`              | Done        | `WHEA_THROTTLE_PCIE_REMOVE_EVENT`                           |           |                 |
| `0x80000045` | `KeyNotificationFailed`         | Done        | `WHEA_REGISTER_KEY_NOTIFICATION_FAILED_EVENT`               |           | Empty event     |
| `0x80000047` | `PcieAddDevice`                 | Done        | `WHEA_THROTTLE_PCIE_ADD_EVENT`                              |           |                 |
| `0x80000048` | `PcieSpuriousErrSource`         | WiP         | `WHEAP_SPURIOUS_AER_EVENT`                                  |           |                 |
| `0x80000049` | `MemoryAddDevice`               | Done        | `WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT`                  |           |                 |
| `0x8000004a` | `MemoryRemoveDevice`            | Done        | `WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT`                  |           |                 |
| `0x8000004b` | `MemorySummaryFailed`           | Done        | `WHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT`                 |           |                 |
| `0x8000004c` | `PcieDpcError`                  | Done        | `WHEAP_DPC_ERROR_EVENT`                                     |           |                 |
| `0x8000004d` | `CpuBusesInitFailed`            | Done        | `WHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT`                 |           |                 |
| `0x8000004e` | `PshedPluginInitFailed`         | Done        | `WHEA_PSHED_PLUGIN_INIT_FAILED_EVENT`                       |           |                 |
| `0x8000004f` | `FailedAddToDefectList`         | Done        | `WHEA_FAILED_ADD_DEFECT_LIST_EVENT`                         |           | Empty event     |
| `0x80000050` | `DefectListFull`                | Done        | `WHEAP_PLUGIN_DEFECT_LIST_FULL_EVENT`                       |           | Empty event     |
| `0x80000051` | `DefectListUEFIVarFailed`       | Done        | `WHEAP_PLUGIN_DEFECT_LIST_UEFI_VAR_FAILED`                  |           | Empty event     |
| `0x80000052` | `DefectListCorrupt`             | Done        | `WHEAP_PLUGIN_DEFECT_LIST_CORRUPT`                          |           | Empty event     |
| `0x80000053` | `BadHestNotifyData`             | Done        | `WHEAP_BAD_HEST_NOTIFY_DATA_EVENT`                          |           |                 |
*| `0x80000054` | `RowFailure`                    | WiP         | `WHEAP_ROW_FAILURE_EVENT`                                   |           |                 |
| `0x80000058` | `PFANotifyCallbackAction`       | Done        | `WHEAP_PFA_MEMORY_OFFLINED_NOTIFY_CALLBACK_ACTION`          |           |                 |
| `0x8000005a` | `PshedPiCpuid`                  | Done        | `WHEA_PSHED_PI_CPUID`                                       |           |                 |
| `0x80000062` | `RegNotifyPolicyChange`         | Done        | `WHEA_REGNOTIFY_POLICY_CHANGE_EVENT`                        |           |                 |
| `0x80000063` | `RegError`                      | Done        | `WHEA_REGISTRY_ERROR_EVENT`                                 |           |                 |
| `0x80000064` | `RowOfflineEvent`               | Done        | `WHEAP_ROW_OFFLINE_EVENT`                                   |           |                 |
| `0x80000066` | `BadGasFields`                  | Done        | `WHEA_GAS_ERROR_EVENT`                                      |           |                 |
| `0x80000067` | `CrashDumpError`                | Done        | `WHEA_CRASHDUMP_EVENT_LOG_ENTRY_WITH_STATUS`                |           |                 |
| `0x80000069` | `CrashDumpProgressPercent`      | Done        | `WHEA_CRASHDUMP_EVENT_LOG_ENTRY_ULONG1`                     |           |                 |
| `0x8000006c` | `PciePromotedAerErr`            | Done        | `WHEAP_PROMOTED_AER_ERROR_EVENT`                            |           |                 |
*| `0x80040010` | `PshedPiTraceLog`               | Done        | `WHEA_PSHED_PI_TRACE_EVENT`                                 |           |                 |

PCI
| `0x80000040` | `PcieSummaryFailed`             | Unknown                                            | No         |                 |

Processor
| `0x80000061` | `CpusFrozenNoCrashDump`         | Unknown                                            | No         |                 |

PSHED
| `0x80000022` | `PshedCallbackCollision`        | Unknown                                            | No         |                 |

TODO
| `0x80000003` | `CmcSwitchToPolling`            | Unknown                                            | No         | Empty event     |
| `0x80000018` | `AerNotGrantedToOs`             | Unknown                                            | No         | Empty event     |
| `0x80000033` | `PageOfflinePendMax`            | Unknown                                            | No         | Empty event     |
| `0x80000036` | `EarlyError`                    | Unknown                                            | No         | Empty event     |
| `0x80000060` | `CpusFrozen`                    | Unknown                                            | No         | Empty event     |



| `0x80000001` | `CmcPollingTimeout`             | Unknown                                            | No         |                 |
| `0x80000002` | `WheaInit`                      | Unknown                                            | No         |                 |
| `0x80000005` | `StartedReportHwError`          | `WHEAP_STARTED_REPORT_HW_ERROR`                    | No         |                 |
| `0x8000000c` | `AddRemoveErrorSource`          | `WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT`              | Yes        |                 |
| `0x8000000d` | `WorkQueueItem`                 | Unknown                                            | No         |                 |
| `0x8000000e` | `AttemptErrorRecovery`          | `WHEAP_ATTEMPT_RECOVERY_EVENT`                     | No         |                 |
| `0x8000000f` | `McaFoundErrorInBank`           | `WHEAP_FOUND_ERROR_IN_BANK_EVENT`                  | No         |                 |
| `0x80000010` | `McaStuckErrorCheck`            | `WHEAP_STUCK_ERROR_EVENT`                          | No         |                 |
| `0x80000011` | `McaErrorCleared`               | `WHEAP_ERROR_CLEARED_EVENT`                        | No         |                 |
| `0x80000015` | `CreateGenericRecord`           | `WHEAP_CREATE_GENERIC_RECORD_EVENT`                | No         |                 |
| `0x80000016` | `ErrorRecord`                   | `WHEAP_ERROR_RECORD_EVENT`                         | No         |                 |
| `0x80000017` | `ErrorRecordLimit`              | Unknown                                            | No         |                 |
| `0x8000001b` | `CmciRestart`                   | `WHEAP_CMCI_RESTART_EVENT`                         | Yes        |                 |
| `0x8000001c` | `CmciFinalRestart`              | Unknown                                            | No         |                 |
| `0x8000001e` | `AzccRootBusSearchErr`          | `WHEA_AZCC_ROOT_BUS_ERR_EVENT`                     | No         |                 |
| `0x80000021` | `GenericErrMemMap`              | `WHEAP_GENERIC_ERR_MEM_MAP_EVENT`                  | Yes        |                 |
| `0x80000027` | `DeviceDriver`                  | `WHEAP_DEVICE_DRV_EVENT`                           | No         |                 |
| `0x80000028` | `CmciImplPresent`               | `WHEAP_CMCI_IMPLEMENTED_EVENT`                     | No         |                 |
| `0x80000029` | `CmciInitError`                 | `WHEAP_CMCI_INITERR_EVENT`                         | No         |                 |
| `0x8000002b` | `DrvErrSrcInvalid`              | Unknown                                            | No         |                 |
| `0x8000002c` | `DrvHandleBusy`                 | Unknown                                            | No         |                 |
| `0x8000002f` | `SELBugCheckInfo`               | Unknown                                            | No         |                 |
| `0x80000034` | `BadPageLimitReached`           | Unknown                                            | No         |                 |
| `0x80000035` | `SrarDetail`                    | `WHEA_SRAR_DETAIL_EVENT`                           | No         |                 |
| `0x80000042` | `ThrottleAddErrSrcFailed`       | `WHEA_THROTTLE_ADD_ERR_SRC_FAILED_EVENT`           | No         | No payload      |
| `0x80000068` | `CrashDumpCheckpoint`           | Done        | `WHEA_CRASHDUMP_EVENT_LOG_ENTRY_ULONG1`        |           |                 |
| `0x80000055` | `SrasTableNotFound`             | `WHEA_SRAS_TABLE_ERROR`                            | No         | No payload      |
| `0x80000056` | `SrasTableError`                | `WHEA_SRAS_TABLE_ENTRIES_EVENT`                    | No         |                 |
| `0x80000057` | `SrasTableEntries`              | `WHEAP_ROW_FAILURE_EVENT`                          | No         |                 |
| `0x80000059` | `SELBugCheckCpusQuiesced`       | `WHEAP_ROW_FAILURE_EVENT`                          | No         |                 |
| `0x8000005b` | `SrasTableBadData`              | `WHEAP_ROW_FAILURE_EVENT`                          | No         |                 |
| `0x8000005c` | `DriFsStatus`                   | `WHEAP_ROW_FAILURE_EVENT`                          | No         |                 |
| `0x80000065` | `BitOfflineEvent`               | `WHEAP_ROW_FAILURE_EVENT`                          | No         |                 |
| `0x8000006a` | `PreviousCrashBugCheckProgress` | `WHEAP_ROW_FAILURE_EVENT`                          | No         |                 |
| `0x8000006b` | `SELBugCheckStackDump`          | `WHEAP_ROW_FAILURE_EVENT`                          | No         |                 |

Glossary
--------

### Buses

#### Types

- **PCI**  
  Peripheral Component Interconnect
- **PCI-X**  
  PCI eXtended
- **PCIe**  
  PCI Express

#### PCIe

|- **AER**  
|  Advanced Error Reporting
|- **DPC**  
|  Downstream Port Containment
|- **eDPC**  
|  Enhanced Downstream Port Containment

### Memory

|- **DIMM**  
|  Dual In-Line Memory Module
|- **ECC**  
|  Error Correction Code
|- **NVDIMM**  
|  Non-Volatile DIMM
|- **PFN**  
|  Page Frame Number
- **PMem**  
  Persistent Memory

### Microsoft

|- **ETW**  
|  Event Tracing for Windows
|- **IRQL**  
|  Interrupt Request Level
- **LLHEH**  
  Low-Level Hardware Error Handler
- **PFA**  
  Predictive Failure Analysis
- **PSHED**  
  Platform-Specific Hardware Error Driver
- **WHEA**  
  Windows Hardware Error Architecture

### Processors

#### Abbreviations

- **IPF**  
  Itanium Platform
- **XPF**  
  x86 Platform

#### Common

- **MMIO**  
  Memory-mapped I/O
|- **IP**  
|  Instruction Pointer
|- **MAE**  
|  Micro-Architecture Error
- **TLB**  
  Translation Lookaside Buffer

#### ARM

- **GIC**  
  Generic Interrupt Controller
- **SMMU**  
  System Memory Management Unit
|- **MIDR**  
|  Main ID Register
|- **MPIDR**  
|  Multiprocessor Affinity Register
|- **PSCI**  
|  Power State Coordination Interface
- **SEA**  
  Synchronous External Abort
- **SEI**  
  SError Interrupt

##### Registers

- **ERR\<n\>ADDR**  
  Error Record Address Register
- **ERR\<n\>CTLR**  
  Error Record Control Register
- **ERR\<n\>FR**  
  Error Record Feature Register
- **ERR\<n\>MISC0**  
  Error Record Miscellaneous Register 0
- **ERR\<n\>MISC1**  
  Error Record Miscellaneous Register 1
- **ERR\<n\>MISC2**  
  Error Record Miscellaneous Register 2
- **ERR\<n\>MISC3**  
  Error Record Miscellaneous Register 3
- **ERR\<n\>STATUS**  
  Error Record Primary Status Register
- **ESR**  
  Exception Syndrome Register
- **FAR**  
  Fault Address Register
- **PAR**  
  Physical Address Register

#### IA-32 (x86)

|- **APIC**  
|  Advanced Programmable Interrupt Controller (maybe move to ACPI section)
|- **CMC**  
|  Corrected Machine Check
|- **CMCI**  
|  Corrected Machine Check Interrupt
- **MCA**  
  Machine Check Architecture
|- **MCE**  
|  Machine Check Exception
|- **MSR**  
|  Model-Specific Register
|- **SRAR**  
|  Software Recoverable Action Required

#### IA-64 (Itanium)

|- **CPE**  
|  Corrected Platform Error
- **MCA**  
  Machine Check Abort
- **SAL**  
  System Abstraction Layer

### Specifications

- **ACPI**  
  Advanced Configuration and Power Interface
- **IPMI**  
  Intelligent Platform Management Interface
- **SDEI**  
  Software Delegated Exception Interface
- **UEFI**  
  Unified Extensible Firmware Interface

#### ACPI

- **AEST**  
  ARM Error Source Table
- **GSIV**  
  Global System Interrupt Vector
- **RAS**  
  Reliability, Availability, and Serviceability
|- **EINJ**  
|  Error Injection table
|- **ERST**  
|  Error Record Serialization Table
|- **GAS**  
|  Generic Address Structure
|- **GHES**  
|  Generic Hardware Error Source
|- **HEST**  
|  Hardware Error Source Table
|- **NFIT**  
|  NVDIMM Firmware Interface Table
|- **OSC**  
|  Operating System Capabilities
|- **SCI**  
|  Service Control Interrupt
|- **SRAS**  
|  Static Resource Allocation Structure

#### IPMI

|- **SEL**  
|  System Event Log

#### UEFI

- **CPER**  
  Common Platform Error Record

### Miscellaneous

|- **BMC**  
|  Baseboard Management Controller
|- **FRU**  
|  Field Replaceable Unit
|- **GPIO**  
|  General Purpose Input/Output
|- **OEM**  
|  Original Equipment Manufacturer
- **NMI**  
  Non-Maskable Interrupt
|- **SOC**  
|  System on Chip

### TODO

AZCC

License
-------

All content is licensed under the terms of [The MIT License](LICENSE).
