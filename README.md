DecodeWheaRecord
================

[![azure devops](https://dev.azure.com/nexiom/DecodeWheaRecord/_apis/build/status/DecodeWheaRecord)](https://dev.azure.com/nexiom/DecodeWheaRecord/_build/latest?definitionId=1)
[![license](https://img.shields.io/github/license/ralish/DecodeWheaRecord)](https://choosealicense.com/licenses/mit/)

A work-in-progress utility to decode hex-encoded Windows Hardware Event Architecture (WHEA) records.

- [Requirements](#requirements)
- [Support status](#support-status)
  - [WHEA events](#whea-events)
- [Glossary](#glossary)
  - [ACPI](#acpi)
  - [Architectures](#architectures)
  - [ARMv8](#armv8)
  - [IA-64 (Itanium)](#ia-64-itanium)
  - [Microsoft](#microsoft)
  - [PCIe](#pcie)
  - [Specifications](#specifications)
  - [UEFI](#uefi)
  - [Miscellaneous](#miscellaneous)
- [License](#license)

Requirements
------------

- .NET Framework 4.6.2 (or newer)  
  *Built-in since Windows 10 1607 and Server 2016*

Support status
--------------

### WHEA events

WHEA events are output by the `Microsoft-Windows-Kernel-WHEA` provider to the `Microsoft-Windows-Kernel-WHEA/Operational` channel. You can view these events using standard Windows tools such as the *Event Viewer* application and `Get-WinEvent` PowerShell command. The events are not parsed, with only the "*raw data*" provided in the form of a hex-encoded string. To parse an event provide the value of the `RawData` field to `DecodeWheaRecord` as the input argument. For example:

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

Support for the large majority of WHEA events is present, as of Windows 11 22H2 and Windows Server 2022, but few have been tested against real test data. Adding support for the minority of events which are unsupported would also benefit by having real events to test against. If you're using this utility to parse an event which doesn't have a test case, as per the table below, please consider submitting it via a [GitHub issue](https://github.com/ralish/DecodeWheaRecord/issues) to help us verify the correctness of the implementation and improve support.

| Entry ID     | Symbolic name                  | Structure name                                     | Test case  | Notes           |
| ------------ | ------------------------------ | -------------------------------------------------- | ---------- | --------------- |
| `0x80000001` | `CmcPollingTimeout`            | Unknown                                            | No         |                 |
| `0x80000002` | `WheaInit`                     | Unknown                                            | No         |                 |
| `0x80000003` | `CmcSwitchToPolling`           | Unknown                                            | No         |                 |
| `0x80000004` | `DroppedCorrectedError`        | `WHEAP_DROPPED_CORRECTED_ERROR_EVENT`              | No         |                 |
| `0x80000005` | `StartedReportHwError`         | `WHEAP_STARTED_REPORT_HW_ERROR`                    | No         |                 |
| `0x80000006` | `PFAMemoryOfflined`            | `WHEAP_PFA_MEMORY_OFFLINED`                        | No         |                 |
| `0x80000007` | `PFAMemoryRemoveMonitor`       | `WHEAP_PFA_MEMORY_REMOVE_MONITOR`                  | No         |                 |
| `0x80000008` | `PFAMemoryPolicy`              | `WHEAP_PFA_MEMORY_POLICY`                          | No         |                 |
| `0x80000009` | `PshedInjectError`             | `WHEAP_PSHED_INJECT_ERROR`                         | No         |                 |
| `0x8000000a` | `OscCapabilities`              | `WHEAP_OSC_IMPLEMENTED`                            | Yes        |                 |
| `0x8000000b` | `PshedPluginRegister`          | `WHEAP_PSHED_PLUGIN_REGISTER`                      | No         |                 |
| `0x8000000c` | `AddRemoveErrorSource`         | `WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT`              | Yes        |                 |
| `0x8000000d` | `WorkQueueItem`                | Unknown                                            | No         |                 |
| `0x8000000e` | `AttemptErrorRecovery`         | `WHEAP_ATTEMPT_RECOVERY_EVENT`                     | No         |                 |
| `0x8000000f` | `McaFoundErrorInBank`          | `WHEAP_FOUND_ERROR_IN_BANK_EVENT`                  | No         |                 |
| `0x80000010` | `McaStuckErrorCheck`           | `WHEAP_STUCK_ERROR_EVENT`                          | No         |                 |
| `0x80000011` | `McaErrorCleared`              | `WHEAP_ERROR_CLEARED_EVENT`                        | No         |                 |
| `0x80000012` | `ClearedPoison`                | `WHEAP_CLEARED_POISON_EVENT`                       | No         |                 |
| `0x80000013` | `ProcessEINJ`                  | `WHEAP_PROCESS_EINJ_EVENT`                         | Yes        |                 |
| `0x80000014` | `ProcessHEST`                  | `WHEAP_PROCESS_HEST_EVENT`                         | Yes        |                 |
| `0x80000015` | `CreateGenericRecord`          | `WHEAP_CREATE_GENERIC_RECORD_EVENT`                | No         |                 |
| `0x80000016` | `ErrorRecord`                  | `WHEAP_ERROR_RECORD_EVENT`                         | No         |                 |
| `0x80000017` | `ErrorRecordLimit`             | Unknown                                            | No         |                 |
| `0x80000018` | `AerNotGrantedToOs`            | None                                               | Yes        | No payload      |
| `0x80000019` | `ErrSrcArrayInvalid`           | `WHEAP_ERR_SRC_ARRAY_INVALID_EVENT`                | No         |                 |
| `0x8000001a` | `AcpiTimeOut`                  | `WHEAP_ACPI_TIMEOUT_EVENT`                         | No         |                 |
| `0x8000001b` | `CmciRestart`                  | `WHEAP_CMCI_RESTART_EVENT`                         | Yes        |                 |
| `0x8000001c` | `CmciFinalRestart`             | Unknown                                            | No         |                 |
| `0x8000001d` | `EntryEtwOverFlow`             | `WHEA_ETW_OVERFLOW_EVENT`                          | No         |                 |
| `0x8000001e` | `AzccRootBusSearchErr`         | `WHEA_AZCC_ROOT_BUS_ERR_EVENT`                     | No         |                 |
| `0x8000001f` | `AzccRootBusList`              | `WHEA_AZCC_ROOT_BUS_LIST_EVENT`                    | No         |                 |
| `0x80000020` | `ErrSrcInvalid`                | `WHEAP_ERR_SRC_INVALID_EVENT`                      | No         |                 |
| `0x80000021` | `GenericErrMemMap`             | `WHEAP_GENERIC_ERR_MEM_MAP_EVENT`                  | Yes        |                 |
| `0x80000022` | `PshedCallbackCollision`       | Unknown                                            | No         |                 |
| `0x80000023` | `SELBugCheckProgress`          | `WHEA_SEL_BUGCHECK_PROGRESS`                       | No         |                 |
| `0x80000024` | `PshedPluginLoad`              | `WHEA_PSHED_PLUGIN_LOAD_EVENT`                     | No         |                 |
| `0x80000025` | `PshedPluginUnload`            | `WHEA_PSHED_PLUGIN_UNLOAD_EVENT`                   | No         |                 |
| `0x80000026` | `PshedPluginSupported`         | `WHEA_PSHED_PLUGIN_PLATFORM_SUPPORT_EVENT`         | No         |                 |
| `0x80000027` | `DeviceDriver`                 | `WHEAP_DEVICE_DRV_EVENT`                           | No         |                 |
| `0x80000028` | `CmciImplPresent`              | `WHEAP_CMCI_IMPLEMENTED_EVENT`                     | No         |                 |
| `0x80000029` | `CmciInitError`                | `WHEAP_CMCI_INITERR_EVENT`                         | No         |                 |
| `0x8000002a` | `SELBugCheckRecovery`          | Unknown                                            | No         |                 |
| `0x8000002b` | `DrvErrSrcInvalid`             | Unknown                                            | No         |                 |
| `0x8000002c` | `DrvHandleBusy`                | Unknown                                            | No         |                 |
| `0x8000002d` | `WheaHeartbeat`                | `WHEA_PSHED_PLUGIN_HEARTBEAT`                      | No         | No payload      |
| `0x8000002e` | `AzccRootBusPoisonSet`         | `WHEA_AZCC_SET_POISON_EVENT`                       | No         |                 |
| `0x8000002f` | `SELBugCheckInfo`              | Unknown                                            | No         |                 |
| `0x80000030` | `ErrDimmInfoMismatch`          | `WHEA_PSHED_PLUGIN_DIMM_MISMATCH`                  | No         |                 |
| `0x80000031` | `eDpcEnabled`                  | `WHEAP_EDPC_ENABLED_EVENT`                         | Yes        |                 |
| `0x80000032` | `PageOfflineDone`              | `WHEA_OFFLINE_DONE_EVENT`                          | No         |                 |
| `0x80000033` | `PageOfflinePendMax`           | Unknown                                            | No         |                 |
| `0x80000034` | `BadPageLimitReached`          | Unknown                                            | No         |                 |
| `0x80000035` | `SrarDetail`                   | `WHEA_SRAR_DETAIL_EVENT`                           | No         |                 |
| `0x80000036` | `EarlyError`                   | Unknown                                            | No         |                 |
| `0x80000037` | `PcieOverrideInfo`             | `WHEAP_PCIE_OVERRIDE_INFO`                         | No         |                 |
| `0x80000038` | `ReadPcieOverridesErr`         | `WHEAP_PCIE_READ_OVERRIDES_ERR`                    | No         |                 |
| `0x80000039` | `PcieConfigInfo`               | `WHEAP_PCIE_CONFIG_INFO`                           | No         |                 |
| `0x80000040` | `PcieSummaryFailed`            | Unknown                                            | No         |                 |
| `0x80000041` | `ThrottleRegCorrupt`           | `WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT`             | No         |                 |
| `0x80000042` | `ThrottleAddErrSrcFailed`      | `WHEA_THROTTLE_ADD_ERR_SRC_FAILED_EVENT`           | No         | No payload      |
| `0x80000043` | `ThrottleRegDataIgnored`       | `WHEA_THROTTLE_REG_DATA_IGNORED_EVENT`             | No         |                 |
| `0x80000044` | `EnableKeyNotifFailed`         | `WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_FAILED_EVENT`     | No         |                 |
| `0x80000045` | `KeyNotificationFailed`        | `WHEA_REGISTER_KEY_NOTIFICATION_FAILED_EVENT`      | No         | No payload      |
| `0x80000046` | `PcieRemoveDevice`             | `WHEA_THROTTLE_PCIE_REMOVE_EVENT`                  | No         |                 |
| `0x80000047` | `PcieAddDevice`                | `WHEA_THROTTLE_PCIE_ADD_EVENT`                     | No         |                 |
| `0x80000048` | `PcieSpuriousErrSource`        | `WHEAP_SPURIOUS_AER_EVENT`                         | No         |                 |
| `0x80000049` | `MemoryAddDevice`              | `WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT`         | No         |                 |
| `0x8000004a` | `MemoryRemoveDevice`           | `WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT`         | No         |                 |
| `0x8000004b` | `MemorySummaryFailed`          | `WHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT`        | No         |                 |
| `0x8000004c` | `PcieDpcError`                 | `WHEAP_DPC_ERROR_EVENT`                            | No         |                 |
| `0x8000004d` | `CpuBusesInitFailed`           | `WHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT`        | No         |                 |
| `0x8000004e` | `PshedPluginInitFailed`        | `WHEA_PSHED_PLUGIN_INIT_FAILED_EVENT`              | No         |                 |
| `0x8000004f` | `FailedAddToDefectList`        | `WHEA_FAILED_ADD_DEFECT_LIST_EVENT`                | No         | No payload      |
| `0x80000050` | `DefectListFull`               | `WHEAP_PLUGIN_DEFECT_LIST_FULL_EVENT`              | No         | No payload      |
| `0x80000051` | `DefectListUEFIVarFailed`      | `WHEAP_PLUGIN_DEFECT_LIST_UEFI_VAR_FAILED`         | No         | No payload      |
| `0x80000052` | `DefectListCorrupt`            | `WHEAP_PLUGIN_DEFECT_LIST_CORRUPT`                 | No         | No payload      |
| `0x80000053` | `BadHestNotifyData`            | `WHEAP_BAD_HEST_NOTIFY_DATA_EVENT`                 | No         |                 |
| `0x80000054` | `SrasTableNotFound`            | `WHEA_SRAS_TABLE_NOT_FOUND`                        | No         | No payload      |
| `0x80000055` | `SrasTableError`               | `WHEA_SRAS_TABLE_ERROR`                            | No         | No payload      |
| `0x80000057` | `SrasTableEntries`             | `WHEA_SRAS_TABLE_ENTRIES_EVENT`                    | No         |                 |
| `0x80000057` | `RowFailure`                   | `WHEAP_ROW_FAILURE_EVENT`                          | No         |                 |
| `0x80000060` | `CpusFrozen`                   | Unknown                                            | No         |                 |
| `0x80000061` | `CpusFrozenNoCrashDump`        | Unknown                                            | No         |                 |
| `0x80040010` | `PshedPiTraceLog`              | `WHEA_PSHED_PI_TRACE_EVENT`                        | No         |                 |

Glossary
--------

### ACPI

- **EINJ**  
  Error Injection table
- **GHES**  
  Generic Hardware Error Source
- **GSIV**  
  Global System Interrupt Vector
- **HEST**  
  Hardware Error Source Table
- **NMI**  
  Non-Maskable Interrupt
- **OSC**  
  Operating System Capabilities
- **SCI**  
  System Control Interrupt
- **SRAS**  
  Static Resource Allocation Structure

### Architectures

### ARMv8

- **SEA**  
  Synchronous External Abort
- **SEI**  
  SError Interrupt

#### IA-32 (x86)

- **CMC**  
  Corrected Machine Check
- **CMCI**  
  Corrected Machine Check Interrupt
- **MCE**  
  Machine Check Exception
- **SRAR**  
  Software Recoverable Action Required

### IA-64 (Itanium)

- **CPE**  
  Corrected Platform Error
- **MCA**  
  Machine Check Abort
- **SAL**  
  System Abstraction Layer

### Microsoft

- **ETW**  
  Event Tracing for Windows
- **LLHEH**  
  asd
- **PFA**  
  Predictive Failure Analysis
- **PSHED**  
  Platform-Specific Hardware Error Driver
- **WHEA**  
  Windows Hardware Error Architecture

### PCIe

- **AER**  
  Advanced Error Reporting
- **DPC**  
  Downstream Port Containment
- **eDPC**  
  Enhanced Downstream Port Containment

### Specifications

- **ACPI**  
  Advanced Configuration and Power Interface
- **IPMI**  
  Intelligent Platform Management Interface
- **SDEI**  
  Software Delegated Exception Interface
- **UEFI**  
  Unified Extensible Firmware Interface

### UEFI

- **CPER**  
  Common Platform Error Record

### Miscellaneous

- **BMC**  
  Baseboard Management Controller
- **FRU**  
  Field Replaceable Unit
- **GPIO**  
  General Purpose Input/Output
- **SEL**  
  System Event Log
- **SOC**  
  System on Chip

License
-------

All content is licensed under the terms of [The MIT License](LICENSE).
