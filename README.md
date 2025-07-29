DecodeWheaRecord
================

![GitHub Release](https://img.shields.io/github/v/release/ralish/DecodeWheaRecord?include_prereleases)
[![azure devops](https://dev.azure.com/nexiom/DecodeWheaRecord/_apis/build/status/DecodeWheaRecord)](https://dev.azure.com/nexiom/DecodeWheaRecord/_build/latest?definitionId=1)
[![license](https://img.shields.io/github/license/ralish/DecodeWheaRecord)](https://choosealicense.com/licenses/mit/)

A utility to decode *Windows Hardware Error Architecture (WHEA)* records.

- [Overview](#overview)
- [Requirements](#requirements)
- [Usage](#usage)
- [Support status](#support-status)
  - [Errors](#errors)
  - [Events](#events)
- [Technical details](#technical-details)
  - [Architecture](#architecture)
  - [Error records](#error-records)
  - [Event records](#event-records)
- [Glossary](#glossary)
  - [Buses](#buses)
  - [Memory](#memory)
  - [Microsoft](#microsoft)
  - [Processors](#processors)
  - [Specifications](#specifications)
  - [Miscellaneous](#miscellaneous)
- [License](#license)

Overview
--------

[Windows Hardware Error Architecture](https://learn.microsoft.com/en-us/windows-hardware/drivers/whea/) provides the Windows infrastructure for hardware error reporting. First introduced with Windows Server 2008 and Windows Vista SP1, it has been part of every Windows release since.

While the the records WHEA emits can be seen through its event log channels, they are only viewable in their raw binary format which Windows has no support for decoding. This utility takes these Base64 encoded binary records and decodes them into a human-readable JSON representation.

Requirements
------------

- A supported .NET runtime, either:
  - .NET Framework 4.7.2 (or newer)  
    *Built-in since Windows 10 1803 and Server 2019*
  - .NET 8 (or newer)  
    Install manually: [Download](https://dotnet.microsoft.com/en-us/download/dotnet/8.0) and run the installer  
    Install with WinGet: `winget install Microsoft.DotNet.Runtime.8`

Usage
-----

WHEA errors and events are logged by the `Microsoft-Windows-Kernel-WHEA` provider to the following event log channels:

- `Microsoft-Windows-Kernel-WHEA/Errors`
- `Microsoft-Windows-Kernel-WHEA/Operational`

For the unfamiliar, you can find these event log channels in *Event Viewer* by expanding the *Applications and Services Logs -> Microsoft -> Windows -> Kernel-WHEA* tree.

To decode an event you need to retrieve the value from its `RawData` field (visible in the *Details* tab). Provide this value as the sole argument to the utility:

```plain
DecodeWheaRecord.exe 57684C67010000002200000000000000504349203100008002000000020000000100
{
  "Header": {
    "Signature": "WhLg",
    "Version": 1,
    "Length": 34,
    "Type": "Informational",
    "OwnerTag": "PCI",
    "Id": "eDpcEnabled",
    "Flags": "LogInternalEtw",
    "PayloadLength": 2
  },
  "Entry": {
    "eDPCEnabled": true,
    "eDPCRecovEnabled": false
  }
}
```

Support status
--------------

All errors and events supported by Windows up to *Windows 11, version 24H2* and *Windows Server 2025* are either fully or partially supported.

### Errors

| Name                             | Implemented?         | GUID                                   | WHEA structure                          | UEFI section | MSFT documentation |
| -------------------------------- | -------------------- | -------------------------------------- | --------------------------------------- | ------------ | ------------------ |
| ARM Processor Error              | Complete             | `e19e3d16-bc11-11e4-9caa-c2051d5d46b0` | `WHEA_ARM_PROCESSOR_ERROR_SECTION`      | N.2.4.4      | Undocumented       |
| ARM RAS Node Error               | Complete             | `e3ebf4a2-df50-4708-b2d7-0b29ec2f7aa9` | `WHEA_ARM_RAS_NODE_SECTION`             | N/A          | Undocumented       |
| ARM SEA Exception                | Complete             | `f5fe48a6-84ce-4c1e-aa64-20c9a53099f1` | `WHEA_SEA_SECTION`                      | N/A          | [Partial](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-whea_sea_section) |
| ARM SEI Exception                | Complete             | `f2a4a152-9c6d-4020-aecf-7695b389251b` | `WHEA_SEI_SECTION`                      | N/A          | [Partial](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-whea_sei_section) |
| Error Recovery Information       | Complete             | `c34832a1-02c3-4c52-a9f1-9f1d5d7723fc` | `WHEA_ERROR_RECOVERY_INFO_SECTION`      | N/A          | Undocumented       |
| Firmware Error Record Reference  | Complete<sup>1</sup> | `81212a96-09ed-4996-9471-8d729c8e69ed` | `WHEA_FIRMWARE_ERROR_RECORD_REFERENCE`  | N.2.10       | [Yes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_firmware_error_record_reference) |
| Generic Error                    | Complete             | `e71254e8-c1b9-4940-ab76-909703a4320f` | `WHEA_GENERIC_ERROR`                    | N/A          | [Yes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_generic_error) |
| Generic Processor Error          | Complete             | `9876ccad-47b4-4bdb-b65e-16f193c4f3db` | `WHEA_PROCESSOR_GENERIC_ERROR_SECTION`  | N.2.4.1      | [Yes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_processor_generic_error_section) |
| Hardware Error Packet (v1)       | Partial              | `e71254e9-c1b9-4940-ab76-909703a4320f` | `WHEA_ERROR_PACKET_V1`                  | N/A          | [Yes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_error_packet_v1) |
| Hardware Error Packet (v2)       | Partial              | `e71254e9-c1b9-4940-ab76-909703a4320f` | `WHEA_ERROR_PACKET_V2`                  | N/A          | [Partial](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_error_packet_v2) |
| IA32 / AMD64 Machine Check Error | Partial              | `8a1e1d01-42f9-4557-9c33-565e5cc3f7e8` | `WHEA_XPF_MCA_SECTION`                  | N/A          | [Partial](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_xpf_mca_section) |
| IA32 / AMD64 Processor Error     | Complete             | `dc3ea0b0-a144-4797-b95b-53fa242b6e1d` | `WHEA_XPF_PROCESSOR_ERROR_SECTION`      | N.2.4.2      | [Yes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_xpf_processor_error_section) |
| Memory Correctable Error Summary | Complete             | `0e36c93e-ca15-4a83-ba8a-cbe80f7f0017` | `WHEA_MEMORY_CORRECTABLE_ERROR_SECTION` | N/A          | [Partial](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-whea_memory_correctable_error_section) |
| Memory Error                     | Complete             | `a5bc1114-6f64-4ede-b863-3e83ed7c83b1` | `WHEA_MEMORY_ERROR_SECTION`             | N.2.5        | [Yes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_memory_error_section) |
| Memory Error (Intel extension)   | Complete             | `e16edb28-6113-4263-a41d-e53f8de78751` | `WHEA_MEMORY_ERROR_EXT_SECTION_INTEL`   | N/A          | Undocumented       |
| MSR Dump                         | Partial              | `1c15b445-9b06-4667-ac25-33c056b88803` | `WHEA_MSR_DUMP_SECTION`                 | N/A          | [Partial](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-whea_msr_dump_section) |
| NMI Error                        | Complete             | `e71254e7-c1b9-4940-ab76-909703a4320f` | `WHEA_NMI_ERROR_SECTION`                | N/A          | [Yes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_nmi_error_section) |
| PCI / PCI-X Bus Error            | Complete             | `c5753963-3b84-4095-bf78-eddad3f9c9dd` | `WHEA_PCIXBUS_ERROR_SECTION`            | N.2.8        | [Yes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_pcixbus_error_section) |
| PCI / PCI-X Device Error         | Complete             | `eb5e4685-ca66-4769-b6a2-26068b001326` | `WHEA_PCIXDEVICE_ERROR_SECTION`         | M.2.9        | [Yes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_pcixdevice_error_section) |
| PCI Express DPC Capability       | Complete             | `ec49534b-30e7-4358-972f-eca6958fae3b` | `PCI_EXPRESS_DPC_CAPABILITY`            | N/A          | [Partial](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-pci_express_dpc_capability) |
| PCI Express Error                | Complete             | `d995e954-bbc1-430f-ad91-b44dcb3c6f35` | `WHEA_PCIEXPRESS_ERROR_SECTION`         | N.2.7        | [Yes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_pciexpress_error_section) |
| PCI Recovery                     | Complete             | `dd060800-f6e1-4204-ac27-c4bca9568402` | `WHEA_PCI_RECOVERY_SECTION`             | N/A          | [Partial](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-whea_pci_recovery_section) |
| PCIe Correctable Error Summary   | Partial              | `e96eca99-53e2-4f52-9be7-d2dbe9508ed0` | `WHEA_PCIE_CORRECTABLE_ERROR_SECTION`   | N/A          | [Partial](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-whea_pcie_correctable_error_section_header) |
| Persistent Memory Error          | Partial              | `81687003-dbfd-4728-9ffd-f0904f97597d` | `WHEA_PMEM_ERROR_SECTION`               | N/A          | [Partial](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-whea_pmem_error_section) |
| Project Mu Telemetry             | Complete             | `85183a8b-9c41-429c-939c-5c3c087ca280` | `MU_TELEMETRY_SECTION`                  | N/A          | Undocumented       |

1. The *Firmware Error Record Reference* error typically includes additional binary data for which it acts as an encapsulating record. The format of this binary data is not defined in the UEFI specification, and both the source of the data and its format is effectively arbitrary, though typically it's from the CPU or the platform firmware. When present this utility will output this additional data in hexadecimal, but it cannot decode it as the structure of the data is not known.

The following error section types are defined in the UEFI specification but are not implemented by Windows and so not supported by this utility. They are listed here for completeness:

| Name                             | GUID                                   | UEFI section |
| -------------------------------- | -------------------------------------- | ------------ |
| AMD IOMMU Specific DMAr Error    | `036f84e1-7f37-428c-a79e-575fdfaa84ec` | N.2.11.3     |
| CCIX PER Log Error               | `91335ef6-ebfb-4478-a6a6-88b728cf75d7` | N.2.12       |
| CXL Protocol Error               | `80b9efb4-52b5-4de3-a777-68784b771048` | N.2.13       |
| DMAr Generic Error               | `5b51fef7-c79d-4434-8f1b-aa62de3e2c64` | N.2.11.1     |
| FRU Memory Poison                | `5e4706c1-5356-48c6-930b-52f2120a4458` | N.2.15       |
| IA64 Processor Error             | `e429faf1-3cb7-11d4-bca7-0080c73c8881` | N.2.4.3      |
| Intel VT-d Specific DMAr Error   | `71761d37-32b2-45cd-a7d0-b0fedd93e8cf` | N.2.11.2     |
| Memory Error 2                   | `61ec04fc-48e6-d813-25c9-8daa44750b12` | N.2.6        |

### Events

| Entry ID     | Symbolic name                   | Implemented? | WHEA structure                                              | Notes       |
| ------------ | ------------------------------- | ------------ | ----------------------------------------------------------- | ----------- |
| `0x80000001` | `CmcPollingTimeout`             | Complete     | `WHEAP_CMC_POLLING_TIMEOUT_EVENT`                           |             |
| `0x80000002` | `WheaInit`                      | Complete     | `WHEAP_INIT_EVENT`                                          |             |
| `0x80000003` | `CmcSwitchToPolling`            | Complete     | `WHEAP_CMC_SWITCH_TO_POLLING_EVENT`                         | Empty       |
| `0x80000004` | `DroppedCorrectedError`         | Complete     | `WHEAP_DROPPED_CORRECTED_ERROR_EVENT`                       |             |
| `0x80000005` | `StartedReportHwError`          | Complete     | `WHEAP_STARTED_REPORT_HW_ERROR`                             | SEL         |
| `0x80000006` | `PFAMemoryOfflined`             | Complete     | `WHEAP_PFA_MEMORY_OFFLINED`                                 |             |
| `0x80000007` | `PFAMemoryRemoveMonitor`        | Complete     | `WHEAP_PFA_MEMORY_REMOVE_MONITOR`                           |             |
| `0x80000008` | `PFAMemoryPolicy`               | Complete     | `WHEAP_PFA_MEMORY_POLICY`                                   |             |
| `0x80000009` | `PshedInjectError`              | Complete     | `WHEAP_PSHED_INJECT_ERROR`                                  |             |
| `0x8000000a` | `OscCapabilities`               | Complete     | `WHEAP_OSC_IMPLEMENTED`                                     |             |
| `0x8000000b` | `PshedPluginRegister`           | Complete     | `WHEAP_PSHED_PLUGIN_REGISTER`                               |             |
| `0x8000000c` | `AddRemoveErrorSource`          | Complete     | `WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT`                       |             |
| `0x8000000d` | `WorkQueueItem`                 | Unsupported  | Unknown                                                     |             |
| `0x8000000e` | `AttemptErrorRecovery`          | Complete     | `WHEAP_ATTEMPT_RECOVERY_EVENT`                              |             |
| `0x8000000f` | `McaFoundErrorInBank`           | Partial      | `WHEAP_FOUND_ERROR_IN_BANK_EVENT`                           |             |
| `0x80000010` | `McaStuckErrorCheck`            | Complete     | `WHEAP_STUCK_ERROR_EVENT`                                   |             |
| `0x80000011` | `McaErrorCleared`               | Complete     | `WHEAP_ERROR_CLEARED_EVENT`                                 |             |
| `0x80000012` | `ClearedPoison`                 | Complete     | `WHEAP_CLEARED_POISON_EVENT`                                |             |
| `0x80000013` | `ProcessEINJ`                   | Complete     | `WHEAP_PROCESS_EINJ_EVENT`                                  |             |
| `0x80000014` | `ProcessHEST`                   | Complete     | `WHEAP_PROCESS_HEST_EVENT`                                  |             |
| `0x80000015` | `CreateGenericRecord`           | Complete     | `WHEAP_CREATE_GENERIC_RECORD_EVENT`                         |             |
| `0x80000016` | `ErrorRecord`                   | Complete     | `WHEAP_ERROR_RECORD_EVENT`                                  |             |
| `0x80000017` | `ErrorRecordLimit`              | Unsupported  | Unknown                                                     |             |
| `0x80000018` | `AerNotGrantedToOs`             | Complete     | `WHEAP_AER_NOT_GRANTED_TO_OS`                               | Empty       |
| `0x80000019` | `ErrSrcArrayInvalid`            | Complete     | `WHEAP_ERR_SRC_ARRAY_INVALID_EVENT`                         |             |
| `0x8000001a` | `AcpiTimeOut`                   | Complete     | `WHEAP_ACPI_TIMEOUT_EVENT`                                  |             |
| `0x8000001b` | `CmciRestart`                   | Complete     | `WHEAP_CMCI_RESTART_EVENT`                                  |             |
| `0x8000001c` | `CmciFinalRestart`              | Complete     | `WHEAP_CMCI_RESTART_EVENT`                                  |             |
| `0x8000001d` | `EtwOverFlow`                   | Complete     | `WHEA_ETW_OVERFLOW_EVENT`                                   |             |
| `0x8000001e` | `AzccRootBusSearchErr`          | Complete     | `WHEA_AZCC_ROOT_BUS_ERR_EVENT`                              |             |
| `0x8000001f` | `AzccRootBusList`               | Complete     | `WHEA_AZCC_ROOT_BUS_LIST_EVENT`                             |             |
| `0x80000020` | `ErrSrcInvalid`                 | Complete     | `WHEAP_ERR_SRC_INVALID_EVENT`                               |             |
| `0x80000021` | `GenericErrMemMap`              | Complete     | `WHEAP_GENERIC_ERR_MEM_MAP_EVENT`                           |             |
| `0x80000022` | `PshedCallbackCollision`        | Complete     | `WHEAP_PSHED_PLUGIN_CALLBACK_COLLISION`                     |             |
| `0x80000023` | `SELBugCheckProgress`           | Complete     | `WHEA_SEL_BUGCHECK_PROGRESS`                                | SEL         |
| `0x80000024` | `PshedPluginLoad`               | Complete     | `WHEA_PSHED_PLUGIN_LOAD_EVENT`                              |             |
| `0x80000025` | `PshedPluginUnload`             | Complete     | `WHEA_PSHED_PLUGIN_UNLOAD_EVENT`                            |             |
| `0x80000026` | `PshedPluginSupported`          | Complete     | `WHEA_PSHED_PLUGIN_PLATFORM_SUPPORT_EVENT`                  |             |
| `0x80000027` | `DeviceDriver`                  | Unsupported  | Unknown                                                     |             |
| `0x80000028` | `CmciImplPresent`               | Complete     | `WHEAP_CMCI_IMPLEMENTED_EVENT`                              |             |
| `0x80000029` | `CmciInitError`                 | Complete     | `WHEAP_CMCI_INITERR_EVENT`                                  |             |
| `0x8000002a` | `SELBugCheckRecovery`           | Complete     | `WHEA_SEL_BUGCHECK_RECOVERY_STATUS_MULTIPLE_BUGCHECK_EVENT` | SEL         |
| `0x8000002a` | `SELBugCheckRecovery`           | Complete     | `WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE1_EVENT`            | SEL         |
| `0x8000002a` | `SELBugCheckRecovery`           | Complete     | `WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE2_EVENT`            | SEL         |
| `0x8000002a` | `SELBugCheckRecovery`           | Complete     | `WHEA_SEL_BUGCHECK_RECOVERY_STATUS_START_EVENT`             | SEL         |
| `0x8000002b` | `DrvErrSrcInvalid`              | Complete     | `WHEAP_DEVICE_DRV_EVENT`                                    | SEL         |
| `0x8000002c` | `DrvHandleBusy`                 | Complete     | `WHEAP_DEVICE_DRV_EVENT`                                    | SEL         |
| `0x8000002d` | `WheaHeartbeat`                 | Complete     | `WHEA_PSHED_PLUGIN_HEARTBEAT`                               | Empty       |
| `0x8000002e` | `AzccRootBusPoisonSet`          | Complete     | `WHEA_AZCC_SET_POISON_EVENT`                                |             |
| `0x8000002f` | `SELBugCheckInfo`               | Unsupported  | Unknown                                                     |             |
| `0x80000030` | `ErrDimmInfoMismatch`           | Complete     | `WHEA_PSHED_PLUGIN_DIMM_MISMATCH`                           |             |
| `0x80000031` | `eDpcEnabled`                   | Complete     | `WHEAP_EDPC_ENABLED_EVENT`                                  |             |
| `0x80000032` | `PageOfflineDone`               | Complete     | `WHEA_OFFLINE_DONE_EVENT`                                   |             |
| `0x80000033` | `PageOfflinePendMax`            | Complete     | `WHEAP_OFFLINE_PENDING_MAX`                                 | Empty       |
| `0x80000034` | `BadPageLimitReached`           | Complete     | `WHEAP_BAD_PAGE_LIMIT_REACHED`                              | Empty       |
| `0x80000035` | `SrarDetail`                    | Partial      | `WHEA_SRAR_DETAIL_EVENT`                                    |             |
| `0x80000036` | `EarlyError`                    | Complete     | `WHEAP_EARLY_ERROR`                                         | Empty       |
| `0x80000037` | `PcieOverrideInfo`              | Partial      | `WHEAP_PCIE_OVERRIDE_INFO`                                  |             |
| `0x80000038` | `ReadPcieOverridesErr`          | Complete     | `WHEAP_PCIE_READ_OVERRIDES_ERR`                             |             |
| `0x80000039` | `PcieConfigInfo`                | Complete     | `WHEAP_PCIE_CONFIG_INFO`                                    |             |
| `0x80000040` | `PcieSummaryFailed`             | Complete     | `WHEA_THROTTLE_PCIE_ADD_EVENT`                              |             |
| `0x80000041` | `ThrottleRegCorrupt`            | Complete     | `WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT`                      |             |
| `0x80000042` | `ThrottleAddErrSrcFailed`       | Complete     | `WHEA_THROTTLE_ADD_ERR_SRC_FAILED_EVENT`                    | Empty       |
| `0x80000043` | `ThrottleRegDataIgnored`        | Complete     | `WHEA_THROTTLE_REG_DATA_IGNORED_EVENT`                      |             |
| `0x80000044` | `EnableKeyNotifFailed`          | Complete     | `WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_FAILED_EVENT`              |             |
| `0x80000045` | `KeyNotificationFailed`         | Complete     | `WHEA_REGISTER_KEY_NOTIFICATION_FAILED_EVENT`               | Empty       |
| `0x80000046` | `PcieRemoveDevice`              | Complete     | `WHEA_THROTTLE_PCIE_REMOVE_EVENT`                           |             |
| `0x80000047` | `PcieAddDevice`                 | Complete     | `WHEA_THROTTLE_PCIE_ADD_EVENT`                              |             |
| `0x80000048` | `PcieSpuriousErrSource`         | Complete     | `WHEAP_SPURIOUS_AER_EVENT`                                  |             |
| `0x80000049` | `MemoryAddDevice`               | Complete     | `WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT`                  |             |
| `0x8000004a` | `MemoryRemoveDevice`            | Complete     | `WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT`                  |             |
| `0x8000004b` | `MemorySummaryFailed`           | Complete     | `WHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT`                 |             |
| `0x8000004c` | `PcieDpcError`                  | Complete     | `WHEAP_DPC_ERROR_EVENT`                                     |             |
| `0x8000004d` | `CpuBusesInitFailed`            | Complete     | `WHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT`                 |             |
| `0x8000004e` | `PshedPluginInitFailed`         | Complete     | `WHEA_PSHED_PLUGIN_INIT_FAILED_EVENT`                       |             |
| `0x8000004f` | `FailedAddToDefectList`         | Complete     | `WHEA_FAILED_ADD_DEFECT_LIST_EVENT`                         | Empty       |
| `0x80000050` | `DefectListFull`                | Complete     | `WHEAP_PLUGIN_DEFECT_LIST_FULL_EVENT`                       | Empty       |
| `0x80000051` | `DefectListUEFIVarFailed`       | Complete     | `WHEAP_PLUGIN_DEFECT_LIST_UEFI_VAR_FAILED`                  | Empty       |
| `0x80000052` | `DefectListCorrupt`             | Complete     | `WHEAP_PLUGIN_DEFECT_LIST_CORRUPT`                          | Empty       |
| `0x80000053` | `BadHestNotifyData`             | Complete     | `WHEAP_BAD_HEST_NOTIFY_DATA_EVENT`                          |             |
| `0x80000054` | `RowFailure`                    | Complete     | `WHEAP_ROW_FAILURE_EVENT`                                   |             |
| `0x80000055` | `SrasTableNotFound`             | Complete     | `WHEA_SRAS_TABLE_NOT_FOUND`                                 | Empty       |
| `0x80000056` | `SrasTableError`                | Complete     | `WHEA_SRAS_TABLE_ERROR`                                     | Empty       |
| `0x80000057` | `SrasTableEntries`              | Partial      | `WHEA_SRAS_TABLE_ENTRIES_EVENT`                             |             |
| `0x80000058` | `PFANotifyCallbackAction`       | Complete     | `WHEAP_PFA_MEMORY_OFFLINED_NOTIFY_CALLBACK_ACTION`          |             |
| `0x80000059` | `SELBugCheckCpusQuiesced`       | Unsupported  | Unknown                                                     |             |
| `0x8000005a` | `PshedPiCpuid`                  | Complete     | `WHEA_PSHED_PI_CPUID`                                       |             |
| `0x8000005b` | `SrasTableBadData`              | Complete     | `WHEAP_SRAS_TABLE_BAD_DATA`                                 | Empty       |
| `0x8000005c` | `DriFsStatus`                   | Unsupported  | Unknown                                                     |             |
| `0x80000060` | `CpusFrozen`                    | Complete     | `WHEAP_BUGCHECK_CPUS_FROZEN_EVENT`                          | Empty, SEL  |
| `0x80000061` | `CpusFrozenNoCrashDump`         | Unsupported  | Unknown                                                     |             |
| `0x80000062` | `RegNotifyPolicyChange`         | Complete     | `WHEA_REGNOTIFY_POLICY_CHANGE_EVENT`                        |             |
| `0x80000063` | `RegError`                      | Complete     | `WHEA_REGISTRY_ERROR_EVENT`                                 |             |
| `0x80000064` | `RowOfflineEvent`               | Complete     | `WHEAP_ROW_OFFLINE_EVENT`                                   |             |
| `0x80000065` | `BitOfflineEvent`               | Complete     | `WHEAP_BIT_OFFLINE_EVENT`                                   |             |
| `0x80000066` | `BadGasFields`                  | Complete     | `WHEA_GAS_ERROR_EVENT`                                      |             |
| `0x80000067` | `CrashDumpError`                | Complete     | `WHEA_CRASHDUMP_EVENT_LOG_ENTRY_WITH_STATUS`                | SEL         |
| `0x80000068` | `CrashDumpCheckpoint`           | Unsupported  | Unknown                                                     |             |
| `0x80000069` | `CrashDumpProgressPercent`      | Complete     | `WHEA_CRASHDUMP_EVENT_LOG_ENTRY_ULONG1`                     | SEL         |
| `0x8000006a` | `PreviousCrashBugCheckProgress` | Unsupported  | Unknown                                                     |             |
| `0x8000006b` | `SELBugCheckStackDump`          | Complete     | `WHEA_SEL_RAW_EVENT`                                        | SEL         |
| `0x8000006c` | `PciePromotedAerErr`            | Complete     | `WHEAP_PROMOTED_AER_ERROR_EVENT`                            |             |
| `0x80040010` | `PshedPiTraceLog`               | Complete     | `WHEA_PSHED_PI_TRACE_EVENT`                                 |             |

Notes:

- *Empty* means the event has no payload data; i.e. they consist only of an event log entry header.
- *SEL* means the event is logged to the *System Event Log* of the BMC via IPMI. It's possible these events are later read back from the SEL and inserted into the Windows Event Log when the system returns to a "healthy" state, but I haven't verified if this is the case.

Technical details
-----------------

### Architecture

The functionality that comprises WHEA is implemented across several system components:

- Windows NT kernel (`ntoskrnl.exe`)  
  WHEA itself is implemented directly in the Windows NT kernel. All of the kernel-mode WHEA APIs and associated functionality are a part of the main kernel binary.
- *Platform-specific Hardware Error Driver (PSHED)* (`pshed.dll`)  
  The PSHED ships with Windows and is implemented as a kernel-mode driver with the role of abstracting the platform's hardware error reporting facilities. It is analogous to the *Hardware Abstraction Layer (HAL)* but for functionality specific to WHEA.
- PSHED plug-ins  
  For supporting additional hardware error reporting functionality present in a platform which is not handled by the built-in PSHED, 3rd-parties can provide a *PSHED plug-in*. A PSHED plug-in is a kernel-mode driver which registers with PSHED, providing a set of callback functions to expose the additional platform hardware error reporting capabilities. In practice, this class of driver appears to be quite rare(?).
- Hardware drivers  
  WHEA exposes a public API which drivers can integrate with to report hardware errors and where possible recover from them. Several built-in Windows drivers integrate with WHEA, for example, the PCI bus driver (`pci.sys`).

### Error records

Error records take the form of *Common Platform Error Records (CPER)* as defined in the *Unified Extensible Firmware Interface (UEFI)* specification. These records consist of three parts:

- Header  
  An initial error record header, the structure of which is defined in the UEFI specification.
- Section Descriptor  
  One or more error record section descriptors, the structure of which is defined in the UEFI specification. Each section descriptor maps to an error record section.
- Section  
  One or more error record sections. Each error record section has an associated error record section descriptor which, among other things, defines the type of error section.

Error sections have their own unique binary format as informed by the section type, specified as a GUID, in the corresponding section descriptor. The UEFI specification defines several standard error section types (e.g. generic processor error, memory error), but 3rd-parties are free to define their own sections.

In terms of the data structure layout, the header always comes first, then the section descriptors, and finally the sections. There can be unused space between the section descriptors and the sections, and at the end of the last section, to facilitate adding additional section descriptors and sections to an existing allocation.

### Event records

Event records are purely a WHEA concept; they are not defined in the UEFI specification. While there are many more event record types defined than error record types, they are generally simpler to decode. Most event records have a simple structure containing a few fields that are primitive types. In contrast, many error records have a complex format with multiple embedded structures which in turn have many fields.

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

- **AER**  
  Advanced Error Reporting
- **DPC**  
  Downstream Port Containment
- **eDPC**  
  Enhanced Downstream Port Containment

### Memory

- **DIMM**  
  Dual In-Line Memory Module
- **ECC**  
  Error Correction Code
- **PFN**  
  Page Frame Number
- **PMem**  
  Persistent Memory

### Microsoft

- **ETW**  
  Event Tracing for Windows
- **IRQL**  
  Interrupt Request Level
- **LLHEH**  
  Low-Level Hardware Error Handler
- **PFA**  
  Predictive Failure Analysis
- **PSHED**  
  Platform-Specific Hardware Error Driver
- **WHEA**  
  Windows Hardware Error Architecture

### Processors

#### Generic

- **IP**  
  Instruction Pointer
- **MAE**  
  Micro-Architecture Error
- **MMIO**  
  Memory-mapped I/O
- **TLB**  
  Translation Lookaside Buffer

#### Architectures

- **IA32**  
  Intel Architecture, 32-bit
- **IA64**  
  Intel Architecture, 64-bit (Itanium)
- **IPF**  
  Itanium Platform
- **XPF**  
  x86 Platform

#### Arm

- **GIC**  
  Generic Interrupt Controller
- **PSCI**  
  Power State Coordination Interface
- **SMMU**  
  System Memory Management Unit
- **SEA**  
  Synchronous External Abort
- **SEI**  
  SError Interrupt

#### IA-32 (x86)

- **APIC**  
  Advanced Programmable Interrupt Controller
- **CMC**  
  Corrected Machine Check
- **CMCI**  
  Corrected Machine Check Interrupt
- **MCA**  
  Machine Check Architecture
- **MCE**  
  Machine Check Exception
- **MCI**  
  Machine Check Interrupt
- **MSR**  
  Model-Specific Register
- **SRAR**  
  Software Recoverable Action Required

#### IA-64 (Itanium)

- **CPE**  
  Corrected Platform Error
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
  Arm Error Source Table
- **EINJ**  
  Error Injection table
- **GAS**  
  Generic Address Structure
- **GHES**  
  Generic Hardware Error Source
- **GSIV**  
  Global System Interrupt Vector
- **HEST**  
  Hardware Error Source Table
- **NFIT**  
  NVDIMM Firmware Interface Table
- **OSC**  
  Operating System Capabilities
- **SCI**  
  Service Control Interrupt
- **SRAS**  
  Static Resource Allocation Structure

#### IPMI

- **SEL**  
  System Event Log

#### UEFI

- **CPER**  
  Common Platform Error Record
- **PRM**  
  Platform Runtime Mechanism

### Miscellaneous

- **BMC**  
  Baseboard Management Controller
- **CCIX**  
  Cache Coherent Interconnect for Accelerators
- **CXL**  
  Compute Express Link
- **DMA**  
  Direct Memory Access
- **DMAr**  
  DMA remapping
- **FRU**  
  Field Replaceable Unit
- **GPIO**  
  General Purpose Input/Output
- **IOMMU**  
  Input/Output Memory Management Unit
- **NMI**  
  Non-Maskable Interrupt
- **OEM**  
  Original Equipment Manufacturer
- **RAS**  
  Reliability, Availability, and Serviceability
- **SOC**  
  System on Chip

License
-------

All content is licensed under the terms of [The MIT License](LICENSE).
