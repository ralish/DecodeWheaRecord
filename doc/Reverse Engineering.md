Reverse Engineering
===================

- [Magic numbers](#magic-numbers)
- [PSHED](#pshed)
  - [Callbacks](#callbacks)
  - [Functions](#functions)
- [WHEA](#whea)
  - [Callbacks](#callbacks-1)
  - [Functions](#functions-1)

Magic numbers
-------------

There are many magic numbers specific to WHEA. This is a curated set of some of the most valuable:

- `0x52455043`  
  The string `CPER` as a 32-bit integer. Signature value in error record headers.
- `0x74507245`  
  The string `ErPt` as a 32-bit integer. Signature value in hardware error packets (v1).
- `0x41454857`  
  The string `WHEA` as a 32-bit integer. Signature value in hardware error packets (v2).
- `0x674c6857`
  The string `WhLg` as a 32-bit integer. Signature value in event log entry headers.
- All of the GUIDs in [src/DecodeWheaRecord/Shared/WheaGuids.cs]  
  If you have debug symbols you can easily find these as global symbols.

PSHED
-----

### Callbacks

| Signature |
| --------- |
| `NTSTATUS (*PSHED_PI_ATTEMPT_ERROR_RECOVERY) (PVOID PluginContext, ULONG BufferLength, PWHEA_ERROR_RECORD ErrorRecord);` |
| `NTSTATUS (*PSHED_PI_CLEAR_ERROR_RECORD) (PVOID PluginContext, ULONG Flags, ULONGLONG ErrorRecordId);` |
| `NTSTATUS (*PSHED_PI_CLEAR_ERROR_STATUS) (PVOID PluginContext, PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource, ULONG BufferLength, PWHEA_ERROR_RECORD ErrorRecord);` |
| `NTSTATUS (*PSHED_PI_DISABLE_ERROR_SOURCE) (PVOID PluginContext, PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource);` |
| `NTSTATUS (*PSHED_PI_ENABLE_ERROR_SOURCE) (PVOID PluginContext, PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource);` |
| `NTSTATUS (*PSHED_PI_FINALIZE_ERROR_RECORD) (PVOID PluginContext, PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource, ULONG BufferLength, PWHEA_ERROR_RECORD ErrorRecord);` |
| `NTSTATUS (*PSHED_PI_GET_ALL_ERROR_SOURCES) (PVOID PluginContext, PULONG Count, PWHEA_ERROR_SOURCE_DESCRIPTOR *ErrorSrcs, PULONG Length);` |
| `NTSTATUS (*PSHED_PI_GET_ERROR_SOURCE_INFO) (PVOID PluginContext, PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource);` |
| `NTSTATUS (*PSHED_PI_GET_INJECTION_CAPABILITIES) (PVOID PluginContext, PWHEA_ERROR_INJECTION_CAPABILITIES Capabilities);` |
| `NTSTATUS (*PSHED_PI_INJECT_ERROR) (PVOID PluginContext, ULONGLONG ErrorType, ULONGLONG Parameter1, ULONGLONG Parameter2, ULONGLONG Parameter3, ULONGLONG Parameter4);` |
| `NTSTATUS (*PSHED_PI_READ_ERROR_RECORD) (PVOID PluginContext, ULONG Flags, ULONGLONG ErrorRecordId, PULONGLONG NextErrorRecordId, PULONG RecordLength, PWHEA_ERROR_RECORD ErrorRecord);` |
| `NTSTATUS (*PSHED_PI_RETRIEVE_ERROR_INFO) (PVOID PluginContext, PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource, ULONGLONG BufferLength, PWHEA_ERROR_PACKET Packet);` |
| `NTSTATUS (*PSHED_PI_SET_ERROR_SOURCE_INFO) (PVOID PluginContext, PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource);` |
| `NTSTATUS (*PSHED_PI_WRITE_ERROR_RECORD) (PVOID PluginContext, ULONG Flags, ULONG RecordLength, PWHEA_ERROR_RECORD ErrorRecord);` |

### Functions

| Signature |
| --------- |
| `PVOID PshedAllocateMemory (ULONG Size);` |
| `VOID PshedFreeMemory (PVOID Address);` |
| `BOOLEAN PshedIsSystemWheaEnabled (VOID);` |
| `NTSTATUS PshedRegisterPlugin (PWHEA_PSHED_PLUGIN_REGISTRATION_PACKET Packet);` |
| `BOOLEAN PshedSynchronizeExecution (PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource, PKSYNCHRONIZE_ROUTINE SynchronizeRoutine, PVOID SynchronizeContext);` |
| `VOID PshedUnregisterPlugin (PVOID PluginHandle);` |

WHEA
----

### Callbacks

| Signature |
| --------- |
| `BOOLEAN (*PFN_IN_USE_PAGE_OFFLINE_NOTIFY) (PFN_NUMBER Page, BOOLEAN Poisoned, PVOID Context, PNTSTATUS CallbackStatus);` |
| `NTSTATUS (*PFN_WHEA_HIGH_IRQL_LOG_SEL_EVENT_HANDLER) (PVOID Context, PIPMI_OS_SEL_RECORD OsSelRecord);` |
| `NTSTATUS (*PHVL_WHEA_ERROR_NOTIFICATION) (PWHEA_RECOVERY_CONTEXT RecoveryContext, BOOLEAN Poisoned);` |
| `NTSTATUS (*WHEA_ERROR_SOURCE_CORRECT) (PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource, PULONG MaximumSectionLength);` |
| `NTSTATUS (*WHEA_ERROR_SOURCE_CORRECT_DEVICE_DRIVER) (PVOID ErrorSourceDesc, PULONG MaximumSectionLength);` |
| `NTSTATUS (*WHEA_ERROR_SOURCE_CREATE_RECORD) (PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource, PWHEA_ERROR_PACKET ErrorPacket, PWHEA_ERROR_RECORD ErrorRecord, ULONG BufferSize, PVOID Context);` |
| `NTSTATUS (*WHEA_ERROR_SOURCE_INITIALIZE) (ULONG Phase, PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource, PVOID Context);` |
| `NTSTATUS (*WHEA_ERROR_SOURCE_INITIALIZE_DEVICE_DRIVER) (PVOID Context, ULONG ErrorSourceId);` |
| `NTSTATUS (*WHEA_ERROR_SOURCE_RECOVER) (PVOID RecoveryContext, PWHEA_ERROR_SEVERITY Severity);` |
| `VOID (*WHEA_ERROR_SOURCE_UNINITIALIZE) (PVOID Context);` |
| `VOID (*WHEA_ERROR_SOURCE_UNINITIALIZE_DEVICE_DRIVER) (PVOID Context);` |
| `BOOLEAN (*WHEA_SIGNAL_HANDLER_OVERRIDE_CALLBACK)(UINT_PTR Context);` |

### Functions

| Signature |
| --------- |
| `NTSTATUS HvlRegisterWheaErrorNotification (PHVL_WHEA_ERROR_NOTIFICATION Callback);` |
| `NTSTATUS HvlUnregisterWheaErrorNotification (PHVL_WHEA_ERROR_NOTIFICATION Callback);` |
| `NTSTATUS WheaAddErrorSource(PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource, PVOID Context);` |
| `NTSTATUS WheaAddErrorSourceDeviceDriver (PVOID Context, PWHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER Configuration, ULONG NumberPreallocatedErrorReports);` |
| `NTSTATUS WheaAddErrorSourceDeviceDriverV1 (PVOID Context, PWHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER Configuration, ULONG NumBuffersToPreallocate, ULONG MaxDataLength);` |
| `NTSTATUS WheaAddHwErrorReportSectionDeviceDriver (WHEA_ERROR_HANDLE ErrorHandle, ULONG SectionDataLength, PWHEA_DRIVER_BUFFER_SET BufferSet);` |
| `VOID WheaAttemptRowOffline (PFN_NUMBER Page, PMEMORY_DEFECT MemDefect, ULONG PageCount, PWHEA_RECOVERY_CONTEXT Context);` |
| `NTSTATUS WheaConfigureErrorSource (WHEA_ERROR_SOURCE_TYPE SourceType, PWHEA_ERROR_SOURCE_CONFIGURATION Configuration);` |
| `WHEA_ERROR_HANDLE WheaCreateHwErrorReportDeviceDriver (ULONG ErrorSourceId, PDEVICE_OBJECT DeviceObject);` |
| `WHEA_ERROR_SOURCE_STATE WheaErrorSourceGetState (ULONG ErrorSourceId);` |
| `NTSTATUS WheaGetErrorSourceInfo (WHEA_ERROR_SOURCE_TYPE SourceType, PULONG ErrorCount, PERROR_SOURCE_INFO* SourceInfo, ULONG PoolTag);` |
| `BOOLEAN WheaGetNotifyAllOfflinesPolicy (VOID);` |
| `BOOLEAN WheaHighIrqlLogSelEventHandlerRegister (PFN_WHEA_HIGH_IRQL_LOG_SEL_EVENT_HANDLER Handler, PVOID Context);` |
| `VOID WheaHighIrqlLogSelEventHandlerUnregister (VOID);` |
| `NTSTATUS WheaHwErrorReportAbandonDeviceDriver (WHEA_ERROR_HANDLE ErrorHandle);` |
| `NTSTATUS WheaHwErrorReportSetSectionNameDeviceDriver (PWHEA_DRIVER_BUFFER_SET BufferSet, ULONG NameLength, PUCHAR Name);` |
| `NTSTATUS WheaHwErrorReportSetSeverityDeviceDriver (WHEA_ERROR_HANDLE ErrorHandle, WHEA_ERROR_SEVERITY ErrorSeverity);` |
| `NTSTATUS WheaHwErrorReportSubmitDeviceDriver (WHEA_ERROR_HANDLE ErrorHandle);` |
| `NTSTATUS WheaInitializeRecordHeader (PWHEA_ERROR_RECORD_HEADER Header);` |
| `BOOLEAN WheaIsCriticalState (VOID);` |
| `BOOLEAN WheaIsLogSelHandlerInitialized();` |
| `VOID WheaLogInternalEvent (PWHEA_EVENT_LOG_ENTRY Entry);` |
| `NTSTATUS WheaRegisterErrorSourceOverride (WHEA_ERROR_SOURCE_OVERRIDE_SETTINGS OverrideSettings, PWHEA_ERROR_SOURCE_CONFIGURATION OverrideConfig, WHEA_SIGNAL_HANDLER_OVERRIDE_CALLBACK OverrideCallback);` |
| `NTSTATUS WheaRegisterInUsePageOfflineNotification (PFN_IN_USE_PAGE_OFFLINE_NOTIFY Callback, PVOID Context);` |
| `VOID WheaRemoveErrorSource (ULONG ErrorSourceId);` |
| `NTSTATUS WheaRemoveErrorSourceDeviceDriver (ULONG ErrorSourceId);` |
| `NTSTATUS WheaReportHwError(PWHEA_ERROR_PACKET ErrorPacket);` |
| `NTSTATUS WheaReportHwErrorDeviceDriver (ULONG ErrorSourceId, PDEVICE_OBJECT DeviceObject, PUCHAR ErrorData, ULONG ErrorDataLength, LPGUID SectionTypeGuid, WHEA_ERROR_SEVERITY ErrorSeverity, LPSTR DeviceFriendlyName);` |
| `BOOLEAN WheaSignalHandlerOverride (WHEA_ERROR_SOURCE_TYPE SourceType, UINT_PTR Context);` |
| `NTSTATUS WheaUnconfigureErrorSource (WHEA_ERROR_SOURCE_TYPE SourceType);` |
| `VOID WheaUnregisterErrorSourceOverride (WHEA_ERROR_SOURCE_TYPE Type, ULONG32 OverrideErrorSourceId);` |
| `NTSTATUS WheaUnregisterInUsePageOfflineNotification (PFN_IN_USE_PAGE_OFFLINE_NOTIFY Callback);` |
