/*++ BUILD Version: 0185    // Increment this if a change has global effects

Copyright (c) Microsoft Corporation. All rights reserved.

Module Name:

 ntddk.h

Abstract:

    This module defines the NT types, constants, and functions that are
    exposed to device drivers.

Revision History:

--*/

#ifndef _NTDDK_
#define _NTDDK_

#if !defined(_NTHAL_) && !defined(_NTIFS_)
#define _NTDDK_INCLUDED_
#define _DDK_DRIVER_
#endif

#ifndef RC_INVOKED
#if _MSC_VER < 1300
#error Compiler version not supported by Windows DDK
#endif
#endif

#define NT_INCLUDED
#define _CTYPE_DISABLE_MACROS

#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning(disable:4115) // named type definition in parentheses
#pragma warning(disable:4201) // nameless struct/union
#pragma warning(disable:4214) // bit field types other than int
#pragma warning(disable:4625) // copy constructor was implicitly defined as deleted
#pragma warning(disable:4626) // assignment operator was implicitly defined as deleted
#pragma warning(disable:4668) // #if not_defined treated as #if 0
#pragma warning(disable:4820) // padding added

#include <wdm.h>
#include <excpt.h>
#include <ntdef.h>
#include <ntstatus.h>
#include <bugcodes.h>
#include <ntiologc.h>

// X86 and ARM
//typedef ULONG PFN_COUNT;
//typedef LONG SPFN_NUMBER, *PSPFN_NUMBER;
//typedef ULONG PFN_NUMBER, *PPFN_NUMBER;

// AMD64 and ARM64
typedef ULONG PFN_COUNT;
typedef LONG64 SPFN_NUMBER, *PSPFN_NUMBER;
typedef ULONG64 PFN_NUMBER, *PPFN_NUMBER;


//------------------------------------------------------ WHEA_ERROR_SOURCE_TYPE

#define WHEA_PHYSICAL_ADDRESS LARGE_INTEGER

//
// This enumeration defines the various types of error sources that a platform
// can expose to the operating system.
//

typedef enum _WHEA_ERROR_SOURCE_TYPE {
    WheaErrSrcTypeMCE          = 0x00,    // Machine Check Exception
    WheaErrSrcTypeCMC          = 0x01,    // Corrected Machine Check
    WheaErrSrcTypeCPE          = 0x02,    // Corrected Platform Error
    WheaErrSrcTypeNMI          = 0x03,    // Non-Maskable Interrupt
    WheaErrSrcTypePCIe         = 0x04,    // PCI Express Error
    WheaErrSrcTypeGeneric      = 0x05,    // Other types of error sources
    WheaErrSrcTypeINIT         = 0x06,    // IA64 INIT Error Source
    WheaErrSrcTypeBOOT         = 0x07,    // BOOT Error Source
    WheaErrSrcTypeSCIGeneric   = 0x08,    // SCI-based generic error source
    WheaErrSrcTypeIPFMCA       = 0x09,    // Itanium Machine Check Abort
    WheaErrSrcTypeIPFCMC       = 0x0a,    // Itanium Machine check
    WheaErrSrcTypeIPFCPE       = 0x0b,    // Itanium Corrected Platform Error
    WheaErrSrcTypeGenericV2    = 0x0c,    // Other types of error sources v2
    WheaErrSrcTypeSCIGenericV2 = 0x0d,    // SCI-based GHESv2
    WheaErrSrcTypeBMC          = 0x0e,    // BMC error info
    WheaErrSrcTypePMEM         = 0x0f,    // ARS PMEM Error Source
    WheaErrSrcTypeDeviceDriver = 0x10,    // Device Driver Error Source
    WheaErrSrcTypeSea          = 0x11,    // Arm Sync External Abort
    WheaErrSrcTypeSei          = 0x12,    // Arm Sync External Abort
    WheaErrSrcTypeMax
} WHEA_ERROR_SOURCE_TYPE, *PWHEA_ERROR_SOURCE_TYPE;

//
// Error sources have a runtime state associated with them. The following are
// the valid states for an error source.
//

typedef enum _WHEA_ERROR_SOURCE_STATE {
    WheaErrSrcStateStopped       = 0x01,
    WheaErrSrcStateStarted       = 0x02,
    WheaErrSrcStateRemoved       = 0x03,
    WheaErrSrcStateRemovePending = 0x04
} WHEA_ERROR_SOURCE_STATE, *PWHEA_ERROR_SOURCE_STATE;

#define WHEA_ERROR_SOURCE_DESCRIPTOR_VERSION_10          10
#define WHEA_ERROR_SOURCE_DESCRIPTOR_VERSION_11          11

#define WHEA_MAX_MC_BANKS                                32

#define WHEA_ERROR_SOURCE_FLAG_FIRMWAREFIRST             0x00000001
#define WHEA_ERROR_SOURCE_FLAG_GLOBAL                    0x00000002
#define WHEA_ERROR_SOURCE_FLAG_GHES_ASSIST               0x00000004
#define WHEA_ERROR_SOURCE_FLAG_DEFAULTSOURCE             0x80000000

//
// This flag is added to an error source descriptor to indicate this source
// is an override, and not a normal error source.
//
// Some error sources such as PCI populate the HEST flags into their OS
// error source flags, so this bit is defined to not conflict with them.
//

#define WHEA_ERR_SRC_OVERRIDE_FLAG 0x40000000

//
// The definition of invalid related source comes from the ACPI spec
//

#define WHEA_ERROR_SOURCE_INVALID_RELATED_SOURCE         0xFFFF

#define WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_XPFMCE         0
#define WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_XPFCMC         1
#define WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_XPFNMI         2
#define WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_IPFMCA         3
#define WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_IPFCMC         4
#define WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_IPFCPE         5
#define WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_AERROOTPORT    6
#define WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_AERENDPOINT    7
#define WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_AERBRIDGE      8
#define WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_GENERIC        9
#define WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_GENERIC_V2     10

#define WHEA_XPF_MC_BANK_STATUSFORMAT_IA32MCA            0
#define WHEA_XPF_MC_BANK_STATUSFORMAT_Intel64MCA         1
#define WHEA_XPF_MC_BANK_STATUSFORMAT_AMD64MCA           2

#define WHEA_NOTIFICATION_TYPE_POLLED                    0
#define WHEA_NOTIFICATION_TYPE_EXTERNALINTERRUPT         1
#define WHEA_NOTIFICATION_TYPE_LOCALINTERRUPT            2
#define WHEA_NOTIFICATION_TYPE_SCI                       3
#define WHEA_NOTIFICATION_TYPE_NMI                       4
#define WHEA_NOTIFICATION_TYPE_CMCI                      5
#define WHEA_NOTIFICATION_TYPE_MCE                       6
#define WHEA_NOTIFICATION_TYPE_GPIO_SIGNAL               7
#define WHEA_NOTIFICATION_TYPE_ARMV8_SEA                 8
#define WHEA_NOTIFICATION_TYPE_ARMV8_SEI                 9
#define WHEA_NOTIFICATION_TYPE_EXTERNALINTERRUPT_GSIV    10
#define WHEA_NOTIFICATION_TYPE_SDEI                      11

#include <pshpack1.h>

//---------------------- -------- WHEA_ERROR_SOURCE_CALLBACKS for device drivers

typedef
NTSTATUS
(_WHEA_ERROR_SOURCE_INITIALIZE_DEVICE_DRIVER)(
    _Inout_opt_ PVOID Context,
    _In_ ULONG ErrorSourceId
    );

typedef _WHEA_ERROR_SOURCE_INITIALIZE_DEVICE_DRIVER
    *WHEA_ERROR_SOURCE_INITIALIZE_DEVICE_DRIVER;

typedef
VOID
(_WHEA_ERROR_SOURCE_UNINITIALIZE_DEVICE_DRIVER)(
    _Inout_opt_ PVOID Context
    );

typedef _WHEA_ERROR_SOURCE_UNINITIALIZE_DEVICE_DRIVER
    *WHEA_ERROR_SOURCE_UNINITIALIZE_DEVICE_DRIVER;

typedef
NTSTATUS
(_WHEA_ERROR_SOURCE_CORRECT_DEVICE_DRIVER)(
    _Inout_ PVOID ErrorSourceDesc,
    _Out_ PULONG MaximumSectionLength
    );

typedef _WHEA_ERROR_SOURCE_CORRECT_DEVICE_DRIVER
    *WHEA_ERROR_SOURCE_CORRECT_DEVICE_DRIVER;

typedef struct _WHEA_ERROR_SOURCE_CONFIGURATION_DD {
    WHEA_ERROR_SOURCE_INITIALIZE_DEVICE_DRIVER Initialize;
    WHEA_ERROR_SOURCE_UNINITIALIZE_DEVICE_DRIVER Uninitialize;
    WHEA_ERROR_SOURCE_CORRECT_DEVICE_DRIVER Correct;
} WHEA_ERROR_SOURCE_CONFIGURATION_DD, *PWHEA_ERROR_SOURCE_CONFIGURATION_DD;

typedef PVOID WHEA_ERROR_HANDLE;

typedef struct _WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1 {
    ULONG Version;
    GUID SourceGuid;
    USHORT LogTag;
    UCHAR Reserved[6];
    WHEA_ERROR_SOURCE_INITIALIZE_DEVICE_DRIVER Initialize;
    WHEA_ERROR_SOURCE_UNINITIALIZE_DEVICE_DRIVER Uninitialize;
} WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1,
  *PWHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1;

typedef struct _WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER {
    ULONG Version;
    GUID SourceGuid;
    USHORT LogTag;
    UCHAR Reserved[6];
    WHEA_ERROR_SOURCE_INITIALIZE_DEVICE_DRIVER Initialize;
    WHEA_ERROR_SOURCE_UNINITIALIZE_DEVICE_DRIVER Uninitialize;
    ULONG  MaxSectionDataLength;
    ULONG MaxSectionsPerReport;
    GUID CreatorId;
    GUID PartitionId;
} WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER,
  *PWHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER;

typedef struct _WHEA_DRIVER_BUFFER_SET {
    ULONG Version;
    _Field_size_full_(DataSize)
        PUCHAR Data;
    ULONG DataSize;
    LPGUID SectionTypeGuid;
    _Field_size_full_(20)
        PUCHAR SectionFriendlyName;
    PUCHAR Flags;
} WHEA_DRIVER_BUFFER_SET, *PWHEA_DRIVER_BUFFER_SET;


#define WHEA_DEVICE_DRIVER_CONFIG_V1 1
#define WHEA_DEVICE_DRIVER_CONFIG_V2 2
#define WHEA_DEVICE_DRIVER_CONFIG_MIN 1
#define WHEA_DEVICE_DRIVER_CONFIG_MAX 2

#define WHEA_DEVICE_DRIVER_BUFFER_SET_V1 1
#define WHEA_DEVICE_DRIVER_BUFFER_SET_MIN 1
#define WHEA_DEVICE_DRIVER_BUFFER_SET_MAX 1

#define WHEA_ERROR_HANDLE_INVALID NULL

//------------------------------------------------ WHEA_ERROR_SOURCE_DESCRIPTOR

typedef union _WHEA_NOTIFICATION_FLAGS {
    struct {
        USHORT PollIntervalRW:1;
        USHORT SwitchToPollingThresholdRW:1;
        USHORT SwitchToPollingWindowRW:1;
        USHORT ErrorThresholdRW:1;
        USHORT ErrorThresholdWindowRW:1;
        USHORT Reserved:11;
    } DUMMYSTRUCTNAME;
    USHORT AsUSHORT;
} WHEA_NOTIFICATION_FLAGS, *PWHEA_NOTIFICATION_FLAGS;

typedef union _XPF_MC_BANK_FLAGS {
    struct {
        UCHAR ClearOnInitializationRW:1;
        UCHAR ControlDataRW:1;
        UCHAR Reserved:6;
    } DUMMYSTRUCTNAME;
    UCHAR AsUCHAR;
} XPF_MC_BANK_FLAGS, *PXPF_MC_BANK_FLAGS;

typedef union _XPF_MCE_FLAGS {
    struct {
        ULONG MCG_CapabilityRW:1;
        ULONG MCG_GlobalControlRW:1;
        ULONG Reserved:30;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} XPF_MCE_FLAGS, *PXPF_MCE_FLAGS;

typedef union _AER_ROOTPORT_DESCRIPTOR_FLAGS {
    struct {
        USHORT UncorrectableErrorMaskRW:1;
        USHORT UncorrectableErrorSeverityRW:1;
        USHORT CorrectableErrorMaskRW:1;
        USHORT AdvancedCapsAndControlRW:1;
        USHORT RootErrorCommandRW:1;
        USHORT Reserved:11;
    } DUMMYSTRUCTNAME;
    USHORT AsUSHORT;
} AER_ROOTPORT_DESCRIPTOR_FLAGS, *PAER_ROOTPORT_DESCRIPTOR_FLAGS;

typedef union _AER_ENDPOINT_DESCRIPTOR_FLAGS {
    struct {
        USHORT UncorrectableErrorMaskRW:1;
        USHORT UncorrectableErrorSeverityRW:1;
        USHORT CorrectableErrorMaskRW:1;
        USHORT AdvancedCapsAndControlRW:1;
        USHORT Reserved:12;
    } DUMMYSTRUCTNAME;
    USHORT AsUSHORT;
} AER_ENDPOINT_DESCRIPTOR_FLAGS, *PAER_ENDPOINT_DESCRIPTOR_FLAGS;

typedef union _AER_BRIDGE_DESCRIPTOR_FLAGS {
    struct {
        USHORT UncorrectableErrorMaskRW:1;
        USHORT UncorrectableErrorSeverityRW:1;
        USHORT CorrectableErrorMaskRW:1;
        USHORT AdvancedCapsAndControlRW:1;
        USHORT SecondaryUncorrectableErrorMaskRW:1;
        USHORT SecondaryUncorrectableErrorSevRW:1;
        USHORT SecondaryCapsAndControlRW:1;
        USHORT Reserved:9;
    } DUMMYSTRUCTNAME;
    USHORT AsUSHORT;
} AER_BRIDGE_DESCRIPTOR_FLAGS, *PAER_BRIDGE_DESCRIPTOR_FLAGS;

//
// The following structure is used to describe how a given error source reports
// errors to the OS.
//

typedef struct _WHEA_NOTIFICATION_DESCRIPTOR {
    UCHAR Type;
    UCHAR Length;
    WHEA_NOTIFICATION_FLAGS Flags;

    union {
        struct {
            ULONG PollInterval;
        } Polled;

        struct {
            ULONG PollInterval;
            ULONG Vector;
            ULONG SwitchToPollingThreshold;
            ULONG SwitchToPollingWindow;
            ULONG ErrorThreshold;
            ULONG ErrorThresholdWindow;
        } Interrupt;

        struct {
            ULONG PollInterval;
            ULONG Vector;
            ULONG SwitchToPollingThreshold;
            ULONG SwitchToPollingWindow;
            ULONG ErrorThreshold;
            ULONG ErrorThresholdWindow;
        } LocalInterrupt;

        struct {
            ULONG PollInterval;
            ULONG Vector;
            ULONG SwitchToPollingThreshold;
            ULONG SwitchToPollingWindow;
            ULONG ErrorThreshold;
            ULONG ErrorThresholdWindow;
        } Sci;

        struct {
            ULONG PollInterval;
            ULONG Vector;
            ULONG SwitchToPollingThreshold;
            ULONG SwitchToPollingWindow;
            ULONG ErrorThreshold;
            ULONG ErrorThresholdWindow;
        } Nmi;

        struct {
            ULONG PollInterval;
            ULONG Vector;
            ULONG SwitchToPollingThreshold;
            ULONG SwitchToPollingWindow;
            ULONG ErrorThreshold;
            ULONG ErrorThresholdWindow;
        } Sea;

        struct {
            ULONG PollInterval;
            ULONG Vector;
            ULONG SwitchToPollingThreshold;
            ULONG SwitchToPollingWindow;
            ULONG ErrorThreshold;
            ULONG ErrorThresholdWindow;
        } Sei;

        struct {
            ULONG PollInterval;
            ULONG Vector;
            ULONG SwitchToPollingThreshold;
            ULONG SwitchToPollingWindow;
            ULONG ErrorThreshold;
            ULONG ErrorThresholdWindow;
        } Gsiv;
    } u;
} WHEA_NOTIFICATION_DESCRIPTOR, *PWHEA_NOTIFICATION_DESCRIPTOR;

//
// The following structure describes an XPF machine check bank. It identifies
// the bank with a BankNumber and it contains information that is used to
// configure the bank. MCE and CMC error sources make use of this descriptor
// to describe and configure each bank.
//

typedef struct _WHEA_XPF_MC_BANK_DESCRIPTOR {
    UCHAR BankNumber;
    BOOLEAN ClearOnInitialization;
    UCHAR StatusDataFormat;
    XPF_MC_BANK_FLAGS Flags;
    ULONG ControlMsr;
    ULONG StatusMsr;
    ULONG AddressMsr;
    ULONG MiscMsr;
    ULONGLONG ControlData;
} WHEA_XPF_MC_BANK_DESCRIPTOR, *PWHEA_XPF_MC_BANK_DESCRIPTOR;

//
// The following structure describes an XPF platform's machine check exception
// error source mechanism. The information represented in this structure tells
// the OS how to configure the platform's MCE error source.
//

typedef struct _WHEA_XPF_MCE_DESCRIPTOR {
    USHORT Type;
    UCHAR Enabled;
    UCHAR NumberOfBanks;
    XPF_MCE_FLAGS Flags;
    ULONGLONG MCG_Capability;
    ULONGLONG MCG_GlobalControl;
    WHEA_XPF_MC_BANK_DESCRIPTOR Banks[WHEA_MAX_MC_BANKS];
} WHEA_XPF_MCE_DESCRIPTOR, *PWHEA_XPF_MCE_DESCRIPTOR;

//
// The following structure describes an XPF platform's corrected machine check
// error source mechanism. The information represented in this structure tells
// the OS how to configure the platform's CMC error source.
//

typedef struct _WHEA_XPF_CMC_DESCRIPTOR {
    USHORT Type;
    BOOLEAN Enabled;
    UCHAR NumberOfBanks;
    ULONG Reserved;
    WHEA_NOTIFICATION_DESCRIPTOR Notify;
    WHEA_XPF_MC_BANK_DESCRIPTOR Banks[WHEA_MAX_MC_BANKS];
} WHEA_XPF_CMC_DESCRIPTOR, *PWHEA_XPF_CMC_DESCRIPTOR;

typedef struct _WHEA_PCI_SLOT_NUMBER {
    union {
        struct {
            ULONG DeviceNumber:5;
            ULONG FunctionNumber:3;
            ULONG Reserved:24;
        } bits;
        ULONG AsULONG;
    } u;
} WHEA_PCI_SLOT_NUMBER, *PWHEA_PCI_SLOT_NUMBER;

//
// The following structure describes an XPF platform's non-maskable interrupt
// error source mechanism. The information represented in this structure tells
// the OS how to configure the platform's NMI error source.
//

typedef struct _WHEA_XPF_NMI_DESCRIPTOR {
    USHORT Type;
    BOOLEAN Enabled;
} WHEA_XPF_NMI_DESCRIPTOR, *PWHEA_XPF_NMI_DESCRIPTOR;

//
// The following structure describes a platform's PCI Express AER root port
// error source. The information represented in this structure tells the OS how
// to configure the root port's AER settings.
//

typedef struct _WHEA_AER_ROOTPORT_DESCRIPTOR {
    USHORT Type;
    BOOLEAN Enabled;
    UCHAR Reserved;
    ULONG BusNumber;
    WHEA_PCI_SLOT_NUMBER Slot;
    USHORT DeviceControl;
    AER_ROOTPORT_DESCRIPTOR_FLAGS Flags;
    ULONG UncorrectableErrorMask;
    ULONG UncorrectableErrorSeverity;
    ULONG CorrectableErrorMask;
    ULONG AdvancedCapsAndControl;
    ULONG RootErrorCommand;
} WHEA_AER_ROOTPORT_DESCRIPTOR, *PWHEA_AER_ROOTPORT_DESCRIPTOR;

//
// The following structure describes a platform's PCI Express AER endpoint
// error source. The information represented in this structure tells the OS how
// to configure the device's AER settings.
//

typedef struct _WHEA_AER_ENDPOINT_DESCRIPTOR {
    USHORT Type;
    BOOLEAN Enabled;
    UCHAR Reserved;
    ULONG BusNumber;
    WHEA_PCI_SLOT_NUMBER Slot;
    USHORT DeviceControl;
    AER_ENDPOINT_DESCRIPTOR_FLAGS Flags;
    ULONG UncorrectableErrorMask;
    ULONG UncorrectableErrorSeverity;
    ULONG CorrectableErrorMask;
    ULONG AdvancedCapsAndControl;
} WHEA_AER_ENDPOINT_DESCRIPTOR, *PWHEA_AER_ENDPOINT_DESCRIPTOR;

//
// The following structure describes a platform's PCI Express AER bridge
// error source. The information represented in this structure tells the OS how
// to configure the bridge's AER settings.
//

typedef struct _WHEA_AER_BRIDGE_DESCRIPTOR {
    USHORT Type;
    BOOLEAN Enabled;
    UCHAR Reserved;
    ULONG BusNumber;
    WHEA_PCI_SLOT_NUMBER Slot;
    USHORT DeviceControl;
    AER_BRIDGE_DESCRIPTOR_FLAGS Flags;
    ULONG UncorrectableErrorMask;
    ULONG UncorrectableErrorSeverity;
    ULONG CorrectableErrorMask;
    ULONG AdvancedCapsAndControl;
    ULONG SecondaryUncorrectableErrorMask;
    ULONG SecondaryUncorrectableErrorSev;
    ULONG SecondaryCapsAndControl;
} WHEA_AER_BRIDGE_DESCRIPTOR, *PWHEA_AER_BRIDGE_DESCRIPTOR;

//
// The following structure describes a generic error source to the OS. Using
// the information in this structure the OS is able to configure a handler for
// the generic error source.
//

typedef struct _WHEA_GENERIC_ERROR_DESCRIPTOR {

    //
    // Type is WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_GENERIC.
    //

    USHORT Type;

    //
    // This field is reserved.
    //

    UCHAR Reserved;

    //
    // Indicates whether the generic error source is to be enabled.
    //

    UCHAR Enabled;

    //
    // Length of the error status block.
    //

    ULONG ErrStatusBlockLength;

    //
    // If this generic error source relates back to another error source, keep
    // it's identifier here.
    //

    ULONG RelatedErrorSourceId;

    //
    // The following 5 fields have the same layout as a GEN_ADDR structure. They
    // describe the address at which the OS reads error status information
    // from the error source.
    //

    UCHAR ErrStatusAddressSpaceID;
    UCHAR ErrStatusAddressBitWidth;
    UCHAR ErrStatusAddressBitOffset;
    UCHAR ErrStatusAddressAccessSize;
    WHEA_PHYSICAL_ADDRESS ErrStatusAddress;

    //
    // Notify describes how the generic error source notifies the OS that error
    // information is available.
    //

    WHEA_NOTIFICATION_DESCRIPTOR Notify;

} WHEA_GENERIC_ERROR_DESCRIPTOR, *PWHEA_GENERIC_ERROR_DESCRIPTOR;

typedef struct _WHEA_GENERIC_ERROR_DESCRIPTOR_V2 {

    //
    // Type is WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_GENERIC_V2.
    //

    USHORT Type;

    //
    // This field is reserved.
    //

    UCHAR Reserved;

    //
    // Indicates whether the generic error source is to be enabled.
    //

    UCHAR Enabled;

    //
    // Length of the error status block.
    //

    ULONG ErrStatusBlockLength;

    //
    // If this generic error source relates back to another error source, keep
    // it's identifier here.
    //

    ULONG RelatedErrorSourceId;

    //
    // The following 5 fields have the same layout as a GEN_ADDR structure. They
    // describe the address at which the OS reads error status information
    // from the error source.
    //

    UCHAR ErrStatusAddressSpaceID;
    UCHAR ErrStatusAddressBitWidth;
    UCHAR ErrStatusAddressBitOffset;
    UCHAR ErrStatusAddressAccessSize;
    WHEA_PHYSICAL_ADDRESS ErrStatusAddress;

    //
    // Notify describes how the generic error source notifies the OS that error
    // information is available.
    //

    WHEA_NOTIFICATION_DESCRIPTOR Notify;

    //
    // The following 5 fields have the same layout as a GEN_ADDR structure. They
    // describe the address at which the OS will acknoledge the consumption of the
    // error status block.
    //

    UCHAR ReadAckAddressSpaceID;
    UCHAR ReadAckAddressBitWidth;
    UCHAR ReadAckAddressBitOffset;
    UCHAR ReadAckAddressAccessSize;
    WHEA_PHYSICAL_ADDRESS ReadAckAddress;
    ULONGLONG ReadAckPreserveMask;
    ULONGLONG ReadAckWriteMask;

} WHEA_GENERIC_ERROR_DESCRIPTOR_V2, *PWHEA_GENERIC_ERROR_DESCRIPTOR_V2;

typedef struct _WHEA_DEVICE_DRIVER_DESCRIPTOR {
    USHORT Type;
    BOOLEAN Enabled;
    UCHAR Reserved;
    GUID SourceGuid;
    USHORT LogTag;
    USHORT Reserved2;
    ULONG PacketLength;
    ULONG PacketCount;
    PUCHAR PacketBuffer;
    WHEA_ERROR_SOURCE_CONFIGURATION_DD Config;
    GUID CreatorId;
    GUID PartitionId;
    ULONG MaxSectionDataLength;
    ULONG MaxSectionsPerRecord;
    PUCHAR PacketStateBuffer;
    LONG OpenHandles;
} WHEA_DEVICE_DRIVER_DESCRIPTOR, *PWHEA_DEVICE_DRIVER_DESCRIPTOR;

typedef struct _WHEA_IPF_MCA_DESCRIPTOR {
    USHORT Type;
    UCHAR Enabled;
    UCHAR Reserved;
} WHEA_IPF_MCA_DESCRIPTOR, *PWHEA_IPF_MCA_DESCRIPTOR;

typedef struct _WHEA_IPF_CMC_DESCRIPTOR {
    USHORT Type;
    UCHAR Enabled;
    UCHAR Reserved;
} WHEA_IPF_CMC_DESCRIPTOR, *PWHEA_IPF_CMC_DESCRIPTOR;

typedef struct _WHEA_IPF_CPE_DESCRIPTOR {
    USHORT Type;
    UCHAR Enabled;
    UCHAR Reserved;
} WHEA_IPF_CPE_DESCRIPTOR, *PWHEA_IPF_CPE_DESCRIPTOR;

typedef struct _WHEA_ERROR_SOURCE_DESCRIPTOR {
    ULONG Length;                                              // +00 (0)
    ULONG Version;                                             // +04 (4)
    WHEA_ERROR_SOURCE_TYPE Type;                               // +08 (8)
    WHEA_ERROR_SOURCE_STATE State;                             // +0C (12)
    ULONG MaxRawDataLength;                                    // +10 (16)
    ULONG NumRecordsToPreallocate;                             // +14 (20)
    ULONG MaxSectionsPerRecord;                                // +18 (24)
    ULONG ErrorSourceId;                                       // +1C (28)
    ULONG PlatformErrorSourceId;                               // +20 (32)
    ULONG Flags;                                               // +24 (36)

    union {                                                    // +28 (40)
        WHEA_XPF_MCE_DESCRIPTOR XpfMceDescriptor;
        WHEA_XPF_CMC_DESCRIPTOR XpfCmcDescriptor;
        WHEA_XPF_NMI_DESCRIPTOR XpfNmiDescriptor;
        WHEA_IPF_MCA_DESCRIPTOR IpfMcaDescriptor;
        WHEA_IPF_CMC_DESCRIPTOR IpfCmcDescriptor;
        WHEA_IPF_CPE_DESCRIPTOR IpfCpeDescriptor;
        WHEA_AER_ROOTPORT_DESCRIPTOR AerRootportDescriptor;
        WHEA_AER_ENDPOINT_DESCRIPTOR AerEndpointDescriptor;
        WHEA_AER_BRIDGE_DESCRIPTOR AerBridgeDescriptor;
        WHEA_GENERIC_ERROR_DESCRIPTOR GenErrDescriptor;
        WHEA_GENERIC_ERROR_DESCRIPTOR_V2 GenErrDescriptorV2;
        WHEA_DEVICE_DRIVER_DESCRIPTOR DeviceDriverDescriptor;
    } Info;

} WHEA_ERROR_SOURCE_DESCRIPTOR, *PWHEA_ERROR_SOURCE_DESCRIPTOR;

__inline
BOOLEAN
WheaIsGhesAssistSrc (
    _In_ PWHEA_ERROR_SOURCE_DESCRIPTOR ErrSrc
    )

/*++

Routine Description:

    This routine determines if a error source is providing assistance
    to another.  This check is abstracted to a function due to the logic
    not being obvious upon first pass.  To be a GHES_ASSIST source the source
    must be generic, and have a RelatedErrorSourcedId that is valid.

Arguments:

    ErrSrc - Supplies a pointer to the error source descriptor to be checked.

Return Value:

    True - If the source is providing assistance
    False - If this is a free standing error source

--*/

{
    if ((ErrSrc->Type == WheaErrSrcTypeGeneric) &&
        (ErrSrc->Info.GenErrDescriptor.RelatedErrorSourceId !=
            WHEA_ERROR_SOURCE_INVALID_RELATED_SOURCE)) {

        return TRUE;
    }

    return FALSE;
}

//
// WHEA PFA Policy Type
//

#define    WHEA_DISABLE_OFFLINE                 0
#define    WHEA_MEM_PERSISTOFFLINE              1
#define    WHEA_MEM_PFA_DISABLE                 2
#define    WHEA_MEM_PFA_PAGECOUNT               3
#define    WHEA_MEM_PFA_THRESHOLD               4
#define    WHEA_MEM_PFA_TIMEOUT                 5
#define    WHEA_DISABLE_DUMMY_WRITE             6
#define    WHEA_RESTORE_CMCI_ENABLED            7
#define    WHEA_RESTORE_CMCI_ATTEMPTS           8
#define    WHEA_RESTORE_CMCI_ERR_LIMIT          9
#define    WHEA_CMCI_THRESHOLD_COUNT            10
#define    WHEA_CMCI_THRESHOLD_TIME             11
#define    WHEA_CMCI_THRESHOLD_POLL_COUNT       12
#define    WHEA_PENDING_PAGE_LIST_SZ            13
#define    WHEA_BAD_PAGE_LIST_MAX_SIZE          14
#define    WHEA_BAD_PAGE_LIST_LOCATION          15
#define    WHEA_NOTIFY_ALL_OFFLINES             16
#define    WHEA_ROW_FAIL_CHECK_EXTENT           17
#define    WHEA_ROW_FAIL_CHECK_ENABLE           18
#define    WHEA_ROW_FAIL_CHECK_THRESHOLD        19
#define    WHEA_DISABLE_PRM_ADDRESS_TRANSLATION 20
#define    WHEA_ENABLE_BATCHED_ROW_OFFLINE      21

#define IPMI_OS_SEL_RECORD_SIGNATURE 'RSSO'
#define IPMI_OS_SEL_RECORD_VERSION_1 1
#define IPMI_OS_SEL_RECORD_VERSION IPMI_OS_SEL_RECORD_VERSION_1

#define IPMI_IOCTL_INDEX 0x0400

#define IOCTL_IPMI_INTERNAL_RECORD_SEL_EVENT  CTL_CODE(FILE_DEVICE_UNKNOWN,  \
                                                       IPMI_IOCTL_INDEX + 0, \
                                                       METHOD_BUFFERED,      \
                                                       FILE_ANY_ACCESS)

//
// Enumeration of OS SEL record types.
//

typedef enum _IPMI_OS_SEL_RECORD_TYPE {
    IpmiOsSelRecordTypeWhea = 0,
    IpmiOsSelRecordTypeOther,
    IpmiOsSelRecordTypeWheaErrorXpfMca,
    IpmiOsSelRecordTypeWheaErrorPci,
    IpmiOsSelRecordTypeWheaErrorNmi,
    IpmiOsSelRecordTypeWheaErrorOther,
    IpmiOsSelRecordTypeRaw,
    IpmiOsSelRecordTypeDriver,
    IpmiOsSelRecordTypeBugcheckRecovery,
    IpmiOsSelRecordTypeBugcheckData,
    IpmiOsSelRecordTypeMax
} IPMI_OS_SEL_RECORD_TYPE, *PIPMI_OS_SEL_RECORD_TYPE;

//
// Mask to extract the correct record type from requests using subtypes.
//

#define IPMI_OS_SEL_RECORD_MASK 0xFFFF

//
// This structure represents an OS BMC SEL record.
//

typedef struct _IPMI_OS_SEL_RECORD {
    ULONG Signature;
    ULONG Version;
    ULONG Length;
    IPMI_OS_SEL_RECORD_TYPE RecordType;
    ULONG DataLength;
    UCHAR Data[ANYSIZE_ARRAY];
} IPMI_OS_SEL_RECORD, *PIPMI_OS_SEL_RECORD;

#define IPMI_OS_SEL_RECORD_SIGNATURE 'RSSO'
#define IPMI_OS_SEL_RECORD_VERSION_1 1
#define IPMI_OS_SEL_RECORD_VERSION IPMI_OS_SEL_RECORD_VERSION_1

#define IPMI_IOCTL_INDEX 0x0400

#define IOCTL_IPMI_INTERNAL_RECORD_SEL_EVENT  CTL_CODE(FILE_DEVICE_UNKNOWN,  \
                                                       IPMI_IOCTL_INDEX + 0, \
                                                       METHOD_BUFFERED,      \
                                                       FILE_ANY_ACCESS)

typedef union _DIMM_ADDRESS {

    //
    // DDR4 Address
    //

    struct {
        UINT64 SocketId : 4;            // 16 Sockets
        UINT64 MemoryControllerId : 2;  // 4 Memory Controllers
        UINT64 ChannelId : 2;           // 4 Channels
        UINT64 DimmSlot : 2;            // 3 DIMMs
        UINT64 DimmRank : 2;            // 4 Ranks
        UINT64 Device : 5;              // 18 Devices
        UINT64 ChipSelect : 3;          // 8 Chip IDs
        UINT64 Bank : 8;                // 16 Banks-includes BankGroup and Bank
        UINT64 Dq : 4;                  // 16 DQs
        UINT64 Reserved : 32;
        UINT32 Row;
        UINT32 Column;
        UINT64 Info;
    } Ddr4;

    //
    // DDR5 Address
    //

    struct {
        UINT64 SocketId : 5;            // Up to 32 Sockets
        UINT64 MemoryControllerId : 4;  // Up to 16 Memory Controllers/Socket
        UINT64 ChannelId : 3;           // Up to 8 Channels/Memory Controller
        UINT64 SubChannelId : 2;        // 4 Subchannels/Channel
        UINT64 DimmSlot : 2;            // Up to 4 DIMMs/(Subchannel/Channel)
        UINT64 DimmRank : 4;            // Up to 16 Electrical ranks/DIMM
        UINT64 Device : 6;              // Up to 64 Devices/Electrical rank
        UINT64 ChipId : 4;              // Up to 16 Chip IDs/DRAM Device
        UINT64 Bank : 8;                // 256 Banks-includes BankGroup and Bank
        UINT64 Dq : 5;                  // 32 DQs
        UINT64 Reserved : 21;
        UINT32 Row;                     // Up to 18 Row Bits
        UINT32 Column;                  // Up to 11 Column Bits
        UINT64 Info;
    } Ddr5;
} DIMM_ADDRESS, *PDIMM_ADDRESS;

typedef enum _PAGE_OFFLINE_ERROR_TYPES {
    BitErrorDdr4,
    RowErrorDdr4,
    BitErrorDdr5,
    RowErrorDdr5
} PAGE_OFFLINE_ERROR_TYPES, *PPAGE_OFFLINE_ERROR_TYPES;

typedef union _PAGE_OFFLINE_VALID_BITS {
    struct {
        UINT8 PhysicalAddress: 1;
        UINT8 MemDefect: 1;
        UINT8 Reserved: 6;
    };

    UINT8 AsUINT8;
} PAGE_OFFLINE_VALID_BITS, *PPAGE_OFFLINE_VALID_BITS;

typedef struct _DIMM_ADDR_VALID_BITS_DDR4 {
    UINT32 SocketId: 1;
    UINT32 MemoryControllerId: 1;
    UINT32 ChannelId: 1;
    UINT32 DimmSlot: 1;
    UINT32 DimmRank: 1;
    UINT32 Device: 1;
    UINT32 ChipSelect: 1;
    UINT32 Bank: 1;
    UINT32 Dq: 1;
    UINT32 Row: 1;
    UINT32 Column: 1;
    UINT32 Info: 1;
    UINT32 Reserved: 20;
} DIMM_ADDR_VALID_BITS_DDR4, *PDIMM_ADDR_VALID_BITS_DDR4;

typedef struct _DIMM_ADDR_VALID_BITS_DDR5 {
    UINT32 SocketId : 1;
    UINT32 MemoryControllerId : 1;
    UINT32 ChannelId : 1;
    UINT32 SubChannelId : 1;
    UINT32 DimmSlot : 1;
    UINT32 DimmRank : 1;
    UINT32 Device : 1;
    UINT32 ChipId : 1;
    UINT32 Bank : 1;
    UINT32 Dq : 1;
    UINT32 Row : 1;
    UINT32 Column : 1;
    UINT32 Info : 1;
    UINT32 Reserved : 19;
} DIMM_ADDR_VALID_BITS_DDR5, *PDIMM_ADDR_VALID_BITS_DDR5;

typedef union _DIMM_ADDR_VALID_BITS {
    DIMM_ADDR_VALID_BITS_DDR4 VB_DDR4;
    DIMM_ADDR_VALID_BITS_DDR5 VB_DDR5;
    UINT32 AsUINT32;
} DIMM_ADDR_VALID_BITS, *PDIMM_ADDR_VALID_BITS;

typedef struct _DIMM_INFO {
    DIMM_ADDRESS DimmAddress;
    DIMM_ADDR_VALID_BITS ValidBits;
} DIMM_INFO, *PDIMM_INFO;

typedef struct _MEMORY_DEFECT {
    UINT32 Version;
    DIMM_INFO DimmInfo;
    PAGE_OFFLINE_ERROR_TYPES ErrType;
} MEMORY_DEFECT, * PMEMORY_DEFECT;

#include <poppack.h>


//
// The general format of the common platform error record is illustrated below.
// A record consists of a header; followed by one or more section descriptors;
// and for each descriptor, an associated section which may contain either error
// or informational data.
//
// The record may include extra buffer space to allow for the dynamic addition
// of error sections descriptors and bodies, as well as for dynamically
// increasing the size of existing sections.
//
// +---------------------------------------------+
// | Record Header                               |
// |   SectionCount == N                         |
// +---------------------------------------------+
// | Section Descriptor 1                        |
// |   Offset, size                              | ---+
// +---------------------------------------------+    |
// | Section Descriptor 2                        |    |
// |   Offset, size                              | ---+---+
// +---------------------------------------------+    |   |
// |                                             |    |   |
// | ....                                        |    |   |
// |                                             |    |   |
// +---------------------------------------------+    |   |
// | Section Descriptor N                        | ---+---+---+
// |   Offset, size                              |    |   |   |
// +---------------------------------------------+    |   |   |
// |                     Buffer space for adding |    |   |   |
// |                   more section descriptors. |    |   |   |
// +---------------------------------------------|    |   |   |
// | Section 1                                   | <--+   |   |
// |                                             |        |   |
// +---------------------------------------------+        |   |
// | Section 2                                   | <------+   |
// |                                             |            |
// +---------------------------------------------+            |
// |                                             |            |
// |                                             |            |
// | ....                                        |            |
// |                                             |            |
// |                                             |            |
// +---------------------------------------------+            |
// | Section N                                   | <----------+
// |                                             |
// +---------------------------------------------+
// |                                             |
// |                                             |
// |                                             |
// |                     Buffer space for adding |
// |                        more section bodies. |
// |                                             |
// |                                             |
// |                                             |
// +---------------------------------------------+
//

// -------------------------------------------- Specification validation macros

//
// The following macro implements a compile-time check for the offset and length
// of the specified structure member. This can be used to validate the defined
// structures against the specification.
//

#define CPER_FIELD_CHECK(type, field, offset, length) \
    C_ASSERT(((FIELD_OFFSET(type, field) == (offset)) && \
              (RTL_FIELD_SIZE(type, field) == (length))))

#include <pshpack1.h>

//------------------------------------------ Common Platform Error Record types

//
// These types are used in several of the common platform error record
// structures.
//

typedef union _WHEA_REVISION {
    struct {
        UCHAR MinorRevision;
        UCHAR MajorRevision;
    } DUMMYSTRUCTNAME;
    USHORT AsUSHORT;
} WHEA_REVISION, *PWHEA_REVISION;

typedef enum _WHEA_ERROR_SEVERITY {
    WheaErrSevRecoverable   = 0,
    WheaErrSevFatal         = 1,
    WheaErrSevCorrected     = 2,
    WheaErrSevInformational = 3
} WHEA_ERROR_SEVERITY, *PWHEA_ERROR_SEVERITY;

typedef union _WHEA_TIMESTAMP {
    struct {
        ULONGLONG Seconds:8;
        ULONGLONG Minutes:8;
        ULONGLONG Hours:8;
        ULONGLONG Precise:1;
        ULONGLONG Reserved:7;
        ULONGLONG Day:8;
        ULONGLONG Month:8;
        ULONGLONG Year:8;
        ULONGLONG Century:8;
    } DUMMYSTRUCTNAME;
    LARGE_INTEGER AsLARGE_INTEGER;
} WHEA_TIMESTAMP, *PWHEA_TIMESTAMP;

typedef union _WHEA_PERSISTENCE_INFO {
    struct {
        ULONGLONG Signature:16;
        ULONGLONG Length:24;
        ULONGLONG Identifier:16;
        ULONGLONG Attributes:2;
        ULONGLONG DoNotLog:1;
        ULONGLONG Reserved:5;
    } DUMMYSTRUCTNAME;
    ULONGLONG AsULONGLONG;
} WHEA_PERSISTENCE_INFO, *PWHEA_PERSISTENCE_INFO;

#define ERRTYP_INTERNAL                 0x01 // 1
#define ERRTYP_BUS                      0x10 // 16
#define ERRTYP_MEM                      0x04 // 4
#define ERRTYP_TLB                      0x05 // 5
#define ERRTYP_CACHE                    0x06 // 6
#define ERRTYP_FUNCTION                 0x07 // 7
#define ERRTYP_SELFTEST                 0x08 // 8
#define ERRTYP_FLOW                     0x09 // 9
#define ERRTYP_MAP                      0x11 // 17
#define ERRTYP_IMPROPER                 0x12 // 18
#define ERRTYP_UNIMPL                   0x13 // 19
#define ERRTYP_LOSSOFLOCKSTEP           0x14 // 20
#define ERRTYP_RESPONSE                 0x15 // 21
#define ERRTYP_PARITY                   0x16 // 22
#define ERRTYP_PROTOCOL                 0x17 // 23
#define ERRTYP_PATHERROR                0x18 // 24
#define ERRTYP_TIMEOUT                  0x19 // 25
#define ERRTYP_POISONED                 0x1A // 26

typedef union _WHEA_ERROR_STATUS {
    ULONGLONG ErrorStatus;
    struct {
        ULONGLONG Reserved1:8;
        ULONGLONG ErrorType:8;
        ULONGLONG Address:1;
        ULONGLONG Control:1;
        ULONGLONG Data:1;
        ULONGLONG Responder:1;
        ULONGLONG Requester:1;
        ULONGLONG FirstError:1;
        ULONGLONG Overflow:1;
        ULONGLONG Reserved2:41;
    } DUMMYSTRUCTNAME;
} WHEA_ERROR_STATUS, *PWHEA_ERROR_STATUS;

//---------------------------------------------------- WHEA_ERROR_RECORD_HEADER

typedef union _WHEA_ERROR_RECORD_HEADER_VALIDBITS {
    struct {
        ULONG PlatformId:1;
        ULONG Timestamp:1;
        ULONG PartitionId:1;
        ULONG Reserved:29;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_ERROR_RECORD_HEADER_VALIDBITS, *PWHEA_ERROR_RECORD_HEADER_VALIDBITS;

#define WHEA_ERROR_RECORD_VALID_PLATFORMID           0x00000001
#define WHEA_ERROR_RECORD_VALID_TIMESTAMP            0x00000002
#define WHEA_ERROR_RECORD_VALID_PARTITIONID          0x00000004

typedef union _WHEA_ERROR_RECORD_HEADER_FLAGS {
    struct {
        ULONG Recovered:1;
        ULONG PreviousError:1;
        ULONG Simulated:1;
        ULONG DeviceDriver:1;
        ULONG CriticalEvent:1;
        ULONG PersistPfn:1;
        ULONG SectionsTruncated:1;
        ULONG RecoveryInProgress:1;
        ULONG Throttle:1;
        ULONG Reserved:23;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_ERROR_RECORD_HEADER_FLAGS, *PWHEA_ERROR_RECORD_HEADER_FLAGS;

#define WHEA_ERROR_RECORD_FLAGS_RECOVERED            0x00000001
#define WHEA_ERROR_RECORD_FLAGS_PREVIOUSERROR        0x00000002
#define WHEA_ERROR_RECORD_FLAGS_SIMULATED            0x00000004
#define WHEA_ERROR_RECORD_FLAGS_DEVICE_DRIVER        0x00000008

typedef struct _WHEA_ERROR_RECORD_HEADER {
    ULONG Signature;
    WHEA_REVISION Revision;
    ULONG SignatureEnd;
    USHORT SectionCount;
    WHEA_ERROR_SEVERITY Severity;
    WHEA_ERROR_RECORD_HEADER_VALIDBITS ValidBits;
    _Field_range_(>=, (sizeof(WHEA_ERROR_RECORD_HEADER)
                       + (SectionCount
                          * sizeof(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR))))
        ULONG Length;
    WHEA_TIMESTAMP Timestamp;
    GUID PlatformId;
    GUID PartitionId;
    GUID CreatorId;
    GUID NotifyType;
    ULONGLONG RecordId;
    WHEA_ERROR_RECORD_HEADER_FLAGS Flags;
    WHEA_PERSISTENCE_INFO PersistenceInfo;
    union {
        struct {
            ULONG OsBuildNumber; // Pupulated by AzPshedPi, not in vanilla windows
            UCHAR Reserved2[8];
        };

        UCHAR Reserved[12];
    };
} WHEA_ERROR_RECORD_HEADER, *PWHEA_ERROR_RECORD_HEADER;

//
// Distinguished values used in the common platform error record header
// signature.
//

#define WHEA_ERROR_RECORD_SIGNATURE         'REPC'
#define WHEA_ERROR_RECORD_REVISION          0x0210
#define WHEA_ERROR_RECORD_SIGNATURE_END     0xFFFFFFFF

//
// Validate the error record header structure against the definitions in the
// UEFI specification.
//

CPER_FIELD_CHECK(WHEA_ERROR_RECORD_HEADER, Signature,         0,  4);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_HEADER, Revision,          4,  2);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_HEADER, SignatureEnd,      6,  4);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_HEADER, SectionCount,     10,  2);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_HEADER, Severity,         12,  4);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_HEADER, ValidBits,        16,  4);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_HEADER, Length,           20,  4);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_HEADER, Timestamp,        24,  8);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_HEADER, PlatformId,       32, 16);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_HEADER, PartitionId,      48, 16);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_HEADER, CreatorId,        64, 16);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_HEADER, NotifyType,       80, 16);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_HEADER, RecordId,         96,  8);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_HEADER, Flags,           104,  4);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_HEADER, PersistenceInfo, 108,  8);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_HEADER, Reserved,        116, 12);

//---------------------------------------- WHEA_ERROR_RECORD_SECTION_DESCRIPTOR

typedef union _WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS {
    struct {
        ULONG Primary:1;
        ULONG ContainmentWarning:1;
        ULONG Reset:1;
        ULONG ThresholdExceeded:1;
        ULONG ResourceNotAvailable:1;
        ULONG LatentError:1;
        ULONG Propagated:1;
        ULONG FruTextByPlugin:1;
        ULONG Reserved:24;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS,
    *PWHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS;

#define WHEA_SECTION_DESCRIPTOR_FLAGS_PRIMARY            0x00000001
#define WHEA_SECTION_DESCRIPTOR_FLAGS_CONTAINMENTWRN     0x00000002
#define WHEA_SECTION_DESCRIPTOR_FLAGS_RESET              0x00000004
#define WHEA_SECTION_DESCRIPTOR_FLAGS_THRESHOLDEXCEEDED  0x00000008
#define WHEA_SECTION_DESCRIPTOR_FLAGS_RESOURCENA         0x00000010
#define WHEA_SECTION_DESCRIPTOR_FLAGS_LATENTERROR        0x00000020
#define WHEA_SECTION_DESCRIPTOR_FLAGS_PROPAGATED         0x00000040
#define WHEA_SECTION_DESCRIPTOR_FLAGS_FRU_TEXT_BY_PLUGIN 0x00000080

typedef union _WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS {
    struct {
        UCHAR FRUId:1;
        UCHAR FRUText:1;
        UCHAR Reserved:6;
    } DUMMYSTRUCTNAME;
    UCHAR AsUCHAR;
} WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS,
    *PWHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS;

typedef struct _WHEA_ERROR_RECORD_SECTION_DESCRIPTOR {
    ULONG SectionOffset;
    ULONG SectionLength;
    WHEA_REVISION Revision;
    WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS ValidBits;
    UCHAR Reserved;
    WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS Flags;
    GUID SectionType;
    GUID FRUId;
    WHEA_ERROR_SEVERITY SectionSeverity;
    CCHAR FRUText[20];
} WHEA_ERROR_RECORD_SECTION_DESCRIPTOR, *PWHEA_ERROR_RECORD_SECTION_DESCRIPTOR;

#define WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_REVISION   0x0300

//
// Validate the error record section descriptor structure against the
// definitions in the UEFI specification.
//

CPER_FIELD_CHECK(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR, SectionOffset,    0,  4);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR, SectionLength,    4,  4);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR, Revision,         8,  2);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR, ValidBits,       10,  1);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR, Reserved,        11,  1);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR, Flags,           12,  4);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR, SectionType,     16, 16);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR, FRUId,           32, 16);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR, SectionSeverity, 48,  4);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR, FRUText,         52, 20);

//----------------------------------------------------------- WHEA_ERROR_RECORD

typedef _Struct_size_bytes_(Header.Length) struct _WHEA_ERROR_RECORD {
    WHEA_ERROR_RECORD_HEADER Header;
    _Field_size_(Header.SectionCount)
        WHEA_ERROR_RECORD_SECTION_DESCRIPTOR SectionDescriptor[ANYSIZE_ARRAY];
} WHEA_ERROR_RECORD, *PWHEA_ERROR_RECORD;

//
// Validate the error record structure against the definitions in the UEFI
// specification.
//

CPER_FIELD_CHECK(WHEA_ERROR_RECORD, Header,              0,  128);
CPER_FIELD_CHECK(WHEA_ERROR_RECORD, SectionDescriptor, 128,   72);

//---------------------------------------- WHEA_PROCESSOR_GENERIC_ERROR_SECTION

#define GENPROC_PROCTYPE_XPF                 0
#define GENPROC_PROCTYPE_IPF                 1
#define GENPROC_PROCTYPE_ARM                 2

#define GENPROC_PROCISA_X86                  0
#define GENPROC_PROCISA_IPF                  1
#define GENPROC_PROCISA_X64                  2
#define GENPROC_PROCISA_ARM32                4
#define GENPROC_PROCISA_ARM64                8

#define GENPROC_PROCERRTYPE_UNKNOWN          0
#define GENPROC_PROCERRTYPE_CACHE            1
#define GENPROC_PROCERRTYPE_TLB              2
#define GENPROC_PROCERRTYPE_BUS              4
#define GENPROC_PROCERRTYPE_MAE              8

#define GENPROC_OP_GENERIC                   0
#define GENPROC_OP_DATAREAD                  1
#define GENPROC_OP_DATAWRITE                 2
#define GENPROC_OP_INSTRUCTIONEXE            3

#define GENPROC_FLAGS_RESTARTABLE            0x01
#define GENPROC_FLAGS_PRECISEIP              0x02
#define GENPROC_FLAGS_OVERFLOW               0x04
#define GENPROC_FLAGS_CORRECTED              0x08

typedef union _WHEA_PROCESSOR_FAMILY_INFO {
    struct {
        ULONG Stepping:4;
        ULONG Model:4;
        ULONG Family:4;
        ULONG ProcessorType:2;
        ULONG Reserved1:2;
        ULONG ExtendedModel:4;
        ULONG ExtendedFamily:8;
        ULONG Reserved2:4;
        ULONG NativeModelId;
    } DUMMYSTRUCTNAME;
    ULONGLONG AsULONGLONG;
} WHEA_PROCESSOR_FAMILY_INFO, *PWHEA_PROCESSOR_FAMILY_INFO;

typedef union _WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS {
    struct {
        ULONGLONG ProcessorType:1;
        ULONGLONG InstructionSet:1;
        ULONGLONG ErrorType:1;
        ULONGLONG Operation:1;
        ULONGLONG Flags:1;
        ULONGLONG Level:1;
        ULONGLONG CPUVersion:1;
        ULONGLONG CPUBrandString:1;
        ULONGLONG ProcessorId:1;
        ULONGLONG TargetAddress:1;
        ULONGLONG RequesterId:1;
        ULONGLONG ResponderId:1;
        ULONGLONG InstructionPointer:1;
        ULONGLONG NativeModelId:1;
        ULONGLONG Reserved:50;
    } DUMMYSTRUCTNAME;
    ULONGLONG ValidBits;
} WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS,
  *PWHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS;

typedef struct _WHEA_PROCESSOR_GENERIC_ERROR_SECTION {
    WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS ValidBits;
    UCHAR ProcessorType;
    UCHAR InstructionSet;
    UCHAR ErrorType;
    UCHAR Operation;
    UCHAR Flags;
    UCHAR Level;
    USHORT Reserved;
    ULONGLONG CPUVersion;
    UCHAR CPUBrandString[128];
    ULONGLONG ProcessorId;
    ULONGLONG TargetAddress;
    ULONGLONG RequesterId;
    ULONGLONG ResponderId;
    ULONGLONG InstructionPointer;
} WHEA_PROCESSOR_GENERIC_ERROR_SECTION, *PWHEA_PROCESSOR_GENERIC_ERROR_SECTION;

//
// Validate the processor generic error section structure against the
// definitions in the UEFI  specification.
//

CPER_FIELD_CHECK(WHEA_PROCESSOR_GENERIC_ERROR_SECTION, ValidBits,            0,   8);
CPER_FIELD_CHECK(WHEA_PROCESSOR_GENERIC_ERROR_SECTION, ProcessorType,        8,   1);
CPER_FIELD_CHECK(WHEA_PROCESSOR_GENERIC_ERROR_SECTION, InstructionSet,       9,   1);
CPER_FIELD_CHECK(WHEA_PROCESSOR_GENERIC_ERROR_SECTION, ErrorType,           10,   1);
CPER_FIELD_CHECK(WHEA_PROCESSOR_GENERIC_ERROR_SECTION, Operation,           11,   1);
CPER_FIELD_CHECK(WHEA_PROCESSOR_GENERIC_ERROR_SECTION, Flags,               12,   1);
CPER_FIELD_CHECK(WHEA_PROCESSOR_GENERIC_ERROR_SECTION, Level,               13,   1);
CPER_FIELD_CHECK(WHEA_PROCESSOR_GENERIC_ERROR_SECTION, Reserved,            14,   2);
CPER_FIELD_CHECK(WHEA_PROCESSOR_GENERIC_ERROR_SECTION, CPUVersion,          16,   8);
CPER_FIELD_CHECK(WHEA_PROCESSOR_GENERIC_ERROR_SECTION, CPUBrandString,      24, 128);
CPER_FIELD_CHECK(WHEA_PROCESSOR_GENERIC_ERROR_SECTION, ProcessorId,        152,   8);
CPER_FIELD_CHECK(WHEA_PROCESSOR_GENERIC_ERROR_SECTION, TargetAddress,      160,   8);
CPER_FIELD_CHECK(WHEA_PROCESSOR_GENERIC_ERROR_SECTION, RequesterId,        168,   8);
CPER_FIELD_CHECK(WHEA_PROCESSOR_GENERIC_ERROR_SECTION, ResponderId,        176,   8);
CPER_FIELD_CHECK(WHEA_PROCESSOR_GENERIC_ERROR_SECTION, InstructionPointer, 184,   8);

//-------------------------------------------- WHEA_XPF_PROCESSOR_ERROR_SECTION

//
// x86/x64 cache check structure.
//

#define XPF_CACHE_CHECK_TRANSACTIONTYPE_INSTRUCTION     0
#define XPF_CACHE_CHECK_TRANSACTIONTYPE_DATAACCESS      1
#define XPF_CACHE_CHECK_TRANSACTIONTYPE_GENERIC         2

#define XPF_CACHE_CHECK_OPERATION_GENERIC               0
#define XPF_CACHE_CHECK_OPERATION_GENREAD               1
#define XPF_CACHE_CHECK_OPERATION_GENWRITE              2
#define XPF_CACHE_CHECK_OPERATION_DATAREAD              3
#define XPF_CACHE_CHECK_OPERATION_DATAWRITE             4
#define XPF_CACHE_CHECK_OPERATION_INSTRUCTIONFETCH      5
#define XPF_CACHE_CHECK_OPERATION_PREFETCH              6
#define XPF_CACHE_CHECK_OPERATION_EVICTION              7
#define XPF_CACHE_CHECK_OPERATION_SNOOP                 8

typedef union _WHEA_XPF_CACHE_CHECK {
    struct {
        ULONGLONG TransactionTypeValid:1;
        ULONGLONG OperationValid:1;
        ULONGLONG LevelValid:1;
        ULONGLONG ProcessorContextCorruptValid:1;
        ULONGLONG UncorrectedValid:1;
        ULONGLONG PreciseIPValid:1;
        ULONGLONG RestartableIPValid:1;
        ULONGLONG OverflowValid:1;
        ULONGLONG ReservedValid:8;

        ULONGLONG TransactionType:2;
        ULONGLONG Operation:4;
        ULONGLONG Level:3;
        ULONGLONG ProcessorContextCorrupt:1;
        ULONGLONG Uncorrected:1;
        ULONGLONG PreciseIP:1;
        ULONGLONG RestartableIP:1;
        ULONGLONG Overflow:1;

        ULONGLONG Reserved:34;
    } DUMMYSTRUCTNAME;
    ULONGLONG XpfCacheCheck;
} WHEA_XPF_CACHE_CHECK, *PWHEA_XPF_CACHE_CHECK;

//
// x86/x64 TLB check structure.
//

#define XPF_TLB_CHECK_TRANSACTIONTYPE_INSTRUCTION     0
#define XPF_TLB_CHECK_TRANSACTIONTYPE_DATAACCESS      1
#define XPF_TLB_CHECK_TRANSACTIONTYPE_GENERIC         2

#define XPF_TLB_CHECK_OPERATION_GENERIC               0
#define XPF_TLB_CHECK_OPERATION_GENREAD               1
#define XPF_TLB_CHECK_OPERATION_GENWRITE              2
#define XPF_TLB_CHECK_OPERATION_DATAREAD              3
#define XPF_TLB_CHECK_OPERATION_DATAWRITE             4
#define XPF_TLB_CHECK_OPERATION_INSTRUCTIONFETCH      5
#define XPF_TLB_CHECK_OPERATION_PREFETCH              6

typedef union _WHEA_XPF_TLB_CHECK {
    struct {
        ULONGLONG TransactionTypeValid:1;
        ULONGLONG OperationValid:1;
        ULONGLONG LevelValid:1;
        ULONGLONG ProcessorContextCorruptValid:1;
        ULONGLONG UncorrectedValid:1;
        ULONGLONG PreciseIPValid:1;
        ULONGLONG RestartableIPValid:1;
        ULONGLONG OverflowValid:1;
        ULONGLONG ReservedValid:8;

        ULONGLONG TransactionType:2;
        ULONGLONG Operation:4;
        ULONGLONG Level:3;
        ULONGLONG ProcessorContextCorrupt:1;
        ULONGLONG Uncorrected:1;
        ULONGLONG PreciseIP:1;
        ULONGLONG RestartableIP:1;
        ULONGLONG Overflow:1;
        ULONGLONG Reserved:34;
    } DUMMYSTRUCTNAME;
    ULONGLONG XpfTLBCheck;
} WHEA_XPF_TLB_CHECK, *PWHEA_XPF_TLB_CHECK;

//
// x86/x64 bus check structure.
//

#define XPF_BUS_CHECK_TRANSACTIONTYPE_INSTRUCTION     0
#define XPF_BUS_CHECK_TRANSACTIONTYPE_DATAACCESS      1
#define XPF_BUS_CHECK_TRANSACTIONTYPE_GENERIC         2

#define XPF_BUS_CHECK_OPERATION_GENERIC               0
#define XPF_BUS_CHECK_OPERATION_GENREAD               1
#define XPF_BUS_CHECK_OPERATION_GENWRITE              2
#define XPF_BUS_CHECK_OPERATION_DATAREAD              3
#define XPF_BUS_CHECK_OPERATION_DATAWRITE             4
#define XPF_BUS_CHECK_OPERATION_INSTRUCTIONFETCH      5
#define XPF_BUS_CHECK_OPERATION_PREFETCH              6

#define XPF_BUS_CHECK_PARTICIPATION_PROCORIGINATED    0
#define XPF_BUS_CHECK_PARTICIPATION_PROCRESPONDED     1
#define XPF_BUS_CHECK_PARTICIPATION_PROCOBSERVED      2
#define XPF_BUS_CHECK_PARTICIPATION_GENERIC           3

#define XPF_BUS_CHECK_ADDRESS_MEMORY                  0
#define XPF_BUS_CHECK_ADDRESS_RESERVED                1
#define XPF_BUS_CHECK_ADDRESS_IO                      2
#define XPF_BUS_CHECK_ADDRESS_OTHER                   3

typedef union _WHEA_XPF_BUS_CHECK {
    struct {
        ULONGLONG TransactionTypeValid:1;
        ULONGLONG OperationValid:1;
        ULONGLONG LevelValid:1;
        ULONGLONG ProcessorContextCorruptValid:1;
        ULONGLONG UncorrectedValid:1;
        ULONGLONG PreciseIPValid:1;
        ULONGLONG RestartableIPValid:1;
        ULONGLONG OverflowValid:1;
        ULONGLONG ParticipationValid:1;
        ULONGLONG TimeoutValid:1;
        ULONGLONG AddressSpaceValid:1;
        ULONGLONG ReservedValid:5;

        ULONGLONG TransactionType:2;
        ULONGLONG Operation:4;
        ULONGLONG Level:3;
        ULONGLONG ProcessorContextCorrupt:1;
        ULONGLONG Uncorrected:1;
        ULONGLONG PreciseIP:1;
        ULONGLONG RestartableIP:1;
        ULONGLONG Overflow:1;
        ULONGLONG Participation:2;
        ULONGLONG Timeout:1;
        ULONGLONG AddressSpace:2;
        ULONGLONG Reserved:29;
    } DUMMYSTRUCTNAME;
    ULONGLONG XpfBusCheck;
} WHEA_XPF_BUS_CHECK, *PWHEA_XPF_BUS_CHECK;

//
// x86/x64 micro-architecture specific check structure.
//

#define XPF_MS_CHECK_ERRORTYPE_NOERROR               0
#define XPF_MS_CHECK_ERRORTYPE_UNCLASSIFIED          1
#define XPF_MS_CHECK_ERRORTYPE_MCROMPARITY           2
#define XPF_MS_CHECK_ERRORTYPE_EXTERNAL              3
#define XPF_MS_CHECK_ERRORTYPE_FRC                   4
#define XPF_MS_CHECK_ERRORTYPE_INTERNALUNCLASSIFIED  5

typedef union _WHEA_XPF_MS_CHECK {
    struct {
        ULONGLONG ErrorTypeValid:1;
        ULONGLONG ProcessorContextCorruptValid:1;
        ULONGLONG UncorrectedValid:1;
        ULONGLONG PreciseIPValid:1;
        ULONGLONG RestartableIPValid:1;
        ULONGLONG OverflowValid:1;
        ULONGLONG ReservedValue:10;

        ULONGLONG ErrorType:3;
        ULONGLONG ProcessorContextCorrupt:1;
        ULONGLONG Uncorrected:1;
        ULONGLONG PreciseIP:1;
        ULONGLONG RestartableIP:1;
        ULONGLONG Overflow:1;
        ULONGLONG Reserved:40;
    } DUMMYSTRUCTNAME;
    ULONGLONG XpfMsCheck;
} WHEA_XPF_MS_CHECK, *PWHEA_XPF_MS_CHECK;

//
// x86/x64 Processor Error Information Structure.
//

typedef union _WHEA_XPF_PROCINFO_VALIDBITS {
    struct {
        ULONGLONG CheckInfo:1;
        ULONGLONG TargetId:1;
        ULONGLONG RequesterId:1;
        ULONGLONG ResponderId:1;
        ULONGLONG InstructionPointer:1;
        ULONGLONG Reserved:59;
    } DUMMYSTRUCTNAME;
    ULONGLONG ValidBits;
} WHEA_XPF_PROCINFO_VALIDBITS, *PWHEA_XPF_PROCINFO_VALIDBITS;

typedef struct _WHEA_XPF_PROCINFO {
    GUID CheckInfoId;
    WHEA_XPF_PROCINFO_VALIDBITS ValidBits;
    union {
        WHEA_XPF_CACHE_CHECK CacheCheck;
        WHEA_XPF_TLB_CHECK TlbCheck;
        WHEA_XPF_BUS_CHECK BusCheck;
        WHEA_XPF_MS_CHECK MsCheck;
        ULONGLONG AsULONGLONG;
    } CheckInfo;
    ULONGLONG TargetId;
    ULONGLONG RequesterId;
    ULONGLONG ResponderId;
    ULONGLONG InstructionPointer;
} WHEA_XPF_PROCINFO, *PWHEA_XPF_PROCINFO;

//
// x86/x64 Processor Context Information Structure.
//

typedef struct _WHEA_X86_REGISTER_STATE {
    ULONG Eax;
    ULONG Ebx;
    ULONG Ecx;
    ULONG Edx;
    ULONG Esi;
    ULONG Edi;
    ULONG Ebp;
    ULONG Esp;
    USHORT Cs;
    USHORT Ds;
    USHORT Ss;
    USHORT Es;
    USHORT Fs;
    USHORT Gs;
    ULONG Eflags;
    ULONG Eip;
    ULONG Cr0;
    ULONG Cr1;
    ULONG Cr2;
    ULONG Cr3;
    ULONG Cr4;
    ULONGLONG Gdtr;
    ULONGLONG Idtr;
    USHORT Ldtr;
    USHORT Tr;
} WHEA_X86_REGISTER_STATE, *PWHEA_X86_REGISTER_STATE;

typedef struct DECLSPEC_ALIGN(16) _WHEA128A {
    ULONGLONG Low;
    LONGLONG High;
} WHEA128A, *PWHEA128A;

typedef struct _WHEA_X64_REGISTER_STATE {
    ULONGLONG Rax;
    ULONGLONG Rbx;
    ULONGLONG Rcx;
    ULONGLONG Rdx;
    ULONGLONG Rsi;
    ULONGLONG Rdi;
    ULONGLONG Rbp;
    ULONGLONG Rsp;
    ULONGLONG R8;
    ULONGLONG R9;
    ULONGLONG R10;
    ULONGLONG R11;
    ULONGLONG R12;
    ULONGLONG R13;
    ULONGLONG R14;
    ULONGLONG R15;
    USHORT Cs;
    USHORT Ds;
    USHORT Ss;
    USHORT Es;
    USHORT Fs;
    USHORT Gs;
    ULONG Reserved;
    ULONGLONG Rflags;
    ULONGLONG Eip;
    ULONGLONG Cr0;
    ULONGLONG Cr1;
    ULONGLONG Cr2;
    ULONGLONG Cr3;
    ULONGLONG Cr4;
    ULONGLONG Cr8;
    WHEA128A Gdtr;
    WHEA128A Idtr;
    USHORT Ldtr;
    USHORT Tr;
} WHEA_X64_REGISTER_STATE, *PWHEA_X64_REGISTER_STATE;

#define XPF_CONTEXT_INFO_UNCLASSIFIEDDATA       0
#define XPF_CONTEXT_INFO_MSRREGISTERS           1
#define XPF_CONTEXT_INFO_32BITCONTEXT           2
#define XPF_CONTEXT_INFO_64BITCONTEXT           3
#define XPF_CONTEXT_INFO_FXSAVE                 4
#define XPF_CONTEXT_INFO_32BITDEBUGREGS         5
#define XPF_CONTEXT_INFO_64BITDEBUGREGS         6
#define XPF_CONTEXT_INFO_MMREGISTERS            7

typedef struct _WHEA_XPF_CONTEXT_INFO {
    USHORT RegisterContextType;
    USHORT RegisterDataSize;
    ULONG MSRAddress;
    ULONGLONG MmRegisterAddress;

    //
    // UCHAR RegisterData[ANYSIZE_ARRAY];
    //

} WHEA_XPF_CONTEXT_INFO, *PWHEA_XPF_CONTEXT_INFO;

//
// x86/x64 Processor Error Section
//

typedef union _WHEA_XPF_PROCESSOR_ERROR_SECTION_VALIDBITS {
    struct {
        ULONGLONG LocalAPICId:1;
        ULONGLONG CpuId:1;
        ULONGLONG ProcInfoCount:6;
        ULONGLONG ContextInfoCount:6;
        ULONGLONG Reserved:50;
    } DUMMYSTRUCTNAME;
    ULONGLONG ValidBits;
} WHEA_XPF_PROCESSOR_ERROR_SECTION_VALIDBITS,
  *PWHEA_XPF_PROCESSOR_ERROR_SECTION_VALIDBITS;

typedef struct _WHEA_XPF_PROCESSOR_ERROR_SECTION {
    WHEA_XPF_PROCESSOR_ERROR_SECTION_VALIDBITS ValidBits;
    ULONGLONG LocalAPICId;
    UCHAR CpuId[48];

    //
    // WHEA_XPF_PROCINFO ProcInfo[ANYSIZE_ARRAY];
    // WHEA_XPF_CONTEXT_INFO ContextInfo[ANYSIZE_ARRAY];
    //

    UCHAR VariableInfo[ANYSIZE_ARRAY];
} WHEA_XPF_PROCESSOR_ERROR_SECTION, *PWHEA_XPF_PROCESSOR_ERROR_SECTION;

//
// Validate the x86/x64 processor error section structures against the
// definitions in the UEFI  specification.
//

CPER_FIELD_CHECK(WHEA_XPF_PROCINFO, CheckInfoId,         0, 16);
CPER_FIELD_CHECK(WHEA_XPF_PROCINFO, ValidBits,          16,  8);
CPER_FIELD_CHECK(WHEA_XPF_PROCINFO, CheckInfo,          24,  8);
CPER_FIELD_CHECK(WHEA_XPF_PROCINFO, TargetId,           32,  8);
CPER_FIELD_CHECK(WHEA_XPF_PROCINFO, RequesterId,        40,  8);
CPER_FIELD_CHECK(WHEA_XPF_PROCINFO, ResponderId,        48,  8);
CPER_FIELD_CHECK(WHEA_XPF_PROCINFO, InstructionPointer, 56,  8);

CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Eax,       0,   4);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Ebx,       4,   4);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Ecx,       8,   4);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Edx,      12,   4);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Esi,      16,   4);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Edi,      20,   4);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Ebp,      24,   4);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Esp,      28,   4);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Cs,       32,   2);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Ds,       34,   2);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Ss,       36,   2);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Es,       38,   2);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Fs,       40,   2);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Gs,       42,   2);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Eflags,   44,   4);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Eip,      48,   4);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Cr0,      52,   4);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Cr1,      56,   4);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Cr2,      60,   4);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Cr3,      64,   4);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Cr4,      68,   4);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Gdtr,     72,   8);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Idtr,     80,   8);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Ldtr,     88,   2);
CPER_FIELD_CHECK(WHEA_X86_REGISTER_STATE, Tr,       90,   2);

CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Rax,       0,   8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Rbx,       8,   8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Rcx,      16,   8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Rdx,      24,   8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Rsi,      32,   8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Rdi,      40,   8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Rbp,      48,   8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Rsp,      56,   8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, R8,       64,   8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, R9,       72,   8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, R10,      80,   8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, R11,      88,   8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, R12,      96,   8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, R13,      104,  8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, R14,      112,  8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, R15,      120,  8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Cs,       128,  2);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Ds,       130,  2);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Ss,       132,  2);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Es,       134,  2);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Fs,       136,  2);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Gs,       138,  2);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Reserved, 140,  4);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Rflags,   144,  8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Eip,      152,  8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Cr0,      160,  8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Cr1,      168,  8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Cr2,      176,  8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Cr3,      184,  8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Cr4,      192,  8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Cr8,      200,  8);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Gdtr,     208, 16);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Idtr,     224, 16);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Ldtr,     240,  2);
CPER_FIELD_CHECK(WHEA_X64_REGISTER_STATE, Tr,       242,  2);

CPER_FIELD_CHECK(WHEA_XPF_CONTEXT_INFO, RegisterContextType,  0, 2);
CPER_FIELD_CHECK(WHEA_XPF_CONTEXT_INFO, RegisterDataSize,     2, 2);
CPER_FIELD_CHECK(WHEA_XPF_CONTEXT_INFO, MSRAddress,           4, 4);
CPER_FIELD_CHECK(WHEA_XPF_CONTEXT_INFO, MmRegisterAddress,    8, 8);

CPER_FIELD_CHECK(WHEA_XPF_PROCESSOR_ERROR_SECTION, ValidBits,     0,  8);
CPER_FIELD_CHECK(WHEA_XPF_PROCESSOR_ERROR_SECTION, LocalAPICId,   8,  8);
CPER_FIELD_CHECK(WHEA_XPF_PROCESSOR_ERROR_SECTION, CpuId,        16, 48);
CPER_FIELD_CHECK(WHEA_XPF_PROCESSOR_ERROR_SECTION, VariableInfo, 64, ANYSIZE_ARRAY);

//--------------------------------------------------- WHEA_MEMORY_ERROR_SECTION

typedef union _WHEA_MEMORY_ERROR_SECTION_VALIDBITS {
    struct {
        ULONGLONG ErrorStatus:1;
        ULONGLONG PhysicalAddress:1;
        ULONGLONG PhysicalAddressMask:1;
        ULONGLONG Node:1;
        ULONGLONG Card:1;
        ULONGLONG Module:1;
        ULONGLONG Bank:1;
        ULONGLONG Device:1;
        ULONGLONG Row:1;
        ULONGLONG Column:1;
        ULONGLONG BitPosition:1;
        ULONGLONG RequesterId:1;
        ULONGLONG ResponderId:1;
        ULONGLONG TargetId:1;
        ULONGLONG ErrorType:1;
        ULONGLONG RankNumber:1;
        ULONGLONG CardHandle:1;
        ULONGLONG ModuleHandle:1;
        ULONGLONG ExtendedRow:1;
        ULONGLONG BankGroup:1;
        ULONGLONG BankAddress:1;
        ULONGLONG ChipIdentification:1;
        ULONGLONG Reserved:42;
    } DUMMYSTRUCTNAME;
    ULONGLONG ValidBits;
} WHEA_MEMORY_ERROR_SECTION_VALIDBITS,
  *PWHEA_MEMORY_ERROR_SECTION_VALIDBITS;

#define WHEA_MEMERRTYPE_UNKNOWN                 0x00
#define WHEA_MEMERRTYPE_NOERROR                 0x01
#define WHEA_MEMERRTYPE_SINGLEBITECC            0x02
#define WHEA_MEMERRTYPE_MULTIBITECC             0x03
#define WHEA_MEMERRTYPE_SINGLESYMCHIPKILL       0x04
#define WHEA_MEMERRTYPE_MULTISYMCHIPKILL        0x05
#define WHEA_MEMERRTYPE_MASTERABORT             0x06
#define WHEA_MEMERRTYPE_TARGETABORT             0x07
#define WHEA_MEMERRTYPE_PARITYERROR             0x08
#define WHEA_MEMERRTYPE_WATCHDOGTIMEOUT         0x09
#define WHEA_MEMERRTYPE_INVALIDADDRESS          0x0A
#define WHEA_MEMERRTYPE_MIRRORBROKEN            0x0B
#define WHEA_MEMERRTYPE_MEMORYSPARING           0x0C

typedef struct _WHEA_MEMORY_ERROR_SECTION {
    WHEA_MEMORY_ERROR_SECTION_VALIDBITS ValidBits;
    WHEA_ERROR_STATUS ErrorStatus;
    ULONGLONG PhysicalAddress;
    ULONGLONG PhysicalAddressMask;
    USHORT Node;
    USHORT Card;
    USHORT Module;
    USHORT Bank;
    USHORT Device;
    USHORT Row;
    USHORT Column;
    USHORT BitPosition;
    ULONGLONG RequesterId;
    ULONGLONG ResponderId;
    ULONGLONG TargetId;
    UCHAR ErrorType;
    UCHAR Extended;
    USHORT RankNumber;
    USHORT CardHandle;
    USHORT ModuleHandle;
} WHEA_MEMORY_ERROR_SECTION, *PWHEA_MEMORY_ERROR_SECTION;

//
// Validate the memory error section structures against the definitions in the
// UEFI  specification.
//

CPER_FIELD_CHECK(WHEA_MEMORY_ERROR_SECTION, ValidBits,            0, 8);
CPER_FIELD_CHECK(WHEA_MEMORY_ERROR_SECTION, ErrorStatus,          8, 8);
CPER_FIELD_CHECK(WHEA_MEMORY_ERROR_SECTION, PhysicalAddress,     16, 8);
CPER_FIELD_CHECK(WHEA_MEMORY_ERROR_SECTION, PhysicalAddressMask, 24, 8);
CPER_FIELD_CHECK(WHEA_MEMORY_ERROR_SECTION, Node,                32, 2);
CPER_FIELD_CHECK(WHEA_MEMORY_ERROR_SECTION, Card,                34, 2);
CPER_FIELD_CHECK(WHEA_MEMORY_ERROR_SECTION, Module,              36, 2);
CPER_FIELD_CHECK(WHEA_MEMORY_ERROR_SECTION, Bank,                38, 2);
CPER_FIELD_CHECK(WHEA_MEMORY_ERROR_SECTION, Device,              40, 2);
CPER_FIELD_CHECK(WHEA_MEMORY_ERROR_SECTION, Row,                 42, 2);
CPER_FIELD_CHECK(WHEA_MEMORY_ERROR_SECTION, Column,              44, 2);
CPER_FIELD_CHECK(WHEA_MEMORY_ERROR_SECTION, BitPosition,         46, 2);
CPER_FIELD_CHECK(WHEA_MEMORY_ERROR_SECTION, RequesterId,         48, 8);
CPER_FIELD_CHECK(WHEA_MEMORY_ERROR_SECTION, ResponderId,         56, 8);
CPER_FIELD_CHECK(WHEA_MEMORY_ERROR_SECTION, TargetId,            64, 8);
CPER_FIELD_CHECK(WHEA_MEMORY_ERROR_SECTION, ErrorType,           72, 1);

//----------------------------------------------- WHEA_MEMORY_ERROR_EXT_SECTION

typedef enum _WHEA_MEMORY_DEFINITION {
    WheaMemoryUndefined = 0,
    WheaMemoryFm,
    WheaMemoryNm,
    WheaMemoryHbm,
    WheaMemoryMax
} WHEA_MEMORY_DEFINITION, *PWHEA_MEMORY_DEFINITION;

typedef union _WHEA_MEMORY_ERROR_EXT_SECTION_FLAGS {
    struct {
        UINT64 AddressTranslationByPrmSuccess : 1;
        UINT64 AddressTranslationByPrmFailed : 1;
        UINT64 AddressTranslationByPrmNotSupported : 1;
        UINT64 AddressTranslationByPluginSuccess : 1;
        UINT64 AddressTranslationByPluginFailed : 1;
        UINT64 AddressTranslationByPluginNotSupported : 1;
        UINT64 Reserved : 58;
    } DUMMYSTRUCTNAME;

    UINT64 AsUINT64;
} WHEA_MEMORY_ERROR_EXT_SECTION_FLAGS, *PWHEA_MEMORY_ERROR_EXT_SECTION_FLAGS;

typedef union _WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS {
    struct {
        UINT64 MemDef : 1;
        UINT64 SystemAddress : 1;
        UINT64 SpareSystemAddress : 1;
        UINT64 DevicePhysicalAddress : 1;
        UINT64 ChannelAddress : 1;
        UINT64 RankAddress : 1;
        UINT64 ProcessorSocketId : 1;
        UINT64 MemoryControllerId : 1;
        UINT64 TargetId : 1;
        UINT64 LogicalChannelId : 1;
        UINT64 ChannelId : 1;
        UINT64 SubChannelId : 1;
        UINT64 PhysicalRankId : 1;
        UINT64 DimmSlotId : 1;
        UINT64 DimmRankId : 1;
        UINT64 Bank : 1;
        UINT64 BankGroup : 1;
        UINT64 Row : 1;
        UINT64 Column : 1;
        UINT64 LockStepRank : 1;
        UINT64 LockStepPhysicalRank : 1;
        UINT64 LockStepBank : 1;
        UINT64 LockStepBankGroup : 1;
        UINT64 ChipSelect : 1;
        UINT64 Node : 1;
        UINT64 ChipId : 1;
        UINT64 Reserved : 38;
    } DUMMYSTRUCTNAME;

    UINT64 ValidBits;
} WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS,
  *PWHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS;

typedef struct _WHEA_MEMORY_HARDWARE_ADDRESS_INTEL {
    WHEA_MEMORY_DEFINITION MemDef;
    UINT64 SystemAddress;
    UINT64 SpareSystemAddress;
    UINT64 DevicePhysicalAddress;
    UINT64 ChannelAddress;
    UINT64 RankAddress;
    UINT8 ProcessorSocketId;
    UINT8 MemoryControllerId;
    UINT8 TargetId;
    UINT8 LogicalChannelId;
    UINT8 ChannelId;
    UINT8 SubChannelId;
    UINT8 PhysicalRankId;
    UINT8 DimmSlotId;
    UINT8 DimmRankId;
    UINT8 Bank;
    UINT8 BankGroup;
    UINT32 Row;
    UINT32 Column;
    UINT8 LockStepRank;
    UINT8 LockStepPhysicalRank;
    UINT8 LockStepBank;
    UINT8 LockStepBankGroup;
    UINT8 ChipSelect;
    UINT8 Node;
    UINT8 ChipId;
    UINT8 Reserved[40];
} WHEA_MEMORY_HARDWARE_ADDRESS_INTEL, *PWHEA_MEMORY_HARDWARE_ADDRESS_INTEL;

typedef struct _WHEA_MEMORY_ERROR_EXT_SECTION_INTEL {
    WHEA_MEMORY_ERROR_EXT_SECTION_FLAGS Flags;
    WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS ValidBits;
    WHEA_MEMORY_HARDWARE_ADDRESS_INTEL HardwareAddress;
    UINT8 Reserved[40];
} WHEA_MEMORY_ERROR_EXT_SECTION_INTEL, *PWHEA_MEMORY_ERROR_EXT_SECTION_INTEL;

//----------------------------------------------------- WHEA_PMEM_ERROR_SECTION

#define WHEA_PMEM_ERROR_SECTION_LOCATION_INFO_SIZE 64
#define WHEA_PMEM_ERROR_SECTION_MAX_PAGES 50

typedef union _WHEA_PMEM_ERROR_SECTION_VALIDBITS {
    struct {
        ULONGLONG ErrorStatus:1;
        ULONGLONG NFITHandle:1;
        ULONGLONG LocationInfo:1;
        ULONGLONG Reserved:61;
    } DUMMYSTRUCTNAME;
    ULONGLONG ValidBits;
} WHEA_PMEM_ERROR_SECTION_VALIDBITS,
  *PWHEA_PMEM_ERROR_SECTION_VALIDBITS;

typedef struct _WHEA_PMEM_PAGE_RANGE {
    ULONG64 StartingPfn;
    ULONG64 PageCount;
    ULONG64 MarkedBadBitmap;
} WHEA_PMEM_PAGE_RANGE, *PWHEA_PMEM_PAGE_RANGE;

#define WHEA_PMEM_IS_PFN_ALREADY_MARKED_BAD(PageRange, TargetPfn) \
    (((TargetPfn) - ((PageRange)->StartingPfn) < sizeof(ULONG64) * 8) && \
     ((((PageRange)->MarkedBadBitmap) & (1ull << ((TargetPfn) - ((PageRange)->StartingPfn)))) != 0))

#define WHEA_PMEM_IS_PAGE_RANGE_ALREADY_MARKED_BAD(PageRange) \
    (((PageRange)->PageCount <= sizeof(ULONG64) * 8) && \
     (((PageRange)->MarkedBadBitmap) == (ULONG64_MAX >> (sizeof(ULONG64) * 8 - (PageRange)->PageCount))))

typedef struct _WHEA_PMEM_ERROR_SECTION {
    WHEA_PMEM_ERROR_SECTION_VALIDBITS ValidBits;
    UCHAR LocationInfo[WHEA_PMEM_ERROR_SECTION_LOCATION_INFO_SIZE];
    WHEA_ERROR_STATUS ErrorStatus;
    ULONG NFITHandle;
    ULONG PageRangeCount;
    WHEA_PMEM_PAGE_RANGE PageRange[ANYSIZE_ARRAY];
} WHEA_PMEM_ERROR_SECTION, *PWHEA_PMEM_ERROR_SECTION;

CPER_FIELD_CHECK(WHEA_PMEM_ERROR_SECTION, ValidBits,            0, 8);
CPER_FIELD_CHECK(WHEA_PMEM_ERROR_SECTION, LocationInfo,         8, 64);
CPER_FIELD_CHECK(WHEA_PMEM_ERROR_SECTION, ErrorStatus,         72, 8);
CPER_FIELD_CHECK(WHEA_PMEM_ERROR_SECTION, NFITHandle,          80, 4);
CPER_FIELD_CHECK(WHEA_PMEM_ERROR_SECTION, PageRangeCount,      84, 4);

//----------------------------------------- WHEA_PCIE_CORRECTABLE_ERROR_SECTION

#define WHEA_PCIE_CORRECTABLE_ERROR_SECTION_COUNT_SIZE 32

typedef struct _WHEA_PCIE_ADDRESS {
    UINT32 Segment;
    UINT32 Bus;
    UINT32 Device;
    UINT32 Function;
} WHEA_PCIE_ADDRESS, *PWHEA_PCIE_ADDRESS;

typedef union _WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS {
    struct {
        ULONGLONG Segment:1;
        ULONGLONG Bus:1;
        ULONGLONG Device:1;
        ULONGLONG Function:1;
        ULONGLONG Mask:1;
        ULONGLONG CorrectableErrorCount:1;
        ULONGLONG Reserved:58;
    } DUMMYSTRUCTNAME;
    ULONGLONG ValidBits;
} WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS,
  *PWHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS;

typedef struct _WHEA_PCIE_CORRECTABLE_ERROR_DEVICES {
    WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS ValidBits;
    WHEA_PCIE_ADDRESS Address;
    UINT32 Mask;
    UINT32 CorrectableErrorCount
               [WHEA_PCIE_CORRECTABLE_ERROR_SECTION_COUNT_SIZE];
} WHEA_PCIE_CORRECTABLE_ERROR_DEVICES, *PWHEA_PCIE_CORRECTABLE_ERROR_DEVICES;

typedef struct _WHEA_PCIE_CORRECTABLE_ERROR_SECTION_HEADER {
    UINT16 Version;
    UINT16 Count;
} WHEA_PCIE_CORRECTABLE_ERROR_SECTION_HEADER,
      *PWHEA_PCIE_CORRECTABLE_ERROR_SECTION_HEADER;

typedef struct _WHEA_PCIE_CORRECTABLE_ERROR_SECTION {
    WHEA_PCIE_CORRECTABLE_ERROR_SECTION_HEADER Header;
    _Field_size_(Header.Count)
        WHEA_PCIE_CORRECTABLE_ERROR_DEVICES Devices[ANYSIZE_ARRAY];
} WHEA_PCIE_CORRECTABLE_ERROR_SECTION, *PWHEA_PCIE_CORRECTABLE_ERROR_SECTION;

CPER_FIELD_CHECK(WHEA_PCIE_CORRECTABLE_ERROR_SECTION, Header,  0,   4);
CPER_FIELD_CHECK(WHEA_PCIE_CORRECTABLE_ERROR_SECTION, Devices, 4, 156);

//----------------------------------------- WHEA_MEMORY_CORRECTABLE_ERROR_SECTION

typedef union _WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS {
    struct {
        ULONGLONG SocketId:1;
        ULONGLONG ChannelId:1;
        ULONGLONG DimmSlot:1;
        ULONGLONG CorrectableErrorCount:1;
        ULONGLONG Reserved:60;
    } DUMMYSTRUCTNAME;
    ULONGLONG ValidBits;
} WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS,
  *PWHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS;

typedef struct _WHEA_MEMORY_CORRECTABLE_ERROR_HEADER {
    UINT16 Version;
    UINT16 Count;
} WHEA_MEMORY_CORRECTABLE_ERROR_HEADER, *PWHEA_MEMORY_CORRECTABLE_ERROR_HEADER;

typedef struct _WHEA_MEMORY_CORRECTABLE_ERROR_DATA {
    WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS ValidBits;
    UINT32 SocketId;
    UINT32 ChannelId;
    UINT32 DimmSlot;
    UINT32 CorrectableErrorCount;
} WHEA_MEMORY_CORRECTABLE_ERROR_DATA, *PWHEA_MEMORY_CORRECTABLE_ERROR_DATA;

typedef struct _WHEA_MEMORY_CORRECTABLE_ERROR_SECTION {
    WHEA_MEMORY_CORRECTABLE_ERROR_HEADER Header;
    WHEA_MEMORY_CORRECTABLE_ERROR_DATA Data[ANYSIZE_ARRAY];
} WHEA_MEMORY_CORRECTABLE_ERROR_SECTION,
    *PWHEA_MEMORY_CORRECTABLE_ERROR_SECTION;

CPER_FIELD_CHECK(WHEA_MEMORY_CORRECTABLE_ERROR_SECTION, Header, 0,  4);
CPER_FIELD_CHECK(WHEA_MEMORY_CORRECTABLE_ERROR_SECTION, Data,   4,  24);

//----------------------------------------------- WHEA_PCIEXPRESS_ERROR_SECTION

typedef union _WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS {
    struct {
        ULONGLONG PortType:1;
        ULONGLONG Version:1;
        ULONGLONG CommandStatus:1;
        ULONGLONG DeviceId:1;
        ULONGLONG DeviceSerialNumber:1;
        ULONGLONG BridgeControlStatus:1;
        ULONGLONG ExpressCapability:1;
        ULONGLONG AerInfo:1;
        ULONGLONG Reserved:56;
    } DUMMYSTRUCTNAME;
    ULONGLONG ValidBits;
} WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS,
  *PWHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS;

typedef struct _WHEA_PCIEXPRESS_DEVICE_ID {
    USHORT VendorID;
    USHORT DeviceID;
    ULONG ClassCode:24;
    ULONG FunctionNumber:8;
    ULONG DeviceNumber:8;
    ULONG Segment:16;
    ULONG PrimaryBusNumber:8;
    ULONG SecondaryBusNumber:8;
    ULONG Reserved1:3;
    ULONG SlotNumber:13;
    ULONG Reserved2:8;
} WHEA_PCIEXPRESS_DEVICE_ID, *PWHEA_PCIEXPRESS_DEVICE_ID;

typedef union _WHEA_PCIEXPRESS_VERSION {
    struct {
        UCHAR MinorVersion;
        UCHAR MajorVersion;
        USHORT Reserved;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_PCIEXPRESS_VERSION, *PWHEA_PCIEXPRESS_VERSION;

typedef union _WHEA_PCIEXPRESS_COMMAND_STATUS {
    struct {
        USHORT Command;
        USHORT Status;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_PCIEXPRESS_COMMAND_STATUS, *PWHEA_PCIEXPRESS_COMMAND_STATUS;

typedef union _WHEA_PCIEXPRESS_BRIDGE_CONTROL_STATUS {
    struct {
        USHORT BridgeSecondaryStatus;
        USHORT BridgeControl;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_PCIEXPRESS_BRIDGE_CONTROL_STATUS,
    *PWHEA_PCIEXPRESS_BRIDGE_CONTROL_STATUS;

typedef enum _WHEA_PCIEXPRESS_DEVICE_TYPE {
    WheaPciExpressEndpoint = 0,
    WheaPciExpressLegacyEndpoint,
    WheaPciExpressRootPort = 4,
    WheaPciExpressUpstreamSwitchPort,
    WheaPciExpressDownstreamSwitchPort,
    WheaPciExpressToPciXBridge,
    WheaPciXToExpressBridge,
    WheaPciExpressRootComplexIntegratedEndpoint,
    WheaPciExpressRootComplexEventCollector
} WHEA_PCIEXPRESS_DEVICE_TYPE;

typedef struct _WHEA_PCIEXPRESS_ERROR_SECTION {
    WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS ValidBits;
    WHEA_PCIEXPRESS_DEVICE_TYPE PortType;
    WHEA_PCIEXPRESS_VERSION Version;
    WHEA_PCIEXPRESS_COMMAND_STATUS CommandStatus;
    ULONG Reserved;
    WHEA_PCIEXPRESS_DEVICE_ID DeviceId;
    ULONGLONG DeviceSerialNumber;
    WHEA_PCIEXPRESS_BRIDGE_CONTROL_STATUS BridgeControlStatus;
    UCHAR ExpressCapability[60];
    UCHAR AerInfo[96];
} WHEA_PCIEXPRESS_ERROR_SECTION, *PWHEA_PCIEXPRESS_ERROR_SECTION;

//
// Validate the PCI Express error section structures against the definitions
// in the UEFI  specification.
//

CPER_FIELD_CHECK(WHEA_PCIEXPRESS_ERROR_SECTION, ValidBits,             0,  8);
CPER_FIELD_CHECK(WHEA_PCIEXPRESS_ERROR_SECTION, PortType,              8,  4);
CPER_FIELD_CHECK(WHEA_PCIEXPRESS_ERROR_SECTION, Version,              12,  4);
CPER_FIELD_CHECK(WHEA_PCIEXPRESS_ERROR_SECTION, CommandStatus,        16,  4);
CPER_FIELD_CHECK(WHEA_PCIEXPRESS_ERROR_SECTION, Reserved,             20,  4);
CPER_FIELD_CHECK(WHEA_PCIEXPRESS_ERROR_SECTION, DeviceId,             24, 16);
CPER_FIELD_CHECK(WHEA_PCIEXPRESS_ERROR_SECTION, DeviceSerialNumber,   40,  8);
CPER_FIELD_CHECK(WHEA_PCIEXPRESS_ERROR_SECTION, BridgeControlStatus,  48,  4);
CPER_FIELD_CHECK(WHEA_PCIEXPRESS_ERROR_SECTION, ExpressCapability,    52, 60);
CPER_FIELD_CHECK(WHEA_PCIEXPRESS_ERROR_SECTION, AerInfo,             112, 96);

//-------------------------------------------------- WHEA_PCIXBUS_ERROR_SECTION

#define PCIXBUS_ERRTYPE_UNKNOWN             0x0000
#define PCIXBUS_ERRTYPE_DATAPARITY          0x0001
#define PCIXBUS_ERRTYPE_SYSTEM              0x0002
#define PCIXBUS_ERRTYPE_MASTERABORT         0x0003
#define PCIXBUS_ERRTYPE_BUSTIMEOUT          0x0004
#define PCIXBUS_ERRTYPE_MASTERDATAPARITY    0x0005
#define PCIXBUS_ERRTYPE_ADDRESSPARITY       0x0006
#define PCIXBUS_ERRTYPE_COMMANDPARITY       0x0007

typedef union _WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS {
    struct {
        ULONGLONG ErrorStatus:1;
        ULONGLONG ErrorType:1;
        ULONGLONG BusId:1;
        ULONGLONG BusAddress:1;
        ULONGLONG BusData:1;
        ULONGLONG BusCommand:1;
        ULONGLONG RequesterId:1;
        ULONGLONG CompleterId:1;
        ULONGLONG TargetId:1;
        ULONGLONG Reserved:55;
    } DUMMYSTRUCTNAME;
    ULONGLONG ValidBits;
} WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS, *PWHEA_PCIXBUS_ERROR_SECTION_VALIDBITS;

typedef union _WHEA_PCIXBUS_ID {
    struct {
        UCHAR BusNumber;
        UCHAR BusSegment;
    } DUMMYSTRUCTNAME;
    USHORT AsUSHORT;
} WHEA_PCIXBUS_ID, *PWHEA_PCIXBUS_ID;

typedef union _WHEA_PCIXBUS_COMMAND {
    struct {
        ULONGLONG Command:56;
        ULONGLONG PCIXCommand:1;
        ULONGLONG Reserved:7;
    } DUMMYSTRUCTNAME;
    ULONGLONG AsULONGLONG;
} WHEA_PCIXBUS_COMMAND, *PWHEA_PCIXBUS_COMMAND;

typedef struct _WHEA_PCIXBUS_ERROR_SECTION {
    WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS ValidBits;
    WHEA_ERROR_STATUS ErrorStatus;
    USHORT ErrorType;
    WHEA_PCIXBUS_ID BusId;
    ULONG Reserved;
    ULONGLONG BusAddress;
    ULONGLONG BusData;
    WHEA_PCIXBUS_COMMAND BusCommand;
    ULONGLONG RequesterId;
    ULONGLONG CompleterId;
    ULONGLONG TargetId;
} WHEA_PCIXBUS_ERROR_SECTION, *PWHEA_PCIXBUS_ERROR_SECTION;

CPER_FIELD_CHECK(WHEA_PCIXBUS_ERROR_SECTION, ValidBits,    0, 8);
CPER_FIELD_CHECK(WHEA_PCIXBUS_ERROR_SECTION, ErrorStatus,  8, 8);
CPER_FIELD_CHECK(WHEA_PCIXBUS_ERROR_SECTION, ErrorType,   16, 2);
CPER_FIELD_CHECK(WHEA_PCIXBUS_ERROR_SECTION, BusId,       18, 2);
CPER_FIELD_CHECK(WHEA_PCIXBUS_ERROR_SECTION, Reserved,    20, 4);
CPER_FIELD_CHECK(WHEA_PCIXBUS_ERROR_SECTION, BusAddress,  24, 8);
CPER_FIELD_CHECK(WHEA_PCIXBUS_ERROR_SECTION, BusData,     32, 8);
CPER_FIELD_CHECK(WHEA_PCIXBUS_ERROR_SECTION, BusCommand,  40, 8);
CPER_FIELD_CHECK(WHEA_PCIXBUS_ERROR_SECTION, RequesterId, 48, 8);
CPER_FIELD_CHECK(WHEA_PCIXBUS_ERROR_SECTION, CompleterId, 56, 8);
CPER_FIELD_CHECK(WHEA_PCIXBUS_ERROR_SECTION, TargetId,    64, 8);

//----------------------------------------------- WHEA_PCIXDEVICE_ERROR_SECTION

typedef union _WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS {
    struct {
        ULONGLONG ErrorStatus:1;
        ULONGLONG IdInfo:1;
        ULONGLONG MemoryNumber:1;
        ULONGLONG IoNumber:1;
        ULONGLONG RegisterDataPairs:1;
        ULONGLONG Reserved:59;
    } DUMMYSTRUCTNAME;
    ULONGLONG ValidBits;
} WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS,
  *PWHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS;

typedef struct _WHEA_PCIXDEVICE_ID {
    USHORT VendorId;
    USHORT DeviceId;
    ULONG ClassCode:24;
    ULONG FunctionNumber:8;
    ULONG DeviceNumber:8;
    ULONG BusNumber:8;
    ULONG SegmentNumber:8;
    ULONG Reserved1:8;
    ULONG Reserved2;
} WHEA_PCIXDEVICE_ID, *PWHEA_PCIXDEVICE_ID;

typedef struct WHEA_PCIXDEVICE_REGISTER_PAIR {
    ULONGLONG Register;
    ULONGLONG Data;
} WHEA_PCIXDEVICE_REGISTER_PAIR, *PWHEA_PCIXDEVICE_REGISTER_PAIR;

typedef struct _WHEA_PCIXDEVICE_ERROR_SECTION {
    WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS ValidBits;
    WHEA_ERROR_STATUS ErrorStatus;
    WHEA_PCIXDEVICE_ID IdInfo;
    ULONG MemoryNumber;
    ULONG IoNumber;
    WHEA_PCIXDEVICE_REGISTER_PAIR RegisterDataPairs[ANYSIZE_ARRAY];
} WHEA_PCIXDEVICE_ERROR_SECTION, *PWHEA_PCIXDEVICE_ERROR_SECTION;

CPER_FIELD_CHECK(WHEA_PCIXDEVICE_ERROR_SECTION, ValidBits,          0,  8);
CPER_FIELD_CHECK(WHEA_PCIXDEVICE_ERROR_SECTION, ErrorStatus,        8,  8);
CPER_FIELD_CHECK(WHEA_PCIXDEVICE_ERROR_SECTION, IdInfo,            16, 16);
CPER_FIELD_CHECK(WHEA_PCIXDEVICE_ERROR_SECTION, MemoryNumber,      32,  4);
CPER_FIELD_CHECK(WHEA_PCIXDEVICE_ERROR_SECTION, IoNumber,          36,  4);
CPER_FIELD_CHECK(WHEA_PCIXDEVICE_ERROR_SECTION, RegisterDataPairs, 40, 16);

//---------------------------------------- WHEA_FIRMWARE_ERROR_RECORD_REFERENCE

#define WHEA_FIRMWARE_RECORD_TYPE_IPFSAL 0

typedef struct _WHEA_FIRMWARE_ERROR_RECORD_REFERENCE {
    UCHAR Type;
    UCHAR Reserved[7];
    ULONGLONG FirmwareRecordId;
} WHEA_FIRMWARE_ERROR_RECORD_REFERENCE, *PWHEA_FIRMWARE_ERROR_RECORD_REFERENCE;

CPER_FIELD_CHECK(WHEA_FIRMWARE_ERROR_RECORD_REFERENCE, Type,             0,  1);
CPER_FIELD_CHECK(WHEA_FIRMWARE_ERROR_RECORD_REFERENCE, Reserved,         1,  7);
CPER_FIELD_CHECK(WHEA_FIRMWARE_ERROR_RECORD_REFERENCE, FirmwareRecordId, 8,  8);

//
// This is the start of the Microsoft specific extensions to the Common Platform
// Error Record specification. This is in accordance with Appendix N, section
// 2.3 of the Unified Extensible Firmware Interface specification, which allows
// the specification of non-standard section bodies.
//

//------------------------------------------------------------- XPF_MCA_SECTION

//
// The IA32_MCG_CAP register provides information about the machine-check
// architecture of the processor.
// From: Intel 64 and IA-32 Architectures SDM
//       Volume 3B; December 2017; Chapter 15.3.1.1
//

typedef union _MCG_CAP {
    struct {
        ULONG64 CountField: 8;
        ULONG64 ControlMsrPresent: 1;
        ULONG64 ExtendedMsrsPresent: 1;
        ULONG64 SignalingExtensionPresent: 1;
        ULONG64 ThresholdErrorStatusPresent: 1;
        ULONG64 Reserved: 4;
        ULONG64 ExtendedRegisterCount: 8;
        ULONG64 SoftwareErrorRecoverySupported: 1;
        ULONG64 EnhancedMachineCheckCapability: 1;
        ULONG64 ExtendedErrorLogging: 1;
        ULONG64 LocalMachineCheckException: 1;
    } DUMMYSTRUCTNAME;
    ULONG64 QuadPart;
} MCG_CAP, *PMCG_CAP;

typedef union _MCG_STATUS {
    struct {
        ULONG RestartIpValid:1;
        ULONG ErrorIpValid:1;
        ULONG MachineCheckInProgress:1;
        ULONG LocalMceValid:1;
        ULONG Reserved1:28;
        ULONG Reserved2;
    } DUMMYSTRUCTNAME;
    ULONGLONG QuadPart;
} MCG_STATUS, *PMCG_STATUS;

typedef struct _MCI_STATUS_BITS_COMMON {
        ULONG64 McaErrorCode : 16;
        ULONG64 ModelErrorCode : 16;
        ULONG64 Reserved : 25;
        ULONG64 ContextCorrupt : 1;
        ULONG64 AddressValid : 1;
        ULONG64 MiscValid : 1;
        ULONG64 ErrorEnabled : 1;
        ULONG64 UncorrectedError : 1;
        ULONG64 StatusOverFlow : 1;
        ULONG64 Valid : 1;
} MCI_STATUS_BITS_COMMON, *PMCI_STATUS_BITS_COMMON;

//
// WHEA specific implementations of MCI_STATUS register
// Allows for more machine specific granularity
// From: AMD64 Archtecture Programmer's Manual
//       Volume 2; Revision 3.29; Chapter 13
//

typedef struct _MCI_STATUS_AMD_BITS {
        ULONG64 McaErrorCode : 16;
        ULONG64 ModelErrorCode : 16;
        ULONG64 ImplementationSpecific2 : 11;
        ULONG64 Poison : 1;
        ULONG64 Deferred : 1;
        ULONG64 ImplementationSpecific1 : 12;
        ULONG64 ContextCorrupt : 1;
        ULONG64 AddressValid : 1;
        ULONG64 MiscValid : 1;
        ULONG64 ErrorEnabled : 1;
        ULONG64 UncorrectedError : 1;
        ULONG64 StatusOverFlow : 1;
        ULONG64 Valid : 1;
} MCI_STATUS_AMD_BITS, *PMCI_STATUS_AMD_BITS;

//
// From: Intel 64 and IA-32 Architectures SDM
//       Volume 3B; December 2017; Chapter 15
//

typedef struct _MCI_STATUS_INTEL_BITS {
        ULONG64 McaErrorCode : 16;
        ULONG64 ModelErrorCode : 16;
        ULONG64 OtherInfo : 5;
        ULONG64 FirmwareUpdateError : 1;
        ULONG64 CorrectedErrorCount : 15;
        ULONG64 ThresholdErrorStatus : 2;
        ULONG64 ActionRequired : 1;
        ULONG64 Signalling : 1;
        ULONG64 ContextCorrupt : 1;
        ULONG64 AddressValid : 1;
        ULONG64 MiscValid : 1;
        ULONG64 ErrorEnabled : 1;
        ULONG64 UncorrectedError : 1;
        ULONG64 StatusOverFlow : 1;
        ULONG64 Valid : 1;
} MCI_STATUS_INTEL_BITS, *PMCI_STATUS_INTEL_BITS;


typedef union _MCI_STATUS {
    MCI_STATUS_BITS_COMMON CommonBits;
    MCI_STATUS_AMD_BITS AmdBits;
    MCI_STATUS_INTEL_BITS IntelBits;
    ULONG64 QuadPart;
} MCI_STATUS, *PMCI_STATUS;

typedef enum _WHEA_CPU_VENDOR {
    WheaCpuVendorOther = 0,
    WheaCpuVendorIntel,
    WheaCpuVendorAmd
} WHEA_CPU_VENDOR, *PWHEA_CPU_VENDOR;

#define WHEA_XPF_MCA_EXTREG_MAX_COUNT            24
#define WHEA_XPF_MCA_SECTION_VERSION_2           2
#define WHEA_XPF_MCA_SECTION_VERSION_3           3
#define WHEA_XPF_MCA_SECTION_VERSION_4           4
#define WHEA_XPF_MCA_SECTION_VERSION             WHEA_XPF_MCA_SECTION_VERSION_4
#define WHEA_AMD_EXT_REG_NUM                     10
#define WHEA_XPF_MCA_EXBANK_COUNT                32

//
// NOTE: You must update WHEA_AMD_EXT_REG_NUM if you add additional registers
// to this struct to keep the size the same.
//

typedef struct _WHEA_AMD_EXTENDED_REGISTERS {
    ULONGLONG IPID;
    ULONGLONG SYND;
    ULONGLONG CONFIG;
    ULONGLONG DESTAT;
    ULONGLONG DEADDR;
    ULONGLONG MISC1;
    ULONGLONG MISC2;
    ULONGLONG MISC3;
    ULONGLONG MISC4;
    ULONGLONG RasCap;
    ULONGLONG Reserved[WHEA_XPF_MCA_EXTREG_MAX_COUNT - WHEA_AMD_EXT_REG_NUM];
} WHEA_AMD_EXTENDED_REGISTERS, *PWHEA_AMD_EXTENDED_REGISTERS;

typedef struct _XPF_RECOVERY_INFO {
    struct {
        UINT32 NotSupported : 1;
        UINT32 Overflow : 1;
        UINT32 ContextCorrupt : 1;
        UINT32 RestartIpErrorIpNotValid : 1;
        UINT32 NoRecoveryContext : 1;
        UINT32 MiscOrAddrNotValid : 1;
        UINT32 InvalidAddressMode : 1;
        UINT32 HighIrql : 1;
        UINT32 InterruptsDisabled : 1;
        UINT32 SwapBusy : 1;
        UINT32 StackOverflow : 1;
        UINT32 Reserved : 21;
    } FailureReason;

    struct {
        UINT32 RecoveryAttempted : 1;
        UINT32 HvHandled : 1;
        UINT32 Reserved : 30;
    } Action;

    BOOLEAN ActionRequired;
    BOOLEAN RecoverySucceeded;
    BOOLEAN RecoveryKernel;
    UINT8 Reserved;
    UINT16 Reserved2;
    UINT16 Reserved3;
    UINT32 Reserved4;
} XPF_RECOVERY_INFO, *PXPF_RECOVERY_INFO;

typedef struct _WHEA_XPF_MCA_SECTION {
    ULONG VersionNumber;
    WHEA_CPU_VENDOR CpuVendor;
    LARGE_INTEGER Timestamp;
    ULONG ProcessorNumber;
    MCG_STATUS GlobalStatus;
    ULONGLONG InstructionPointer;
    ULONG BankNumber;
    MCI_STATUS Status;
    ULONGLONG Address;
    ULONGLONG Misc;
    ULONG ExtendedRegisterCount;
    ULONG ApicId;
    union {
        ULONGLONG ExtendedRegisters[WHEA_XPF_MCA_EXTREG_MAX_COUNT];
        WHEA_AMD_EXTENDED_REGISTERS AMDExtendedRegisters;
    };
    MCG_CAP GlobalCapability;

    //
    // Version 3 Fields follow.
    //

    XPF_RECOVERY_INFO RecoveryInfo;

    //
    // Version 4 Fields follow.
    //

    ULONG ExBankCount;
    ULONG BankNumberEx[WHEA_XPF_MCA_EXBANK_COUNT];
    MCI_STATUS StatusEx[WHEA_XPF_MCA_EXBANK_COUNT];
    ULONGLONG AddressEx[WHEA_XPF_MCA_EXBANK_COUNT];
    ULONGLONG MiscEx[WHEA_XPF_MCA_EXBANK_COUNT];
} WHEA_XPF_MCA_SECTION, *PWHEA_XPF_MCA_SECTION;

//------------------------------------------------------ WHEA_NMI_ERROR_SECTION

typedef union _WHEA_NMI_ERROR_SECTION_FLAGS {
    struct {
        ULONG HypervisorError:1;
        ULONG Reserved:31;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_NMI_ERROR_SECTION_FLAGS, *PWHEA_NMI_ERROR_SECTION_FLAGS;

typedef struct _WHEA_NMI_ERROR_SECTION {
    UCHAR Data[8];
    WHEA_NMI_ERROR_SECTION_FLAGS Flags;
} WHEA_NMI_ERROR_SECTION, *PWHEA_NMI_ERROR_SECTION;

//------------------------------------------------------ WHEA_MSR_DUMP_SECTION

typedef struct _WHEA_MSR_DUMP_SECTION {
    UCHAR MsrDumpBuffer;
    ULONG MsrDumpLength;
    UCHAR MsrDumpData[1];
} WHEA_MSR_DUMP_SECTION, *PWHEA_MSR_DUMP_SECTION;

//------------------------------------------------------ MU_TELEMETRY_SECTION

typedef struct _MU_TELEMETRY_SECTION {
  GUID ComponentID;
  GUID SubComponentID;
  UINT32 Reserved;
  UINT32 ErrorStatusValue;
  UINT64 AdditionalInfo1;
  UINT64 AdditionalInfo2;
} MU_TELEMETRY_SECTION, *PMU_TELEMETRY_SECTION;

//------------------------------------------------------ WHEA_ARM_PROCESSOR_ERROR_SECTION

typedef union _WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS {
    struct {
        ULONG MPIDR:1;
        ULONG AffinityLevel:1;
        ULONG RunningState:1;
        ULONG VendorSpecificInfo:1;
        ULONG Reserved:28;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS,
  *PWHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS;

typedef struct _WHEA_ARM_PROCESSOR_ERROR_SECTION {
    WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS ValidBits;
    USHORT ErrorInformationStructures;
    USHORT ContextInformationStructures;
    ULONG SectionLength;
    UCHAR ErrorAffinityLevel;
    UCHAR Reserved[3];
    ULONGLONG MPIDR_EL1;
    ULONGLONG MIDR_EL1;
    ULONG RunningState;
    ULONG PSCIState;
    UCHAR Data[1];
} WHEA_ARM_PROCESSOR_ERROR_SECTION, *PWHEA_ARM_PROCESSOR_ERROR_SECTION;

CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_SECTION, ValidBits,                    0,    4);
CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_SECTION, ErrorInformationStructures,   4,    2);
CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_SECTION, ContextInformationStructures, 6,    2);
CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_SECTION, SectionLength,                8,    4);
CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_SECTION, ErrorAffinityLevel,           12,   1);
CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_SECTION, Reserved,                     13,   3);
CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_SECTION, MPIDR_EL1,                    16,   8);
CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_SECTION, MIDR_EL1,                     24,   8);
CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_SECTION, RunningState,                 32,   4);
CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_SECTION, PSCIState,                    36,   4);
CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_SECTION, Data,                         40,   1);

//--------------------------------------------------------------- ERROR RECOVERY_INFO_SECTION

typedef enum _WHEA_RECOVERY_TYPE {
    WheaRecoveryTypeActionRequired = 1,
    WheaRecoveryTypeActionOptional,
    WheaRecoveryTypeMax
} WHEA_RECOVERY_TYPE, *PWHEA_RECOVERY_TYPE;

typedef union _WHEA_RECOVERY_ACTION {
    struct {
        UINT64 NoneAttempted : 1;
        UINT64 TerminateProcess : 1;
        UINT64 ForwardedToVm : 1;
        UINT64 MarkPageBad : 1;
        UINT64 PoisonNotPresent :1;
        UINT64 Reserved : 59;
    } DUMMYSTRUCTNAME;

    UINT64 AsUINT64;
} WHEA_RECOVERY_ACTION, *PWHEA_RECOVERY_ACTION;

typedef enum _WHEA_RECOVERY_FAILURE_REASON {
    WheaRecoveryFailureReasonKernelCouldNotMarkMemoryBad = 1,
    WheaRecoveryFailureReasonKernelMarkMemoryBadTimedOut,
    WheaRecoveryFailureReasonNoRecoveryContext,
    WheaRecoveryFailureReasonNotContinuable,
    WheaRecoveryFailureReasonPcc,
    WheaRecoveryFailureReasonOverflow,
    WheaRecoveryFailureReasonNotSupported,
    WheaRecoveryFailureReasonMiscOrAddrNotValid,
    WheaRecoveryFailureReasonInvalidAddressMode,
    WheaRecoveryFailureReasonHighIrql,
    WheaRecoveryFailureReasonInsufficientAltContextWrappers,
    WheaRecoveryFailureReasonInterruptsDisabled,
    WheaRecoveryFailureReasonSwapBusy,
    WheaRecoveryFailureReasonStackOverflow,
    WheaRecoveryFailureReasonUnexpectedFailure,
    WheaRecoveryFailureReasonKernelWillPageFaultBCAtCurrentIrql,
    WheaRecoveryFailureReasonFarNotValid,
    WheaRecoveryFailureReasonMax
} WHEA_RECOVERY_FAILURE_REASON, *PWHEA_RECOVERY_FAILURE_REASON;

typedef struct _WHEA_ERROR_RECOVERY_INFO_SECTION {
    BOOLEAN RecoveryKernel;
    WHEA_RECOVERY_ACTION RecoveryAction;
    WHEA_RECOVERY_TYPE RecoveryType;
    KIRQL Irql;
    BOOLEAN RecoverySucceeded;
    WHEA_RECOVERY_FAILURE_REASON FailureReason;
    CCHAR ProcessName[20];
} WHEA_ERROR_RECOVERY_INFO_SECTION, *PWHEA_ERROR_RECOVERY_INFO_SECTION;

//------------------------------------------------------ WHEA_ARM_PROCESSOR_ERROR_INFORMATION

typedef union _WHEA_ARM_PROCESSOR_ERROR_INFORMATION_VALID_BITS {
    struct {
        USHORT MultipleError:1;
        USHORT Flags:1;
        USHORT ErrorInformation:1;
        USHORT VirtualFaultAddress:1;
        USHORT PhysicalFaultAddress:1;
        USHORT Reserved:11;
    } DUMMYSTRUCTNAME;
    USHORT AsUSHORT;
} WHEA_ARM_PROCESSOR_ERROR_INFORMATION_VALID_BITS,
  *PWHEA_ARM_PROCESSOR_ERROR_INFORMATION_VALID_BITS;

typedef union _WHEA_ARM_CACHE_ERROR_VALID_BITS {
    struct {
        USHORT TransactionType:1;
        USHORT Operation:1;
        USHORT Level:1;
        USHORT ProcessorContextCorrupt:1;
        USHORT Corrected:1;
        USHORT PrecisePC:1;
        USHORT RestartablePC:1;
        USHORT Reserved:9;
    } DUMMYSTRUCTNAME;
    USHORT AsUSHORT;
} WHEA_ARM_CACHE_ERROR_VALID_BITS, *PWHEA_ARM_CACHE_ERROR_VALID_BITS;

typedef struct _WHEA_ARM_CACHE_ERROR {
    WHEA_ARM_CACHE_ERROR_VALID_BITS ValidationBit;
    UCHAR TransactionType:2;
    UCHAR Operation:4;
    UCHAR Level:3;
    UCHAR ProcessorContextCorrupt:1;
    UCHAR Corrected:1;
    UCHAR PrecisePC:1;
    UCHAR RestartablePC:1;
    ULONGLONG Reserved:35;
} WHEA_ARM_CACHE_ERROR, *PWHEA_ARM_CACHE_ERROR;

typedef union _WHEA_ARM_TLB_ERROR_VALID_BITS {
    struct {
        USHORT TransactionType:1;
        USHORT Operation:1;
        USHORT Level:1;
        USHORT ProcessorContextCorrupt:1;
        USHORT Corrected:1;
        USHORT PrecisePC:1;
        USHORT RestartablePC:1;
        USHORT Reserved:9;
    } DUMMYSTRUCTNAME;
    USHORT AsUSHORT;
} WHEA_ARM_TLB_ERROR_VALID_BITS, *PWHEA_ARM_TLB_ERROR_VALID_BITS;

typedef struct _WHEA_ARM_TLB_ERROR {
    WHEA_ARM_TLB_ERROR_VALID_BITS ValidationBit;
    UCHAR TransactionType:2;
    UCHAR Operation:4;
    UCHAR Level:3;
    UCHAR ProcessorContextCorrupt:1;
    UCHAR Corrected:1;
    UCHAR PrecisePC:1;
    UCHAR RestartablePC:1;
    ULONGLONG Reserved:36;
} WHEA_ARM_TLB_ERROR, *PWHEA_ARM_TLB_ERROR;

typedef union _WHEA_ARM_BUS_ERROR_VALID_BITS {
    struct {
        USHORT TransactionType:1;
        USHORT Operation:1;
        USHORT Level:1;
        USHORT ProcessorContextCorrupt:1;
        USHORT Corrected:1;
        USHORT PrecisePC:1;
        USHORT RestartablePC:1;
        USHORT ParticipationType:1;
        USHORT Timeout:1;
        USHORT AddressSpace:1;
        USHORT MemoryAttributes:1;
        USHORT AccessMode:1;
        USHORT Reserved:4;
    } DUMMYSTRUCTNAME;
    USHORT AsUSHORT;
} WHEA_ARM_BUS_ERROR_VALID_BITS, *PWHEA_ARM_BUS_ERROR_VALID_BITS;

typedef struct _WHEA_ARM_BUS_ERROR {
    WHEA_ARM_BUS_ERROR_VALID_BITS ValidationBit;
    UCHAR TransactionType:2;
    UCHAR Operation:4;
    UCHAR Level:3;
    UCHAR ProcessorContextCorrupt:1;
    UCHAR Corrected:1;
    UCHAR PrecisePC:1;
    UCHAR RestartablePC:1;
    UCHAR ParticipationType:2;
    UCHAR TimeOut:1;
    UCHAR AddressSpace:2;
    USHORT MemoryAccessAttributes:9;
    UCHAR AccessMode:1;
    ULONG Reserved:20;
} WHEA_ARM_BUS_ERROR, *PWHEA_ARM_BUS_ERROR;

typedef union _WHEA_ARM_PROCESSOR_ERROR {
    WHEA_ARM_CACHE_ERROR CacheError;
    WHEA_ARM_TLB_ERROR TlbError;
    WHEA_ARM_BUS_ERROR BusError;
    ULONGLONG AsULONGLONG;
} WHEA_ARM_PROCESSOR_ERROR, *PWHEA_ARM_PROCESSOR_ERROR;

typedef struct _WHEA_ARM_PROCESSOR_ERROR_INFORMATION {
    UCHAR Version;
    UCHAR Length;
    WHEA_ARM_PROCESSOR_ERROR_INFORMATION_VALID_BITS ValidationBit;
    UCHAR Type;
    USHORT MultipleError;
    UCHAR Flags;
    ULONGLONG ErrorInformation;
    ULONGLONG VirtualFaultAddress;
    ULONGLONG PhysicalFaultAddress;
} WHEA_ARM_PROCESSOR_ERROR_INFORMATION, *PWHEA_ARM_PROCESSOR_ERROR_INFORMATION;

CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_INFORMATION, Version,                 0,   1);
CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_INFORMATION, Length,                  1,   1);
CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_INFORMATION, ValidationBit,           2,   2);
CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_INFORMATION, Type,                    4,   1);
CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_INFORMATION, MultipleError,           5,   2);
CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_INFORMATION, Flags,                   7,   1);
CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_INFORMATION, ErrorInformation,        8,   8);
CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_INFORMATION, VirtualFaultAddress,    16,   8);
CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_INFORMATION, PhysicalFaultAddress,  24,   8);

//------------------------------------------------------ WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER

typedef union _WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_FLAGS {
    struct {
        ULONG ExceptionLevel:1;
        ULONG NonSecure:1;
        ULONG AArch64:1;
        ULONG Reserved:29;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_FLAGS,
  *PWHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_FLAGS;

typedef struct _WHEA_ARMV8_AARCH32_GPRS {
    ULONG R0;
    ULONG R1;
    ULONG R2;
    ULONG R3;
    ULONG R4;
    ULONG R5;
    ULONG R6;
    ULONG R7;
    ULONG R8;
    ULONG R9;
    ULONG R10;
    ULONG R11;
    ULONG R12;
    ULONG R13; // SP
    ULONG R14; // LR
    ULONG R15; // PC
} WHEA_ARMV8_AARCH32_GPRS, *PWHEA_ARMV8_AARCH32_GPRS;

typedef struct _WHEA_ARM_AARCH32_EL1_CSR {
    ULONG DFAR;
    ULONG DFSR;
    ULONG IFAR;
    ULONG ISR;
    ULONG MAIR0;
    ULONG MAIR1;
    ULONG MIDR;
    ULONG MPIDR;
    ULONG NMRR;
    ULONG PRRR;
    ULONG SCTLR; // NS
    ULONG SPSR;
    ULONG SPSR_abt;
    ULONG SPSR_fiq;
    ULONG SPSR_irq;
    ULONG SPSR_svc;
    ULONG SPSR_und;
    ULONG TPIDRPRW;
    ULONG TPIDRURO;
    ULONG TPIDRURW;
    ULONG TTBCR;
    ULONG TTBR0;
    ULONG TTBR1;
    ULONG DACR;
} WHEA_ARM_AARCH32_EL1_CSR, *PWHEA_ARM_AARCH32_EL1;

typedef struct _WHEA_ARM_AARCH32_EL2_CSR {
    ULONG ELR_hyp;
    ULONG HAMAIR0;
    ULONG HAMAIR1;
    ULONG HCR;
    ULONG HCR2;
    ULONG HDFAR;
    ULONG HIFAR;
    ULONG HPFAR;
    ULONG HSR;
    ULONG HTCR;
    ULONG HTPIDR;
    ULONG HTTBR;
    ULONG SPSR_hyp;
    ULONG VTCR;
    ULONG VTTBR;
    ULONG DACR32_EL2;
} WHEA_ARM_AARCH32_EL2_CSR, *PWHEA_ARM_AARCH32_EL2_CSR;

typedef struct _WHEA_ARM_AARCH32_SECURE_CSR {
    ULONG SCTLR;
    ULONG SPSR_mon;
} WHEA_ARM_AARCH32_SECURE_CSR, *PWHEA_ARM_AARCH32_SECURE_CSR;

typedef struct _WHEA_ARMV8_AARCH64_GPRS {
    ULONGLONG X0;
    ULONGLONG X1;
    ULONGLONG X2;
    ULONGLONG X3;
    ULONGLONG X4;
    ULONGLONG X5;
    ULONGLONG X6;
    ULONGLONG X7;
    ULONGLONG X8;
    ULONGLONG X9;
    ULONGLONG X10;
    ULONGLONG X11;
    ULONGLONG X12;
    ULONGLONG X13;
    ULONGLONG X14;
    ULONGLONG X15;
    ULONGLONG X16;
    ULONGLONG X17;
    ULONGLONG X18;
    ULONGLONG X19;
    ULONGLONG X20;
    ULONGLONG X21;
    ULONGLONG X22;
    ULONGLONG X23;
    ULONGLONG X24;
    ULONGLONG X25;
    ULONGLONG X26;
    ULONGLONG X27;
    ULONGLONG X28;
    ULONGLONG X29;
    ULONGLONG X30;
    ULONGLONG SP;
} WHEA_ARMV8_AARCH64_GPRS, *PWHEA_ARMV8_AARCH64_GPRS;

typedef struct _WHEA_ARM_AARCH64_EL1_CSR {
    ULONGLONG ELR_EL1;
    ULONGLONG ESR_EL2;
    ULONGLONG FAR_EL1;
    ULONGLONG ISR_EL1;
    ULONGLONG MAIR_EL1;
    ULONGLONG MIDR_EL1;
    ULONGLONG MPIDR_EL1;
    ULONGLONG SCTLR_EL1;
    ULONGLONG SP_EL0;
    ULONGLONG SP_EL1;
    ULONGLONG SPSR_EL1;
    ULONGLONG TCR_EL1;
    ULONGLONG TPIDR_EL0;
    ULONGLONG TPIDR_EL1;
    ULONGLONG TPIDRRO_EL0;
    ULONGLONG TTBR0_EL1;
    ULONGLONG TTBR1_EL1;
} WHEA_ARM_AARCH64_EL1_CSR, *PWHEA_ARM_AARCH64_EL1_CSR;

typedef struct _WHEA_ARM_AARCH64_EL2_CSR {
    ULONGLONG ELR_EL2;
    ULONGLONG ESR_EL2;
    ULONGLONG FAR_EL2;
    ULONGLONG HACR_EL2;
    ULONGLONG HCR_EL2;
    ULONGLONG HPFAR_EL2;
    ULONGLONG MAIR_EL2;
    ULONGLONG SCTLR_EL2;
    ULONGLONG SP_EL2;
    ULONGLONG SPSR_EL2;
    ULONGLONG TCR_EL2;
    ULONGLONG TPIDR_EL2;
    ULONGLONG TTBR0_EL2;
    ULONGLONG VTCR_EL2;
    ULONGLONG VTTBR_EL2;
} WHEA_ARM_AARCH64_EL2_CSR, *PWHEA_ARM_AARCH64_EL2_CSR;

typedef struct _WHEA_ARMV8_AARCH64_EL3_CSR {
    ULONGLONG ELR_EL3;
    ULONGLONG ESR_EL3;
    ULONGLONG FAR_EL3;
    ULONGLONG MAIR_EL3;
    ULONGLONG SCTLR_EL3;
    ULONGLONG SP_EL3;
    ULONGLONG SPSR_EL3;
    ULONGLONG TCR_EL3;
    ULONGLONG TPIDR_EL3;
    ULONGLONG TTBR0_EL3;
} WHEA_ARMV8_AARCH64_EL3_CSR, *PWHEA_ARMV8_AARCH64_EL3_CSR;

typedef struct _WHEA_ARM_MISC_CSR {
    USHORT MRSEncoding;
    ULONGLONG Value;
} WHEA_ARM_MISC_CSR, *PWHEA_ARM_MISC_CSR;

typedef struct _WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER {
    USHORT Version;
    USHORT RegisterContextType;
    ULONG RegisterArraySize;
    UCHAR RegisterArray[1];
} WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER,
  *PWHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER;

CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER, Version,               0,    2);
CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER, RegisterContextType,   2,    2);
CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER, RegisterArraySize,     4,    4);
CPER_FIELD_CHECK(WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER, RegisterArray,         8,    1);

// ----------------------------------------------------------------- SEA Section

typedef struct _WHEA_SEA_SECTION {
    ULONG Esr;
    ULONG64 Far;
    ULONG64 Par;
    BOOLEAN WasKernel;
} WHEA_SEA_SECTION, *PWHEA_SEA_SECTION;

typedef struct _WHEA_SEI_SECTION {
    ULONG Esr;
    ULONG64 Far;
} WHEA_SEI_SECTION, *PWHEA_SEI_SECTION;

// -------------------------------------------------------- Arm RAS Node Section

typedef struct _WHEA_ARM_RAS_NODE_SECTION {
    UINT32 NodeFieldCount;
    UINT32 NodeIndex;
    UINT8 InterfaceType;
    UINT8 AestNodeType;
    UINT8 Reserved[6];
    // Fields as defined in the Arm RAS extensions version 8.6  (ARM DDI 0587)
    UINT64 ErrFr;
    UINT64 ErrCtlr;
    UINT64 ErrStatus;
    UINT64 ErrAddr;
    UINT64 ErrMisc0;
    UINT64 ErrMisc1;
    UINT64 ErrMisc2;
    UINT64 ErrMisc3;
} WHEA_ARM_RAS_NODE_SECTION, *PWHEA_ARM_RAS_NODE_SECTION;

//
// To make ensure backwards compatability in the future the number of node field's
// is recorded. This allows expanding the section on new machines without breaking
// parsing for older generations.
//

#define WHEA_ARM_RAS_NODE_FIELD_COUNT 8

//
// Interface types possible for Arm Ras Nodes, as defined in the AEST ACPI table
// definition in "ACPI for the Armv8 RAS Extenstions"  (Document Number DEN0085)
//

typedef enum _WHEA_ARM_RAS_NODE_INTERFACES {
    WheaArmRasNodeInterfaceSystemRegister = 0,
    WheaArmRasNodeInterfaceMmio = 1
} WHEA_ARM_RAS_NODE_INTERFACES, *PWHEA_ARM_RAS_NODE_INTERFACES;

// -------------------------------------------------------- PCI Recovery Section

typedef enum _WHEA_PCI_RECOVERY_SIGNAL {
    WheaPciRecoverySignalUnknown = 0,
    WheaPciRecoverySignalAer,
    WheaPciRecoverySignalDpc
}WHEA_PCI_RECOVERY_SIGNAL, *PWHEA_PCI_RECOVERY_SIGNAL;

typedef enum _WHEA_PCI_RECOVERY_STATUS {
    WheaPciREcoveryStatusUnknown = 0,
    WheaPciRecoveryStatusNoError,
    WheaPciRecoveryStatusLinkDisableTimeout,
    WheaPciRecoveryStatusLinkEnableTimeout,
    WheaPciRecoveryStatusRpBusyTimeout,
    WheaPciRecoveryStatusComplexTree,
    WheaPciRecoveryStatusBusNotFound,
    WheaPciRecoveryStatusDeviceNotFound,
    WheaPciRecoveryStatusDdaAerNotRecoverable,
    WheaPciRecoveryStatusFailedRecovery,
}WHEA_PCI_RECOVERY_STATUS,  *PWHEA_PCI_RECOVERY_STATUS;

typedef struct _WHEA_PCI_RECOVERY_SECTION {
    UINT8 SignalType;
    BOOLEAN RecoveryAttempted;
    UINT8 RecoveryStatus;
} WHEA_PCI_RECOVERY_SECTION, *PWHEA_PCI_RECOVERY_SECTION;

#include <poppack.h>


//-------------------------------------- Standard Error Notification Type GUIDs

/* 2dce8bb1-bdd7-450e-b9ad-9cf4ebd4f890 */
DEFINE_GUID(CMC_NOTIFY_TYPE_GUID,
            0x2dce8bb1, 0xbdd7, 0x450e, 0xb9, 0xad,
            0x9c, 0xf4, 0xeb, 0xd4, 0xf8, 0x90);

/* 4e292f96-d843-4a55-a8c2-d481f27ebeee */
DEFINE_GUID(CPE_NOTIFY_TYPE_GUID,
            0x4e292f96, 0xd843, 0x4a55, 0xa8, 0xc2,
            0xd4, 0x81, 0xf2, 0x7e, 0xbe, 0xee);

/* e8f56ffe-919c-4cc5-ba88-65abe14913bb */
DEFINE_GUID(MCE_NOTIFY_TYPE_GUID,
            0xe8f56ffe, 0x919c, 0x4cc5, 0xba, 0x88,
            0x65, 0xab, 0xe1, 0x49, 0x13, 0xbb);

/* cf93c01f-1a16-4dfc-b8bc-9c4daf67c104 */
DEFINE_GUID(PCIe_NOTIFY_TYPE_GUID,
            0xcf93c01f, 0x1a16, 0x4dfc, 0xb8, 0xbc,
            0x9c, 0x4d, 0xaf, 0x67, 0xc1, 0x04);

/* cc5263e8-9308-454a-89d0-340bd39bc98e */
DEFINE_GUID(INIT_NOTIFY_TYPE_GUID,
            0xcc5263e8, 0x9308, 0x454a, 0x89, 0xd0,
            0x34, 0x0b, 0xd3, 0x9b, 0xc9, 0x8e);

/* 5bad89ff-b7e6-42c9-814a-cf2485d6e98a */
DEFINE_GUID(NMI_NOTIFY_TYPE_GUID,
            0x5bad89ff, 0xb7e6, 0x42c9, 0x81, 0x4a,
            0xcf, 0x24, 0x85, 0xd6, 0xe9, 0x8a);

/* 3d61a466-ab40-409a-a698-f362d464b38f */
DEFINE_GUID(BOOT_NOTIFY_TYPE_GUID,
            0x3d61a466, 0xab40, 0x409a, 0xa6, 0x98,
            0xf3, 0x62, 0xd4, 0x64, 0xb3, 0x8f);

/* 9a78788a-bbe8-11e4-809e-67611e5d46b0 */
DEFINE_GUID(SEA_NOTIFY_TYPE_GUID,
            0x9a78788a, 0xbbe8, 0x11e4, 0x80, 0x9e,
            0x67, 0x61, 0x1e, 0x5d, 0x46, 0xb0);

/* 5c284c81-b0ae-4e87-a322-b04c85624323 */
DEFINE_GUID(SEI_NOTIFY_TYPE_GUID,
            0x5c284c81, 0xb0ae, 0x4e87, 0xa3, 0x22,
            0xb0, 0x4c, 0x85, 0x62, 0x43, 0x23);

/* 09a9d5ac-5204-4214-96e5-94992e752bcd */
DEFINE_GUID(PEI_NOTIFY_TYPE_GUID,
            0x09a9D5ac, 0x5204, 0x4214, 0x96, 0xe5,
            0x94, 0x99, 0x2e, 0x75, 0x2b, 0xcd);

/* 487565ba-6494-4367-95ca-4eff893522f6 */
DEFINE_GUID(BMC_NOTIFY_TYPE_GUID,
            0x487565ba, 0x6494, 0x4367, 0x95, 0xca,
            0x4e, 0xff, 0x89, 0x35, 0x22, 0xf6);

/* e9d59197-94ee-4a4f-8ad8-9b7d8bd93d2e */
DEFINE_GUID(SCI_NOTIFY_TYPE_GUID,
            0xe9d59197, 0x94ee, 0x4a4f, 0x8a, 0xd8,
            0x9b, 0x7d, 0x8b, 0xd9, 0x3d, 0x2e);

/* fe84086e-b557-43cf-ac1b-17982e078470 */
DEFINE_GUID(EXTINT_NOTIFY_TYPE_GUID,
            0xfe84086e, 0xb557, 0x43cf, 0xac, 0x1b,
            0x17, 0x98, 0x2e, 0x07, 0x84, 0x70);

/* 0033f803-2e70-4e88-992c-6f26daf3db7a */
DEFINE_GUID(DEVICE_DRIVER_NOTIFY_TYPE_GUID,
            0x0033f803, 0x2e70, 0x4e88, 0x99, 0x2c,
            0x6f, 0x26, 0xda, 0xf3, 0xdb, 0x7a);

/* 919448b2-3739-4b7f-a8f1-e0062805c2a3 */
DEFINE_GUID(CMCI_NOTIFY_TYPE_GUID,
            0x919448b2, 0x3739, 0x4b7f, 0xa8, 0xf1,
            0xe0, 0x06, 0x28, 0x05, 0xc2, 0xa3);

//------------------------------------------- Summary Error Section type GUIDs

/* 990b31e9-541a-4db0-a42f-837d344f6923 */
DEFINE_GUID(WHEA_DEVICE_ERROR_SUMMARY_GUID,
            0x990b31e9, 0x541a, 0x4db0, 0xa4, 0x2f,
            0x83, 0x7d, 0x34, 0x4f, 0x69, 0x23);

//------------------------------------------- Standard Error Section type GUIDs

/* 9876ccad-47b4-4bdb-b65e-16f193c4f3db */
DEFINE_GUID(PROCESSOR_GENERIC_ERROR_SECTION_GUID,
            0x9876ccad, 0x47b4, 0x4bdb, 0xb6, 0x5e,
            0x16, 0xf1, 0x93, 0xc4, 0xf3, 0xdb);

/* dc3ea0b0-a144-4797-b95b-53fa242b6e1d */
DEFINE_GUID(XPF_PROCESSOR_ERROR_SECTION_GUID,
            0xdc3ea0b0, 0xa144, 0x4797, 0xb9, 0x5b,
            0x53, 0xfa, 0x24, 0x2b, 0x6e, 0x1d);

/* e429faf1-3cb7-11d4-bca7-0080c73c8881 */
DEFINE_GUID(IPF_PROCESSOR_ERROR_SECTION_GUID,
            0xe429faf1, 0x3cb7, 0x11d4, 0xbc, 0xa7,
            0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81);

/* e19e3d16-bc11-11e4-9caa-c2051d5d46b0 */
DEFINE_GUID(ARM_PROCESSOR_ERROR_SECTION_GUID,
            0xe19e3d16, 0xbc11, 0x11e4, 0x9c, 0xaa,
            0xc2, 0x05, 0x1d, 0x5d, 0x46, 0xb0);

/* a5bc1114-6f64-4ede-b863-3e83ed7c83b1 */
DEFINE_GUID(MEMORY_ERROR_SECTION_GUID,
            0xa5bc1114, 0x6f64, 0x4ede, 0xb8, 0x63,
            0x3e, 0x83, 0xed, 0x7c, 0x83, 0xb1);

/* d995e954-bbc1-430f-ad91-b44dcb3c6f35 */
DEFINE_GUID(PCIEXPRESS_ERROR_SECTION_GUID,
            0xd995e954, 0xbbc1, 0x430f, 0xad, 0x91,
            0xb4, 0x4d, 0xcb, 0x3c, 0x6f, 0x35);

/* c5753963-3b84-4095-bf78-eddad3f9c9dd */
DEFINE_GUID(PCIXBUS_ERROR_SECTION_GUID,
            0xc5753963, 0x3b84, 0x4095, 0xbf, 0x78,
            0xed, 0xda, 0xd3, 0xf9, 0xc9, 0xdd);

/* eb5e4685-ca66-4769-b6a2-26068b001326 */
DEFINE_GUID(PCIXDEVICE_ERROR_SECTION_GUID,
            0xeb5e4685, 0xca66, 0x4769, 0xb6, 0xa2,
            0x26, 0x06, 0x8b, 0x00, 0x13, 0x26);

/* 81212a96-09ed-4996-9471-8d729c8e69ed */
DEFINE_GUID(FIRMWARE_ERROR_RECORD_REFERENCE_GUID,
            0x81212a96, 0x09ed, 0x4996, 0x94, 0x71,
            0x8d, 0x72, 0x9c, 0x8e, 0x69, 0xed);

/* 81687003-dbfd-4728-9ffd-f0904f97597d */
DEFINE_GUID(PMEM_ERROR_SECTION_GUID,
            0x81687003, 0xdbfd, 0x4728, 0x9f, 0xfd,
            0xf0, 0x90, 0x4f, 0x97, 0x59, 0x7d);

/* 85183a8b-9c41-429c-939c-5c3c087ca280 */
DEFINE_GUID(MU_TELEMETRY_SECTION_GUID,
            0x85183a8b, 0x9c41, 0x429c, 0x93, 0x9c,
            0x5c, 0x3c, 0x08, 0x7c, 0xa2, 0x80);

/* c34832a1-02c3-4c52-a9f1-9f1d5d7723fc */
DEFINE_GUID(RECOVERY_INFO_SECTION_GUID,
            0xc34832a1, 0x02c3, 0x4c52, 0xa9, 0xf1,
            0x9f, 0x1d, 0x5d, 0x77, 0x23, 0xfc);

//-------------------------------------- Processor check information type GUIDs

/* a55701f5-e3ef-43de-ac72-249b573fad2c */
DEFINE_GUID(WHEA_CACHECHECK_GUID,
            0xa55701f5, 0xe3ef, 0x43de, 0xac, 0x72,
            0x24, 0x9b, 0x57, 0x3f, 0xad, 0x2c);

/* fc06b535-5e1f-4562-9f25-0a3b9adb63c3 */
DEFINE_GUID(WHEA_TLBCHECK_GUID,
            0xfc06b535, 0x5e1f, 0x4562, 0x9f, 0x25,
            0x0a, 0x3b, 0x9a, 0xdb, 0x63, 0xc3);

/* 1cf3f8b3-c5b1-49a2-aa59-5eef92ffa63c */
DEFINE_GUID(WHEA_BUSCHECK_GUID,
            0x1cf3f8b3, 0xc5b1, 0x49a2, 0xaa, 0x59,
            0x5e, 0xef, 0x92, 0xff, 0xa6, 0x3c);

/* 48ab7f57-dc34-4f6c-a7d3-b0b5b0a74314 */
DEFINE_GUID(WHEA_MSCHECK_GUID,
            0x48ab7f57, 0xdc34, 0x4f6c, 0xa7, 0xd3,
            0xb0, 0xb5, 0xb0, 0xa7, 0x43, 0x14);

//
// This is the start of the Microsoft specific extensions to the Common Platform
// Error Record specification. This is in accordance with Appendix N, section
// 2.3 of the Unified Extensible Firmware Interface specification, which allows
// the specification of non-standard section bodies.
//

//---------------------------------------------------- Empty GUID

/* 00000000-0000-0000-0000-00000000000 */
DEFINE_GUID(CPER_EMPTY_GUID, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

//---------------------------------------------------- Microsoft record creator

/* cf07c4bd-b789-4e18-b3c4-1f732cb57131 */
DEFINE_GUID(WHEA_RECORD_CREATOR_GUID,
            0xcf07c4bd,
            0xb789, 0x4e18,
            0xb3, 0xc4, 0x1f, 0x73, 0x2c, 0xb5, 0x71, 0x31);

//---------------------------------------------------- device driver record creator

/* 57217c8d-5e66-44fb-8033-9b74cacedf5b */
DEFINE_GUID(DEFAULT_DEVICE_DRIVER_CREATOR_GUID,
            0x57217c8d,
            0x5e66, 0x44fb,
            0x80, 0x33, 0x9b, 0x74, 0xca, 0xce, 0xdf, 0x5b);

//--------------------------------------- Microsoft specific notification types

/* 3e62a467-ab40-409a-a698-f362d464b38f */
DEFINE_GUID(GENERIC_NOTIFY_TYPE_GUID,
            0x3e62a467,
            0xab40, 0x409a,
            0xa6, 0x98, 0xf3, 0x62, 0xd4, 0x64, 0xb3, 0x8f);

//-------------------------------------- Microsoft specific error section types

/* 6f3380d1-6eb0-497f-a578-4d4c65a71617 */
DEFINE_GUID(IPF_SAL_RECORD_SECTION_GUID,
            0x6f3380d1,
            0x6eb0, 0x497f,
            0xa5, 0x78, 0x4d, 0x4c, 0x65, 0xa7, 0x16, 0x17);

/* 8a1e1d01-42f9-4557-9c33-565e5cc3f7e8 */
DEFINE_GUID(XPF_MCA_SECTION_GUID,
            0x8a1e1d01,
            0x42f9, 0x4557,
            0x9c, 0x33, 0x56, 0x5e, 0x5c, 0xc3, 0xf7, 0xe8);

/* e71254e7-c1b9-4940-ab76-909703a4320f */
DEFINE_GUID(NMI_SECTION_GUID,
            0xe71254e7,
            0xc1b9, 0x4940,
            0xab, 0x76, 0x90, 0x97, 0x03, 0xa4, 0x32, 0x0f);

/* e71254e8-c1b9-4940-ab76-909703a4320f */
DEFINE_GUID(GENERIC_SECTION_GUID,
            0xe71254e8,
            0xc1b9, 0x4940,
            0xab, 0x76, 0x90, 0x97, 0x03, 0xa4, 0x32, 0x0f);

/* 1c15b445-9b06-4667-ac25-33c056b88803 */
DEFINE_GUID(IPMI_MSR_DUMP_SECTION_GUID,
            0x1c15b445,
            0x9b06, 0x4667,
            0xac, 0x25, 0x33, 0xc0, 0x56, 0xb8, 0x88, 0x03);

/* e71254e9-c1b9-4940-ab76-909703a4320f */
DEFINE_GUID(WHEA_ERROR_PACKET_SECTION_GUID,
            0xe71254e9,
            0xc1b9, 0x4940,
            0xab, 0x76, 0x90, 0x97, 0x03, 0xa4, 0x32, 0x0f);

/* ec49534b-30e7-4358-972f-eca6958fae3b */
DEFINE_GUID(WHEA_DPC_CAPABILITY_SECTION_GUID,
            0xec49534b,
            0x30e7, 0x4358,
            0x97, 0x2f, 0xec, 0xa6, 0x95, 0x8f, 0xae, 0x3b);

/* e96eca99-53e2-4f52-9be7-d2dbe9508ed0 */
DEFINE_GUID(PCIE_CORRECTABLE_ERROR_SUMMARY_SECTION_GUID,
            0xe96eca99,
            0x53e2, 0x4f52,
            0x9b, 0xe7, 0xd2, 0xdb, 0xe9, 0x50, 0x8e, 0xd0);

/* 0e36c93e-ca15-4a83-ba8a-cbe80f7f0017 */
DEFINE_GUID(MEMORY_CORRECTABLE_ERROR_SUMMARY_SECTION_GUID,
            0x0e36c93e,
            0xca15, 0x4a83,
            0xba, 0x8a, 0xcb, 0xe8, 0x0f, 0x7f, 0x00, 0x17);

/* f5fe48a6-84ce-4c1e-aa64-20c9a53099f1 */
DEFINE_GUID(SEA_SECTION_GUID,
            0xf5fe48a6, 0x84ce, 0x4c1e, 0xaa, 0x64,
            0x20, 0xc9, 0xa5, 0x30, 0x99, 0xf1);

/* f2a4a152-9c6d-4020-aecf-7695b389251b */
DEFINE_GUID(SEI_SECTION_GUID,
            0xf2a4a152, 0x9c6d, 0x4020, 0xae, 0xcf,
            0x76, 0x95, 0xb3, 0x89, 0x25, 0x1b);

/* dd060800-f6e1-4204-ac27-c4bca9568402 */
DEFINE_GUID(PCI_RECOVERY_SECTION_GUID,
            0xdd060800, 0xf6e1, 0x4204, 0xac, 0x27,
            0xc4, 0xbc, 0xa9, 0x56, 0x84, 0x02);

/* e3ebf4a2-df50-4708-b2d7-0b29ec2f7aa9 */
DEFINE_GUID(ARM_RAS_NODE_SECTION_GUID,
            0xe3ebf4a2, 0xdf50, 0x4708, 0xb2, 0xd7,
            0x0b, 0x29, 0xec, 0x2f, 0x7a, 0xa9);

/* e16edb28-6113-4263-a41d-e53f8de78751 */
DEFINE_GUID(MEMORY_ERROR_EXT_SECTION_INTEL_GUID,
            0xe16edb28, 0x6113, 0x4263, 0xa4, 0x1d,
            0xe5, 0x3f, 0x8d, 0xe7, 0x87, 0x51);


#if defined(_NTPSHEDDLL_)

#define NTPSHEDAPI

#else

#define NTPSHEDAPI DECLSPEC_IMPORT

#endif

#include <pshpack1.h>

#ifndef ANY_SIZE
#define ANY_SIZE 1
#endif

//----------------------------------------------------------- WHEA_ERROR_PACKET

typedef enum _WHEA_ERROR_TYPE {
    WheaErrTypeProcessor = 0,
    WheaErrTypeMemory,
    WheaErrTypePCIExpress,
    WheaErrTypeNMI,
    WheaErrTypePCIXBus,
    WheaErrTypePCIXDevice,
    WheaErrTypeGeneric,
    WheaErrTypePmem,
} WHEA_ERROR_TYPE, *PWHEA_ERROR_TYPE;

typedef union _WHEA_ERROR_PACKET_FLAGS {
    struct {
        ULONG PreviousError:1;
        ULONG CriticalEvent:1;
        ULONG HypervisorError:1;
        ULONG Simulated:1;
        ULONG PlatformPfaControl:1;
        ULONG PlatformDirectedOffline:1;
        ULONG AddressTranslationRequired:1;
        ULONG AddressTranslationCompleted:1;
        ULONG RecoveryOptional:1;
        ULONG Reserved2:23;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_ERROR_PACKET_FLAGS, *PWHEA_ERROR_PACKET_FLAGS;

typedef enum _WHEA_ERROR_PACKET_DATA_FORMAT {
    WheaDataFormatIPFSalRecord = 0,
    WheaDataFormatXPFMCA,
    WheaDataFormatMemory,
    WheaDataFormatPCIExpress,
    WheaDataFormatNMIPort,
    WheaDataFormatPCIXBus,
    WheaDataFormatPCIXDevice,
    WheaDataFormatGeneric,
    WheaDataFormatMax
} WHEA_ERROR_PACKET_DATA_FORMAT, *PWHEA_ERROR_PACKET_DATA_FORMAT;

typedef enum _WHEA_RAW_DATA_FORMAT {
    WheaRawDataFormatIPFSalRecord = 0x00,
    WheaRawDataFormatIA32MCA,
    WheaRawDataFormatIntel64MCA,
    WheaRawDataFormatAMD64MCA,
    WheaRawDataFormatMemory,
    WheaRawDataFormatPCIExpress,
    WheaRawDataFormatNMIPort,
    WheaRawDataFormatPCIXBus,
    WheaRawDataFormatPCIXDevice,
    WheaRawDataFormatGeneric,
    WheaRawDataFormatMax
} WHEA_RAW_DATA_FORMAT, *PWHEA_RAW_DATA_FORMAT;

typedef struct _WHEA_ERROR_PACKET_V1 {
    ULONG                   Signature;                          // +0x00 (0)
    WHEA_ERROR_PACKET_FLAGS Flags;                              // +0x04 (4)
    ULONG                   Size;                               // +0x08 (8)
    ULONG                   RawDataLength;                      // +0x0C (12)
    ULONGLONG               Reserved1;                          // +0x10 (16)
    ULONGLONG               Context;                            // +0x18 (24)
    WHEA_ERROR_TYPE         ErrorType;                          // +0x20 (32)
    WHEA_ERROR_SEVERITY     ErrorSeverity;                      // +0x24 (36)
    ULONG                   ErrorSourceId;                      // +0x28 (40)
    WHEA_ERROR_SOURCE_TYPE  ErrorSourceType;                    // +0x2C (44)
    ULONG                   Reserved2;                          // +0x30 (48)
    ULONG                   Version;                            // +0x34 (52)
    ULONGLONG               Cpu;                                // +0x38 (56)
    union {
        WHEA_PROCESSOR_GENERIC_ERROR_SECTION    ProcessorError; // +0x40 (64)
        WHEA_MEMORY_ERROR_SECTION               MemoryError;
        WHEA_NMI_ERROR_SECTION                  NmiError;
        WHEA_PCIEXPRESS_ERROR_SECTION           PciExpressError;
        WHEA_PCIXBUS_ERROR_SECTION              PciXBusError;
        WHEA_PCIXDEVICE_ERROR_SECTION           PciXDeviceError;
        WHEA_PMEM_ERROR_SECTION                 PmemError;
    } u;
    WHEA_RAW_DATA_FORMAT     RawDataFormat;                     // +0x110 (272)
    ULONG                    RawDataOffset;                     // +0x114 (276)
    UCHAR                    RawData[1];                        // +0x118 (280)

} WHEA_ERROR_PACKET_V1, *PWHEA_ERROR_PACKET_V1;

#define WHEA_ERROR_PACKET_V1_SIGNATURE  'tPrE'
#define WHEA_ERROR_PACKET_V1_VERSION    2

typedef struct _WHEA_ERROR_PACKET_V2 {
    ULONG Signature;
    ULONG Version;
    ULONG Length;
    WHEA_ERROR_PACKET_FLAGS Flags;
    WHEA_ERROR_TYPE ErrorType;
    WHEA_ERROR_SEVERITY ErrorSeverity;
    ULONG ErrorSourceId;
    WHEA_ERROR_SOURCE_TYPE ErrorSourceType;
    GUID NotifyType;
    ULONGLONG Context;
    WHEA_ERROR_PACKET_DATA_FORMAT DataFormat;
    ULONG Reserved1;
    ULONG DataOffset;
    ULONG DataLength;
    ULONG PshedDataOffset;
    ULONG PshedDataLength;
    // UCHAR Data[ANYSIZE_ARRAY];
    // UCHAR PshedData[ANYSIZE_ARRAY];
} WHEA_ERROR_PACKET_V2, *PWHEA_ERROR_PACKET_V2;

CPER_FIELD_CHECK(WHEA_ERROR_PACKET_V2, Signature,         0,   4);
CPER_FIELD_CHECK(WHEA_ERROR_PACKET_V2, Version,           4,   4);
CPER_FIELD_CHECK(WHEA_ERROR_PACKET_V2, Length,            8,   4);
CPER_FIELD_CHECK(WHEA_ERROR_PACKET_V2, Flags,            12,   4);
CPER_FIELD_CHECK(WHEA_ERROR_PACKET_V2, ErrorType,        16,   4);
CPER_FIELD_CHECK(WHEA_ERROR_PACKET_V2, ErrorSeverity,    20,   4);
CPER_FIELD_CHECK(WHEA_ERROR_PACKET_V2, ErrorSourceId,    24,   4);
CPER_FIELD_CHECK(WHEA_ERROR_PACKET_V2, ErrorSourceType,  28,   4);
CPER_FIELD_CHECK(WHEA_ERROR_PACKET_V2, NotifyType,       32,  16);
CPER_FIELD_CHECK(WHEA_ERROR_PACKET_V2, Context,          48,   8);
CPER_FIELD_CHECK(WHEA_ERROR_PACKET_V2, DataFormat,       56,   4);
CPER_FIELD_CHECK(WHEA_ERROR_PACKET_V2, Reserved1,        60,   4);
CPER_FIELD_CHECK(WHEA_ERROR_PACKET_V2, DataOffset,       64,   4);
CPER_FIELD_CHECK(WHEA_ERROR_PACKET_V2, DataLength,       68,   4);
CPER_FIELD_CHECK(WHEA_ERROR_PACKET_V2, PshedDataOffset,  72,   4);
CPER_FIELD_CHECK(WHEA_ERROR_PACKET_V2, PshedDataLength,  76,   4);

#define WHEA_ERROR_PACKET_V2_SIGNATURE 'AEHW'
#define WHEA_ERROR_PACKET_V2_VERSION   3

#if (NTDDI_VERSION >= NTDDI_WIN7)

#define WHEA_ERROR_PACKET_SIGNATURE     WHEA_ERROR_PACKET_V2_SIGNATURE
#define WHEA_ERROR_PACKET_VERSION       WHEA_ERROR_PACKET_V2_VERSION
typedef struct _WHEA_ERROR_PACKET_V2    WHEA_ERROR_PACKET, *PWHEA_ERROR_PACKET;

#else

#define WHEA_ERROR_PACKET_SIGNATURE     WHEA_ERROR_PACKET_V1_SIGNATURE
#define WHEA_ERROR_PACKET_VERSION       WHEA_ERROR_PACKET_V1_VERSION
#define WHEA_ERROR_PKT_SIGNATURE        WHEA_ERROR_PACKET_SIGNATURE
#define WHEA_ERROR_PKT_VERSION          WHEA_ERROR_PACKET_VERSION
typedef struct _WHEA_ERROR_PACKET_V1    WHEA_ERROR_PACKET, *PWHEA_ERROR_PACKET;

#endif

#define WHEA_ERROR_LOG_ENTRY_KERNEL 'LNRK'
#define WHEA_ERROR_LOG_ENTRY_HYPERV 'PVYH'
#define WHEA_ERROR_LOG_ENTRY_HAL    ' LAH'
#define WHEA_ERROR_LOG_ENTRY_PCI    ' ICP'
#define WHEA_ERROR_LOG_ENTRY_ACPI   'IPCA'
#define WHEA_ERROR_LOG_ENTRY_PSHED  'DHSP'
#define WHEA_ERROR_LOG_ENTRY_PSHED_PI 'IPSP'

typedef enum _WHEA_EVENT_LOG_ENTRY_TYPE {
    WheaEventLogEntryTypeInformational = 0,
    WheaEventLogEntryTypeWarning,
    WheaEventLogEntryTypeError
} WHEA_EVENT_LOG_ENTRY_TYPE, *PWHEA_EVENT_LOG_ENTRY_TYPE;

typedef enum _WHEA_EVENT_LOG_ENTRY_ID {
    WheaEventLogEntryIdCmcPollingTimeout       = 0x80000001,
    WheaEventLogEntryIdWheaInit                = 0x80000002,
    WheaEventLogEntryIdCmcSwitchToPolling      = 0x80000003,
    WheaEventLogEntryIdDroppedCorrectedError   = 0x80000004,
    WheaEventLogEntryIdStartedReportHwError    = 0x80000005, //SEL only
    WheaEventLogEntryIdPFAMemoryOfflined       = 0x80000006,
    WheaEventLogEntryIdPFAMemoryRemoveMonitor  = 0x80000007,
    WheaEventLogEntryIdPFAMemoryPolicy         = 0x80000008,
    WheaEventLogEntryIdPshedInjectError        = 0x80000009,
    WheaEventLogEntryIdOscCapabilities         = 0x8000000a,
    WheaEventLogEntryIdPshedPluginRegister     = 0x8000000b,
    WheaEventLogEntryIdAddRemoveErrorSource    = 0x8000000c,
    WheaEventLogEntryIdWorkQueueItem           = 0x8000000d,
    WheaEventLogEntryIdAttemptErrorRecovery    = 0x8000000e,
    WheaEventLogEntryIdMcaFoundErrorInBank     = 0x8000000f,
    WheaEventLogEntryIdMcaStuckErrorCheck      = 0x80000010,
    WheaEventLogEntryIdMcaErrorCleared         = 0x80000011,
    WheaEventLogEntryIdClearedPoison           = 0x80000012,
    WheaEventLogEntryIdProcessEINJ             = 0x80000013,
    WheaEventLogEntryIdProcessHEST             = 0x80000014,
    WheaEventLogEntryIdCreateGenericRecord     = 0x80000015,
    WheaEventLogEntryIdErrorRecord             = 0x80000016,
    WheaEventLogEntryIdErrorRecordLimit        = 0x80000017,
    WheaEventLogEntryIdAerNotGrantedToOs       = 0x80000018,
    WheaEventLogEntryIdErrSrcArrayInvalid      = 0x80000019,
    WheaEventLogEntryIdAcpiTimeOut             = 0x8000001a,
    WheaEventLogCmciRestart                    = 0x8000001b,
    WheaEventLogCmciFinalRestart               = 0x8000001c,
    WheaEventLogEntryEtwOverFlow               = 0x8000001d,
    WheaEventLogAzccRootBusSearchErr           = 0x8000001e,
    WheaEventLogAzccRootBusList                = 0x8000001f,
    WheaEventLogEntryIdErrSrcInvalid           = 0x80000020,
    WheaEventLogEntryIdGenericErrMemMap        = 0x80000021,
    WheaEventLogEntryIdPshedCallbackCollision  = 0x80000022,
    WheaEventLogEntryIdSELBugCheckProgress     = 0x80000023,
    WheaEventLogEntryIdPshedPluginLoad         = 0x80000024,
    WheaEventLogEntryIdPshedPluginUnload       = 0x80000025,
    WheaEventLogEntryIdPshedPluginSupported    = 0x80000026,
    WheaEventLogEntryIdDeviceDriver            = 0x80000027,
    WheaEventLogEntryIdCmciImplPresent         = 0x80000028,
    WheaEventLogEntryIdCmciInitError           = 0x80000029,
    WheaEventLogEntryIdSELBugCheckRecovery     = 0x8000002a,
    WheaEventLogEntryIdDrvErrSrcInvalid        = 0x8000002b,
    WheaEventLogEntryIdDrvHandleBusy           = 0x8000002c,
    WheaEventLogEntryIdWheaHeartbeat           = 0x8000002d,
    WheaEventLogAzccRootBusPoisonSet           = 0x8000002e,
    WheaEventLogEntryIdSELBugCheckInfo         = 0x8000002f,
    WheaEventLogEntryIdErrDimmInfoMismatch     = 0x80000030,
    WheaEventLogEntryIdeDpcEnabled             = 0x80000031,
    WheaEventLogEntryPageOfflineDone           = 0x80000032,
    WheaEventLogEntryPageOfflinePendMax        = 0x80000033,
    WheaEventLogEntryIdBadPageLimitReached     = 0x80000034,
    WheaEventLogEntrySrarDetail                = 0x80000035,
    WheaEventLogEntryEarlyError                = 0x80000036,
    WheaEventLogEntryIdPcieOverrideInfo        = 0x80000037,
    WheaEventLogEntryIdReadPcieOverridesErr    = 0x80000038,
    WheaEventLogEntryIdPcieConfigInfo          = 0x80000039,
    WheaEventLogEntryIdPcieSummaryFailed       = 0x80000040,
    WheaEventLogEntryIdThrottleRegCorrupt      = 0x80000041,
    WheaEventLogEntryIdThrottleAddErrSrcFailed = 0x80000042,
    WheaEventLogEntryIdThrottleRegDataIgnored  = 0x80000043,
    WheaEventLogEntryIdEnableKeyNotifFailed    = 0x80000044,
    WheaEventLogEntryIdKeyNotificationFailed   = 0x80000045,
    WheaEventLogEntryIdPcieRemoveDevice        = 0x80000046,
    WheaEventLogEntryIdPcieAddDevice           = 0x80000047,
    WheaEventLogEntryIdPcieSpuriousErrSource   = 0x80000048,
    WheaEventLogEntryIdMemoryAddDevice         = 0x80000049,
    WheaEventLogEntryIdMemoryRemoveDevice      = 0x8000004a,
    WheaEventLogEntryIdMemorySummaryFailed     = 0x8000004b,
    WheaEventLogEntryIdPcieDpcError            = 0x8000004c,
    WheaEventLogEntryIdCpuBusesInitFailed      = 0x8000004d,
    WheaEventLogEntryIdPshedPluginInitFailed   = 0x8000004e,
    WheaEventLogEntryIdFailedAddToDefectList   = 0x8000004f,
    WheaEventLogEntryIdDefectListFull          = 0x80000050,
    WheaEventLogEntryIdDefectListUEFIVarFailed = 0x80000051,
    WheaEventLogEntryIdDefectListCorrupt       = 0x80000052,
    WheaEventLogEntryIdBadHestNotifyData       = 0x80000053,
    WheaEventLogEntryIdRowFailure              = 0x80000054,
    WheaEventLogEntryIdSrasTableNotFound       = 0x80000055,
    WheaEventLogEntryIdSrasTableError          = 0x80000056,
    WheaEventLogEntryIdSrasTableEntries        = 0x80000057,
    WheaEventLogEntryIdPFANotifyCallbackAction = 0x80000058,
    WheaEventLogEntryIdSELBugCheckCpusQuiesced = 0x80000059,
    WheaEventLogEntryIdPshedPiCpuid            = 0x8000005a,
    WheaEventLogEntryIdSrasTableBadData        = 0x8000005b,
    WheaEventLogEntryIdDriFsStatus             = 0x8000005c,
    WheaEventLogEntryIdCpusFrozen              = 0x80000060,
    WheaEventLogEntryIdCpusFrozenNoCrashDump   = 0x80000061,
    WheaEventLogEntryIdRegNotifyPolicyChange   = 0x80000062,
    WheaEventLogEntryIdRegError                = 0x80000063,
    WheaEventLogEntryIdRowOfflineEvent         = 0x80000064,
    WheaEventLogEntryIdBitOfflineEvent         = 0x80000065,
    WheaEventLogEntryIdBadGasFields            = 0x80000066,
    WheaEventLogEntryIdCrashDumpError                   = 0x80000067,
    WheaEventLogEntryIdCrashDumpCheckpoint              = 0x80000068,
    WheaEventLogEntryIdCrashDumpProgressPercent         = 0x80000069,
    WheaEventLogEntryIdPreviousCrashBugCheckProgress    = 0x8000006a,
    WheaEventLogEntryIdSELBugCheckStackDump             = 0x8000006b,
    WheaEventLogEntryIdPciePromotedAerErr      = 0x8000006c,
    WheaEventLogEntryIdPshedPiTraceLog         = 0x80040010
} WHEA_EVENT_LOG_ENTRY_ID, *PWHEA_EVENT_LOG_ENTRY_ID;

typedef union _WHEA_EVENT_LOG_ENTRY_FLAGS {
    struct {
        ULONG Reserved1:1;
        ULONG LogInternalEtw:1;
        ULONG LogBlackbox:1;
        ULONG LogSel:1;
        ULONG RawSel:1;
        ULONG NoFormat:1;
        ULONG Driver:1;
        ULONG Reserved2:25;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_EVENT_LOG_ENTRY_FLAGS, *PWHEA_EVENT_LOG_ENTRY_FLAGS;

typedef struct _WHEA_EVENT_LOG_ENTRY_HEADER {
    ULONG Signature;
    ULONG Version;
    ULONG Length;
    WHEA_EVENT_LOG_ENTRY_TYPE Type;
    ULONG OwnerTag;
    WHEA_EVENT_LOG_ENTRY_ID Id;
    WHEA_EVENT_LOG_ENTRY_FLAGS Flags;
    ULONG PayloadLength;
} WHEA_EVENT_LOG_ENTRY_HEADER, *PWHEA_EVENT_LOG_ENTRY_HEADER;

typedef struct _WHEA_EVENT_LOG_ENTRY {
    WHEA_EVENT_LOG_ENTRY_HEADER Header;
    // UCHAR Data[ANYSIZE_ARRAY];
} WHEA_EVENT_LOG_ENTRY, *PWHEA_EVENT_LOG_ENTRY;

typedef struct _WHEAP_DEFERRED_EVENT {
    LIST_ENTRY ListEntry;
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
} WHEAP_DEFERRED_EVENT, *PWHEAP_DEFERRED_EVENT;

#define WHEA_ERROR_LOG_ENTRY_SIGNATURE  'gLhW'
#define WHEA_ERROR_LOG_ENTRY_VERSION    1
#define WHEA_ERROR_TEXT_LEN 32

typedef struct _WHEAP_BAD_HEST_NOTIFY_DATA_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    USHORT SourceId;
    USHORT Reserved;
    WHEA_NOTIFICATION_DESCRIPTOR NotifyDesc;
} WHEAP_BAD_HEST_NOTIFY_DATA_EVENT, *PWHEAP_BAD_HEST_NOTIFY_DATA_EVENT;

typedef struct _WHEAP_STARTED_REPORT_HW_ERROR {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    PWHEA_ERROR_PACKET ErrorPacket;
} WHEAP_STARTED_REPORT_HW_ERROR,
  *PWHEAP_STARTED_REPORT_HW_ERROR;

typedef enum _WHEA_RECOVERY_CONTEXT_ACTION_TAKEN {
    WheaRecoveryContextActionTakenNone = 0,
    WheaRecoveryContextActionTakenOfflineDemotion,
    WheaRecoveryContextActionTakenPageNotReplaced,
    WheaRecoveryContextActionTakenPageReplaced,
    WheaRecoveryContextActionTakenMax
} WHEA_RECOVERY_CONTEXT_ACTION_TAKEN, *PWHEA_RECOVERY_CONTEXT_ACTION_TAKEN;

typedef union _WHEA_RECOVERY_CONTEXT_ACTION_TAKEN_ADDITIONAL_INFO {
    struct {
        ULONG64 Reserved: 64;
    } Bits;

    ULONG64 AsULONG64;
} WHEA_RECOVERY_CONTEXT_ACTION_TAKEN_ADDITIONAL_INFO,
  *PWHEA_RECOVERY_CONTEXT_ACTION_TAKEN_ADDITIONAL_INFO;

typedef enum _WHEAP_PFA_OFFLINE_DECISION_TYPE {
    WheapPfaOfflinePredictiveFailure = 1,
    WheapPfaOfflineUncorrectedError = 2
} WHEAP_PFA_OFFLINE_DECISION_TYPE, *PWHEAP_PFA_OFFLINE_DECISION_TYPE;

typedef struct _WHEAP_PFA_MEMORY_OFFLINED {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    WHEAP_PFA_OFFLINE_DECISION_TYPE DecisionType;
    BOOLEAN ImmediateSuccess;
    ULONG Page;
    BOOLEAN NotifyVid;
} WHEAP_PFA_MEMORY_OFFLINED,
  *PWHEAP_PFA_MEMORY_OFFLINED;

typedef struct _WHEAP_PFA_MEMORY_OFFLINED_NOTIFY_CALLBACK_ACTION {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    ULONG Page;
    ULONG ComponentTag;
    NTSTATUS Status;
    WHEA_RECOVERY_CONTEXT_ACTION_TAKEN ActionTaken;
    WHEA_RECOVERY_CONTEXT_ACTION_TAKEN_ADDITIONAL_INFO ActionTakenAdditionalInfo;
} WHEAP_PFA_MEMORY_OFFLINED_NOTIFY_CALLBACK_ACTION,
  *PWHEAP_PFA_MEMORY_OFFLINED_NOTIFY_CALLBACK_ACTION;

typedef struct _WHEAP_PSHED_INJECT_ERROR {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    ULONG ErrorType;
    ULONGLONG Parameter1;
    ULONGLONG Parameter2;
    ULONGLONG Parameter3;
    ULONGLONG Parameter4;
    NTSTATUS InjectionStatus;
    BOOLEAN InjectionAttempted;
    BOOLEAN InjectionByPlugin;
} WHEAP_PSHED_INJECT_ERROR,
  *PWHEAP_PSHED_INJECT_ERROR;

typedef struct _WHEAP_OSC_IMPLEMENTED {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    BOOLEAN OscImplemented;
    BOOLEAN DebugChecked;
} WHEAP_OSC_IMPLEMENTED,
  *PWHEAP_OSC_IMPLEMENTED;

typedef struct _WHEAP_PSHED_PLUGIN_REGISTER {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    ULONG Version;
    ULONG Length;
    ULONG FunctionalAreaMask;
    NTSTATUS Status;
} WHEAP_PSHED_PLUGIN_REGISTER,
  *PWHEAP_PSHED_PLUGIN_REGISTER;

typedef enum _WHEA_PFA_REMOVE_TRIGGER {
    WheaPfaRemoveErrorThreshold = 1,
    WheaPfaRemoveTimeout = 2,
    WheaPfaRemoveCapacity = 3
} WHEA_PFA_REMOVE_TRIGGER, *PWHEA_PFA_REMOVE_TRIGGER;

typedef struct _WHEAP_PFA_MEMORY_REMOVE_MONITOR {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    WHEA_PFA_REMOVE_TRIGGER RemoveTrigger;
    ULONG TimeInList;
    ULONG ErrorCount ;
    ULONG Page;
} WHEAP_PFA_MEMORY_REMOVE_MONITOR,
  *PWHEAP_PFA_MEMORY_REMOVE_MONITOR;

typedef struct _WHEAP_PFA_MEMORY_POLICY {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    ULONG RegistryKeysPresent;
    BOOLEAN DisableOffline;
    BOOLEAN PersistOffline;
    BOOLEAN PfaDisabled;
    ULONG PageCount;
    ULONG ErrorThreshold;
    ULONG TimeOut;
} WHEAP_PFA_MEMORY_POLICY,
  *PWHEAP_PFA_MEMORY_POLICY;

typedef struct _WHEAP_DROPPED_CORRECTED_ERROR_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    WHEA_ERROR_SOURCE_TYPE ErrorSourceType;
    ULONG ErrorSourceId;
} WHEAP_DROPPED_CORRECTED_ERROR_EVENT,
  *PWHEAP_DROPPED_CORRECTED_ERROR_EVENT;

typedef struct _WHEAP_CLEARED_POISON_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    ULONG64 PhysicalAddress;
} WHEAP_CLEARED_POISON_EVENT, *PWHEAP_CLEARED_POISON_EVENT;

typedef struct _WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    WHEA_ERROR_SOURCE_DESCRIPTOR Descriptor;
    NTSTATUS Status;
    BOOLEAN IsRemove;
} WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT, *PWHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT;

typedef struct _WHEAP_ATTEMPT_RECOVERY_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    WHEA_ERROR_RECORD_HEADER ErrorHeader;
    BOOLEAN ArchitecturalRecovery;
    BOOLEAN PshedRecovery;
    NTSTATUS Status;
} WHEAP_ATTEMPT_RECOVERY_EVENT, *PWHEAP_ATTEMPT_RECOVERY_EVENT;

typedef struct _WHEAP_FOUND_ERROR_IN_BANK_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    ULONG EpIndex;
    ULONG Bank;
    ULONG64 MciStatus;
    ULONG ErrorType;
} WHEAP_FOUND_ERROR_IN_BANK_EVENT, *PWHEAP_FOUND_ERROR_IN_BANK_EVENT;

typedef struct _WHEAP_STUCK_ERROR_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    ULONG EpIndex;
    ULONG Bank;
    ULONG64 MciStatus;
} WHEAP_STUCK_ERROR_EVENT, *PWHEAP_STUCK_ERROR_EVENT;

typedef struct _WHEAP_ERROR_CLEARED_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    ULONG EpIndex;
    ULONG Bank;
} WHEAP_ERROR_CLEARED_EVENT, *PWHEAP_ERROR_CLEARED_EVENT;

typedef struct _WHEAP_PROCESS_EINJ_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    CHAR Error[WHEA_ERROR_TEXT_LEN];
    BOOLEAN InjectionActionTableValid;
    ULONG BeginInjectionInstructionCount;
    ULONG GetTriggerErrorActionTableInstructionCount;
    ULONG SetErrorTypeInstructionCount;
    ULONG GetErrorTypeInstructionCount;
    ULONG EndOperationInstructionCount;
    ULONG ExecuteOperationInstructionCount;
    ULONG CheckBusyStatusInstructionCount;
    ULONG GetCommandStatusInstructionCount;
    ULONG SetErrorTypeWithAddressInstructionCount;
    ULONG GetExecuteOperationTimingsInstructionCount;
} WHEAP_PROCESS_EINJ_EVENT, *PWHEAP_PROCESS_EINJ_EVENT;

typedef struct _WHEAP_PROCESS_HEST_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    CHAR Error[WHEA_ERROR_TEXT_LEN];
    CHAR EntryType[WHEA_ERROR_TEXT_LEN];
    ULONG EntryIndex;
    BOOLEAN HestValid;
    ULONG CmcCount;
    ULONG MceCount;
    ULONG NmiCount;
    ULONG AerRootCount;
    ULONG AerBridgeCount;
    ULONG AerEndPointCount;
    ULONG GenericV1Count;
    ULONG GenericV2Count;
} WHEAP_PROCESS_HEST_EVENT, *PWHEAP_PROCESS_HEST_EVENT;

typedef struct _WHEAP_CREATE_GENERIC_RECORD_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    CHAR Error[WHEA_ERROR_TEXT_LEN];
    ULONG EntryCount;
    NTSTATUS Status;
} WHEAP_CREATE_GENERIC_RECORD_EVENT, *PWHEAP_CREATE_GENERIC_RECORD_EVENT;

typedef struct _WHEAP_ERROR_RECORD_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    PWHEA_ERROR_RECORD Record;
} WHEAP_ERROR_RECORD_EVENT, *PWHEAP_ERROR_RECORD_EVENT;

typedef struct _WHEAP_ERR_SRC_ARRAY_INVALID_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    ULONG ErrorSourceCount;
    ULONG ReportedLength;
    ULONG ExpectedLength;
} WHEAP_ERR_SRC_ARRAY_INVALID_EVENT, *PWHEAP_ERR_SRC_ARRAY_INVALID_EVENT;

typedef struct _WHEAP_ERR_SRC_INVALID_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    WHEA_ERROR_SOURCE_DESCRIPTOR ErrDescriptor;
    CHAR Error[WHEA_ERROR_TEXT_LEN];
} WHEAP_ERR_SRC_INVALID_EVENT, *PWHEAP_ERR_SRC_INVALID_EVENT;

typedef struct _WHEAP_GENERIC_ERR_MEM_MAP_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    CHAR MapReason[WHEA_ERROR_TEXT_LEN];
    ULONG64 PhysicalAddress;
    ULONG64 Length;
} WHEAP_GENERIC_ERR_MEM_MAP_EVENT, *PWHEAP_GENERIC_ERR_MEM_MAP_EVENT;

typedef struct _WHEAP_ACPI_TIMEOUT_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    CHAR TableType[WHEA_ERROR_TEXT_LEN];
    CHAR TableRequest[WHEA_ERROR_TEXT_LEN];
} WHEAP_ACPI_TIMEOUT_EVENT, *PWHEAP_ACPI_TIMEOUT_EVENT;

typedef struct _WHEAP_CMCI_RESTART_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    ULONG CmciRestoreAttempts;
    ULONG MaxCmciRestoreLimit;
    ULONG MaxCorrectedErrorsFound;
    ULONG MaxCorrectedErrorLimit;
} WHEAP_CMCI_RESTART_EVENT, *PWHEAP_CMCI_RESTART_EVENT;

typedef struct _WHEA_SEL_BUGCHECK_PROGRESS {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    ULONG BugCheckCode;
    ULONG BugCheckProgressSummary;
} WHEA_SEL_BUGCHECK_PROGRESS, *PWHEA_SEL_BUGCHECK_PROGRESS;

typedef struct _WHEA_SEL_BUGCHECK_RECOVERY_STATUS_START_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    KIRQL StartingIrql;
} WHEA_SEL_BUGCHECK_RECOVERY_STATUS_START_EVENT,
    *PWHEA_SEL_BUGCHECK_RECOVERY_STATUS_START_EVENT;

#define WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE1_VERSION 1

typedef struct _WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE1_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    BOOLEAN Success;
    UCHAR Version;
    USHORT EntryCount;
    struct {

        //
        // Version 1 Information.
        //

        UCHAR DumpPolicy;
        UCHAR Reserved[3];
    } Data;
} WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE1_EVENT,
    *PWHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE1_EVENT;

typedef struct _WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE2_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    ULONG BootId;
    BOOLEAN Success;
} WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE2_EVENT,
    *PWHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE2_EVENT;

typedef struct _WHEA_SEL_BUGCHECK_RECOVERY_STATUS_MULTIPLE_BUGCHECK_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    BOOLEAN IsBugcheckOwner;
    UCHAR RecursionCount;
    BOOLEAN IsBugcheckRecoveryOwner;
} WHEA_SEL_BUGCHECK_RECOVERY_STATUS_MULTIPLE_BUGCHECK_EVENT,
    *PWHEA_SEL_BUGCHECK_RECOVERY_STATUS_MULTIPLE_BUGCHECK_EVENT;

typedef struct _WHEA_PSHED_PLUGIN_LOAD_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    WCHAR PluginName[WHEA_ERROR_TEXT_LEN];
    ULONG MajorVersion;
    ULONG MinorVersion;
} WHEA_PSHED_PLUGIN_LOAD_EVENT, *PWHEA_PSHED_PLUGIN_LOAD_EVENT;

typedef struct _WHEA_PSHED_PLUGIN_UNLOAD_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    WCHAR PluginName[WHEA_ERROR_TEXT_LEN];
} WHEA_PSHED_PLUGIN_UNLOAD_EVENT, *PWHEA_PSHED_PLUGIN_UNLOAD_EVENT;

typedef enum _WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_ERRORS {
    PshedPiEnableNotifyErrorCreateNotifyEvent = 1,
    PshedPiEnableNotifyErrorCreateSystemThread,
    PshedPiEnableNotifyErrorMax
} WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_ERRORS,
    *PWHEA_PSHED_PLUGIN_ENABLE_NOTIFY_ERRORS;

typedef struct _WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_FAILED_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_ERRORS EnableError;
} WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_FAILED_EVENT,
    *PWHEA_PSHED_PLUGIN_ENABLE_NOTIFY_FAILED_EVENT;

typedef struct _WHEA_PSHED_PLUGIN_PLATFORM_SUPPORT_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    WCHAR PluginName[WHEA_ERROR_TEXT_LEN];
    BOOLEAN Supported;
} WHEA_PSHED_PLUGIN_PLATFORM_SUPPORT_EVENT,
    *PWHEA_PSHED_PLUGIN_PLATFORM_SUPPORT_EVENT;

typedef struct _WHEA_PSHED_PLUGIN_INIT_FAILED_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    NTSTATUS Status;
} WHEA_PSHED_PLUGIN_INIT_FAILED_EVENT,
    *PWHEA_PSHED_PLUGIN_INIT_FAILED_EVENT;

typedef struct _WHEA_PSHED_PLUGIN_HEARTBEAT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
} WHEA_PSHED_PLUGIN_HEARTBEAT, *PWHEA_PSHED_PLUGIN_HEARTBEAT;

typedef struct _WHEA_PSHED_PLUGIN_DIMM_MISMATCH {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    UINT16 FirmwareBank;
    UINT16 FirmwareCol;
    UINT16 FirmwareRow;
    UINT16 RetryRdBank;
    UINT16 RetryRdCol;
    UINT16 RetryRdRow;
    UINT16 TaBank;
    UINT16 TaCol;
    UINT16 TaRow;
} WHEA_PSHED_PLUGIN_DIMM_MISMATCH, *PWHEA_PSHED_PLUGIN_DIMM_MISMATCH;

typedef struct _WHEA_ETW_OVERFLOW_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    ULONGLONG RecordId;
} WHEA_ETW_OVERFLOW_EVENT, *PWHEA_ETW_OVERFLOW_EVENT;

typedef struct _WHEAP_CMCI_IMPLEMENTED_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    BOOLEAN CmciAvailable;
} WHEAP_CMCI_IMPLEMENTED_EVENT,
    *PWHEAP_CMCI_IMPLEMENTED_EVENT;

typedef struct _WHEAP_DEVICE_DRV_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    CHAR Function[WHEA_ERROR_TEXT_LEN];
} WHEAP_DEVICE_DRV_EVENT, *PWHEAP_DEVICE_DRV_EVENT;

typedef struct _WHEAP_PLUGIN_PFA_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    BOOLEAN NoFurtherPfa;
} WHEAP_PLUGIN_PFA_EVENT, *PWHEAP_PLUGIN_PFA_EVENT;

typedef struct _WHEAP_CMCI_INITERR_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    ULONGLONG Msr;
    ULONG Type;
    ULONG Bank;
    ULONG EpIndex;
} WHEAP_CMCI_INITERR_EVENT,
    *PWHEAP_CMCI_INITERR_EVENT;

typedef struct _WHEA_AZCC_ROOT_BUS_ERR_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    BOOLEAN MaxBusCountPassed;
    BOOLEAN InvalidBusMSR;
} WHEA_AZCC_ROOT_BUS_ERR_EVENT, *PWHEA_AZCC_ROOT_BUS_ERR_EVENT;

typedef struct _WHEA_AZCC_ROOT_BUS_LIST_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    UINT32 RootBusCount;
    UINT32 RootBuses[8];
} WHEA_AZCC_ROOT_BUS_LIST_EVENT, *PWHEA_AZCC_ROOT_BUS_LIST_EVENT;

typedef struct _WHEA_AZCC_SET_POISON_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    UINT32 Bus;
    BOOLEAN ReadSuccess;
    BOOLEAN WriteSuccess;
    BOOLEAN IsEnable;
} WHEA_AZCC_SET_POISON_EVENT, *PWHEA_AZCC_SET_POISON_EVENT;

typedef struct _WHEA_OFFLINE_DONE_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    ULONG64 Address;
} WHEA_OFFLINE_DONE_EVENT, *PWHEA_OFFLINE_DONE_EVENT;

typedef enum _WHEA_BUGCHECK_RECOVERY_LOG_TYPE {
    WheaEventBugCheckRecoveryEntry,
    WheaEventBugCheckRecoveryReturn,
    WheaEventBugCheckRecoveryMax,
} WHEA_BUGCHECK_RECOVERY_LOG_TYPE, *PWHEA_BUGCHECK_RECOVERY_LOG_TYPE;

typedef struct _WHEAP_EDPC_ENABLED_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    BOOLEAN eDPCEnabled;
    BOOLEAN eDPCRecovEnabled;
} WHEAP_EDPC_ENABLED_EVENT, *PWHEAP_EDPC_ENABLED_EVENT;

typedef struct _WHEA_SRAR_DETAIL_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    UINT32 RecoveryContextFlags;
    UINT64 RecoveryContextPa;
    NTSTATUS PageOfflineStatus;
    BOOLEAN KernelConsumerError;
} WHEA_SRAR_DETAIL_EVENT, *PWHEA_SRAR_DETAIL_EVENT;

typedef struct _WHEA_FAILED_ADD_DEFECT_LIST_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
} WHEA_FAILED_ADD_DEFECT_LIST_EVENT, *PWHEA_FAILED_ADD_DEFECT_LIST_EVENT;

typedef struct _WHEAP_PLUGIN_DEFECT_LIST_FULL_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
} WHEAP_PLUGIN_DEFECT_LIST_FULL_EVENT,
      *PWHEAP_PLUGIN_DEFECT_LIST_FULL_EVENT;

typedef struct _WHEAP_PLUGIN_DEFECT_LIST_UEFI_VAR_FAILED {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
} WHEAP_PLUGIN_DEFECT_LIST_UEFI_VAR_FAILED,
      *PWHEAP_PLUGIN_DEFECT_LIST_UEFI_VAR_FAILED;

typedef struct _WHEAP_PLUGIN_DEFECT_LIST_CORRUPT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
} WHEAP_PLUGIN_DEFECT_LIST_CORRUPT,
      *PWHEAP_PLUGIN_DEFECT_LIST_CORRUPT;

typedef struct _WHEAP_SPURIOUS_AER_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    WHEA_ERROR_SEVERITY ErrorSeverity;

    //
    // N.B. Must be one of PciExpressRootPort, PciExpressDownstreamSwitchPort or
    // PciExpressRootComplexEventCollector.
    //

    ULONG ErrorHandlerType;
    ULONG SpuriousErrorSourceId;
    ULONG RootErrorCommand;
    ULONG RootErrorStatus;
    ULONG DeviceAssociationBitmap;
} WHEAP_SPURIOUS_AER_EVENT, *PWHEAP_SPURIOUS_AER_EVENT;

typedef struct _WHEAP_PROMOTED_AER_ERROR_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    WHEA_ERROR_SEVERITY ErrorSeverity;
    ULONG ErrorHandlerType;
    ULONG ErrorSourceId;
    ULONG RootErrorCommand;
    ULONG RootErrorStatus;
    ULONG DeviceAssociationBitmap;
} WHEAP_PROMOTED_AER_ERROR_EVENT, *PWHEAP_PROMOTED_AER_ERROR_EVENT;

typedef enum _WHEAP_DPC_ERROR_EVENT_TYPE {
    WheapDpcErrNoErr = 0,
    WheapDpcErrBusNotFound,
    WheapDpcErrDpcedSubtree,
    WheapDpcErrDeviceIdBad,
    WheapDpcErrResetFailed,
    WheapDpcErrNoChildren,
} WHEAP_DPC_ERROR_EVENT_TYPE, *PWHEAP_DPC_ERROR_EVENT_TYPE;

typedef struct _WHEAP_DPC_ERROR_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    WHEAP_DPC_ERROR_EVENT_TYPE ErrType;
    ULONG Bus;
    ULONG Device;
    ULONG Function;
    USHORT DeviceId;
    USHORT VendorId;
} WHEAP_DPC_ERROR_EVENT, *PWHEAP_DPC_ERROR_EVENT;

typedef enum _PSHED_PI_ERR_READING_PCIE_OVERRIDES {
    PshedPiErrReadingPcieOverridesNoErr = 0,
    PshedPiErrReadingPcieOverridesNoMemory,
    PshedPiErrReadingPcieOverridesQueryErr,
    PshedPiErrReadingPcieOverridesBadSize,
    PshedPiErrReadingPcieOverridesBadSignature,
    PshedPiErrReadingPcieOverridesNoCapOffset,
    PshedPiErrReadingPcieOverridesNotBinary,
} PSHED_PI_ERR_READING_PCIE_OVERRIDES,
    *PPSHED_PI_ERR_READING_PCIE_OVERRIDES;

typedef struct _WHEAP_PCIE_OVERRIDE_INFO {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    UINT32 Segment;
    UINT32 Bus;
    UINT32 Device;
    UINT32 Function;
    UINT8 ValidBits;
    UINT8 Reserved[3];
    UINT32 UncorrectableErrorMask;
    UINT32 UncorrectableErrorSeverity;
    UINT32 CorrectableErrorMask;
    UINT32 CapAndControl;
} WHEAP_PCIE_OVERRIDE_INFO, *PWHEAP_PCIE_OVERRIDE_INFO;

typedef struct _WHEAP_PCIE_READ_OVERRIDES_ERR {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    UINT32 FailureReason;
    NTSTATUS FailureStatus;
} WHEAP_PCIE_READ_OVERRIDES_ERR, *PWHEAP_PCIE_READ_OVERRIDES_ERR;

typedef struct _WHEAP_PCIE_CONFIG_INFO {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    UINT32 Segment;
    UINT32 Bus;
    UINT32 Device;
    UINT32 Function;
    UINT32 Offset;
    UINT32 Length;
    UINT64 Value;
    UINT8 Succeeded;
    UINT8 Reserved[3];
} WHEAP_PCIE_CONFIG_INFO, *PWHEAP_PCIE_CONFIG_INFO;

typedef struct _WHEA_THROTTLE_PCIE_ADD_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    WHEA_PCIE_ADDRESS Address;
    UINT32 Mask;
    BOOLEAN Updated;
    NTSTATUS Status;
} WHEA_THROTTLE_PCIE_ADD_EVENT, *PWHEA_THROTTLE_PCIE_ADD_EVENT;

typedef struct _WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    UINT32 SocketId;
    UINT32 ChannelId;
    UINT32 DimmSlot;
} WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT, *PWHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT;

typedef struct _WHEA_THROTTLE_PCIE_REMOVE_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    WHEA_PCIE_ADDRESS Address;
    UINT32 Mask;
} WHEA_THROTTLE_PCIE_REMOVE_EVENT, *PWHEA_THROTTLE_PCIE_REMOVE_EVENT;

typedef enum _WHEA_THROTTLE_TYPE {
    WheaPcieThrottle = 0,
    WheaMemoryThrottle
} WHEA_THROTTLE_TYPE, *PWHEA_THROTTLE_TYPE;

typedef struct _WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    WHEA_THROTTLE_TYPE ThrottleType;
} WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT,
    *PWHEA_THROTTLE_REGISTRY_CORRUPT_EVENT;

typedef struct _WHEA_THROTTLE_ADD_ERR_SRC_FAILED_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
} WHEA_THROTTLE_ADD_ERR_SRC_FAILED_EVENT,
    *PWHEA_THROTTLE_ADD_ERR_SRC_FAILED_EVENT;

typedef struct _WHEA_THROTTLE_REG_DATA_IGNORED_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    WHEA_THROTTLE_TYPE ThrottleType;
} WHEA_THROTTLE_REG_DATA_IGNORED_EVENT,
    *PWHEA_THROTTLE_REG_DATA_IGNORED_EVENT;

typedef struct _WHEA_REGISTER_KEY_NOTIFICATION_FAILED_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
} WHEA_REGISTER_KEY_NOTIFICATION_FAILED_EVENT,
    *PWHEA_REGISTER_KEY_NOTIFICATION_FAILED_EVENT;

typedef struct _WHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    NTSTATUS Status;
} WHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT,
    *PWHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT;

typedef struct _WHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    NTSTATUS Status;
} WHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT,
    *PWHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT;

typedef struct _WHEA_PSHED_PI_TRACE_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    CCHAR Buffer[256];
} WHEA_PSHED_PI_TRACE_EVENT, *PWHEA_PSHED_PI_TRACE_EVENT;

typedef struct _WHEA_SRAS_TABLE_NOT_FOUND {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
} WHEA_SRAS_TABLE_NOT_FOUND, *PWHEA_SRAS_TABLE_NOT_FOUND;

typedef struct _WHEA_SRAS_TABLE_ERROR {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
} WHEA_SRAS_TABLE_ERROR, *PWHEA_SRAS_TABLE_ERROR;

typedef struct _WHEA_PSHED_PI_CPUID {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    UINT32 CpuVendor;
    UINT32 CpuFamily;
    UINT32 CpuModel;
    UINT32 CpuStepping;
    UINT32 NumBanks;
} WHEA_PSHED_PI_CPUID, *PWHEA_PSHED_PI_CPUID;

#define WCS_RAS_REGISTER_NAME_MAX_LENGTH 32

typedef struct _WHEA_ACPI_HEADER {
  UINT32  Signature;
  UINT32  Length;
  UINT8   Revision;
  UINT8   Checksum;
  UINT8   OemId[6];
  UINT64  OemTableId;
  UINT32  OemRevision;
  UINT32  CreatorId;
  UINT32  CreatorRevision;
} WHEA_ACPI_HEADER, *PWHEA_ACPI_HEADER;

typedef struct _SIGNAL_REG_VALUE {
    UINT8 RegName[WCS_RAS_REGISTER_NAME_MAX_LENGTH];
    UINT32 MsrAddr;
    UINT64 Value;
} SIGNAL_REG_VALUE, *PSIGNAL_REG_VALUE;

typedef struct _EFI_ACPI_RAS_SIGNAL_TABLE {
    WHEA_ACPI_HEADER Header;
    UINT32 NumberRecord;
    SIGNAL_REG_VALUE Entries[ANY_SIZE];
} EFI_ACPI_RAS_SIGNAL_TABLE, *PEFI_ACPI_RAS_SIGNAL_TABLE;

typedef struct _WHEA_SRAS_TABLE_ENTRIES_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    UINT32 LogNumber;
    UINT32 NumberSignals;
    UINT8 Data[ANY_SIZE];
} WHEA_SRAS_TABLE_ENTRIES_EVENT, *PWHEA_SRAS_TABLE_ENTRIES_EVENT;

typedef struct _WHEAP_ROW_FAILURE_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    PFN_NUMBER LowOrderPage;
    PFN_NUMBER HighOrderPage;
} WHEAP_ROW_FAILURE_EVENT, * PWHEAP_ROW_FAILURE_EVENT;

typedef struct _PSHED_MEMORY_DETAILS_VALID_BITS {
    UINT32 DdrVersion: 1;
    UINT32 IsClosedPaged: 1;
    UINT32 ColsPerRow: 1;
    UINT32 PagesPerRow: 1;
    UINT32 SocketCnt: 1;
    UINT32 ChaOnSktCnt: 1;
    UINT32 DimmSlotCnt: 1;
    UINT32 SubchannelCnt: 1;
    UINT32 Reserved: 24;
} PSHED_MEMORY_DETAILS_VALID_BITS, *PPSHED_MEMORY_DETAILS_VALID_BITS;

typedef struct _PSHED_MEMORY_DETAILS {
    UINT16 Version;
    PSHED_MEMORY_DETAILS_VALID_BITS Vb;
    UINT16 DdrVersion;
    BOOLEAN IsClosedPaged;
    UINT16 ColsPerRow;
    UINT16 PagesPerRow;
    UINT8 SocketCnt;
    UINT8 ChaOnSktCnt;
    UINT8 DimmSlotCnt;
    UINT8 SubchannelCnt;
} PSHED_MEMORY_DETAILS, *PPSHED_MEMORY_DETAILS;

typedef enum _WHEA_OFFLINE_ERRS {
    WheaOfflineNoError = 0,
    GetMemoryDetailsErr,
    RatFailure,
    RatFailureFirstCol,
    RatFailureLastCol,
    ClosedPage,
    BadPageRange,
    InvalidData,
    NotDdr,
    UnsupportedDdrVersion,
    IncorrectDdrVersion,
    NoMemoryForWrapper
} WHEA_OFFLINE_ERRS, * PWHEA_OFFLINE_ERRS;

typedef struct _WHEAP_ROW_OFFLINE_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    PFN_NUMBER FirstPage;
    PFN_NUMBER LastPage;
    UINT32 Range;
    NTSTATUS Status;
    WHEA_OFFLINE_ERRS ErrorReason;
} WHEAP_ROW_OFFLINE_EVENT, * PWHEAP_ROW_OFFLINE_EVENT;

typedef struct _WHEAP_BIT_OFFLINE_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    PFN_NUMBER Page;
    NTSTATUS Status;
    WHEA_OFFLINE_ERRS ErrorReason;
} WHEAP_BIT_OFFLINE_EVENT, * PWHEAP_BIT_OFFLINE_EVENT;

typedef struct _WHEA_REGNOTIFY_POLICY_CHANGE_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    CCHAR PolicyName[WHEA_ERROR_TEXT_LEN];
    ULONG PolicyIndex;
    ULONG PolicyValue;
} WHEA_REGNOTIFY_POLICY_CHANGE_EVENT, *PWHEA_REGNOTIFY_POLICY_CHANGE_EVENT;

typedef enum _WHEA_REGISTRY_ERRORS {
    WheaRegErrNone = 0,
    WheaRegErrFailedToCreateWheaKey,
    WheaRegErrFailedToCreatePolicyKey,
    WheaRegErrFailedToOpenHandle
} WHEA_REGISTRY_ERRORS, *PWHEA_REGISTRY_ERRORS;

typedef struct _WHEA_REGISTRY_ERROR_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    WHEA_REGISTRY_ERRORS RegErr;
    UINT32 Status;
} WHEA_REGISTRY_ERROR_EVENT, *PWHEA_REGISTRY_ERROR_EVENT;

typedef struct _WHEA_CRASHDUMP_EVENT_LOG_ENTRY_WITH_STATUS {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    ULONG SourceLocationId;
    NTSTATUS Status;
} WHEA_CRASHDUMP_EVENT_LOG_ENTRY_WITH_STATUS, *PWHEA_CRASHDUMP_EVENT_LOG_ENTRY_WITH_STATUS;

typedef struct _WHEA_CRASHDUMP_EVENT_LOG_ENTRY_ULONG1 {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    ULONG Value;
} WHEA_CRASHDUMP_EVENT_LOG_ENTRY_ULONG1, *PWHEA_CRASHDUMP_EVENT_LOG_ENTRY_ULONG1;

typedef enum _WHEA_GAS_ERRORS {
    WheaGasErrNone = 0,
    WheaGasErrUnexpectedAddressSpaceId,
    WheaGasErrInvalidStructFields,
    WheaGasErrInvalidAccessSize
} WHEA_GAS_ERRORS, *PWHEA_GAS_ERRORS;

typedef struct _WHEA_GAS_ERROR_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    WHEA_GAS_ERRORS Error;
} WHEA_GAS_ERROR_EVENT, *PWHEA_GAS_ERROR_EVENT;

//
// Make sure MAX_SEL_RAW_EVENT_PAYLOAD_LENGTH is kept in sync with
// MAX_OSSELREC_LENGTH (see onecore\admin\wmi\ipmi\driver\lib\DriverEntry.c).
//

#define MAX_SEL_RAW_EVENT_PAYLOAD_LENGTH 256

typedef struct _WHEA_SEL_RAW_EVENT {
    WHEA_EVENT_LOG_ENTRY WheaEventLogEntry;
    UCHAR Payload[MAX_SEL_RAW_EVENT_PAYLOAD_LENGTH];
} WHEA_SEL_RAW_EVENT, *PWHEA_SEL_RAW_EVENT;

C_ASSERT((FIELD_OFFSET(WHEA_SEL_RAW_EVENT, Payload) % 4) == 0);

__inline
VOID
WheaInitEventLogEntry (
    _In_ PWHEA_EVENT_LOG_ENTRY LogEntry,
    _In_ WHEA_EVENT_LOG_ENTRY_TYPE Type,
    _In_ WHEA_EVENT_LOG_ENTRY_ID Id,
    _In_ WHEA_EVENT_LOG_ENTRY_FLAGS Flags,
    _In_ ULONG OwnerTag,
    _In_ ULONG PayloadLength
    )
{

    PUCHAR PayloadData;

    PayloadData = (PUCHAR)LogEntry + sizeof(WHEA_EVENT_LOG_ENTRY);
    LogEntry->Header.Signature = WHEA_ERROR_LOG_ENTRY_SIGNATURE;
    LogEntry->Header.Version = WHEA_ERROR_LOG_ENTRY_VERSION;
    LogEntry->Header.Length = sizeof(WHEA_EVENT_LOG_ENTRY) + PayloadLength;
    LogEntry->Header.Type = Type;
    LogEntry->Header.Id = Id;
    LogEntry->Header.OwnerTag = OwnerTag;
    LogEntry->Header.Flags = Flags;
    LogEntry->Header.PayloadLength = PayloadLength;
    return;
}

//---------------------------------------------------------- WHEA_GENERIC_ERROR

//
// These structure define the data format that must be used by error sources
// when reporting errors of the generic error type.
//

typedef union _WHEA_GENERIC_ERROR_BLOCKSTATUS {
    struct {
        ULONG UncorrectableError:1;
        ULONG CorrectableError:1;
        ULONG MultipleUncorrectableErrors:1;
        ULONG MultipleCorrectableErrors:1;
        ULONG ErrorDataEntryCount:10;
        ULONG Reserved:18;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_GENERIC_ERROR_BLOCKSTATUS, *PWHEA_GENERIC_ERROR_BLOCKSTATUS;

typedef struct _WHEA_GENERIC_ERROR {
    WHEA_GENERIC_ERROR_BLOCKSTATUS BlockStatus;
    ULONG RawDataOffset;
    ULONG RawDataLength;
    ULONG DataLength;
    WHEA_ERROR_SEVERITY ErrorSeverity;
    UCHAR Data[1];
} WHEA_GENERIC_ERROR, *PWHEA_GENERIC_ERROR;

typedef struct _WHEA_GENERIC_ERROR_DATA_ENTRY_V1 {
    GUID SectionType;
    WHEA_ERROR_SEVERITY ErrorSeverity;
    WHEA_REVISION Revision;
    UCHAR ValidBits;
    UCHAR Flags;
    ULONG ErrorDataLength;
    GUID FRUId;
    UCHAR FRUText[20];
    UCHAR Data[1];
} WHEA_GENERIC_ERROR_DATA_ENTRY_V1, *PWHEA_GENERIC_ERROR_DATA_ENTRY_V1;

#define WHEA_GENERIC_ENTRY_TEXT_LEN 20

typedef struct _WHEA_GENERIC_ERROR_DATA_ENTRY_V2 {
    GUID SectionType;
    WHEA_ERROR_SEVERITY ErrorSeverity;
    WHEA_REVISION Revision;
    UCHAR ValidBits;
    UCHAR Flags;
    ULONG ErrorDataLength;
    GUID FRUId;
    UCHAR FRUText[WHEA_GENERIC_ENTRY_TEXT_LEN];
    WHEA_TIMESTAMP Timestamp;
    UCHAR Data[1];
} WHEA_GENERIC_ERROR_DATA_ENTRY_V2, *PWHEA_GENERIC_ERROR_DATA_ENTRY_V2;

#define WHEA_GENERIC_ENTRY_V2_VERSION   0x300

//
// Use V2 Generic Data Entry.
//

#define WHEA_GENERIC_ENTRY_VERSION      WHEA_GENERIC_ENTRY_V2_VERSION
typedef struct _WHEA_GENERIC_ERROR_DATA_ENTRY_V2    WHEA_GENERIC_ERROR_DATA_ENTRY, *PWHEA_GENERIC_ERROR_DATA_ENTRY;

#include <poppack.h>

//------------------------------------------------- WHEA_ERROR_SOURCE_CALLBACKS

typedef
NTSTATUS
(_WHEA_ERROR_SOURCE_CORRECT)(
    _Inout_ PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource,
    _Out_ PULONG MaximumSectionLength
    );

typedef _WHEA_ERROR_SOURCE_CORRECT *WHEA_ERROR_SOURCE_CORRECT;

typedef
NTSTATUS
(_WHEA_ERROR_SOURCE_INITIALIZE)(
    _In_ ULONG Phase,
    _Inout_ PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource,
    _Inout_opt_ PVOID Context
    );

typedef _WHEA_ERROR_SOURCE_INITIALIZE *WHEA_ERROR_SOURCE_INITIALIZE;

typedef
NTSTATUS
(_WHEA_ERROR_SOURCE_CREATE_RECORD)(
    _Inout_ PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource,
    _Inout_ PWHEA_ERROR_PACKET ErrorPacket,
    _Out_writes_bytes_to_(BufferSize, ErrorRecord->Header.Length) PWHEA_ERROR_RECORD ErrorRecord,
    _In_ ULONG BufferSize,
    _Inout_opt_ PVOID Context
    );

typedef _WHEA_ERROR_SOURCE_CREATE_RECORD *WHEA_ERROR_SOURCE_CREATE_RECORD;

typedef
NTSTATUS
(_WHEA_ERROR_SOURCE_RECOVER)(
    _Inout_ PVOID RecoveryContext,
    _Inout_ PWHEA_ERROR_SEVERITY Severity
    );

typedef _WHEA_ERROR_SOURCE_RECOVER *WHEA_ERROR_SOURCE_RECOVER;

typedef
VOID
(_WHEA_ERROR_SOURCE_UNINITIALIZE)(
   _Inout_opt_ PVOID Context
    );

typedef _WHEA_ERROR_SOURCE_UNINITIALIZE *WHEA_ERROR_SOURCE_UNINITIALIZE;

typedef struct _WHEA_ERROR_SOURCE_CONFIGURATION {
    ULONG Flags;
    WHEA_ERROR_SOURCE_CORRECT Correct;
    WHEA_ERROR_SOURCE_INITIALIZE Initialize;
    WHEA_ERROR_SOURCE_CREATE_RECORD CreateRecord;
    WHEA_ERROR_SOURCE_RECOVER Recover;
    WHEA_ERROR_SOURCE_UNINITIALIZE Uninitialize;
    PVOID Reserved;
} WHEA_ERROR_SOURCE_CONFIGURATION, *PWHEA_ERROR_SOURCE_CONFIGURATION;

NTKERNELAPI
NTSTATUS
WheaAddErrorSourceDeviceDriver (
    _Inout_opt_ PVOID Context,
    _In_ PWHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER Configuration,
    _In_ ULONG NumberPreallocatedErrorReports
    );

NTKERNELAPI
NTSTATUS
WheaAddErrorSourceDeviceDriverV1 (
    _Inout_opt_ PVOID Context,
    _In_ PWHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER Configuration,
    _In_ ULONG NumBuffersToPreallocate,
    _In_ ULONG MaxDataLength
    );

NTKERNELAPI
NTSTATUS
WheaRemoveErrorSourceDeviceDriver (
    _In_ ULONG ErrorSourceId
    );

typedef union _WHEA_REPORT_HW_ERROR_DEVICE_DRIVER_FLAGS {
    struct {
        ULONG Reserved : 32;
    } DUMMYSTRUCTNAME;

    ULONG AsULONG;
} WHEA_REPORT_HW_ERROR_DEVICE_DRIVER_FLAGS,
  *PWHEA_REPORT_HW_ERROR_DEVICE_DRIVER_FLAGS;

#define WHEA_MAX_LOG_DATA_LEN 36

typedef struct _WHEA_PACKET_LOG_DATA {
    UCHAR LogData[WHEA_MAX_LOG_DATA_LEN];
    UCHAR ExtraBytes[WHEA_MAX_LOG_DATA_LEN];
    ULONG_PTR BcParam3;
    ULONG_PTR BcParam4;
    ULONG LogDataLength;
    USHORT LogTag;
    USHORT Reserved;
    WHEA_REPORT_HW_ERROR_DEVICE_DRIVER_FLAGS Flags;
} WHEA_PACKET_LOG_DATA, *PWHEA_PACKET_LOG_DATA;

typedef struct _ERROR_SOURCE_INFO {
    ULONG ErrorCount;
    ULONG ErrorSourceId;
} ERROR_SOURCE_INFO, *PERROR_SOURCE_INFO;

NTKERNELAPI
NTSTATUS
WheaReportHwErrorDeviceDriver (
    _In_ ULONG ErrorSourceId,
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_reads_bytes_(ErrorDataLength) PUCHAR ErrorData,
    _In_ ULONG ErrorDataLength,
    _In_ LPGUID SectionTypeGuid,
    _In_ WHEA_ERROR_SEVERITY ErrorSeverity,
    _In_ LPSTR DeviceFriendlyName
    );

NTKERNELAPI
WHEA_ERROR_HANDLE
WheaCreateHwErrorReportDeviceDriver (
    _In_ ULONG ErrorSourceId,
    _In_ PDEVICE_OBJECT DeviceObject
    );

NTKERNELAPI
NTSTATUS
WheaAddHwErrorReportSectionDeviceDriver (
    _In_ WHEA_ERROR_HANDLE ErrorHandle,
    _In_ ULONG SectionDataLength,
    _Out_ PWHEA_DRIVER_BUFFER_SET BufferSet
    );

NTKERNELAPI
NTSTATUS
WheaHwErrorReportAbandonDeviceDriver (
    _In_ WHEA_ERROR_HANDLE ErrorHandle
    );

NTKERNELAPI
NTSTATUS
WheaHwErrorReportSubmitDeviceDriver (
    _In_ WHEA_ERROR_HANDLE ErrorHandle
    );

NTKERNELAPI
NTSTATUS
WheaHwErrorReportSetSeverityDeviceDriver (
    _In_ WHEA_ERROR_HANDLE ErrorHandle,
    _In_ WHEA_ERROR_SEVERITY ErrorSeverity
    );

NTKERNELAPI
NTSTATUS
WheaHwErrorReportSetSectionNameDeviceDriver (
    _In_ PWHEA_DRIVER_BUFFER_SET BufferSet,
    _In_range_(0, WHEA_GENERIC_ENTRY_TEXT_LEN) ULONG NameLength,
    _In_reads_bytes_(NameLength) PUCHAR Name
    );


NTKERNELAPI
NTSTATUS
WheaReportHwError(
    _Inout_ PWHEA_ERROR_PACKET ErrorPacket
    );

NTKERNELAPI
NTSTATUS
WheaAddErrorSource(
    _In_ PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource,
    _In_opt_ PVOID Context
    );

NTKERNELAPI
NTSTATUS
WheaInitializeRecordHeader (
    _Out_ PWHEA_ERROR_RECORD_HEADER Header
    );

NTKERNELAPI
NTSTATUS
WheaConfigureErrorSource (
    _In_ WHEA_ERROR_SOURCE_TYPE SourceType,
    _In_ PWHEA_ERROR_SOURCE_CONFIGURATION Configuration
    );

NTKERNELAPI
NTSTATUS
WheaUnconfigureErrorSource (
    _In_ WHEA_ERROR_SOURCE_TYPE SourceType
    );

NTKERNELAPI
VOID
WheaRemoveErrorSource(
    _In_ ULONG ErrorSourceId
    );

NTKERNELAPI
BOOLEAN
WheaIsLogSelHandlerInitialized();

NTKERNELAPI
VOID
WheaLogInternalEvent (
    _In_ PWHEA_EVENT_LOG_ENTRY Entry
    );

WHEA_ERROR_SOURCE_STATE
WheaErrorSourceGetState (
    _In_ ULONG ErrorSourceId
    );

#define WHEA_INVALID_ERR_SRC_ID 0

BOOLEAN
WheaIsCriticalState (
    VOID
    );

typedef
BOOLEAN
(_WHEA_SIGNAL_HANDLER_OVERRIDE_CALLBACK)(
   _Inout_opt_ UINT_PTR Context
   );

typedef _WHEA_SIGNAL_HANDLER_OVERRIDE_CALLBACK
    *WHEA_SIGNAL_HANDLER_OVERRIDE_CALLBACK;

typedef struct _WHEA_ERROR_SOURCE_OVERRIDE_SETTINGS {
    WHEA_ERROR_SOURCE_TYPE Type;
    ULONG MaxRawDataLength;
    ULONG NumRecordsToPreallocate;
    ULONG MaxSectionsPerRecord;
} WHEA_ERROR_SOURCE_OVERRIDE_SETTINGS, *PWHEA_ERROR_SOURCE_OVERRIDE_SETTINGS;

BOOLEAN
WheaSignalHandlerOverride (
    _In_ WHEA_ERROR_SOURCE_TYPE SourceType,
    _Inout_opt_ UINT_PTR Context
    );

VOID
WheaUnregisterErrorSourceOverride (
    _In_ WHEA_ERROR_SOURCE_TYPE Type,
    _In_ ULONG32 OverrideErrorSourceId
    );

NTSTATUS
WheaRegisterErrorSourceOverride (
    _In_ WHEA_ERROR_SOURCE_OVERRIDE_SETTINGS OverrideSettings,
    _In_ PWHEA_ERROR_SOURCE_CONFIGURATION OverrideConfig,
    _In_ WHEA_SIGNAL_HANDLER_OVERRIDE_CALLBACK OverrideCallback
    );

NTKERNELAPI
NTSTATUS
WheaGetErrorSourceInfo (
    _In_ WHEA_ERROR_SOURCE_TYPE SourceType,
    _Out_ PULONG ErrorCount,
    _Out_ PERROR_SOURCE_INFO* SourceInfo,
    _In_ ULONG PoolTag
    );


typedef
NTSTATUS
(*PFN_WHEA_HIGH_IRQL_LOG_SEL_EVENT_HANDLER) (
    _In_ PVOID Context,
    _In_ PIPMI_OS_SEL_RECORD OsSelRecord
    );

NTKERNELAPI
BOOLEAN
WheaHighIrqlLogSelEventHandlerRegister (
    _In_  PFN_WHEA_HIGH_IRQL_LOG_SEL_EVENT_HANDLER Handler,
    _In_ PVOID Context
    );

NTKERNELAPI
VOID
WheaHighIrqlLogSelEventHandlerUnregister (
    VOID
    );

//----------------------------------------------- WheaGetErrPacketFromErrRecord

_Must_inspect_result_
__inline
PWHEA_ERROR_PACKET
WheaGetErrPacketFromErrRecord (
    _In_ PWHEA_ERROR_RECORD Record
    )

/*++

Routine Description:

    This routine will search out the error packet contained within an error
    record and return a reference to it.

Arguments:

    Record - Supplies a pointer to the error record to be searched.

Return Value:

    If successful, a pointer to the error packet.

    NULL otherwise.

--*/

{

    PWHEA_ERROR_PACKET Packet;
    PWHEA_ERROR_RECORD_SECTION_DESCRIPTOR Descriptor;
    ULONG Section;
    ULONG SizeRequired;

    Packet = NULL;
    if (Record->Header.Signature != WHEA_ERROR_RECORD_SIGNATURE) {
        goto GetErrPacketFromErrRecordEnd;
    }

    //
    // Calculate the size required for the header and section descriptors.
    // Ensure that at least these will be properly contained within the extent
    // of the error record.
    //

    SizeRequired = sizeof(WHEA_ERROR_RECORD_HEADER) +
        (sizeof(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR) *
         Record->Header.SectionCount);

    if (Record->Header.Length < SizeRequired) {
        goto GetErrPacketFromErrRecordEnd;
    }

    //
    // Step through the section descriptors looking for the error packet. If the
    // error packet descriptor is found, ensure that the error packet section is
    // properly contained within the extent of the error record.
    //

    Descriptor = &Record->SectionDescriptor[0];
    for (Section = 0; Section < Record->Header.SectionCount; Section += 1) {

        if (RtlCompareMemory(&Descriptor->SectionType,
                             &WHEA_ERROR_PACKET_SECTION_GUID,
                             sizeof(GUID)) == sizeof(GUID)) {

                SizeRequired = Descriptor->SectionOffset +
                    Descriptor->SectionLength;

                if (Record->Header.Length < SizeRequired) {
                    goto GetErrPacketFromErrRecordEnd;
                }

                Packet = (PWHEA_ERROR_PACKET)
                    (((PUCHAR)Record) + Descriptor->SectionOffset);

                if (Packet->Signature != WHEA_ERROR_PACKET_SIGNATURE) {
                    Packet = NULL;
                }

                goto GetErrPacketFromErrRecordEnd;
        }

        Descriptor += 1;
    }

GetErrPacketFromErrRecordEnd:
    return Packet;
}

//------------------------------------------- WHEA_ERROR_INJECTION_CAPABILITIES

//
// PSHED plug-ins use this structure to communicate error injection capabilities
// to the operating system.
//

typedef union _WHEA_ERROR_INJECTION_CAPABILITIES {
    struct {
        ULONG ProcessorCorrectable:1;                   // 0x00000001
        ULONG ProcessorUncorrectableNonFatal:1;         // 0x00000002
        ULONG ProcessorUncorrectableFatal:1;            // 0x00000004
        ULONG MemoryCorrectable:1;                      // 0x00000008
        ULONG MemoryUncorrectableNonFatal:1;            // 0x00000010
        ULONG MemoryUncorrectableFatal:1;               // 0x00000020
        ULONG PCIExpressCorrectable:1;                  // 0x00000040
        ULONG PCIExpressUncorrectableNonFatal:1;        // 0x00000080
        ULONG PCIExpressUncorrectableFatal:1;           // 0x00000100
        ULONG PlatformCorrectable:1;                    // 0x00000200
        ULONG PlatformUncorrectableNonFatal:1;          // 0x00000400
        ULONG PlatformUncorrectableFatal:1;             // 0x00000800
        ULONG IA64Corrected:1;                          // 0x00001000
        ULONG IA64Recoverable:1;                        // 0x00002000
        ULONG IA64Fatal:1;                              // 0x00004000
        ULONG IA64RecoverableCache:1;                   // 0x00008000
        ULONG IA64RecoverableRegFile:1;                 // 0x00010000
        ULONG Reserved:15;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_ERROR_INJECTION_CAPABILITIES, *PWHEA_ERROR_INJECTION_CAPABILITIES;

#define INJECT_ERRTYPE_PROCESSOR_CORRECTABLE                    0x00000001
#define INJECT_ERRTYPE_PROCESSOR_UNCORRECTABLENONFATAL          0x00000002
#define INJECT_ERRTYPE_PROCESSOR_UNCORRECTABLEFATAL             0x00000004
#define INJECT_ERRTYPE_MEMORY_CORRECTABLE                       0x00000008
#define INJECT_ERRTYPE_MEMORY_UNCORRECTABLENONFATAL             0x00000010
#define INJECT_ERRTYPE_MEMORY_UNCORRECTABLEFATAL                0x00000020
#define INJECT_ERRTYPE_PCIEXPRESS_CORRECTABLE                   0x00000040
#define INJECT_ERRTYPE_PCIEXPRESS_UNCORRECTABLENONFATAL         0x00000080
#define INJECT_ERRTYPE_PCIEXPRESS_UNCORRECTABLEFATAL            0x00000100
#define INJECT_ERRTYPE_PLATFORM_CORRECTABLE                     0x00000200
#define INJECT_ERRTYPE_PLATFORM_UNCORRECTABLENONFATAL           0x00000400
#define INJECT_ERRTYPE_PLATFORM_UNCORRECTABLEFATAL              0x00000800

//----------------------------------------------------------- In-use Page Offline Callbacks

typedef
BOOLEAN
(*PFN_IN_USE_PAGE_OFFLINE_NOTIFY) (
    _In_ PFN_NUMBER Page,
    _In_ BOOLEAN Poisoned,
    _Inout_ PVOID Context,
    _Out_ PNTSTATUS CallbackStatus
    );

NTKERNELAPI
NTSTATUS
WheaRegisterInUsePageOfflineNotification (
    _In_ PFN_IN_USE_PAGE_OFFLINE_NOTIFY Callback,
    _In_opt_ PVOID Context
    );

NTKERNELAPI
NTSTATUS
WheaUnregisterInUsePageOfflineNotification (
    _In_ PFN_IN_USE_PAGE_OFFLINE_NOTIFY Callback
    );

NTKERNELAPI
BOOLEAN
WheaGetNotifyAllOfflinesPolicy (
    VOID
    );

typedef union _WHEA_IN_USE_PAGE_NOTIFY_FLAGS {
    struct {
        UCHAR PlatformDirected : 1;
        UCHAR PageSwapped : 1;
        UCHAR PageDemoted : 1;
        UCHAR Reserved : 3;
        UCHAR NotifyAllOfflines: 1;
        UCHAR PageOfflined : 1;
    } Bits;

    UINT8 AsUCHAR;
} WHEA_IN_USE_PAGE_NOTIFY_FLAGS, *PWHEA_IN_USE_PAGE_NOTIFY_FLAGS;

typedef enum _WHEA_RECOVERY_CONTEXT_ERROR_TYPE {
    WheaRecoveryContextErrorTypeMemory = 1,
    WheaRecoveryContextErrorTypePmem,
    WheaRecoveryContextErrorTypeMax
} WHEA_RECOVERY_CONTEXT_ERROR_TYPE,
    *PWHEA_RECOVERY_CONTEXT_ERROR_TYPE;

#define WHEA_PFA_PAGE_RANGE_MAX 256
typedef struct _WHEA_RECOVERY_CONTEXT_PAGE_INFO {
    ULONG ComponentTag;
    NTSTATUS PageStatus;
    WHEA_RECOVERY_CONTEXT_ACTION_TAKEN ActionTaken;
    WHEA_IN_USE_PAGE_NOTIFY_FLAGS NotifyFlags;
    BOOLEAN ImmediateSuccess;
    UINT16 Reserved;
    WHEA_RECOVERY_CONTEXT_ACTION_TAKEN_ADDITIONAL_INFO ActionTakenAdditionalInfo;
} WHEA_RECOVERY_CONTEXT_PAGE_INFO, *PWHEA_RECOVERY_CONTEXT_PAGE_INFO;

typedef struct _WHEA_RECOVERY_CONTEXT {
    union {
        struct {
            ULONG_PTR Address;
            BOOLEAN Consumed;
            UINT16 ErrorCode;
            BOOLEAN ErrorIpValid;
            BOOLEAN RestartIpValid;
            BOOLEAN ClearPoison;
        } MemoryError;

        struct {
            ULONG_PTR PmemErrInfo;
        } PmemError;
    };

    UINT64 PartitionId;  //HV_PARTITION_ID
    UINT32 VpIndex;      //HV_VP_INDEX
    WHEA_RECOVERY_CONTEXT_ERROR_TYPE ErrorType;
    ULONG PageCount;
    WHEA_RECOVERY_CONTEXT_PAGE_INFO PageInfo[WHEA_PFA_PAGE_RANGE_MAX];
} WHEA_RECOVERY_CONTEXT, *PWHEA_RECOVERY_CONTEXT;

NTKERNELAPI
VOID
WheaAttemptRowOffline (
    _In_ PFN_NUMBER Page,
    _In_opt_ PMEMORY_DEFECT MemDefect,
    _In_ ULONG PageCount,
    _In_ PWHEA_RECOVERY_CONTEXT Context
    );

#if !defined(XBOX_SYSTEMOS)

typedef
NTSTATUS
(HVL_WHEA_ERROR_NOTIFICATION) (
    _In_ PWHEA_RECOVERY_CONTEXT RecoveryContext,
    _In_ BOOLEAN Poisoned
    );

typedef HVL_WHEA_ERROR_NOTIFICATION *PHVL_WHEA_ERROR_NOTIFICATION;

extern PHVL_WHEA_ERROR_NOTIFICATION HvlpWheaErrorNotificationCallback;

NTKERNELAPI
NTSTATUS
HvlRegisterWheaErrorNotification (
    _In_ PHVL_WHEA_ERROR_NOTIFICATION Callback
    );

NTKERNELAPI
NTSTATUS
HvlUnregisterWheaErrorNotification(
    _In_ PHVL_WHEA_ERROR_NOTIFICATION Callback
    );

#endif


//------------------------------------------------ PSHED Plug-in Callback Types

_Must_inspect_result_
typedef
NTSTATUS
(*PSHED_PI_GET_ALL_ERROR_SOURCES) (
    _Inout_opt_ PVOID PluginContext,
    _Inout_ PULONG Count,
    _Inout_updates_bytes_(*Length) PWHEA_ERROR_SOURCE_DESCRIPTOR *ErrorSrcs,
    _Inout_ PULONG Length
    );

_Must_inspect_result_
typedef
NTSTATUS
(*PSHED_PI_GET_ERROR_SOURCE_INFO) (
    _Inout_opt_ PVOID PluginContext,
    _Inout_ PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

_Must_inspect_result_
typedef
NTSTATUS
(*PSHED_PI_SET_ERROR_SOURCE_INFO) (
    _Inout_opt_ PVOID PluginContext,
    _In_ PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

typedef
NTSTATUS
 (*PSHED_PI_ENABLE_ERROR_SOURCE) (
    _Inout_opt_ PVOID PluginContext,
    _In_ PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

typedef
NTSTATUS
 (*PSHED_PI_DISABLE_ERROR_SOURCE) (
    _Inout_opt_ PVOID PluginContext,
    _In_ PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

typedef
NTSTATUS
(*PSHED_PI_WRITE_ERROR_RECORD) (
    _Inout_opt_ PVOID PluginContext,
    _In_ ULONG Flags,
    _In_ ULONG RecordLength,
    _In_reads_bytes_(RecordLength) PWHEA_ERROR_RECORD ErrorRecord
    );

_Must_inspect_result_
typedef
NTSTATUS
(*PSHED_PI_READ_ERROR_RECORD) (
    _Inout_opt_ PVOID PluginContext,
    _In_ ULONG Flags,
    _In_ ULONGLONG ErrorRecordId,
    _Out_ PULONGLONG NextErrorRecordId,
    _Inout_ PULONG RecordLength,
    _Out_writes_bytes_(*RecordLength) PWHEA_ERROR_RECORD ErrorRecord
    );

typedef
NTSTATUS
(*PSHED_PI_CLEAR_ERROR_RECORD) (
    _Inout_opt_ PVOID PluginContext,
    _In_ ULONG Flags,
    _In_ ULONGLONG ErrorRecordId
    );

typedef
NTSTATUS
(*PSHED_PI_RETRIEVE_ERROR_INFO) (
    _Inout_opt_ PVOID PluginContext,
    _In_ PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource,
    _In_ ULONGLONG BufferLength,
    _Inout_updates_bytes_(BufferLength) PWHEA_ERROR_PACKET Packet
    );

typedef
NTSTATUS
(*PSHED_PI_FINALIZE_ERROR_RECORD) (
    _Inout_opt_ PVOID PluginContext,
    _In_ PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource,
    _In_ ULONG BufferLength,
    _Inout_updates_bytes_(BufferLength) PWHEA_ERROR_RECORD ErrorRecord
    );

typedef
NTSTATUS
(*PSHED_PI_CLEAR_ERROR_STATUS) (
    _Inout_opt_ PVOID PluginContext,
    _In_ PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource,
    _In_ ULONG BufferLength,
    _In_reads_bytes_(BufferLength) PWHEA_ERROR_RECORD ErrorRecord
    );

_Must_inspect_result_
typedef
NTSTATUS
(*PSHED_PI_ATTEMPT_ERROR_RECOVERY) (
    _Inout_opt_ PVOID PluginContext,
    _In_ ULONG BufferLength,
    _In_reads_bytes_(BufferLength) PWHEA_ERROR_RECORD ErrorRecord
    );

_Must_inspect_result_
typedef
NTSTATUS
(*PSHED_PI_GET_INJECTION_CAPABILITIES) (
    _Inout_opt_ PVOID PluginContext,
    _Out_ PWHEA_ERROR_INJECTION_CAPABILITIES Capabilities
    );

_Must_inspect_result_
typedef
NTSTATUS
(*PSHED_PI_INJECT_ERROR) (
    _Inout_opt_ PVOID PluginContext,
    _In_ ULONGLONG ErrorType,
    _In_ ULONGLONG Parameter1,
    _In_ ULONGLONG Parameter2,
    _In_ ULONGLONG Parameter3,
    _In_ ULONGLONG Parameter4
    );

//--------------------------------------- WHEA_PSHED_PLUGIN_REGISTRATION_PACKET

typedef struct _WHEA_PSHED_PLUGIN_CALLBACKS {
    PSHED_PI_GET_ALL_ERROR_SOURCES GetAllErrorSources;
    PVOID Reserved;
    PSHED_PI_GET_ERROR_SOURCE_INFO GetErrorSourceInfo;
    PSHED_PI_SET_ERROR_SOURCE_INFO SetErrorSourceInfo;
    PSHED_PI_ENABLE_ERROR_SOURCE EnableErrorSource;
    PSHED_PI_DISABLE_ERROR_SOURCE DisableErrorSource;
    PSHED_PI_WRITE_ERROR_RECORD WriteErrorRecord;
    PSHED_PI_READ_ERROR_RECORD ReadErrorRecord;
    PSHED_PI_CLEAR_ERROR_RECORD ClearErrorRecord;
    PSHED_PI_RETRIEVE_ERROR_INFO RetrieveErrorInfo;
    PSHED_PI_FINALIZE_ERROR_RECORD FinalizeErrorRecord;
    PSHED_PI_CLEAR_ERROR_STATUS ClearErrorStatus;
    PSHED_PI_ATTEMPT_ERROR_RECOVERY AttemptRecovery;
    PSHED_PI_GET_INJECTION_CAPABILITIES GetInjectionCapabilities;
    PSHED_PI_INJECT_ERROR InjectError;
} WHEA_PSHED_PLUGIN_CALLBACKS, *PWHEA_PSHED_PLUGIN_CALLBACKS;

typedef struct _WHEA_PSHED_PLUGIN_REGISTRATION_PACKET_V1 {
    ULONG Length;
    ULONG Version;
    PVOID Context;
    ULONG FunctionalAreaMask;
    ULONG Reserved;
    WHEA_PSHED_PLUGIN_CALLBACKS Callbacks;
} WHEA_PSHED_PLUGIN_REGISTRATION_PACKET_V1;

#define WHEA_PLUGIN_REGISTRATION_PACKET_V1      0x00010000

typedef struct _WHEA_PSHED_PLUGIN_REGISTRATION_PACKET_V2 {
    ULONG Length;
    ULONG Version;
    PVOID Context;
    ULONG FunctionalAreaMask;
    ULONG Reserved;
    WHEA_PSHED_PLUGIN_CALLBACKS Callbacks;
    PVOID PluginHandle;
} WHEA_PSHED_PLUGIN_REGISTRATION_PACKET_V2;

typedef WHEA_PSHED_PLUGIN_REGISTRATION_PACKET_V2
        WHEA_PSHED_PLUGIN_REGISTRATION_PACKET;

typedef WHEA_PSHED_PLUGIN_REGISTRATION_PACKET
        *PWHEA_PSHED_PLUGIN_REGISTRATION_PACKET;

#define WHEA_PLUGIN_REGISTRATION_PACKET_V2      0x00020000
#define WHEA_PLUGIN_REGISTRATION_PACKET_VERSION WHEA_PLUGIN_REGISTRATION_PACKET_V2

//
// These defines specify the values of the bits in the functional area mask
// field of the PSHED plug-in registration packet.
//

#define PshedFADiscovery              0x00000001
#define PshedFAErrorSourceControl     0x00000002
#define PshedFAErrorRecordPersistence 0x00000004
#define PshedFAErrorInfoRetrieval     0x00000008
#define PshedFAErrorRecovery          0x00000010
#define PshedFAErrorInjection         0x00000020


//------------------------------------------------------ PSHED Plug-in services

#define WHEA_WRITE_FLAG_DUMMY 0x00000001

//
// The following services are exported by the PSHED for use by PSHED plug-ins.
//

#if (NTDDI_VERSION >= NTDDI_WS08)
_IRQL_requires_max_(DISPATCH_LEVEL)
__drv_allocatesMem(Mem)
_Post_writable_byte_size_(Size)
_Must_inspect_result_
NTPSHEDAPI
PVOID
PshedAllocateMemory (
    _In_ ULONG Size
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS08)
_IRQL_requires_max_(DISPATCH_LEVEL)
NTPSHEDAPI
VOID
PshedFreeMemory (
    _In_ __drv_freesMem(Mem) PVOID Address
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS08)
NTPSHEDAPI
BOOLEAN
PshedIsSystemWheaEnabled (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS08)
_IRQL_requires_max_(PASSIVE_LEVEL)
NTPSHEDAPI
NTSTATUS
PshedRegisterPlugin (
    _Inout_ PWHEA_PSHED_PLUGIN_REGISTRATION_PACKET Packet
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_19H1)
_IRQL_requires_max_(PASSIVE_LEVEL)
NTPSHEDAPI
VOID
PshedUnregisterPlugin (
    _In_ PVOID PluginHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS08)
NTPSHEDAPI
BOOLEAN
PshedSynchronizeExecution (
    _In_ PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource,
    _In_ PKSYNCHRONIZE_ROUTINE SynchronizeRoutine,
    _In_ PVOID SynchronizeContext
    );
#endif

//-------------------------------------------------------------------- WHEA_PRM

////////////////////////////////////////////////////////////////////////////////
//                                     INTEL                                  //
////////////////////////////////////////////////////////////////////////////////

/* 1DE4055D-D2F3-4E11-B7D9-7D6C19173FEE */
DEFINE_GUID(INTEL_ADDRESS_TRANSLATION_PRM_HANDLER_GUID,
            0x1DE4055D,
            0xD2F3, 0x4E11,
            0xB7, 0xD9, 0x7D, 0x6C, 0x19, 0x17, 0x3F, 0xEE);

//
// PRM/DSM Address Translation Commands
//

#define WHEA_PRM_ADDRESS_TRANSLATION_INTEL_GET_ADDRESS_PARAMETERS    1
#define WHEA_PRM_ADDRESS_TRANSLATION_INTEL_FORWARD_ADDRESS_TRANSLATE 2
#define WHEA_PRM_ADDRESS_TRANSLATION_INTEL_REVERSE_ADDRESS_TRANSLATE 3

//
// Address Translation Status
//

#define WHEA_PRM_ADDRESS_TRANSLATION_INTEL_SUCCESS         0
#define WHEA_PRM_ADDRESS_TRANSLATION_INTEL_UNKNOWN_FAILURE 1
#define WHEA_PRM_ADDRESS_TRANSLATION_INTEL_INVALID_COMMAND 2
#define WHEA_PRM_ADDRESS_TRANSLATION_INTEL_INTERNAL_ERROR  3

#pragma pack(push, 1)
typedef struct _WHEA_PRM_ADDRESS_TRANSLATION_BUFFER_INTEL {
  UINT32  SwSmi;
  UINT32  Command;
  UINT32  Status;

  UINT64  SystemAddress;
  UINT64  NmSystemAddress;
  UINT64  SpareSystemAddress;
  UINT64  DevicePhysicalAddress;
  UINT64  ProcessorSocketId;
  UINT64  MemoryControllerId;
  UINT64  NmMemoryControllerId;
  UINT64  TargetId;
  UINT64  LogicalChannelId;
  UINT64  ChannelAddress;
  UINT64  NmChannelAddress;
  UINT64  ChannelId;
  UINT64  NmChannelId;
  UINT64  RankAddress;
  UINT64  NmRankAddress;
  UINT64  PhysicalRankId;
  UINT64  NmPhysicalRankId;
  UINT64  DimmSlotId;
  UINT64  NmDimmSlotId;
  UINT64  DimmRankId;
  UINT64  Row;
  UINT64  NmRow;
  UINT64  Column;
  UINT64  NmColumn;
  UINT64  Bank;
  UINT64  NmBank;
  UINT64  BankGroup;
  UINT64  NmBankGroup;
  UINT64  LockStepRank;
  UINT64  LockStepPhysicalRank;
  UINT64  LockStepBank;
  UINT64  LockStepBankGroup;
  UINT64  ChipSelect;
  UINT64  NmChipSelect;
  UINT64  Node;
  UINT64  ChipId;
  UINT64  NmChipId;
} WHEA_PRM_ADDRESS_TRANSLATION_BUFFER_INTEL, * PWHEA_PRM_ADDRESS_TRANSLATION_BUFFER_INTEL;
#pragma pack(pop)

NTSTATUS
WheaPrmTranslatePhysicalAddress(
    _In_ UINT64 PhysicalAddress,
    _Out_ PVOID DimmAddress
    );

NTSTATUS
WheaPrmTranslateDimmAddress(
    _Inout_ PVOID DimmAddress,
    _Out_ PUINT64 PhysicalAddress
    );

//----------------------------------------------- Error record access functions

_Must_inspect_result_
__inline
BOOLEAN
WheaIsValidErrorRecordSignature (
    _In_ PWHEA_ERROR_RECORD Record
    )

/*++

Routine Description:

    This routine will compare the error record signature with the proper values
    and signal whether it is correct or not.

Arguments:

    Record - Supplies a pointer to the error record.

Return Value:

    TRUE if the error record signature is correct.

    FALSE otherwise.

--*/

{

    BOOLEAN Valid;

    if ((Record->Header.Signature == WHEA_ERROR_RECORD_SIGNATURE) &&
        (Record->Header.Revision.AsUSHORT == WHEA_ERROR_RECORD_REVISION) &&
        (Record->Header.SignatureEnd == WHEA_ERROR_RECORD_SIGNATURE_END)) {

        Valid = TRUE;

    } else {
        Valid = FALSE;
    }

    return Valid;
}

#define WheaAdd2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))

_Must_inspect_result_
__inline
NTSTATUS
WheaFindErrorRecordSection (
    _In_ PWHEA_ERROR_RECORD Record,
    _In_ const GUID *SectionType,
    _Out_ PWHEA_ERROR_RECORD_SECTION_DESCRIPTOR *SectionDescriptor,
    _Out_opt_ PVOID *SectionData
    )

/*++

Routine Description:

    This routine provides a means to search an error record for a specific
    section.

Arguments:

    Record - Supplies a pointer to the error record.

    SectionType - Supplies a GUID specifying the section being sought. This may
        be any standard common platform error record or implementation specific
        section type.

    Descriptor - Supplies a location in which a pointer to the descriptor for
        the found section is returned.

    Section - Supplies an optional location in which a pointer to the found
        section is returned.

Return Value:

    STATUS_SUCCESS if the specified section is found.

    STATUS_NOT_FOUND if the specified section is not found.

    STATUS_INVALID_PARAMETER if the record does not appear well formed or the
        context parameter is null in cases where it is required.

--*/

{

    NTSTATUS Status;
    PWHEA_ERROR_RECORD_SECTION_DESCRIPTOR Descriptor;
    ULONG Index;
    ULONG MinimumLength;

    if ((Record == NULL) ||
        (SectionType == NULL) ||
        (SectionDescriptor == NULL) ||
        (WheaIsValidErrorRecordSignature(Record) == FALSE) ||
        (Record->Header.SectionCount == 0)) {

        Status = STATUS_INVALID_PARAMETER;
        goto FindErrorRecordSectionEnd;
    }

    //
    // Ensure that the supplied record is at least as long as required to store
    // the descriptors for the sections supposedly in the record.
    //

    MinimumLength = sizeof(WHEA_ERROR_RECORD_HEADER) +
        (Record->Header.SectionCount *
         sizeof(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR));

    if (Record->Header.Length < MinimumLength) {
        Status = STATUS_INVALID_PARAMETER;
        goto FindErrorRecordSectionEnd;
    }

    //
    // Iterate through the record searching for the section in question.
    //

    Descriptor = &Record->SectionDescriptor[0];
    for (Index = 0; Index < Record->Header.SectionCount; Index += 1) {
        if (RtlCompareMemory(&Descriptor->SectionType,
                             SectionType,
                             sizeof(GUID)) == sizeof(GUID)) {

            break;
        }

        Descriptor += 1;
    }

    if (Index >= Record->Header.SectionCount) {
        Status = STATUS_NOT_FOUND;
        goto FindErrorRecordSectionEnd;
    }

    //
    // If the descriptor describes a section that is not completely contained
    // within the record then the record is invalid.
    //

    if ((Descriptor->SectionOffset + Descriptor->SectionLength) >
        Record->Header.Length) {

        Status = STATUS_INVALID_PARAMETER;
        goto FindErrorRecordSectionEnd;
    }

    //
    // Return the descriptor and optionally a pointer to the section itself.
    //

    *SectionDescriptor = Descriptor;
    if (SectionData != NULL) {
        *SectionData = WheaAdd2Ptr(Record, Descriptor->SectionOffset);
    }

    Status = STATUS_SUCCESS;

FindErrorRecordSectionEnd:
    return Status;
}

_Must_inspect_result_
__inline
NTSTATUS
WheaFindNextErrorRecordSection (
    _In_ PWHEA_ERROR_RECORD Record,
    _Inout_ ULONG *Context,
    _Out_ PWHEA_ERROR_RECORD_SECTION_DESCRIPTOR *SectionDescriptor,
    _Out_opt_ PVOID *SectionData
    )

/*++

Routine Description:

    This routine allows the caller to iterate through the sections in an error
    record.

Arguments:

    Record - Supplies a pointer to the error record.

    Context - Supplies a pointer to a variable that maintains the current state
        of the search. This variable should be zero for the first call, and the
        same variable should be used in subsequent calls to enumerate the next
        sections in the record.

    Descriptor - Supplies a location in which a pointer to the descriptor for
        the found section is returned.

    Section - Supplies an optional location in which a pointer to the found
        section is returned.

Return Value:

    STATUS_SUCCESS if the specified section is found.

    STATUS_NOT_FOUND if the specified section is not found.

    STATUS_INVALID_PARAMETER if the record does not appear well formed or a
        required parameter is null.

--*/

{

    NTSTATUS Status;
    PWHEA_ERROR_RECORD_SECTION_DESCRIPTOR Descriptor;
    ULONG Index;
    ULONG MinimumLength;

    if ((Record == NULL) ||
        (Context == NULL) ||
        (SectionDescriptor == NULL) ||
        (WheaIsValidErrorRecordSignature(Record) == FALSE) ||
        (Record->Header.SectionCount == 0)) {

        Status = STATUS_INVALID_PARAMETER;
        goto FindNextErrorRecordSectionEnd;
    }

    //
    // Ensure that the supplied record is at least as long as required to store
    // the descriptors for the sections supposedly in the record.
    //

    MinimumLength = sizeof(WHEA_ERROR_RECORD_HEADER) +
        (Record->Header.SectionCount *
         sizeof(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR));

    if (Record->Header.Length < MinimumLength) {
        Status = STATUS_INVALID_PARAMETER;
        goto FindNextErrorRecordSectionEnd;
    }

    //
    // If the index is greater than the number of sections, then it has been
    // incorrectly fabricated by the caller or the record had section removed
    // during the enumeration. Either way, this is different to the case where
    // there are no sections left.
    //

    Index = *Context;
    if (Index > Record->Header.SectionCount) {
        Status = STATUS_INVALID_PARAMETER;
        goto FindNextErrorRecordSectionEnd;
    }

    if (Index == Record->Header.SectionCount) {
        Status = STATUS_NOT_FOUND;
        goto FindNextErrorRecordSectionEnd;
    }

    Descriptor = &Record->SectionDescriptor[Index];

    //
    // If the descriptor describes a section that is not completely contained
    // within the record then the record is invalid.
    //

    if ((Descriptor->SectionOffset + Descriptor->SectionLength) >
        Record->Header.Length) {

        Status = STATUS_INVALID_PARAMETER;
        goto FindNextErrorRecordSectionEnd;
    }

    *Context = Index + 1;
    *SectionDescriptor = Descriptor;
    if (SectionData != NULL) {
        *SectionData = WheaAdd2Ptr(Record, Descriptor->SectionOffset);
    }

    Status = STATUS_SUCCESS;

FindNextErrorRecordSectionEnd:
    return Status;
}

__inline
VOID
WheaErrorRecordBuilderInit (
    _Out_writes_bytes_(RecordLength) PWHEA_ERROR_RECORD Record,
    _In_ UINT32 RecordLength,
    _In_ WHEA_ERROR_SEVERITY Severity,
    _In_ GUID Notify
    )

/*++

Routine Description:

    The routine sets-up an error record to the record builder helper functions.

Arguments:

    Record - Supplies a buffer that holds the error record contents

    RecordLength - Supplies the total buffer size for Record

    Severity - Supplies the overall record severity

    Notify - Supplies the GUID for the notification type

Return Value:

    None.

--*/

{

    WheaInitializeRecordHeader(&Record->Header);
    Record->Header.SectionCount = 0;
    Record->Header.Severity = Severity;
    Record->Header.Length = RecordLength;
    Record->Header.NotifyType = Notify;
    return;
}

__inline
PVOID
WheaErrorRecordBuilderAddSection (
    _Inout_updates_bytes_(Record->Header.Length) PWHEA_ERROR_RECORD Record,
    _In_ UINT32 MaxSectionCount,
    _In_ UINT32 SectionLength,
    _In_ WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS Flags,
    _In_ GUID SectionType,
    _Inout_opt_ PVOID DescriptorOut
    )

/*++

Routine Description:

    This routine finds the next section, initializes its descriptor, and
    returns a pointer for the caller to populate with data.

Arguments:

    Record - Supplies a buffer that contains the error record data.

    SectionLength - Supplies a length for the new section to be added.

    Flags - Supplies the flags for the section.

    SectionType - Supplies the GUID to identify the section.

    DescriptorOut - Supplies an optional buffer to get the section descriptor
        if additional information needs to be added.

Return Value:

    A pointer to the next available space for error record information. Null if
    the record buffer is full.

--*/

{

    UINT32 CurrentSectionCount;
    PWHEA_ERROR_RECORD_SECTION_DESCRIPTOR Descriptor;
    UINT32 Offset;
    PVOID SectionData;

    SectionData = NULL;
    CurrentSectionCount = Record->Header.SectionCount;
    if (Record->Header.SectionCount == 0) {
        Offset = sizeof(Record->Header);
        Offset += MaxSectionCount * sizeof(*Descriptor);

    } else {
        Offset = Record->SectionDescriptor[CurrentSectionCount - 1].SectionOffset;
        Offset += Record->SectionDescriptor[CurrentSectionCount - 1].SectionLength;
    }

    if ((Offset + SectionLength) > Record->Header.Length) {
        goto cleanup;
    }

    SectionData = WheaAdd2Ptr(Record, Offset);
    Descriptor = &Record->SectionDescriptor[CurrentSectionCount];
    Descriptor->SectionOffset = Offset;
    Descriptor->SectionLength = SectionLength;
    Descriptor->Revision.AsUSHORT =
        WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_REVISION;

    Descriptor->Flags = Flags;
    Descriptor->SectionType = SectionType;
    Descriptor->SectionSeverity = Record->Header.Severity;
    if (DescriptorOut != NULL) {
        RtlCopyMemory(DescriptorOut, &Descriptor, sizeof(Descriptor));
    }

    Record->Header.SectionCount += 1;
    ASSERT(Record->Header.SectionCount <= MaxSectionCount);

    cleanup:

    return SectionData;
}

__inline
PVOID
WheaErrorRecordBuilderAddPacket (
    _Inout_updates_bytes_(Record->RecordLength) PWHEA_ERROR_RECORD Record,
    _Inout_updates_bytes_(Packet->Length) PWHEA_ERROR_PACKET_V2 Packet,
    _In_ UINT32 MaxSectionCount
    )

/*++

Routien Description:

    This routine adds a packet into an error record.

Arguments:

    Record - Supplies a buffer for error record data.

    Packet - Supplies a buffer holding the error packet data.

Return Value:

    A pointer to the added section, NULL if not added.

--*/

{
    PVOID Section;
    WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS Flags;

    Flags.AsULONG = 0;
    Section = WheaErrorRecordBuilderAddSection(Record,
                                               MaxSectionCount,
                                               Packet->Length,
                                               Flags,
                                               WHEA_ERROR_PACKET_SECTION_GUID,
                                               NULL);

    if (Section == NULL) {
        goto cleanup;
    }

    RtlCopyMemory(Section, Packet, Packet->Length);

cleanup:

    return Section;
}

//
// SOC Subsystem bugcheck reporting information
//
typedef enum _SOC_SUBSYSTEM_TYPE {
    SOC_SUBSYS_WIRELESS_MODEM = 0,
    SOC_SUBSYS_AUDIO_DSP = 1,
    SOC_SUBSYS_WIRELSS_CONNECTIVITY = 2,
    SOC_SUBSYS_SENSORS = 3,
    SOC_SUBSYS_COMPUTE_DSP = 4,
    SOC_SUBSYS_SECURE_PROC = 5,


    //
    // Subsystem types starting from 0x10000 are reserved for SoC vendor use.
    //

    SOC_SUBSYS_VENDOR_DEFINED = 0x10000
} SOC_SUBSYSTEM_TYPE, *PSOC_SUBSYSTEM_TYPE;


typedef struct _SOC_SUBSYSTEM_FAILURE_DETAILS {
    SOC_SUBSYSTEM_TYPE SubsysType;
    ULONG64 FirmwareVersion;
    ULONG64 HardwareVersion;
    ULONG   UnifiedFailureRegionSize;
    CHAR    UnifiedFailureRegion[1];
} SOC_SUBSYSTEM_FAILURE_DETAILS, *PSOC_SUBSYSTEM_FAILURE_DETAILS;


#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning(default:4115)
#pragma warning(default:4201)
#pragma warning(default:4214)
#endif

#endif // _NTDDK_
