/*++ BUILD Version: 0186    // Increment this if a change has global effects

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
#endif // RC_INVOKED

#define NT_INCLUDED
#define _CTYPE_DISABLE_MACROS

#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning(disable:4115) // named type definition in parentheses
#pragma warning(disable:4201) // nameless struct/union
#pragma warning(disable:4214) // bit field types other than int

#include <wdm.h>
#include <excpt.h>
#include <ntdef.h>
#include <ntstatus.h>
#include <bugcodes.h>
#include <ntiologc.h>

#include <driverspecs.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// Windows Error Record Creator GUID.
//

DEFINE_GUID( WHEA_RECORD_CREATOR_GUID,
    0xcf07c4bd,0xb789,0x4e18,0xb3,0xc4,0x1f,0x73,0x2c,0xb5,0x71,0x31 );

//
// Error notification type GUIDs.
//

DEFINE_GUID( CMC_NOTIFY_TYPE_GUID,
    0x2dce8bb1,0xbdd7,0x450e,0xb9,0xad,0x9c,0xf4,0xeb,0xd4,0xf8,0x90 );
DEFINE_GUID( CPE_NOTIFY_TYPE_GUID,
    0x4e292f96,0xd843,0x4a55,0xa8,0xc2,0xd4,0x81,0xf2,0x7e,0xbe,0xee );
DEFINE_GUID( MCE_NOTIFY_TYPE_GUID,
    0xe8f56ffe,0x919c,0x4cc5,0xba,0x88,0x65,0xab,0xe1,0x49,0x13,0xbb );
DEFINE_GUID( PCIe_NOTIFY_TYPE_GUID,
    0xcf93c01f,0x1a16,0x4dfc,0xb8,0xbc,0x9c,0x4d,0xaf,0x67,0xc1,0x04 );
DEFINE_GUID( INIT_NOTIFY_TYPE_GUID,
    0xcc5263e8,0x9308,0x454a,0x89,0xd0,0x34,0x0b,0xd3,0x9b,0xc9,0x8e );
DEFINE_GUID( NMI_NOTIFY_TYPE_GUID,
    0x5bad89ff,0xb7e6,0x42c9,0x81,0x4a,0xcf,0x24,0x85,0xd6,0xe9,0x8a );
DEFINE_GUID( BOOT_NOTIFY_TYPE_GUID,
    0x3d61a466,0xab40,0x409a,0xa6,0x98,0xf3,0x62,0xd4,0x64,0xb3,0x8f );
DEFINE_GUID( GENERIC_NOTIFY_TYPE_GUID,
    0x3e62a467,0xab40,0x409a,0xa6,0x98,0xf3,0x62,0xd4,0x64,0xb3,0x8f );

//
// Error Section type GUIDs.
//

DEFINE_GUID( PROCESSOR_GENERIC_SECTION_GUID,
    0x9876ccad,0x47b4,0x4bdb,0xb6,0x5e,0x16,0xf1,0x93,0xc4,0xf3,0xdb );
DEFINE_GUID( X86_PROCESSOR_SPECIFIC_SECTION_GUID,
    0xdc3ea0b0,0xa144,0x4797,0xb9,0x5b,0x53,0xfa,0x24,0x2b,0x6e,0x1d );
DEFINE_GUID( IPF_PROCESSOR_SPECIFIC_SECTION_GUID,
    0xe429faf1,0x3cb7,0x11d4,0xbc,0xa7,0x00,0x80,0xc7,0x3c,0x88,0x81 );
DEFINE_GUID( X64_PROCESSOR_SPECIFIC_SECTION_GUID,
    0x390f56d5,0xca86,0x4649,0x95,0xc4,0x73,0xa4,0x08,0xae,0x58,0x34 );
DEFINE_GUID( PLATFORM_MEMORY_SECTION_GUID,
    0xa5bc1114,0x6f64,0x4ede,0xb8,0x63,0x3e,0x83,0xed,0x7c,0x83,0xb1 );
DEFINE_GUID( PCIEXPRESS_SECTION_GUID,
    0xd995e954,0xbbc1,0x430f,0xad,0x91,0xb4,0x4d,0xcb,0x3c,0x6f,0x35 );
DEFINE_GUID( PCIX_BUS_SECTION_GUID,
    0xc5753963,0x3b84,0x4095,0xbf,0x78,0xed,0xda,0xd3,0xf9,0xc9,0xdd );
DEFINE_GUID( PCIX_COMPONENT_SECTION_GUID,
    0xeb5e4685,0xca66,0x4769,0xb6,0xa2,0x26,0x06,0x8b,0x00,0x13,0x26 );
DEFINE_GUID( NMI_SECTION_GUID,
    0xe71254e7,0xc1b9,0x4940,0xab,0x76,0x90,0x97,0x03,0xa4,0x32,0x0f );
DEFINE_GUID( GENERIC_SECTION_GUID,
    0xe71254e8,0xc1b9,0x4940,0xab,0x76,0x90,0x97,0x03,0xa4,0x32,0x0f );
DEFINE_GUID( WHEA_PACKET_SECTION_GUID,
    0xe71254e9,0xc1b9,0x4940,0xab,0x76,0x90,0x97,0x03,0xa4,0x32,0x0f );
DEFINE_GUID( PLATFORM_CACHE_SECTION_GUID,
    0x59a0a229,0x9399,0x4140,0x85,0xb3,0x06,0xd4,0x8a,0x9e,0x00,0x60 );
DEFINE_GUID( IPF_SAL_RECORD_REFERENCE_SECTION_GUID,
    0x81212A96,0x09ED,0x4996,0x94,0x71,0x8D,0x72,0x9C,0x8E,0x69,0xED );

//
// Processor error check section GUIDs.
//

DEFINE_GUID( WHEA_CACHECHECK_GUID,
    0xA55701F5,0xE3EF,0x43de,0xAC,0x72,0x24,0x9B,0x57,0x3F,0xAD,0x2C );
DEFINE_GUID( WHEA_TLBCHECK_GUID,
    0xFC06B535,0x5E1F,0x4562,0x9F,0x25,0x0A,0x3B,0x9A,0xDB,0x63,0xC3 );
DEFINE_GUID( WHEA_BUSCHECK_GUID,
    0x1CF3F8B3,0xC5B1,0x49A2,0xAA,0x59,0x5E,0xEF,0x92,0xFF,0xA6,0x3C );
DEFINE_GUID( WHEA_MSCHECK_GUID,
    0x48AB7F57,0xDC34,0x4F6C,0xA7,0xD3,0xB0,0xB5,0xB0,0xA7,0x43,0x14 );

#define WHEA_PHYSICAL_ADDRESS LARGE_INTEGER

//;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
//
// The following definitions and structures are used to describe platform-
// implemented hardware error sources to the OS.
//
//;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

//
//
// This enumeration defines the various types of error sources a platform can
// expose to the OS.
//

typedef enum _WHEA_ERROR_SOURCE_TYPE {
    WheaErrSrcTypeMCE       = 0x00,   // Machine Check Exception
    WheaErrSrcTypeCMC       = 0x01,   // Corrected Machine Check
    WheaErrSrcTypeCPE       = 0x02,   // Corrected Platform Error
    WheaErrSrcTypeNMI       = 0x03,   // Non-Maskable Interrupt
    WheaErrSrcTypePCIe      = 0x04,   // PCI Express Error
    WheaErrSrcTypeGeneric   = 0x05,   // Other types of error sources
    WheaErrSrcTypeINIT      = 0x06,   // IA64 INIT Error Source
    WheaErrSrcTypeBOOT      = 0x07,   // BOOT Error Source
    WheaErrSrcTypeSCIGeneric= 0x08,   // SCI-based generic error source
    WheaErrSrcTypeIPFMCA    = 0x09,   // IPF MCA
    WheaErrSrcTypeIPFCMC    = 0x0a,   // IPF CMC
    WheaErrSrcTypeIPFCPE    = 0x0b,   // IPF CPE
    WheaErrSrcTypeMax       = 0x0c
} WHEA_ERROR_SOURCE_TYPE, *PWHEA_ERROR_SOURCE_TYPE;

//
// The information encoded within an error source's status registers is
// encoded in one of the following standardized formats.
//

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

//
// Error sources have a runtime state associated with them. The following are
// the valid states for an error source.
//

typedef enum _WHEA_ERROR_SOURCE_STATE {
    WheaErrSrcStateStopped = 0x01,
    WheaErrSrcStateStarted = 0x02
} WHEA_ERROR_SOURCE_STATE, *PWHEA_ERROR_SOURCE_STATE;

#define WHEA_ERROR_SOURCE_DESCRIPTOR_VERSION_10          10

#define WHEA_MAX_MC_BANKS                                32

#define WHEA_ERROR_SOURCE_FLAG_FIRMWAREFIRST             0x00000001
#define WHEA_ERROR_SOURCE_FLAG_GLOBAL                    0x00000002
#define WHEA_ERROR_SOURCE_FLAG_DEFAULTSOURCE             0x80000000

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

#define WHEA_XPF_MC_BANK_STATUSFORMAT_IA32MCA            0
#define WHEA_XPF_MC_BANK_STATUSFORMAT_Intel64MCA         1
#define WHEA_XPF_MC_BANK_STATUSFORMAT_AMD64MCA           2

#define WHEA_NOTIFICATION_TYPE_POLLED                    0
#define WHEA_NOTIFICATION_TYPE_EXTERNALINTERRUPT         1
#define WHEA_NOTIFICATION_TYPE_LOCALINTERRUPT            2
#define WHEA_NOTIFICATION_TYPE_SCI                       3
#define WHEA_NOTIFICATION_TYPE_NMI                       4

#include <pshpack1.h>

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

//
// This structure describes a hardware error source.
//

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
    } Info;

} WHEA_ERROR_SOURCE_DESCRIPTOR, *PWHEA_ERROR_SOURCE_DESCRIPTOR;

typedef union _WHEA_REVISION {
    struct {
        UCHAR MinorRevision;
        UCHAR MajorRevision;
    } DUMMYSTRUCTNAME;
    USHORT AsUSHORT;
} WHEA_REVISION, *PWHEA_REVISION;

//
// These are the different types of hardware that can report errors.
//
typedef enum _WHEA_ERROR_TYPE {
    WheaErrTypeProcessor = 0,
    WheaErrTypeMemory,
    WheaErrTypePCIExpress,
    WheaErrTypeNMI,
    WheaErrTypePCIXBus,
    WheaErrTypePCIXDevice,
    WheaErrTypeGeneric
} WHEA_ERROR_TYPE, *PWHEA_ERROR_TYPE;

//
// WHEA_ERROR_SEVERITY enumeration defines the valid severity levels of a
// reported hardware error.
//

typedef enum _WHEA_ERROR_SEVERITY {
    WheaErrSevRecoverable = 0,
    WheaErrSevFatal       = 1,
    WheaErrSevCorrected   = 2,
    WheaErrSevNone        = 3
} WHEA_ERROR_SEVERITY, *PWHEA_ERROR_SEVERITY;

//
// Error Status Structure
//

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

//
// Processor generic error section.
//

#define GENPROC_PROCTYPE_XPF                 0
#define GENPROC_PROCTYPE_IPF                 1

#define GENPROC_PROCISA_X86                  0
#define GENPROC_PROCISA_IPF                  1
#define GENPROC_PROCISA_X64                  2

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
        ULONG Reserved3;
    } DUMMYSTRUCTNAME;
    ULONGLONG AsULONGLONG;
} WHEA_PROCESSOR_FAMILY_INFO, *PWHEA_PROCESSOR_FAMILY_INFO;

typedef union _WHEA_GENERIC_PROCESSOR_ERROR_VALIDBITS {
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
        ULONGLONG Reserved:51;
    } DUMMYSTRUCTNAME;
    ULONGLONG ValidBits;
} WHEA_GENERIC_PROCESSOR_ERROR_VALIDBITS,
  *PWHEA_GENERIC_PROCESSOR_ERROR_VALIDBITS;

typedef struct _WHEA_GENERIC_PROCESSOR_ERROR {
    WHEA_GENERIC_PROCESSOR_ERROR_VALIDBITS ValidBits; // +0x00 (00)
    UCHAR ProcessorType;                              // +0x08 (08)
    UCHAR InstructionSet;                             // +0x09 (09)
    UCHAR ErrorType;                                  // +0x0A (10)
    UCHAR Operation;                                  // +0x0B (11)
    UCHAR Flags;                                      // +0x0C (12)
    UCHAR Level;                                      // +0x0D (13)
    USHORT Reserved;                                  // +0x0E (14)
    ULONGLONG CPUVersion;                             // +0x10 (16)
    UCHAR CPUBrandString[128];                        // +0x18 (24)
    ULONGLONG ProcessorId;                            // +0x98 (152)
    ULONGLONG TargetAddress;                          // +0xA0 (160)
    ULONGLONG RequesterId;                            // +0xA8 (168)
    ULONGLONG ResponderId;                            // +0xB0 (176)
    ULONGLONG InstructionPointer;                     // +0xB8 (184)
                                                      // +0xC0 (192)
} WHEA_GENERIC_PROCESSOR_ERROR, *PWHEA_GENERIC_PROCESSOR_ERROR;

//
// IA32/X64 Processor Cache Check Structure
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
// IA32/X64 Processor TLB Check Structure
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
// IA32/X64 Processor Bus Check Structure
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
// IA32/X64 Micro-Architecture Specific Check Structure
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
// IA32/X64 Processor Error Information
//

typedef union _WHEA_XPF_PROCESSOR_ERROR_VALIDBITS {
    struct {
        ULONGLONG LocalAPICId:1;
        ULONGLONG CpuId:1;
        ULONGLONG ProcInfoCount:6;
        ULONGLONG ContextInfoCount:6;
        ULONGLONG Reserved:50;
    } DUMMYSTRUCTNAME;
    ULONGLONG ValidBits;
} WHEA_XPF_PROCESSOR_ERROR_VALIDBITS, *PWHEA_XPF_PROCESSOR_ERROR_VALIDBITS;

typedef struct _WHEA_XPF_PROCESSOR_ERROR {
    WHEA_XPF_PROCESSOR_ERROR_VALIDBITS ValidBits;
    ULONGLONG LocalAPICId;
    UCHAR CpuId[48];
    UCHAR VariableInfo[1];
} WHEA_XPF_PROCESSOR_ERROR, *PWHEA_XPF_PROCESSOR_ERROR;

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
        WHEA_XPF_BUS_CHECK BusCheck;
        WHEA_XPF_CACHE_CHECK CacheCheck;
        WHEA_XPF_MS_CHECK MsCheck;
        WHEA_XPF_TLB_CHECK TlbCheck;
        ULONGLONG AsULONGLONG;
    } CheckInfo;
    ULONGLONG TargetId;
    ULONGLONG RequesterId;
    ULONGLONG ResponderId;
    ULONGLONG InstructionPointer;
} WHEA_XPF_PROCINFO, *PWHEA_XPF_PROCINFO;

//
// IA32/X64 Process Context Structure
//

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
    UCHAR RegisterData[1];
} WHEA_XPF_CONTEXT_INFO, *PWHEA_XPF_CONTEXT_INFO;

typedef struct _WHEA_X86_REGISTER_STATE {
    ULONG Eax;        // +00 (00)
    ULONG Ebx;        // +04 (04)
    ULONG Ecx;        // +08 (08)
    ULONG Edx;        // +0C (12)
    ULONG Esi;        // +10 (16)
    ULONG Edi;        // +14 (20)
    ULONG Ebp;        // +18 (24)
    ULONG Esp;        // +1C (28)
    USHORT Cs;        // +20 (32)
    USHORT Ds;        // +22 (34)
    USHORT Ss;        // +24 (36)
    USHORT Es;        // +26 (38)
    USHORT Fs;        // +28 (40)
    USHORT Gs;        // +2A (42)
    ULONG Eflags;     // +2C (44)
    ULONG Eip;        // +30 (48)
    ULONG Cr0;        // +34 (52)
    ULONG Cr1;        // +38 (56)
    ULONG Cr2;        // +3C (60)
    ULONG Cr3;        // +40 (64)
    ULONG Cr4;        // +44 (68)
    ULONGLONG Gdtr;   // +48 (72)
    ULONGLONG Idtr;   // +50 (80)
    USHORT Ldtr;      // +58 (88)
    USHORT Tr;        // +5A (90)
                      // +5C (92)
} WHEA_X86_REGISTER_STATE, *PWHEA_X86_REGISTER_STATE;

typedef struct _WHEA128A {
    ULONGLONG Low;
    LONGLONG High;
} WHEA128A, *PWHEA128A;

#if defined(_MSC_VER)
#if (_MSC_VER >= 1200)
#pragma warning(push)
#pragma warning(disable:4324) // structure padded due to __declspec(align())
#endif
#endif

typedef struct _WHEA_X64_REGISTER_STATE {
    ULONGLONG     Rax;            // +00 (00)
    ULONGLONG     Rbx;            // +08 (08)
    ULONGLONG     Rcx;            // +10 (16)
    ULONGLONG     Rdx;            // +18 (24)
    ULONGLONG     Rsi;            // +20 (32)
    ULONGLONG     Rdi;            // +28 (40)
    ULONGLONG     Rbp;            // +30 (48)
    ULONGLONG     Rsp;            // +38 (56)
    ULONGLONG     R8;             // +40 (64)
    ULONGLONG     R9;             // +48 (72)
    ULONGLONG     R10;            // +50 (80)
    ULONGLONG     R11;            // +58 (88)
    ULONGLONG     R12;            // +60 (96)
    ULONGLONG     R13;            // +68 (104)
    ULONGLONG     R14;            // +70 (112)
    ULONGLONG     R15;            // +78 (120)
    USHORT      Cs;               // +80 (128)
    USHORT      Ds;               // +82 (130)
    USHORT      Ss;               // +84 (132)
    USHORT      Es;               // +86 (134)
    USHORT      Fs;               // +88 (136)
    USHORT      Gs;               // +8A (138)
    USHORT      Reserved;         // +8C (140)
    ULONGLONG     Rflags;         // +90 (144)
    ULONGLONG     Eip;            // +98 (152)
    ULONGLONG     Cr0;            // +A0 (160)
    ULONGLONG     Cr1;            // +A8 (168)
    ULONGLONG     Cr2;            // +B0 (176)
    ULONGLONG     Cr3;            // +B8 (184)
    ULONGLONG     Cr4;            // +C0 (192)
    ULONGLONG     Cr8;            // +C8 (200)
    WHEA128A    Gdtr;             // +D0 (208)
    WHEA128A    Idtr;             // +E0 (224)
    USHORT      Ldtr;             // +F0 (240)
    USHORT      Tr;               // +F2 (242)
                                  // +F4 (244)
} WHEA_X64_REGISTER_STATE, *PWHEA_X64_REGISTER_STATE;

#if defined(_MSC_VER)
#if (_MSC_VER >= 1200)
#pragma warning(pop)
#endif
#endif

//
// Platform Memory Error
//

typedef union _WHEA_MEMORY_ERROR_VALIDBITS {
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
        ULONGLONG Reserved:49;
    } DUMMYSTRUCTNAME;
    ULONGLONG ValidBits;
} WHEA_MEMORY_ERROR_VALIDBITS, *PWHEA_MEMORY_ERROR_VALIDBITS;

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

typedef struct _WHEA_MEMORY_ERROR {
    WHEA_MEMORY_ERROR_VALIDBITS ValidBits; // 0x00 (00)
    WHEA_ERROR_STATUS ErrorStatus;         // 0x08 (08)
    ULONGLONG PhysicalAddress;             // 0x10 (16)
    ULONGLONG PhysicalAddressMask;         // 0x18 (24)
    USHORT Node;                           // 0x20 (32)
    USHORT Card;                           // 0x22 (34)
    USHORT Module;                         // 0x24 (36)
    USHORT Bank;                           // 0x26 (38)
    USHORT Device;                         // 0x28 (40)
    USHORT Row;                            // 0x2A (42)
    USHORT Column;                         // 0x2C (44)
    USHORT BitPosition;                    // 0x2E (46)
    ULONGLONG RequesterId;                 // 0x30 (48)
    ULONGLONG ResponderId;                 // 0x38 (56)
    ULONGLONG TargetId;                    // 0x40 (64)
    UCHAR ErrorType;                       // 0x48 (72)
                                           // 0x49 (73)
} WHEA_MEMORY_ERROR, *PWHEA_MEMORY_ERROR;

//
// NMI Error.
//

typedef union _WHEA_NMI_ERROR_FLAGS {
    struct {
        ULONG HypervisorError:1;
        ULONG Reserved:31;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_NMI_ERROR_FLAGS, *PWHEA_NMI_ERROR_FLAGS;

typedef struct _WHEA_NMI_ERROR {
    UCHAR Data[8];                         // 0x00 (00)
    WHEA_NMI_ERROR_FLAGS Flags;            // 0x08 (08)
                                           // 0x0C (12)
} WHEA_NMI_ERROR, *PWHEA_NMI_ERROR;

//
// PCI Express Error
//

typedef union _WHEA_PCIEXPRESS_ERROR_VALIDBITS {
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
} WHEA_PCIEXPRESS_ERROR_VALIDBITS, *PWHEA_PCIEXPRESS_ERROR_VALIDBITS;

typedef struct _WHEA_PCIEXPRESS_DEVICE_ID {
    USHORT VendorID;                         // 0x00 (00)
    USHORT DeviceID;                         // 0x02 (02)
    ULONG ClassCode:24;                      // 0x04 (04)
    ULONG FunctionNumber:8;                  // 0x07 (07)
    ULONG DeviceNumber:8;                    // 0x08 (08)
    ULONG Segment:16;                        // 0x09 (09)
    ULONG PrimaryBusNumber:8;                // 0x0B (11)
    ULONG SecondaryBusNumber:8;              // 0x0C (12)
    ULONG Reserved1:2;                       // 0x0D (13)
    ULONG SlotNumber:14;                     // 0x0E (14)
    ULONG Reserved2:8;                       // 0x0F (15)
                                             // 0x10 (16)
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

typedef enum {
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

typedef struct _WHEA_PCIEXPRESS_ERROR {
    WHEA_PCIEXPRESS_ERROR_VALIDBITS ValidBits;                 // 0x00 (00)
    WHEA_PCIEXPRESS_DEVICE_TYPE PortType;                      // 0x08 (08)
    WHEA_PCIEXPRESS_VERSION Version;                           // 0x0C (12)
    WHEA_PCIEXPRESS_COMMAND_STATUS CommandStatus;              // 0x10 (16)
    ULONG Reserved;                                            // 0x14 (20)
    WHEA_PCIEXPRESS_DEVICE_ID DeviceId;                        // 0x18 (24)
    ULONGLONG DeviceSerialNumber;                              // 0x28 (40)
    WHEA_PCIEXPRESS_BRIDGE_CONTROL_STATUS BridgeControlStatus; // 0x30 (48)
    UCHAR ExpressCapability[60];                               // 0x34 (52)
    UCHAR AerInfo[96];                                         // 0x70 (112)
                                                               // 0xD0 (208)
} WHEA_PCIEXPRESS_ERROR, *PWHEA_PCIEXPRESS_ERROR;

//
// PCI/PCI-X Bus Error
//

#define PCIXBUS_ERRTYPE_UNKNOWN             0x0000
#define PCIXBUS_ERRTYPE_DATAPARITY          0x0001
#define PCIXBUS_ERRTYPE_SYSTEM              0x0002
#define PCIXBUS_ERRTYPE_MASTERABORT         0x0003
#define PCIXBUS_ERRTYPE_BUSTIMEOUT          0x0004
#define PCIXBUS_ERRTYPE_MASTERDATAPARITY    0x0005
#define PCIXBUS_ERRTYPE_ADDRESSPARITY       0x0006
#define PCIXBUS_ERRTYPE_COMMANDPARITY       0x0007

typedef union _WHEA_PCIXBUS_ERROR_VALIDBITS {
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
} WHEA_PCIXBUS_ERROR_VALIDBITS, *PWHEA_PCIXBUS_ERROR_VALIDBITS;

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

typedef struct _WHEA_PCIXBUS_ERROR {
    WHEA_PCIXBUS_ERROR_VALIDBITS ValidBits;         // 0x00 (00)
    WHEA_ERROR_STATUS ErrorStatus;                  // 0x08 (08)
    USHORT ErrorType;                               // 0x10 (16)
    WHEA_PCIXBUS_ID BusId;                          // 0x12 (18)
    ULONG Reserved;                                 // 0x14 (20)
    ULONGLONG BusAddress;                           // 0x18 (24)
    ULONGLONG BusData;                              // 0x20 (32)
    WHEA_PCIXBUS_COMMAND BusCommand;                // 0x28 (40)
    ULONGLONG RequesterId;                          // 0x30 (48)
    ULONGLONG CompleterId;                          // 0x38 (56)
    ULONGLONG TargetId;                             // 0x40 (64)
                                                    // 0x48 (72)
} WHEA_PCIXBUS_ERROR, *PWHEA_PCIXBUS_ERROR;

//
// PCI/PCI_X Component Error
//

typedef union _WHEA_PCIXDEVICE_ERROR_VALIDBITS {
    struct {
        ULONGLONG ErrorStatus:1;
        ULONGLONG IdInfo:1;
        ULONGLONG MemoryNumber:1;
        ULONGLONG IoNumber:1;
        ULONGLONG RegisterDataPairs:1;
        ULONGLONG Reserved:59;
    } DUMMYSTRUCTNAME;
    ULONGLONG ValidBits;
} WHEA_PCIXDEVICE_ERROR_VALIDBITS, *PWHEA_PCIXDEVICE_ERROR_VALIDBITS;

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

typedef struct _WHEA_PCIXDEVICE_ERROR {
    WHEA_PCIXDEVICE_ERROR_VALIDBITS ValidBits;          // 0x00 (00)
    WHEA_ERROR_STATUS ErrorStatus;                      // 0x08 (08)
    WHEA_PCIXDEVICE_ID IdInfo;                          // 0x10 (16)
    ULONG MemoryNumber;                                 // 0x20 (32)
    ULONG IoNumber;                                     // 0x24 (36)
    WHEA_PCIXDEVICE_REGISTER_PAIR RegisterDataPairs[4]; // 0x28 (42)
                                                        // 0x8C (140)
} WHEA_PCIXDEVICE_ERROR, *PWHEA_PCIXDEVICE_ERROR;

//
// Firmware reference.
//

#define WHEA_FIRMWARE_RECORD_TYPE_IPFSAL 0

typedef struct _WHEA_FIRMWARE_RECORD {
    UCHAR Type;
    UCHAR Reserved[7];
    ULONGLONG FirmwareRecordId;
} WHEA_FIRMWARE_RECORD, *PWHEA_FIRMWARE_RECORD;

//
// All generic error status blocks must have the following format.
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

typedef struct _WHEA_GENERIC_ERROR_DATA_ENTRY {
    GUID SectionType;
    WHEA_ERROR_SEVERITY ErrorSeverity;
    WHEA_REVISION Revision;
    UCHAR ValidBits;
    UCHAR Flags;
    ULONG ErrorDataLength;
    GUID FRUId;
    UCHAR FRUText[20];
    UCHAR Data[1];
} WHEA_GENERIC_ERROR_DATA_ENTRY, *PWHEA_GENERIC_ERROR_DATA_ENTRY;

typedef union _WHEA_BOOT_ERROR_VALIDBITS {
    struct {
        UCHAR FRUId:1;
        UCHAR FRUString:1;
        UCHAR ErrorData:1;
        UCHAR Reserved:5;
    } DUMMYSTRUCTNAME;
    UCHAR AsUCHAR;
} WHEA_BOOT_ERROR_VALIDBITS, *PWHEA_BOOT_ERROR_VALIDBITS;

#define WHEA_BOOT_ERROR_DESCRIPTION_UNKNOWN      0
#define WHEA_BOOT_ERROR_DESCRIPTION_FWRESET      1
#define WHEA_BOOT_ERROR_DESCRIPTION_SPRESET      2
#define WHEA_BOOT_ERROR_DESCRIPTION_HUNGSYSTEM   3

#define WHEA_BOOT_ERROR_TYPE_PROCESSOR           0x00
#define WHEA_BOOT_ERROR_TYPE_MEMORY              0x01
#define WHEA_BOOT_ERROR_TYPE_PCIEXPRESS          0x02
#define WHEA_BOOT_ERROR_TYPE_NMI                 0x03
#define WHEA_BOOT_ERROR_TYPE_PCIXBUS             0x04
#define WHEA_BOOT_ERROR_TYPE_PCIXDEVICE          0x05
#define WHEA_BOOT_ERROR_TYPE_GENERIC             0x06

typedef struct _WHEA_BOOT_ERROR_STATUS {
    UCHAR ErrorPresent;
    WHEA_BOOT_ERROR_VALIDBITS ValidBits;
    UCHAR ErrorDescription;
    UCHAR Reserved;
    ULONG ErrorDataLength;
    GUID Type;
    UCHAR FRUId[16];
    UCHAR FRUString[24];
    UCHAR ErrorData[1];
} WHEA_BOOT_ERROR_STATUS, *PWHEA_BOOT_ERROR_STATUS;

#define WHEA_ERROR_PKT_SIGNATURE 'tPrE'
#define WHEA_ERROR_PKT_VERSION   2

#define WHEA_ERROR_PKT_FLAGS_PREVERROR             0x00000001
#define WHEA_ERROR_PKT_FLAGS_CPUVALID              0x00000002
#define WHEA_ERROR_PKT_FLAGS_HVERROR               0x00000004
#define WHEA_ERROR_PKT_FLAGS_SIMULATED             0x00000008

typedef union _WHEA_ERROR_PACKET_FLAGS {
    struct {
        ULONG PreviousError:1;
        ULONG CpuValid:1;
        ULONG HypervisorError:1;
        ULONG Simulated:1;
        ULONG Reserved:28;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_ERROR_PACKET_FLAGS, *PWHEA_ERROR_PACKET_FLAGS;

typedef struct _WHEA_ERROR_PACKET {

    ULONG                   Signature;                  // +0x00 (0)
    WHEA_ERROR_PACKET_FLAGS Flags;                      // +0x04 (4)
    ULONG                   Size;                       // +0x08 (8)
    ULONG                   RawDataLength;              // +0x0C (12)
    ULONGLONG               Reserved1;                  // +0x10 (16)
    ULONGLONG               Context;                    // +0x18 (24)
    WHEA_ERROR_TYPE         ErrorType;                  // +0x20 (32)
    WHEA_ERROR_SEVERITY     ErrorSeverity;              // +0x24 (36)
    ULONG                   ErrorSourceId;              // +0x28 (40)
    WHEA_ERROR_SOURCE_TYPE  ErrorSourceType;            // +0x2C (44)
    ULONG                   Reserved2;                  // +0x30 (48)
    ULONG                   Version;                    // +0x34 (52)
    ULONGLONG               Cpu;                        // +0x38 (56)

    union {                                             // +0x40 (64)
        WHEA_GENERIC_PROCESSOR_ERROR ProcessorError;
        WHEA_MEMORY_ERROR            MemoryError;
        WHEA_NMI_ERROR               NmiError;
        WHEA_PCIEXPRESS_ERROR        PciExpressError;
        WHEA_PCIXBUS_ERROR           PciXBusError;
        WHEA_PCIXDEVICE_ERROR        PciXDeviceError;
    } u;

    WHEA_RAW_DATA_FORMAT     RawDataFormat;             // +0x110 (272)
    ULONG                    RawDataOffset;             // +0x114 (276)
    UCHAR                    RawData[1];               // +0x118 (280)

} WHEA_ERROR_PACKET, *PWHEA_ERROR_PACKET;

#define WHEA_ERROR_PACKET_LENGTH FIELD_OFFSET(WHEA_ERROR_PACKET, RawData)

typedef USHORT WHEA_ERROR_RECORD_ID, *PWHEA_ERROR_RECORD_ID;

//
// An error section descriptor provides key information about an error section
// contained in an error record.
//

#define WHEA_SECTION_DESCRIPTOR_FLAGS_PRIMARY            0x00000001
#define WHEA_SECTION_DESCRIPTOR_FLAGS_CONTAINMENTWRN     0x00000002
#define WHEA_SECTION_DESCRIPTOR_FLAGS_RESET              0x00000004
#define WHEA_SECTION_DESCRIPTOR_FLAGS_THRESHOLDEXCEEDED  0x00000008
#define WHEA_SECTION_DESCRIPTOR_FLAGS_RESOURCENA         0x00000010
#define WHEA_SECTION_DESCRIPTOR_FLAGS_LATENTERROR        0x00000020

#define WHEA_SECTION_DESCRIPTOR_REVISION                 0x0201

typedef union _WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS {
    struct {
        ULONG Primary:1;
        ULONG ContainmentWarning:1;
        ULONG Reset:1;
        ULONG ThresholdExceeded:1;
        ULONG ResourceNotAvailable:1;
        ULONG LatentError:1;
        ULONG Reserved:26;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS,
    *PWHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS;

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
    ULONG SectionOffset;                                       // +0x00
    ULONG SectionLength;                                       // +0x04
    WHEA_REVISION Revision;                                    // +0x08
    WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS ValidBits;  // +0x0A
    UCHAR Reserved;                                            // +0x0B
    WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS Flags;          // +0x0C
    GUID SectionType;                                          // +0x10
    GUID FRUId;                                                // +0x20
    WHEA_ERROR_SEVERITY SectionSeverity;                       // +0x30
    CCHAR FRUText[20];                                         // +0x34
                                                               // +0x48
} WHEA_ERROR_RECORD_SECTION_DESCRIPTOR, *PWHEA_ERROR_RECORD_SECTION_DESCRIPTOR;

//
// Information used by the error record serialization interface.
//

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

#define WHEA_ERROR_RECORD_FLAGS_RECOVERED            0x00000001
#define WHEA_ERROR_RECORD_FLAGS_PREVIOUSERROR        0x00000002
#define WHEA_ERROR_RECORD_FLAGS_SIMULATED            0x00000004

typedef union _WHEA_ERROR_RECORD_HEADER_FLAGS {
    struct {
        ULONG Recovered:1;
        ULONG PreviousError:1;
        ULONG Simulated:1;
        ULONG Reserved:29;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_ERROR_RECORD_HEADER_FLAGS, *PWHEA_ERROR_RECORD_HEADER_FLAGS;

#define WHEA_ERROR_RECORD_VALID_PLATFORMID           0x00000001
#define WHEA_ERROR_RECORD_VALID_TIMESTAMP            0x00000002
#define WHEA_ERROR_RECORD_VALID_PARTITIONID          0x00000004

typedef union _WHEA_ERROR_RECORD_HEADER_VALIDBITS {
    struct {
        ULONG Timestamp:1;
        ULONG PlatformId:1;
        ULONG PartitionId:1;
        ULONG Reserved:29;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_ERROR_RECORD_HEADER_VALIDBITS, *PWHEA_ERROR_RECORD_HEADER_VALIDBITS;

typedef union _WHEA_TIMESTAMP {
    struct {
        ULONGLONG Seconds:8;
        ULONGLONG Minutes:8;
        ULONGLONG Hours:8;
        ULONGLONG Reserved:8;
        ULONGLONG Day:8;
        ULONGLONG Month:8;
        ULONGLONG Year:8;
        ULONGLONG Century:8;
    } DUMMYSTRUCTNAME;
    LARGE_INTEGER AsLARGE_INTEGER;
} WHEA_TIMESTAMP, *PWHEA_TIMESTAMP;

#define WHEA_ERROR_RECORD_REVISION                   0x0201

//
// The error record header provides key information about a hardware error
// condition. A record consists of the header plus at least one section. There
// can be multiple sections, describing a given error conditions.
//

typedef struct _WHEA_ERROR_RECORD_HEADER {
    ULONG Signature;                                 // +0x00
    WHEA_REVISION Revision;                          // +0x04
    ULONG SignatureEnd;                              // +0x06 Must be 0xFFFFFFFF
    USHORT SectionCount;                             // +0x0A
    WHEA_ERROR_SEVERITY Severity;                    // +0x0C
    WHEA_ERROR_RECORD_HEADER_VALIDBITS ValidBits;    // +0x10
    ULONG Length;                                    // +0x14
    WHEA_TIMESTAMP Timestamp;                        // +0x18
    GUID PlatformId;                                 // +0x20
    GUID PartitionId;                                // +0x30
    GUID CreatorId;                                  // +0x40
    GUID NotifyType;                                 // +0x50
    ULONGLONG RecordId;                              // +0x60
    WHEA_ERROR_RECORD_HEADER_FLAGS Flags;            // +0x68
    WHEA_PERSISTENCE_INFO PersistenceInfo;           // +0x6C
    UCHAR Reserved[12];                              // +0x74
                                                     // +0x80
} WHEA_ERROR_RECORD_HEADER, *PWHEA_ERROR_RECORD_HEADER;

//
// Common hardware error record. An error record is expected to contain at
// least one section.
//
typedef struct _WHEA_ERROR_RECORD {
    WHEA_ERROR_RECORD_HEADER              Header;
    WHEA_ERROR_RECORD_SECTION_DESCRIPTOR  SectionDescriptor[1];
} WHEA_ERROR_RECORD, *PWHEA_ERROR_RECORD;
#include <poppack.h>

#define WHEA_ERROR_RECORD_SIGNATURE 'REPC'

#define WheaIsPreviousError(_record_) \
    ((_record_)->Header.Flags & WHEA_ERROR_RECORD_FLAGS_PREVIOUSERROR)

typedef
NTSTATUS
(*WHEA_ERROR_SOURCE_INITIALIZER)(
    __in ULONG Phase,
    __inout PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource,
    __inout_opt PVOID Context
    );

NTSTATUS
WheaReportHwError(
    __inout PWHEA_ERROR_PACKET ErrPkt
    );

NTKERNELAPI
NTSTATUS
WheaAddErrorSource(
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource,
    __in_opt PVOID Context
    );

NTKERNELAPI
NTSTATUS
WheaRemoveErrorSource(
    __in HANDLE Handle
    );

NTSTATUS
WheaRegisterErrSrcInitializer(
    __in WHEA_ERROR_SOURCE_TYPE ErrorSource,
    __in WHEA_ERROR_SOURCE_INITIALIZER Initializer
    );

PWHEA_ERROR_SOURCE_DESCRIPTOR
WheaGetErrorSource (
    __in ULONG ErrorSourceId
    );

FORCEINLINE
PWHEA_ERROR_PACKET
WheaGetErrPacketFromErrRecord (
    __in PWHEA_ERROR_RECORD Record
    )
{

    GUID Guid;
    ULONG Offset;
    PWHEA_ERROR_PACKET Packet;
    ULONG SectionNumber;
    ULONG Size;
    GUID WheaPktSectionType = WHEA_PACKET_SECTION_GUID;

    NT_ASSERT(Record->Header.Signature == WHEA_ERROR_RECORD_SIGNATURE);
    if (Record->Header.Signature != WHEA_ERROR_RECORD_SIGNATURE) {
        return NULL;
    }

    Size = (sizeof(WHEA_ERROR_RECORD_HEADER)) +
            (sizeof(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR) *
             Record->Header.SectionCount);

    if (Record->Header.Length < Size) {
        return NULL;
    }

    for (SectionNumber = 0;
         SectionNumber < Record->Header.SectionCount;
         SectionNumber += 1) {

        RtlCopyMemory(&Guid,
                      &Record->SectionDescriptor[SectionNumber].SectionType,
                      sizeof(GUID));

        if (RtlCompareMemory(&Guid, &WheaPktSectionType, sizeof(GUID)) ==
            sizeof(GUID)) {

            Offset = Record->SectionDescriptor[SectionNumber].SectionOffset;
            Size = (Offset +
                    Record->SectionDescriptor[SectionNumber].SectionLength);

            if (Record->Header.Length < Size) {
                return NULL;
            }

            Packet = (PWHEA_ERROR_PACKET)((PUCHAR)Record + Offset);
            NT_ASSERT(Packet->Signature == WHEA_ERROR_PKT_SIGNATURE);
            return Packet;
        }
    }

    return NULL;
}

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

//
// This union is used to communicate the platform's error injection capabilities
// to the OS.
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

#define PshedFADiscovery              0x00000001
#define PshedFAErrorSourceControl     0x00000002
#define PshedFAErrorRecordPersistence 0x00000004
#define PshedFAErrorInfoRetrieval     0x00000008
#define PshedFAErrorRecovery          0x00000010
#define PshedFAErrorInjection         0x00000020

typedef
NTSTATUS
(*PSHED_PI_GET_ALL_ERROR_SOURCES) (
    __inout_opt PVOID PluginContext,
    __inout PULONG Count,
    __inout_bcount(*Length) PWHEA_ERROR_SOURCE_DESCRIPTOR *ErrorSrcs,
    __inout PULONG Length
    );

typedef
NTSTATUS
(*PSHED_PI_GET_ERROR_SOURCE_INFO) (
    __inout_opt PVOID PluginContext,
    __inout PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

typedef
NTSTATUS
(*PSHED_PI_SET_ERROR_SOURCE_INFO) (
    __inout_opt PVOID PluginContext,
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

typedef
NTSTATUS
 (*PSHED_PI_ENABLE_ERROR_SOURCE) (
    __inout_opt PVOID PluginContext,
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

typedef
NTSTATUS
 (*PSHED_PI_DISABLE_ERROR_SOURCE) (
    __inout_opt PVOID PluginContext,
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

typedef
NTSTATUS
(*PSHED_PI_WRITE_ERROR_RECORD) (
    __inout_opt PVOID PluginContext,
    __in ULONG Flags,
    __in ULONG RecordLength,
    __in_bcount(RecordLength) PWHEA_ERROR_RECORD ErrorRecord
    );

typedef
NTSTATUS
(*PSHED_PI_READ_ERROR_RECORD) (
    __inout_opt PVOID PluginContext,
    __in ULONG Flags,
    __in ULONGLONG ErrorRecordId,
    __out PULONGLONG NextErrorRecordId,
    __inout PULONG RecordLength,
    __out_bcount(*RecordLength) PWHEA_ERROR_RECORD ErrorRecord
    );

typedef
NTSTATUS
(*PSHED_PI_CLEAR_ERROR_RECORD) (
    __inout_opt PVOID PluginContext,
    __in ULONG Flags,
    __in ULONGLONG ErrorRecordId
    );

typedef
NTSTATUS
(*PSHED_PI_RETRIEVE_ERROR_INFO) (
    __inout_opt PVOID PluginContext,
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource,
    __in ULONGLONG BufferLength,
    __inout_bcount(BufferLength) PWHEA_ERROR_PACKET Packet
    );

typedef
NTSTATUS
(*PSHED_PI_FINALIZE_ERROR_RECORD) (
    __inout_opt PVOID PluginContext,
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource,
    __in ULONG BufferLength,
    __inout_bcount(BufferLength) PWHEA_ERROR_RECORD ErrorRecord
    );

typedef
NTSTATUS
(*PSHED_PI_CLEAR_ERROR_STATUS) (
    __inout_opt PVOID PluginContext,
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource,
    __in ULONG BufferLength,
    __in_bcount(BufferLength) PWHEA_ERROR_RECORD ErrorRecord
    );

typedef
NTSTATUS
(*PSHED_PI_ATTEMPT_ERROR_RECOVERY) (
    __inout_opt PVOID PluginContext,
    __in ULONG BufferLength,
    __in_bcount(BufferLength) PWHEA_ERROR_RECORD ErrorRecord
    );

typedef
NTSTATUS
(*PSHED_PI_GET_INJECTION_CAPABILITIES) (
    __inout_opt PVOID PluginContext,
    __out PWHEA_ERROR_INJECTION_CAPABILITIES Capabilities
    );

typedef
NTSTATUS
(*PSHED_PI_INJECT_ERROR) (
    __inout_opt PVOID PluginContext,
    __in ULONGLONG ErrorType,
    __in ULONGLONG Parameter1,
    __in ULONGLONG Parameter2,
    __in ULONGLONG Parameter3,
    __in ULONGLONG Parameter4
    );

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
} WHEA_PSHED_PLUGIN_CALLBACKS,
 *PWHEA_PSHED_PLUGIN_CALLBACKS;

#define WHEA_PLUGIN_REGISTRATION_PACKET_VERSION 0x00010000

typedef struct _WHEA_PSHED_PLUGIN_REGISTRATION_PACKET {
    ULONG Length;
    ULONG Version;
    PVOID Context;
    ULONG FunctionalAreaMask;
    ULONG Reserved;
    WHEA_PSHED_PLUGIN_CALLBACKS Callbacks;
} WHEA_PSHED_PLUGIN_REGISTRATION_PACKET,
  *PWHEA_PSHED_PLUGIN_REGISTRATION_PACKET;

typedef struct _WHEA_PSHED_INIT_PACKET {
    ULONG Size;
    ULONG Version;
} WHEA_PSHED_INIT_PACKET, *PWHEA_PSHED_INIT_PACKET;

#define WHEA_WRITE_FLAG_DUMMY 0x00000001

PVOID
PshedAllocateMemory (
    __in ULONG Size
    );

NTSTATUS
PshedAttemptErrorRecovery(
    __inout PWHEA_ERROR_RECORD ErrorRecord
    );

VOID
PshedBugCheckSystem(
    __in PWHEA_ERROR_RECORD ErrorRecord
    );

NTSTATUS
PshedClearErrorRecord(
    __in ULONG Flags,
    __in ULONGLONG RecordId
    );

NTSTATUS
PshedDisableErrorSource (
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

NTSTATUS
PshedEnableErrorSource (
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

NTSTATUS
PshedFinalizeErrorRecord(
    __inout PWHEA_ERROR_RECORD ErrorRecord,
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

VOID
PshedFreeMemory (
    __in PVOID Address
    );

NTSTATUS
PshedGetAllErrorSources (
    __out PULONG ErrorSourceCount,
    __inout_bcount(*Length) PUCHAR *Buffer,
    __inout PULONG Length
    );

NTSTATUS
PshedGetBootErrorPacket (
    __out PULONG BootPacketLength,
    __out PWHEA_ERROR_PACKET *BootPacket
    );

NTSTATUS
PshedGetErrorSourceInfo (
    __in WHEA_ERROR_SOURCE_TYPE ErrorSource,
    __inout PWHEA_ERROR_SOURCE_DESCRIPTOR Descriptor
    );

NTSTATUS
PshedGetInjectionCapabilities (
    __out PWHEA_ERROR_INJECTION_CAPABILITIES Capabilities
    );

VOID
PshedHandleCorrectedError (
    __in PWHEA_ERROR_PACKET Packet
    );

NTSTATUS
PshedInjectError (
    __in ULONG ErrorType,
    __in ULONGLONG Parameter1,
    __in ULONGLONG Parameter2,
    __in ULONGLONG Parameter3,
    __in ULONGLONG Parameter4
    );

BOOLEAN
PshedIsSystemWheaEnabled (
    VOID
    );

NTSTATUS
PshedReadErrorRecord(
    __in ULONG Flags,
    __in ULONGLONG ErrorRecordId,
    __out PULONGLONG NextErrorRecordId,
    __out PULONG RecordLength,
    __out_bcount(*RecordLength) PWHEA_ERROR_RECORD *ErrorRecord
    );

NTSTATUS
PshedRegisterPlugin (
    __inout PWHEA_PSHED_PLUGIN_REGISTRATION_PACKET Packet
    );

NTSTATUS
PshedRetrieveErrorInfo (
    __inout PWHEA_ERROR_PACKET ErrorPkt,
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

NTSTATUS
PshedSetErrorSourceInfo (
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

BOOLEAN
PshedSynchronizeExecution (
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource,
    __in PKSYNCHRONIZE_ROUTINE SynchronizeRoutine,
    __in PVOID SynchronizeContext
    );

NTSTATUS
PshedWriteErrorRecord(
    __in ULONG Flags,
    __in ULONG RecordLength,
    __in_bcount(RecordLength) PWHEA_ERROR_RECORD ErrorRecord
    );

#ifdef __cplusplus
}
#endif

#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning(default:4115)
#pragma warning(default:4201)
#pragma warning(default:4214)
#endif

#endif // _NTDDK_
