#pragma once
EXTERN_C __declspec(selectany) const GUID WHEA_ETW_PROVIDER = {0x7b563579, 0x53c8, 0x44e7, {0x82, 0x36,0x0f,0x87,0xb9,0xfe,0x65,0x94}};
#define WHEA_ETW_PROVIDER_CHANNEL_systemChannel 0x8
#define WHEA_CHANNEL 0x10
#define WHEA_ERROR_KEYWORD 0x800
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR EVENT_WHEA_CORRECTED_ERROR = {0x1, 0x0, 0x8, 0x3, 0x0, 0x0, 0x8000000000000000};
#define EVENT_WHEA_CORRECTED_ERROR_value 0x1
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR EVENT_WHEA_UNCORRECTED_ERROR = {0x2, 0x0, 0x8, 0x2, 0x0, 0x0, 0x8000000000000000};
#define EVENT_WHEA_UNCORRECTED_ERROR_value 0x2
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR EVENT_WHEA_CORRECTED_ERROR_OP = {0x3, 0x0, 0x10, 0x3, 0x0, 0x0, 0x4000000000000000};
#define EVENT_WHEA_CORRECTED_ERROR_OP_value 0x3
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR EVENT_WHEA_UNCORRECTED_ERROR_OP = {0x4, 0x0, 0x10, 0x2, 0x0, 0x0, 0x4000000000000000};
#define EVENT_WHEA_UNCORRECTED_ERROR_OP_value 0x4
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR EVENT_WHEA_INIT_OP = {0x5, 0x0, 0x10, 0x4, 0x0, 0x0, 0x4000000000000000};
#define EVENT_WHEA_INIT_OP_value 0x5
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR EVENT_WHEA_MEMHIERARCHY_ERROR = {0x6, 0x0, 0x8, 0x2, 0x0, 0x0, 0x8000000000000000};
#define EVENT_WHEA_MEMHIERARCHY_ERROR_value 0x6
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR EVENT_WHEA_MEMHIERARCHY_WARNING = {0x7, 0x0, 0x10, 0x3, 0x0, 0x0, 0x4000000000000000};
#define EVENT_WHEA_MEMHIERARCHY_WARNING_value 0x7
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR EVENT_WHEA_TLB_ERROR = {0x8, 0x0, 0x8, 0x2, 0x0, 0x0, 0x8000000000000000};
#define EVENT_WHEA_TLB_ERROR_value 0x8
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR EVENT_WHEA_TLB_WARNING = {0x9, 0x0, 0x10, 0x3, 0x0, 0x0, 0x4000000000000000};
#define EVENT_WHEA_TLB_WARNING_value 0x9
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR EVENT_WHEA_BUS_ERROR = {0xa, 0x0, 0x8, 0x2, 0x0, 0x0, 0x8000000000000000};
#define EVENT_WHEA_BUS_ERROR_value 0xa
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR EVENT_WHEA_BUS_WARNING = {0xb, 0x0, 0x10, 0x3, 0x0, 0x0, 0x4000000000000000};
#define EVENT_WHEA_BUS_WARNING_value 0xb
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR EVENT_WHEA_BUSTO_ERROR = {0xc, 0x0, 0x8, 0x2, 0x0, 0x0, 0x8000000000000000};
#define EVENT_WHEA_BUSTO_ERROR_value 0xc
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR EVENT_WHEA_BUSTO_WARNING = {0xd, 0x0, 0x10, 0x3, 0x0, 0x0, 0x4000000000000000};
#define EVENT_WHEA_BUSTO_WARNING_value 0xd
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR EVENT_WHEA_WDTO_ERROR = {0xe, 0x0, 0x8, 0x2, 0x0, 0x0, 0x8000000000000000};
#define EVENT_WHEA_WDTO_ERROR_value 0xe
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR EVENT_WHEA_ROMPARITY_ERROR = {0xf, 0x0, 0x10, 0x2, 0x0, 0x0, 0x4000000000000000};
#define EVENT_WHEA_ROMPARITY_ERROR_value 0xf
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR EVENT_WHEA_EXTERNAL_ERROR = {0x10, 0x0, 0x8, 0x2, 0x0, 0x0, 0x8000000000000000};
#define EVENT_WHEA_EXTERNAL_ERROR_value 0x10
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR EVENT_WHEA_FRC_ERROR = {0x11, 0x0, 0x8, 0x2, 0x0, 0x0, 0x8000000000000000};
#define EVENT_WHEA_FRC_ERROR_value 0x11
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR EVENT_WHEA_PCIE_ERROR = {0x12, 0x0, 0x8, 0x2, 0x0, 0x0, 0x8000000000000000};
#define EVENT_WHEA_PCIE_ERROR_value 0x12
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR EVENT_WHEA_PCIE_WARNING = {0x13, 0x0, 0x10, 0x3, 0x0, 0x0, 0x4000000000000000};
#define EVENT_WHEA_PCIE_WARNING_value 0x13
EXTERN_C __declspec(selectany) const EVENT_DESCRIPTOR EVENT_WHEA_ERROR = {0x14, 0x0, 0x10, 0x4, 0x0, 0x0, 0x4000000000000800};
#define EVENT_WHEA_ERROR_value 0x14
#define MSG_CorrectedError_EventMessage  0xB0000001L

#define MSG_Init_EventMessage            0xB0000005L

#define MSG_MCABusErr_EventMessage       0xB000000AL

#define MSG_MCABusTOErr_EventMessage     0xB000000CL

#define MSG_MCABusTOWrn_EventMessage     0xB000000DL

#define MSG_MCABusWrn_EventMessage       0xB000000BL

#define MSG_MCAExternalErr_EventMessage  0xB0000010L

#define MSG_MCAFRCErr_EventMessage       0xB0000011L

#define MSG_MCAMemHierarchyErr_EventMessage 0xB0000006L

#define MSG_MCAMemHierarchyWrn_EventMessage 0xB0000007L

#define MSG_MCAROMParityErr_EventMessage 0xB000000FL

#define MSG_MCATLBErr_EventMessage       0xB0000008L

#define MSG_MCATLBWrn_EventMessage       0xB0000009L

#define MSG_MCAWDTOErr_EventMessage      0xB000000EL

#define MSG_PCIeErr_EventMessage         0xB0000012L

#define MSG_PCIeWrn_EventMessage         0xB0000013L

#define MSG_UncorrectedError_EventMessage 0xB0000002L

#define MSG_WHEA_EventMessage            0xB0000014L

#define MSG_WHEA_ERROR_KEYWORD_KeywordMessage 0x1000000CL

#define MSG_eventProviderName            0x90000001L


