// ReSharper disable InconsistentNaming
// ReSharper disable MemberCanBePrivate.Global

using System;
using System.Collections.Generic;

namespace DecodeWheaRecord.Shared {
    internal static class WheaGuids {
        /*
         * Creator IDs
         */

        // Microsoft extensions
        internal static readonly Guid WHEA_RECORD_CREATOR_GUID = Guid.Parse("cf07c4bd-b789-4e18-b3c4-1f732cb57131");
        internal static readonly Guid DEFAULT_DEVICE_DRIVER_CREATOR_GUID = Guid.Parse("57217c8d-5e66-44fb-8033-9b74cacedf5b");

        internal static readonly Dictionary<Guid, string> CreatorIds = new Dictionary<Guid, string> {
            // Microsoft extensions
            { WHEA_RECORD_CREATOR_GUID, "Microsoft" }, { DEFAULT_DEVICE_DRIVER_CREATOR_GUID, "Device Driver (default)" }
        };


        /*
         * Notification types
         */

        // Standard notifications
        internal static readonly Guid BOOT_NOTIFY_TYPE_GUID = Guid.Parse("3d61a466-ab40-409a-a698-f362d464b38f");
        internal static readonly Guid CMC_NOTIFY_TYPE_GUID = Guid.Parse("2dce8bb1-bdd7-450e-b9ad-9cf4ebd4f890");
        internal static readonly Guid CPE_NOTIFY_TYPE_GUID = Guid.Parse("4e292f96-d843-4a55-a8c2-d481f27ebeee");
        internal static readonly Guid INIT_NOTIFY_TYPE_GUID = Guid.Parse("cc5263e8-9308-454a-89d0-340bd39bc98e");
        internal static readonly Guid MCE_NOTIFY_TYPE_GUID = Guid.Parse("e8f56ffe-919c-4cc5-ba88-65abe14913bb");
        internal static readonly Guid NMI_NOTIFY_TYPE_GUID = Guid.Parse("5bad89ff-b7e6-42c9-814a-cf2485d6e98a");
        internal static readonly Guid PCIe_NOTIFY_TYPE_GUID = Guid.Parse("cf93c01f-1a16-4dfc-b8bc-9c4daf67c104");
        internal static readonly Guid PEI_NOTIFY_TYPE_GUID = Guid.Parse("09a9d5ac-5204-4214-96e5-94992e752bcd");
        internal static readonly Guid SEA_NOTIFY_TYPE_GUID = Guid.Parse("9a78788a-bbe8-11e4-809e-67611e5d46b0");
        internal static readonly Guid SEI_NOTIFY_TYPE_GUID = Guid.Parse("5c284c81-b0ae-4e87-a322-b04c85624323");

        // Microsoft notifications
        internal static readonly Guid BMC_NOTIFY_TYPE_GUID = Guid.Parse("487565ba-6494-4367-95ca-4eff893522f6");
        internal static readonly Guid CMCI_NOTIFY_TYPE_GUID = Guid.Parse("919448b2-3739-4b7f-a8f1-e0062805c2a3");
        internal static readonly Guid DEVICE_DRIVER_NOTIFY_TYPE_GUID = Guid.Parse("0033f803-2e70-4e88-992c-6f26daf3db7a");
        internal static readonly Guid EXTINT_NOTIFY_TYPE_GUID = Guid.Parse("fe84086e-b557-43cf-ac1b-17982e078470");
        internal static readonly Guid GENERIC_NOTIFY_TYPE_GUID = Guid.Parse("3e62a467-ab40-409a-a698-f362d464b38f");
        internal static readonly Guid SCI_NOTIFY_TYPE_GUID = Guid.Parse("e9d59197-94ee-4a4f-8ad8-9b7d8bd93d2e");

        internal static readonly Dictionary<Guid, string> NotifyTypes = new Dictionary<Guid, string> {
            // Standard notifications
            { BOOT_NOTIFY_TYPE_GUID, "Boot Error Record (BOOT)" },
            { CMC_NOTIFY_TYPE_GUID, "Corrected Machine Check (CMC)" },
            { CPE_NOTIFY_TYPE_GUID, "Corrected Platform Error (CPE)" },
            { INIT_NOTIFY_TYPE_GUID, "Init Error Record (INIT)" },
            { MCE_NOTIFY_TYPE_GUID, "Machine Check Exception (MCE)" },
            { NMI_NOTIFY_TYPE_GUID, "Non-Maskable Interrupt (NMI)" },
            { PCIe_NOTIFY_TYPE_GUID, "PCI Express Error (PCIe)" },
            { PEI_NOTIFY_TYPE_GUID, "Platform Error Interrupt (PEI)" },
            { SEA_NOTIFY_TYPE_GUID, "Synchronous External Abort (SEA)" },
            { SEI_NOTIFY_TYPE_GUID, "SError Interrupt (SEI)" },

            // Standard notifications not in headers
            { Guid.Parse("69293bc9-41df-49a3-b4bd-4fb0db3041f6"), "Compute Express Link (CXL)" },
            { Guid.Parse("667dd791-c6b3-4c27-8a6b-0f8e722deb41"), "DMA Remapping Error (DMAr)" },

            // Microsoft notifications
            { BMC_NOTIFY_TYPE_GUID, "Baseboard Management Controller (BMC)" },
            { CMCI_NOTIFY_TYPE_GUID, "Corrected Machine Check Interrupt (CMCI)" },
            { DEVICE_DRIVER_NOTIFY_TYPE_GUID, "Device Driver" },
            { EXTINT_NOTIFY_TYPE_GUID, "External Interrupt" },
            { GENERIC_NOTIFY_TYPE_GUID, "Generic Error Record" },
            { SCI_NOTIFY_TYPE_GUID, "Service Control Interrupt (SCI)" }
        };


        /*
         * Section types
         */

        // Standard sections
        internal static readonly Guid ARM_PROCESSOR_ERROR_SECTION_GUID = Guid.Parse("e19e3d16-bc11-11e4-9caa-c2051d5d46b0");
        internal static readonly Guid FIRMWARE_ERROR_RECORD_REFERENCE_GUID = Guid.Parse("81212a96-09ed-4996-9471-8d729c8e69ed");
        internal static readonly Guid IPF_PROCESSOR_ERROR_SECTION_GUID = Guid.Parse("e429faf1-3cb7-11d4-bca7-0080c73c8881");
        internal static readonly Guid MEMORY_ERROR_SECTION_GUID = Guid.Parse("a5bc1114-6f64-4ede-b863-3e83ed7c83b1");
        internal static readonly Guid PCIEXPRESS_ERROR_SECTION_GUID = Guid.Parse("d995e954-bbc1-430f-ad91-b44dcb3c6f35");
        internal static readonly Guid PCIXBUS_ERROR_SECTION_GUID = Guid.Parse("c5753963-3b84-4095-bf78-eddad3f9c9dd");
        internal static readonly Guid PCIXDEVICE_ERROR_SECTION_GUID = Guid.Parse("eb5e4685-ca66-4769-b6a2-26068b001326");
        internal static readonly Guid PROCESSOR_GENERIC_ERROR_SECTION_GUID = Guid.Parse("9876ccad-47b4-4bdb-b65e-16f193c4f3db");
        internal static readonly Guid XPF_PROCESSOR_ERROR_SECTION_GUID = Guid.Parse("dc3ea0b0-a144-4797-b95b-53fa242b6e1d");

        // Microsoft sections
        internal static readonly Guid GENERIC_SECTION_GUID = Guid.Parse("e71254e8-c1b9-4940-ab76-909703a4320f");
        internal static readonly Guid IPF_SAL_RECORD_SECTION_GUID = Guid.Parse("6f3380d1-6eb0-497f-a578-4d4c65a71617");
        internal static readonly Guid IPMI_MSR_DUMP_SECTION_GUID = Guid.Parse("1c15b445-9b06-4667-ac25-33c056b88803");
        internal static readonly Guid MEMORY_CORRECTABLE_ERROR_SUMMARY_SECTION_GUID = Guid.Parse("0e36c93e-ca15-4a83-ba8a-cbe80f7f0017");
        internal static readonly Guid MU_TELEMETRY_SECTION_GUID = Guid.Parse("85183a8b-9c41-429c-939c-5c3c087ca280");
        internal static readonly Guid NMI_SECTION_GUID = Guid.Parse("e71254e7-c1b9-4940-ab76-909703a4320f");
        internal static readonly Guid PCIE_CORRECTABLE_ERROR_SUMMARY_SECTION_GUID = Guid.Parse("e96eca99-53e2-4f52-9be7-d2dbe9508ed0");
        internal static readonly Guid PMEM_ERROR_SECTION_GUID = Guid.Parse("81687003-dbfd-4728-9ffd-f0904f97597d");
        internal static readonly Guid RECOVERY_INFO_SECTION_GUID = Guid.Parse("c34832a1-02c3-4c52-a9f1-9f1d5d7723fc");
        internal static readonly Guid WHEA_DPC_CAPABILITY_SECTION_GUID = Guid.Parse("ec49534b-30e7-4358-972f-eca6958fae3b");
        internal static readonly Guid WHEA_ERROR_PACKET_SECTION_GUID = Guid.Parse("e71254e9-c1b9-4940-ab76-909703a4320f");
        internal static readonly Guid XPF_MCA_SECTION_GUID = Guid.Parse("8a1e1d01-42f9-4557-9c33-565e5cc3f7e8");

        internal static readonly Dictionary<Guid, string> SectionTypes = new Dictionary<Guid, string> {
            // Standard sections not in headers
            { Guid.Parse("91335ef6-ebfb-4478-a6a6-88b728cf75d7"), "CCIX PER Log Error" },
            { Guid.Parse("80b9efb4-52b5-4de3-a777-68784b771048"), "CXL Protocol Error" },
            { Guid.Parse("5b51fef7-c79d-4434-8f1b-aa62de3e2c64"), "DMAr Generic Error" },
            { Guid.Parse("5e4706c1-5356-48c6-930b-52f2120a4458"), "FRU Memory Poison" },
            { Guid.Parse("71761d37-32b2-45cd-a7d0-b0fedd93e8cf"), "Intel VT for Directed I/O Specific DMAr Error" },
            { Guid.Parse("036f84e1-7f37-428c-a79e-575fdfaa84ec"), "IOMMU Specific DMAr Error" },

            // Standard sections
            { ARM_PROCESSOR_ERROR_SECTION_GUID, "ARM Processor Error" },
            { FIRMWARE_ERROR_RECORD_REFERENCE_GUID, "Firmware Error Record Reference" },
            { PROCESSOR_GENERIC_ERROR_SECTION_GUID, "Generic Processor Error" },
            { XPF_PROCESSOR_ERROR_SECTION_GUID, "IA32/AMD64 Processor Error" },
            { IPF_PROCESSOR_ERROR_SECTION_GUID, "IA64 Processor Error" },
            { MEMORY_ERROR_SECTION_GUID, "Memory Error" },
            { PCIXDEVICE_ERROR_SECTION_GUID, "PCI Component/Device Error" },
            { PCIEXPRESS_ERROR_SECTION_GUID, "PCI Express Error" },
            { PCIXBUS_ERROR_SECTION_GUID, "PCI/PCI-X Bus Error" },

            // Microsoft sections
            { MEMORY_CORRECTABLE_ERROR_SUMMARY_SECTION_GUID, "Correctable Memory Error" },
            { PCIE_CORRECTABLE_ERROR_SUMMARY_SECTION_GUID, "Correctable PCIe Error" },
            { RECOVERY_INFO_SECTION_GUID, "Error Recovery Information" },
            { WHEA_ERROR_PACKET_SECTION_GUID, "Hardware Error Packet" },
            { XPF_MCA_SECTION_GUID, "IA32/AMD64 Machine Check Error" },
            { IPMI_MSR_DUMP_SECTION_GUID, "MSR Dump" },
            { NMI_SECTION_GUID, "NMI Error" },
            { PMEM_ERROR_SECTION_GUID, "Persistent Mememory Error" },
            { MU_TELEMETRY_SECTION_GUID, "Project Mu Telemetry" },

            // Microsoft sections (unknown)
            { GENERIC_SECTION_GUID, "GENERIC_SECTION_GUID" },
            { IPF_SAL_RECORD_SECTION_GUID, "IPF_SAL_RECORD_SECTION_GUID" },
            { WHEA_DPC_CAPABILITY_SECTION_GUID, "WHEA_DPC_CAPABILITY_SECTION_GUID" }
        };
    }
}