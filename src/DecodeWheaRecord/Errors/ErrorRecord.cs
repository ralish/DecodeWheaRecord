// ReSharper disable InconsistentNaming

using System;
using System.Collections.Generic;

using DecodeWheaRecord.Descriptors;
using DecodeWheaRecord.Errors.Microsoft;
using DecodeWheaRecord.Errors.UEFI;
using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors {
    internal sealed class WHEA_ERROR_RECORD : WheaRecord {
        private readonly uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        // At least the header and one error section descriptor
        private const uint MinStructSize = WHEA_ERROR_RECORD_HEADER.StructSize + WHEA_ERROR_RECORD_SECTION_DESCRIPTOR.StructSize;

        [JsonProperty(Order = 1)]
        public WHEA_ERROR_RECORD_HEADER Header { get; private set; }

        [JsonProperty(Order = 2)]
        public List<WHEA_ERROR_RECORD_SECTION_DESCRIPTOR> SectionDescriptor { get; private set; } = new List<WHEA_ERROR_RECORD_SECTION_DESCRIPTOR>();

        [JsonProperty(Order = 3)]
        public List<IWheaRecord> Section { get; private set; } = new List<IWheaRecord>();

        public WHEA_ERROR_RECORD(IntPtr recordAddr, uint recordSize) :
            base(typeof(WHEA_ERROR_RECORD), 0, MinStructSize, recordSize) {
            // Deserialize the header
            Header = new WHEA_ERROR_RECORD_HEADER(recordAddr, 0, recordSize);
            var offset = Header.GetNativeSize();

            // Deserialize the error section descriptors
            for (var i = 0; i < Header.SectionCount; i++) {
                var sectionDsc = new WHEA_ERROR_RECORD_SECTION_DESCRIPTOR(recordAddr, offset, recordSize - offset);
                SectionDescriptor.Add(sectionDsc);
                offset += sectionDsc.GetNativeSize();
            }

            // Deserialize the error sections
            var bytesProcessed = offset;
            for (var i = 0; i < Header.SectionCount; i++) {
                var section = DecodeSection(SectionDescriptor[i], recordAddr, recordSize);
                Section.Add(section);
                bytesProcessed += section.GetNativeSize();
            }

            _StructSize = bytesProcessed;
            FinalizeRecord(recordAddr, _StructSize);
        }

        private IWheaRecord DecodeSection(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint recordSize) {
            IWheaRecord section;

            var bytesRemaining = recordSize - sectionDsc.SectionOffset; // TODO: Factor in adjacent sections

            try {
                switch (sectionDsc.SectionTypeGuid) {
                /*
                 * Standard sections
                 */

                case var sectionGuid when sectionGuid == WheaGuids.ARM_PROCESSOR_ERROR_SECTION_GUID:
                    section = new WHEA_ARM_PROCESSOR_ERROR_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.FIRMWARE_ERROR_RECORD_REFERENCE_GUID:
                    section = new WHEA_FIRMWARE_ERROR_RECORD_REFERENCE(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.IPF_PROCESSOR_ERROR_SECTION_GUID:
                    section = new UnsupportedError(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.MEMORY_ERROR_SECTION_GUID:
                    section = new WHEA_MEMORY_ERROR_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.PCIEXPRESS_ERROR_SECTION_GUID:
                    section = new WHEA_PCIEXPRESS_ERROR_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.PCIXBUS_ERROR_SECTION_GUID:
                    section = new WHEA_PCIXBUS_ERROR_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.PCIXDEVICE_ERROR_SECTION_GUID:
                    section = new WHEA_PCIXDEVICE_ERROR_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.PROCESSOR_GENERIC_ERROR_SECTION_GUID:
                    section = new WHEA_PROCESSOR_GENERIC_ERROR_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.XPF_PROCESSOR_ERROR_SECTION_GUID:
                    section = new WHEA_XPF_PROCESSOR_ERROR_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;

                /*
                 * Microsoft sections
                 */

                case var sectionGuid when sectionGuid == WheaGuids.ARM_RAS_NODE_SECTION_GUID:
                    section = new WHEA_ARM_RAS_NODE_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.GENERIC_SECTION_GUID:
                    section = new WHEA_GENERIC_ERROR(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.IPF_SAL_RECORD_SECTION_GUID:
                    section = new UnsupportedError(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.IPMI_MSR_DUMP_SECTION_GUID:
                    section = new WHEA_MSR_DUMP_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.MEMORY_CORRECTABLE_ERROR_SUMMARY_SECTION_GUID:
                    section = new WHEA_MEMORY_CORRECTABLE_ERROR_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.MEMORY_ERROR_EXT_SECTION_INTEL_GUID:
                    section = new WHEA_MEMORY_ERROR_EXT_SECTION_INTEL(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.MU_TELEMETRY_SECTION_GUID:
                    section = new MU_TELEMETRY_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.NMI_SECTION_GUID:
                    section = new WHEA_NMI_ERROR_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.PCI_RECOVERY_SECTION_GUID:
                    section = new WHEA_PCI_RECOVERY_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.PCIE_CORRECTABLE_ERROR_SUMMARY_SECTION_GUID:
                    section = new WHEA_PCIE_CORRECTABLE_ERROR_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.PMEM_ERROR_SECTION_GUID:
                    section = new WHEA_PMEM_ERROR_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.RECOVERY_INFO_SECTION_GUID:
                    section = new WHEA_ERROR_RECOVERY_INFO_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.SEA_SECTION_GUID:
                    section = new WHEA_SEA_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.SEI_SECTION_GUID:
                    section = new WHEA_SEI_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.WHEA_DPC_CAPABILITY_SECTION_GUID:
                    section = new WHEA_PCI_DPC_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.WHEA_ERROR_PACKET_SECTION_GUID:
                    section = WHEA_ERROR_PACKET.CreateBySignature(sectionDsc, recordAddr, bytesRemaining);
                    break;
                case var sectionGuid when sectionGuid == WheaGuids.XPF_MCA_SECTION_GUID:
                    section = new WHEA_XPF_MCA_SECTION(sectionDsc, recordAddr, bytesRemaining);
                    break;

                /*
                 * Unsupported section
                 */

                default:
                    WarnOutput($"Unsupported section: {sectionDsc.SectionTypeGuid}", StructType.Name);
                    section = new UnsupportedError(sectionDsc, recordAddr, bytesRemaining);
                    break;
                }
            } catch (Exception ex) {
                // Warn and treat as unsupported if section parsing fails.
                WarnOutput($"Exception while decoding section {sectionDsc.SectionTypeGuid}: {ex.Message}", StructType.Name);
                section = new UnsupportedError(sectionDsc, recordAddr, bytesRemaining);
            }

            return section;
        }
    }
}
