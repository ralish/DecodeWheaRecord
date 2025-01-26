// ReSharper disable InconsistentNaming

using System;

using DecodeWheaRecord.Descriptors;
using DecodeWheaRecord.Hardware;
using DecodeWheaRecord.Internal;

/*
 * Module       Version             Arch(s)         Function(s)
 * AzPshedPi    11.0.2404.15001     AMD64           PshedPipHasDPCSection
 * pci.sys      10.0.26100.2454     AMD64 / Arm64   PciWheaCreateErrorRecord
 */
namespace DecodeWheaRecord.Errors.Microsoft {
    // Alias for the PCI_EXPRESS_DPC_CAPABILITY structure
    internal sealed class WHEA_PCI_DPC_SECTION : WheaRecord {
        private const uint StructSize = 68;
        public override uint GetNativeSize() => StructSize;

        public PCI_EXPRESS_ENHANCED_CAPABILITY_HEADER Header;

        /*
         * Fields common to root and downstream ports
         */

        public PCI_EXPRESS_DPC_CAPS_REGISTER DpcCapabilities;
        public PCI_EXPRESS_DPC_CONTROL_REGISTER DpcControl;
        public PCI_EXPRESS_DPC_STATUS_REGISTER DpcStatus;
        public PCI_EXPRESS_DPC_ERROR_SOURCE_ID DpcErrSrcId;

        /*
         * Fields only supported by root ports
         */

        public PCI_EXPRESS_DPC_RP_PIO_REGISTER RpPioStatus;
        public PCI_EXPRESS_DPC_RP_PIO_REGISTER RpPioMask;
        public PCI_EXPRESS_DPC_RP_PIO_REGISTER RpPioSeverity;
        public PCI_EXPRESS_DPC_RP_PIO_REGISTER RpPioSysError;
        public PCI_EXPRESS_DPC_RP_PIO_REGISTER RpPioException;
        public PCI_EXPRESS_DPC_RP_PIO_HEADERLOG_REGISTER RpPioHeaderLog;
        public PCI_EXPRESS_DPC_RP_PIO_IMPSPECLOG_REGISTER RpPioImpSpecLog;
        public PCI_EXPRESS_DPC_RP_PIO_TLPPREFIXLOG_REGISTER RpPioPrefixLog;

        public WHEA_PCI_DPC_SECTION(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_PCI_DPC_SECTION), structOffset, StructSize, bytesRemaining) {
            WheaPciDpcSection(recordAddr, structOffset);
        }

        public WHEA_PCI_DPC_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(typeof(WHEA_PCI_DPC_SECTION), sectionDsc, StructSize, bytesRemaining) {
            WheaPciDpcSection(recordAddr, sectionDsc.SectionOffset);
        }

        private void WheaPciDpcSection(IntPtr recordAddr, uint structOffset) {
            var structAddr = recordAddr + (int)structOffset;

            Header = PtrToStructure<PCI_EXPRESS_ENHANCED_CAPABILITY_HEADER>(structAddr);

            DpcCapabilities = PtrToStructure<PCI_EXPRESS_DPC_CAPS_REGISTER>(structAddr + 4);
            DpcControl = PtrToStructure<PCI_EXPRESS_DPC_CONTROL_REGISTER>(structAddr + 6);
            DpcStatus = PtrToStructure<PCI_EXPRESS_DPC_STATUS_REGISTER>(structAddr + 8);
            DpcErrSrcId = PtrToStructure<PCI_EXPRESS_DPC_ERROR_SOURCE_ID>(structAddr + 10);

            RpPioStatus = PtrToStructure<PCI_EXPRESS_DPC_RP_PIO_REGISTER>(structAddr + 12);
            RpPioMask = PtrToStructure<PCI_EXPRESS_DPC_RP_PIO_REGISTER>(structAddr + 16);
            RpPioSeverity = PtrToStructure<PCI_EXPRESS_DPC_RP_PIO_REGISTER>(structAddr + 20);
            RpPioSysError = PtrToStructure<PCI_EXPRESS_DPC_RP_PIO_REGISTER>(structAddr + 24);
            RpPioException = PtrToStructure<PCI_EXPRESS_DPC_RP_PIO_REGISTER>(structAddr + 28);
            RpPioHeaderLog = PtrToStructure<PCI_EXPRESS_DPC_RP_PIO_HEADERLOG_REGISTER>(structAddr + 32);
            RpPioImpSpecLog = PtrToStructure<PCI_EXPRESS_DPC_RP_PIO_IMPSPECLOG_REGISTER>(structAddr + 48);
            RpPioPrefixLog = PtrToStructure<PCI_EXPRESS_DPC_RP_PIO_TLPPREFIXLOG_REGISTER>(structAddr + 52);

            FinalizeRecord(recordAddr, StructSize);
        }
    }
}
