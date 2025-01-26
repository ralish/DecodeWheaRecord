// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Descriptors;
using DecodeWheaRecord.Internal;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

/*
 * Module       Version             Arch(s)         Function(s)
 * pci          10.0.26100.2454     AMD64 / Arm64   PciWheaCreateErrorRecord
 *                                  AMD64           WheaFindErrorRecordSection
 */
namespace DecodeWheaRecord.Errors.Microsoft {
    internal sealed class WHEA_PCI_RECOVERY_SECTION : WheaRecord {
        private const uint StructSize = 3;
        public override uint GetNativeSize() => StructSize;

        // Switched to an enumeration
        private WHEA_PCI_RECOVERY_SIGNAL _SignalType;

        [JsonProperty(Order = 1)]
        public string SignalType => GetEnumValueAsString<WHEA_PCI_RECOVERY_SIGNAL>(_SignalType);

        [JsonProperty(Order = 2)]
        public bool RecoveryAttempted;

        // Switched to an enumeration
        private WHEA_PCI_RECOVERY_STATUS _RecoveryStatus;

        [JsonProperty(Order = 3)]
        public string RecoveryStatus => GetEnumValueAsString<WHEA_PCI_RECOVERY_STATUS>(_RecoveryStatus);

        public WHEA_PCI_RECOVERY_SECTION(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_PCI_RECOVERY_SECTION), structOffset, StructSize, bytesRemaining) {
            WheaPciRecoverySection(recordAddr, structOffset);
        }

        public WHEA_PCI_RECOVERY_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(typeof(WHEA_PCI_RECOVERY_SECTION), sectionDsc, StructSize, bytesRemaining) {
            WheaPciRecoverySection(recordAddr, sectionDsc.SectionOffset);
        }

        private void WheaPciRecoverySection(IntPtr recordAddr, uint structOffset) {
            var structAddr = recordAddr + (int)structOffset;

            _SignalType = (WHEA_PCI_RECOVERY_SIGNAL)Marshal.ReadByte(structAddr);
            RecoveryAttempted = Marshal.ReadByte(structAddr, 1) != 0;
            _RecoveryStatus = (WHEA_PCI_RECOVERY_STATUS)Marshal.ReadByte(structAddr, 2);

            FinalizeRecord(recordAddr, StructSize);
        }
    }

    // @formatter:int_align_fields true

    internal enum WHEA_PCI_RECOVERY_SIGNAL : byte {
        Unknown = 0,
        Aer     = 1,
        Dpc     = 2
    }

    internal enum WHEA_PCI_RECOVERY_STATUS : byte {
        Unknown              = 0,
        NoError              = 1,
        LinkDisableTimeout   = 2,
        LinkEnableTimeout    = 3,
        RpBusyTimeout        = 4,
        ComplexTree          = 5,
        BusNotFound          = 6,
        DeviceNotFound       = 7,
        DdaAerNotRecoverable = 8,
        FailedRecovery       = 9
    }

    // @formatter:int_align_fields false
}
