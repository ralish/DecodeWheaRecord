// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Descriptors;
using DecodeWheaRecord.Internal;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

/*
 * Module       Version             Arch(s)         Function(s)
 * AzPshedPi    11.0.2404.15001     AMD64           PshedPiGetMemoryErrorSections
 * ntoskrnl     10.0.26100.2605     AMD64           HalpCreateMcaMemoryErrorRecord
 *                                  AMD64           HalpCreateMcaProcessorErrorRecord
 *                                  AMD64           KiMcheckAlternateReturn
 * pshed        10.0.26100.1150     AMD64           PshedpPopulateRecoverySection
 * RADARM       10.0.26100.1        Arm64           RadArmSeaCreateErrorRecord
 *                                  Arm64           RadArmSeaRecover
 */
namespace DecodeWheaRecord.Errors.Microsoft {
    internal sealed class WHEA_ERROR_RECOVERY_INFO_SECTION : WheaRecord {
        private const uint StructSize = 39;
        public override uint GetNativeSize() => StructSize;

        [JsonProperty(Order = 1)]
        public bool RecoveryKernel;

        private WHEA_RECOVERY_ACTION _RecoveryAction;

        [JsonProperty(Order = 2)]
        public string RecoveryAction => GetEnumFlagsAsString(_RecoveryAction);

        private WHEA_RECOVERY_TYPE _RecoveryType;

        [JsonProperty(Order = 3)]
        public string RecoveryType => GetEnumValueAsString<WHEA_RECOVERY_TYPE>(_RecoveryType);

        [JsonProperty(Order = 4)]
        public byte Irql; // KIRQL

        [JsonProperty(Order = 5)]
        public bool RecoverySucceeded;

        private WHEA_RECOVERY_FAILURE_REASON _FailureReason;

        [JsonProperty(Order = 6)]
        public string FailureReason => GetEnumValueAsString<WHEA_RECOVERY_FAILURE_REASON>(_FailureReason);

        private string _ProcessName;

        [JsonProperty(Order = 7)]
        public string ProcessName => _ProcessName.Trim('\0').Trim();

        public WHEA_ERROR_RECOVERY_INFO_SECTION(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_ERROR_RECOVERY_INFO_SECTION), structOffset, StructSize, bytesRemaining) {
            WheaErrorRecoveryInfoSection(recordAddr, structOffset);
        }

        public WHEA_ERROR_RECOVERY_INFO_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(typeof(WHEA_ERROR_RECOVERY_INFO_SECTION), sectionDsc, StructSize, bytesRemaining) {
            WheaErrorRecoveryInfoSection(recordAddr, sectionDsc.SectionOffset);
        }

        private void WheaErrorRecoveryInfoSection(IntPtr recordAddr, uint structOffset) {
            var structAddr = recordAddr + (int)structOffset;

            RecoveryKernel = Marshal.ReadByte(structAddr) != 0;
            _RecoveryAction = (WHEA_RECOVERY_ACTION)Marshal.ReadInt64(structAddr, 1);
            _RecoveryType = (WHEA_RECOVERY_TYPE)Marshal.ReadInt32(structAddr, 9);
            Irql = Marshal.ReadByte(structAddr, 13);
            RecoverySucceeded = Marshal.ReadByte(structAddr, 14) != 0;
            _FailureReason = (WHEA_RECOVERY_FAILURE_REASON)Marshal.ReadInt32(structAddr, 15);
            _ProcessName = Marshal.PtrToStringAnsi(structAddr + 19, 20);

            FinalizeRecord(recordAddr, StructSize);
        }
    }

    // @formatter:int_align_fields true

    [Flags]
    internal enum WHEA_RECOVERY_ACTION : ulong {
        NoneAttempted    = 0x1,
        TerminateProcess = 0x2,
        ForwardedToVm    = 0x4,
        MarkPageBad      = 0x8,
        PoisonNotPresent = 0x10
    }

    internal enum WHEA_RECOVERY_TYPE : uint {
        Invalid        = 0, // Added
        ActionRequired = 1,
        ActionOptional = 2
    }

    internal enum WHEA_RECOVERY_FAILURE_REASON : uint {
        Invalid                            = 0, // Added
        KernelCouldNotMarkMemoryBad        = 1,
        KernelMarkMemoryBadTimedOut        = 2,
        NoRecoveryContext                  = 3,
        NotContinuable                     = 4,
        ProcessorContextCorrupt            = 5,
        Overflow                           = 6,
        NotSupported                       = 7,
        MiscOrAddrNotValid                 = 8,
        InvalidAddressMode                 = 9,
        HighIrql                           = 10,
        InsufficientAltContextWrappers     = 11,
        InterruptsDisabled                 = 12,
        SwapBusy                           = 13,
        StackOverflow                      = 14,
        UnexpectedFailure                  = 15,
        KernelWillPageFaultBCAtCurrentIrql = 16,
        FarNotValid                        = 17
    }

    // @formatter:int_align_fields false
}
