#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Errors.Microsoft {
    // Structure size: 39 bytes
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEA_ERROR_RECOVERY_INFO_SECTION : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_ERROR_RECOVERY_INFO_SECTION>();

        [JsonProperty(Order = 1)]
        [MarshalAs(UnmanagedType.U1)]
        public bool RecoveryKernel;

        private WHEA_RECOVERY_ACTION _RecoveryAction;

        [JsonProperty(Order = 2)]
        public string RecoveryAction => Enum.GetName(typeof(WHEA_RECOVERY_ACTION), _RecoveryAction);

        private WHEA_RECOVERY_TYPE _RecoveryType;

        [JsonProperty(Order = 3)]
        public string RecoveryType => Enum.GetName(typeof(WHEA_RECOVERY_TYPE), _RecoveryType);

        [JsonProperty(Order = 4)]
        public byte Irql; // KIRQL

        [JsonProperty(Order = 5)]
        [MarshalAs(UnmanagedType.U1)]
        public bool RecoverySucceeded;

        private WHEA_RECOVERY_FAILURE_REASON _FailureReason;

        [JsonProperty(Order = 6)]
        public string FailureReason => Enum.GetName(typeof(WHEA_RECOVERY_FAILURE_REASON), _FailureReason);

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 20)]
        private string _ProcessName;

        [JsonProperty(Order = 7)]
        public string ProcessName => _ProcessName.Trim('\0');
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
        ActionRequired = 1,
        ActionOptional = 2
    }

    internal enum WHEA_RECOVERY_FAILURE_REASON : uint {
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
