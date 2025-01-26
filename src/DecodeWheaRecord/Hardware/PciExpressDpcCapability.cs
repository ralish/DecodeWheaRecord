#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable InconsistentNaming

using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;

using JetBrains.Annotations;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Hardware {
    // Structure size: 2 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_DPC_CAPS_REGISTER {
        private ushort _RawBits;

        [JsonProperty(Order = 1)]
        public byte InterruptMsgNumber => (byte)(_RawBits & 0x1F); // Bits 0-4

        [JsonProperty(Order = 2)]
        public bool RpExtensionsForDpc => ((_RawBits >> 5) & 0x1) == 1; // Bit 5

        [JsonProperty(Order = 3)]
        public bool PoisonedTlpEgressBlockingSupported => ((_RawBits >> 6) & 0x1) == 1; // Bit 6

        [JsonProperty(Order = 4)]
        public bool DpcSoftwareTriggeringSupported => ((_RawBits >> 7) & 0x1) == 1; // Bit 7

        [JsonProperty(Order = 5)]
        public byte RpPioLogSize => (byte)((_RawBits >> 8) & 0xF); // Bits 8-11

        [JsonProperty(Order = 6)]
        public bool DlActiveErrCorSignalingSupported => ((_RawBits >> 12) & 0x1) == 1; // Bit 12

        [JsonProperty(Order = 7)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved => (byte)(_RawBits >> 13); // Bits 13-15

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 2 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_DPC_CONTROL_REGISTER {
        private ushort _RawBits;

        [JsonProperty(Order = 1)]
        public byte TriggerEnable => (byte)(_RawBits & 0x3); // Bits 0-1

        [JsonProperty(Order = 2)]
        public bool CompletionControl => ((_RawBits >> 2) & 0x1) == 1; // Bit 2

        [JsonProperty(Order = 3)]
        public bool InterruptEnable => ((_RawBits >> 3) & 0x1) == 1; // Bit 3

        [JsonProperty(Order = 4)]
        public bool ErrCorEnable => ((_RawBits >> 4) & 0x1) == 1; // Bit 4

        [JsonProperty(Order = 5)]
        public bool PoisonedTlpEgressBlockingEnable => ((_RawBits >> 5) & 0x1) == 1; // Bit 5

        [JsonProperty(Order = 6)]
        public bool SoftwareTrigger => ((_RawBits >> 6) & 0x1) == 1; // Bit 6

        [JsonProperty(Order = 7)]
        public bool DlActiveErrCorEnable => ((_RawBits >> 7) & 0x1) == 1; // Bit 7

        [JsonProperty(Order = 8)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved => (byte)(_RawBits >> 8); // Bits 8-15

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 2 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_DPC_STATUS_REGISTER {
        private ushort _RawBits;

        [JsonProperty(Order = 1)]
        public bool TriggerStatus => (_RawBits & 0x1) == 1; // Bit 0

        [JsonProperty(Order = 2)]
        public byte TriggerReason => (byte)((_RawBits >> 1) & 0x3); // Bits 1-2

        [JsonProperty(Order = 3)]
        public bool InterruptStatus => ((_RawBits >> 3) & 0x1) == 1; // Bit 3

        [JsonProperty(Order = 4)]
        public bool RpBusy => ((_RawBits >> 4) & 0x1) == 1; // Bit 4

        [JsonProperty(Order = 5)]
        public byte TriggerReasonExtension => (byte)((_RawBits >> 5) & 0x3); // Bits 5-6

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved1 => (byte)((_RawBits >> 7) & 0x1); // Bit 7

        [JsonProperty(Order = 7)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte PioFirstErrPointer => (byte)((_RawBits >> 8) & 0x1F); // Bits 8-12

        [JsonProperty(Order = 8)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved2 => (byte)(_RawBits >> 13); // Bits 13-15

        [UsedImplicitly]
        public bool ShouldSerializeReserved1() => Reserved1 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved2() => Reserved2 != 0;
    }

    // Structure size: 2 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_DPC_ERROR_SOURCE_ID {
        private ushort _RawBits;

        [JsonProperty(Order = 1)]
        public byte Function => (byte)(_RawBits & 0x7); // Bits 0-2

        [JsonProperty(Order = 2)]
        public byte Device => (byte)((_RawBits >> 3) & 0x1F); // Bits 3-7

        [JsonProperty(Order = 3)]
        public byte Bus => (byte)(_RawBits >> 8); // Bits 8-15
    }

    /*
     * Structure size: 4 bytes
     *
     * The Windows headers define separate structures for the status, mask,
     * severity, system error (SysError), and exception fields in the parent
     * PCI_EXPRESS_DPC_CAPABILITY structure, but they are (almost) identical.
     * Do the obvious thing and just reuse this structure.
     *
     * For the "almost" see the comment on the Reserved3 field.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_DPC_RP_PIO_REGISTER {
        private uint _RawBits;

        [JsonProperty(Order = 1)]
        public bool CfgURCpl => (_RawBits & 0x1) == 1; // Bit 0

        [JsonProperty(Order = 2)]
        public bool CfgCACpl => ((_RawBits >> 1) & 0x1) == 1; // Bit 1

        [JsonProperty(Order = 3)]
        public bool CfgCTO => ((_RawBits >> 2) & 0x1) == 1; // Bit 2

        [JsonProperty(Order = 4)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved1 => (byte)((_RawBits >> 3) & 0x1F); // Bits 3-7

        [JsonProperty(Order = 5)]
        public bool IoURCpl => ((_RawBits >> 8) & 0x1) == 1; // Bit 8

        [JsonProperty(Order = 6)]
        public bool IoCACpl => ((_RawBits >> 9) & 0x1) == 1; // Bit 9

        [JsonProperty(Order = 7)]
        public bool IoCTO => ((_RawBits >> 10) & 0x1) == 1; // Bit 10

        [JsonProperty(Order = 8)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved2 => (byte)((_RawBits >> 11) & 0x1F); // Bits 11-15

        [JsonProperty(Order = 9)]
        public bool MemURCpl => ((_RawBits >> 16) & 0x1) == 1; // Bit 16

        [JsonProperty(Order = 10)]
        public bool MemCACpl => ((_RawBits >> 17) & 0x1) == 1; // Bit 17

        [JsonProperty(Order = 11)]
        public bool MemCTO => ((_RawBits >> 18) & 0x1) == 1; // Bit 18

        /*
         * The original PCI_EXPRESS_DPC_RP_PIO_STATUS_REGISTER structure has
         * this field as 12 bits and an additional 1-bit field named Reserved4.
         * All the other structures have a 13-bit Reserved3 field.
         */
        [JsonProperty(Order = 12)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Reserved3 => (ushort)(_RawBits >> 19); // Bits 19-31

        [UsedImplicitly]
        public bool ShouldSerializeReserved1() => Reserved1 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved2() => Reserved2 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved3() => Reserved3 != 0;
    }

    // Structure size: 16 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_DPC_RP_PIO_HEADERLOG_REGISTER {
        [JsonProperty(ItemConverterType = typeof(HexStringJsonConverter))]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public uint[] PioHeaderLogRegister;
    }

    // Structure size: 4 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_DPC_RP_PIO_IMPSPECLOG_REGISTER {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint PioImpSpecLog;
    }

    // Structure size: 16 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_DPC_RP_PIO_TLPPREFIXLOG_REGISTER {
        [JsonProperty(ItemConverterType = typeof(HexStringJsonConverter))]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public uint[] PioTlpPrefixLogRegister;
    }
}
