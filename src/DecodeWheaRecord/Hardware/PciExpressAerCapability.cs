#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;

using JetBrains.Annotations;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Hardware {
    /*
     * Structure size: 76 bytes
     *
     * The Windows headers define a separate structure for PCIe bridge devices,
     * but it's identical to this structure so we'll just reuse it. Subsequent
     * comments which refer to this structure apply equally to the PCIe bridge
     * device "variant" (original name is PCI_EXPRESS_BRIDGE_AER_CAPABILITY).
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_AER_CAPABILITY {
        [JsonProperty(Order = 1)]
        public PCI_EXPRESS_ENHANCED_CAPABILITY_HEADER Header;

        [JsonProperty(Order = 2)]
        public PCI_EXPRESS_UNCORRECTABLE_ERROR UncorrectableErrorStatus;

        [JsonProperty(Order = 3)]
        public PCI_EXPRESS_UNCORRECTABLE_ERROR UncorrectableErrorMask;

        [JsonProperty(Order = 4)]
        public PCI_EXPRESS_UNCORRECTABLE_ERROR UncorrectableErrorSeverity;

        [JsonProperty(Order = 5)]
        public PCI_EXPRESS_CORRECTABLE_ERROR CorrectableErrorStatus;

        [JsonProperty(Order = 6)]
        public PCI_EXPRESS_CORRECTABLE_ERROR CorrectableErrorMask;

        [JsonProperty(Order = 7)]
        public PCI_EXPRESS_AER_CAPABILITIES CapabilitiesAndControl;

        // Integers in this array are stored big-endian
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        private uint[] _HeaderLog;

        // Reverse the byte order so the integers are little-endian
        [JsonProperty(Order = 8, ItemConverterType = typeof(HexStringJsonConverter))]
        public uint[] HeaderLog {
            get {
                var headerLogLE = new uint[_HeaderLog.Length];

                for (var i = 0; i < headerLogLE.Length; i++) {
                    var elementBytes = BitConverter.GetBytes(_HeaderLog[i]);
                    Array.Reverse(elementBytes);
                    headerLogLE[i] = BitConverter.ToUInt32(elementBytes, 0);
                }

                return headerLogLE;
            }
        }

        [JsonProperty(Order = 9)]
        public PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR SecUncorrectableErrorStatus;

        [JsonProperty(Order = 10)]
        public PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR SecUncorrectableErrorMask;

        [JsonProperty(Order = 11)]
        public PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR SecUncorrectableErrorSeverity;

        [JsonProperty(Order = 12)]
        public PCI_EXPRESS_SEC_AER_CAPABILITIES SecCapabilitiesAndControl;

        /*
         * The documentation doesn't indicate these values are stored as big-
         * endian like they are in HeaderLog, so let's hope for the best until
         * we have some sample errors to inspect.
         */
        [JsonProperty(Order = 13, ItemConverterType = typeof(HexStringJsonConverter))]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public uint[] SecHeaderLog;
    }

    // Structure size: 56 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_ROOTPORT_AER_CAPABILITY {
        [JsonProperty(Order = 1)]
        public PCI_EXPRESS_ENHANCED_CAPABILITY_HEADER Header;

        [JsonProperty(Order = 2)]
        public PCI_EXPRESS_UNCORRECTABLE_ERROR UncorrectableErrorStatus;

        [JsonProperty(Order = 3)]
        public PCI_EXPRESS_UNCORRECTABLE_ERROR UncorrectableErrorMask;

        [JsonProperty(Order = 4)]
        public PCI_EXPRESS_UNCORRECTABLE_ERROR UncorrectableErrorSeverity;

        [JsonProperty(Order = 5)]
        public PCI_EXPRESS_CORRECTABLE_ERROR CorrectableErrorStatus;

        [JsonProperty(Order = 6)]
        public PCI_EXPRESS_CORRECTABLE_ERROR CorrectableErrorMask;

        [JsonProperty(Order = 7)]
        public PCI_EXPRESS_AER_CAPABILITIES CapabilitiesAndControl;

        // Integers in this array are stored big-endian
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        private uint[] _HeaderLog;

        // Reverse the byte order so the integers are little-endian
        [JsonProperty(Order = 8, ItemConverterType = typeof(HexStringJsonConverter))]
        public uint[] HeaderLog {
            get {
                var headerLogLE = new uint[_HeaderLog.Length];

                for (var i = 0; i < headerLogLE.Length; i++) {
                    var elementBytes = BitConverter.GetBytes(_HeaderLog[i]);
                    Array.Reverse(elementBytes);
                    headerLogLE[i] = BitConverter.ToUInt32(elementBytes, 0);
                }

                return headerLogLE;
            }
        }

        [JsonProperty(Order = 9)]
        public PCI_EXPRESS_ROOT_ERROR_COMMAND RootErrorCommand;

        [JsonProperty(Order = 10)]
        public PCI_EXPRESS_ROOT_ERROR_STATUS RootErrorStatus;

        [JsonProperty(Order = 11)]
        public PCI_EXPRESS_ERROR_SOURCE_ID ErrorSourceId;
    }

    /*
     * Structure size: 4 bytes
     *
     * The Windows headers define separate structures for the status, mask, and
     * severity fields in the parent PCI_EXPRESS_AER_CAPABILITY structure, but
     * they are identical. Do the obvious thing and just reuse this structure.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_UNCORRECTABLE_ERROR {
        private uint _RawBits;

        /*
         * Indicates a link training error has occurred in versions of the PCIe
         * specification prior to version 1.1.
         */
        [JsonProperty(Order = 1)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Undefined => (byte)(_RawBits & 0x1); // Bit 0

        [JsonProperty(Order = 2)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved1 => (byte)((_RawBits >> 1) & 0x7); // Bits 1-3

        [JsonProperty(Order = 3)]
        public bool DataLinkProtocolError => ((_RawBits >> 4) & 0x1) == 1; // Bit 4

        [JsonProperty(Order = 4)]
        public bool SurpriseDownError => ((_RawBits >> 5) & 0x1) == 1; // Bit 5

        [JsonProperty(Order = 5)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved2 => (byte)((_RawBits >> 6) & 0x3F); // Bits 6-11

        [JsonProperty(Order = 6)]
        public bool PoisonedTLP => ((_RawBits >> 12) & 0x1) == 1; // Bit 12

        [JsonProperty(Order = 7)]
        public bool FlowControlProtocolError => ((_RawBits >> 13) & 0x1) == 1; // Bit 13

        [JsonProperty(Order = 8)]
        public bool CompletionTimeout => ((_RawBits >> 14) & 0x1) == 1; // Bit 14

        [JsonProperty(Order = 9)]
        public bool CompleterAbort => ((_RawBits >> 15) & 0x1) == 1; // Bit 15

        [JsonProperty(Order = 10)]
        public bool UnexpectedCompletion => ((_RawBits >> 16) & 0x1) == 1; // Bit 16

        [JsonProperty(Order = 11)]
        public bool ReceiverOverflow => ((_RawBits >> 17) & 0x1) == 1; // Bit 17

        [JsonProperty(Order = 12)]
        public bool MalformedTLP => ((_RawBits >> 18) & 0x1) == 1; // Bit 18

        [JsonProperty(Order = 13)]
        public bool ECRCError => ((_RawBits >> 19) & 0x1) == 1; // Bit 19

        [JsonProperty(Order = 14)]
        public bool UnsupportedRequestError => ((_RawBits >> 20) & 0x1) == 1; // Bit 20

        [JsonProperty(Order = 15)]
        public bool AcsViolation => ((_RawBits >> 21) & 0x1) == 1; // Bit 21

        [JsonProperty(Order = 16)]
        public bool UncorrectableInternalError => ((_RawBits >> 22) & 0x1) == 1; // Bit 22

        [JsonProperty(Order = 17)]
        public bool MCBlockedTlp => ((_RawBits >> 23) & 0x1) == 1; // Bit 23

        [JsonProperty(Order = 18)]
        public bool AtomicOpEgressBlocked => ((_RawBits >> 24) & 0x1) == 1; // Bit 24

        [JsonProperty(Order = 19)]
        public bool TlpPrefixBlocked => ((_RawBits >> 25) & 0x1) == 1; // Bit 25

        [JsonProperty(Order = 20)]
        public bool PoisonedTlpEgressBlocked => ((_RawBits >> 26) & 0x1) == 1; // Bit 26

        [JsonProperty(Order = 21)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved3 => (byte)(_RawBits >> 27); // Bits 27-31

        [UsedImplicitly]
        public bool ShouldSerializeUndefined() => Undefined != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved1() => Reserved1 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved2() => Reserved2 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved3() => Reserved3 != 0;
    }

    /*
     * Structure size: 4 bytes
     *
     * The Windows headers define separate structures for the status and mask
     * fields in the parent PCI_EXPRESS_AER_CAPABILITY structure, but they are
     * identical. Do the obvious thing and just reuse this structure.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_CORRECTABLE_ERROR {
        private uint _RawBits;

        [JsonProperty(Order = 1)]
        public bool ReceiverError => (_RawBits & 0x1) == 1; // Bit 0

        [JsonProperty(Order = 2)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved1 => (byte)((_RawBits >> 1) & 0x1F); // Bits 1-5

        [JsonProperty(Order = 3)]
        public bool BadTLP => ((_RawBits >> 6) & 0x1) == 1; // Bit 6

        [JsonProperty(Order = 4)]
        public bool BadDLLP => ((_RawBits >> 7) & 0x1) == 1; // Bit 7

        [JsonProperty(Order = 5)]
        public bool ReplayNumRollover => ((_RawBits >> 8) & 0x1) == 1; // Bit 8

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved2 => (byte)((_RawBits >> 9) & 0x7); // Bits 9-11

        [JsonProperty(Order = 7)]
        public bool ReplayTimerTimeout => ((_RawBits >> 12) & 0x1) == 1; // Bit 12

        [JsonProperty(Order = 8)]
        public bool AdvisoryNonFatalError => ((_RawBits >> 13) & 0x1) == 1; // Bit 13

        [JsonProperty(Order = 9)]
        public bool CorrectedInternalError => ((_RawBits >> 14) & 0x1) == 1; // Bit 14

        [JsonProperty(Order = 10)]
        public bool HeaderLogOverflow => ((_RawBits >> 15) & 0x1) == 1; // Bit 15

        [JsonProperty(Order = 11)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Reserved3 => (ushort)(_RawBits >> 16); // Bits 16-31

        [UsedImplicitly]
        public bool ShouldSerializeReserved1() => Reserved1 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved2() => Reserved2 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved3() => Reserved3 != 0;
    }

    // Structure size: 4 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_AER_CAPABILITIES {
        private uint _RawBits;

        [JsonProperty(Order = 1)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte FirstErrorPointer => (byte)(_RawBits & 0x1F); // Bits 0-4

        [JsonProperty(Order = 2)]
        public bool ECRCGenerationCapable => ((_RawBits >> 5) & 0x1) == 1; // Bit 5

        [JsonProperty(Order = 3)]
        public bool ECRCGenerationEnable => ((_RawBits >> 6) & 0x1) == 1; // Bit 6

        [JsonProperty(Order = 4)]
        public bool ECRCCheckCapable => ((_RawBits >> 7) & 0x1) == 1; // Bit 7

        [JsonProperty(Order = 5)]
        public bool ECRCCheckEnable => ((_RawBits >> 8) & 0x1) == 1; // Bit 8

        [JsonProperty(Order = 6)]
        public bool MultipleHeaderRecordingCapable => ((_RawBits >> 9) & 0x1) == 1; // Bit 9

        [JsonProperty(Order = 7)]
        public bool MultipleHeaderRecordingEnable => ((_RawBits >> 10) & 0x1) == 1; // Bit 10

        [JsonProperty(Order = 8)]
        public bool TlpPrefixLogPresent => ((_RawBits >> 11) & 0x1) == 1; // Bit 11

        [JsonProperty(Order = 9)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Reserved => _RawBits >> 12; // Bits 12-31

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    /*
     * Structure size: 4 bytes
     *
     * The Windows headers define separate structures for the status, mask, and
     * severity fields in the parent PCI_EXPRESS_AER_CAPABILITY structure, but
     * they are identical. Do the obvious thing and just reuse this structure.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_SEC_UNCORRECTABLE_ERROR {
        private uint _RawBits;

        [JsonProperty(Order = 1)]
        public bool TargetAbortOnSplitCompletion => (_RawBits & 0x1) == 1; // Bit 0

        [JsonProperty(Order = 2)]
        public bool MasterAbortOnSplitCompletion => ((_RawBits >> 1) & 0x1) == 1; // Bit 1

        [JsonProperty(Order = 3)]
        public bool ReceivedTargetAbort => ((_RawBits >> 2) & 0x1) == 1; // Bit 2

        [JsonProperty(Order = 4)]
        public bool ReceivedMasterAbort => ((_RawBits >> 3) & 0x1) == 1; // Bit 3

        [JsonProperty(Order = 5)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved1 => (byte)((_RawBits >> 4) & 0x1); // Bit 4

        [JsonProperty(Order = 6)]
        public bool UnexpectedSplitCompletionError => ((_RawBits >> 5) & 0x1) == 1; // Bit 5

        [JsonProperty(Order = 7)]
        public bool UncorrectableSplitCompletion => ((_RawBits >> 6) & 0x1) == 1; // Bit 6

        [JsonProperty(Order = 8)]
        public bool UncorrectableDataError => ((_RawBits >> 7) & 0x1) == 1; // Bit 7

        [JsonProperty(Order = 9)]
        public bool UncorrectableAttributeError => ((_RawBits >> 8) & 0x1) == 1; // Bit 8

        [JsonProperty(Order = 10)]
        public bool UncorrectableAddressError => ((_RawBits >> 9) & 0x1) == 1; // Bit 9

        [JsonProperty(Order = 11)]
        public bool DelayedTransactionDiscardTimerExpired => ((_RawBits >> 10) & 0x1) == 1; // Bit 10

        [JsonProperty(Order = 12)]
        public bool PERRAsserted => ((_RawBits >> 11) & 0x1) == 1; // Bit 11

        [JsonProperty(Order = 13)]
        public bool SERRAsserted => ((_RawBits >> 12) & 0x1) == 1; // Bit 12

        [JsonProperty(Order = 14)]
        public bool InternalBridgeError => ((_RawBits >> 13) & 0x1) == 1; // Bit 13

        [JsonProperty(Order = 15)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Reserved2 => _RawBits >> 14; // Bits 14-31

        [UsedImplicitly]
        public bool ShouldSerializeReserved1() => Reserved1 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved2() => Reserved2 != 0;
    }

    // Structure size: 4 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_SEC_AER_CAPABILITIES {
        private uint _RawBits;

        [JsonProperty(Order = 1)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte SecondaryUncorrectableFirstErrorPtr => (byte)(_RawBits & 0x1F); // Bit 0-4

        [JsonProperty(Order = 2)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Reserved => _RawBits >> 5; // Bits 5-31

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 4 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_ROOT_ERROR_COMMAND {
        private uint _RawBits;

        [JsonProperty(Order = 1)]
        public bool CorrectableErrorReportingEnable => (_RawBits & 0x1) == 1; // Bit 0

        [JsonProperty(Order = 2)]
        public bool NonFatalErrorReportingEnable => ((_RawBits >> 1) & 0x1) == 1; // Bit 1

        [JsonProperty(Order = 3)]
        public bool FatalErrorReportingEnable => ((_RawBits >> 2) & 0x1) == 1; // Bit 2

        [JsonProperty(Order = 4)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Reserved => _RawBits >> 3; // Bits 3-31

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 4 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_ROOT_ERROR_STATUS {
        private uint _RawBits;

        [JsonProperty(Order = 1)]
        public bool CorrectableErrorReceived => (_RawBits & 0x1) == 1; // Bit 0

        [JsonProperty(Order = 2)]
        public bool MultipleCorrectableErrorsReceived => ((_RawBits >> 1) & 0x1) == 1; // Bit 1

        [JsonProperty(Order = 3)]
        public bool UncorrectableErrorReceived => ((_RawBits >> 2) & 0x1) == 1; // Bit 2

        [JsonProperty(Order = 4)]
        public bool MultipleUncorrectableErrorsReceived => ((_RawBits >> 3) & 0x1) == 1; // Bit 3

        [JsonProperty(Order = 5)]
        public bool FirstUncorrectableFatal => ((_RawBits >> 4) & 0x1) == 1; // Bit 4

        [JsonProperty(Order = 6)]
        public bool NonFatalErrorMessagesReceived => ((_RawBits >> 5) & 0x1) == 1; // Bit 5

        [JsonProperty(Order = 7)]
        public bool FatalErrorMessagesReceived => ((_RawBits >> 6) & 0x1) == 1; // Bit 6

        [JsonProperty(Order = 8)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Reserved => (_RawBits >> 7) & 0xFFFFF; // Bits 7-26

        [JsonProperty(Order = 9)]
        public byte AdvancedErrorInterruptMessageNumber => (byte)(_RawBits >> 27); // Bits 27-31

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 4 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_ERROR_SOURCE_ID {
        private uint _RawBits;

        [JsonProperty(Order = 1)]
        public byte CorrectableSourceIdFun => (byte)(_RawBits & 0x7); // Bits 0-2

        [JsonProperty(Order = 2)]
        public byte CorrectableSourceIdDev => (byte)((_RawBits >> 3) & 0x1F); // Bits 3-7

        [JsonProperty(Order = 3)]
        public byte CorrectableSourceIdBus => (byte)(_RawBits >> 8); // Bits 8-15

        [JsonProperty(Order = 4)]
        public byte UncorrectableSourceIdFun => (byte)((_RawBits >> 16) & 0x7); // Bits 16-18

        [JsonProperty(Order = 5)]
        public byte UncorrectableSourceIdDev => (byte)((_RawBits >> 19) & 0x1F); // Bits 19-23

        [JsonProperty(Order = 6)]
        public byte UncorrectableSourceIdBus => (byte)(_RawBits >> 24); // Bits 24-31
    }
}
