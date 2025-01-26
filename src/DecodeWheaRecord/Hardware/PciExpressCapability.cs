#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable InconsistentNaming

using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Hardware {
    // Structure size: 52 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_CAPABILITY {
        public PCI_CAPABILITIES_HEADER Header;
        public PCI_EXPRESS_CAPABILITIES_REGISTER ExpressCapabilities;

        public PCI_EXPRESS_DEVICE_CAPABILITIES_REGISTER DeviceCapabilities;
        public PCI_EXPRESS_DEVICE_CONTROL_REGISTER DeviceControl;
        public PCI_EXPRESS_DEVICE_STATUS_REGISTER DeviceStatus;

        public PCI_EXPRESS_LINK_CAPABILITIES_REGISTER LinkCapabilities;
        public PCI_EXPRESS_LINK_CONTROL_REGISTER LinkControl;
        public PCI_EXPRESS_LINK_STATUS_REGISTER LinkStatus;

        public PCI_EXPRESS_SLOT_CAPABILITIES_REGISTER SlotCapabilities;
        public PCI_EXPRESS_SLOT_CONTROL_REGISTER SlotControl;
        public PCI_EXPRESS_SLOT_STATUS_REGISTER SlotStatus;

        public PCI_EXPRESS_ROOT_CONTROL_REGISTER RootControl;
        public PCI_EXPRESS_ROOT_CAPABILITIES_REGISTER RootCapabilities;
        public PCI_EXPRESS_ROOT_STATUS_REGISTER RootStatus;

        public PCI_EXPRESS_DEVICE_CAPABILITIES_2_REGISTER DeviceCapabilities2;
        public PCI_EXPRESS_DEVICE_CONTROL_2_REGISTER DeviceControl2;
        public PCI_EXPRESS_DEVICE_STATUS_2_REGISTER DeviceStatus2;

        public PCI_EXPRESS_LINK_CAPABILITIES_2_REGISTER LinkCapabilities2;
        public PCI_EXPRESS_LINK_CONTROL_2_REGISTER LinkControl2;
        public PCI_EXPRESS_LINK_STATUS_2_REGISTER LinkStatus2;
    }

    // Structure size: 2 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_CAPABILITIES_HEADER {
        // Switched to an enumeration
        private PCI_CAPABILITY_ID _CapabilityID;

        [JsonProperty(Order = 1)]
        public string CapabilityID => GetEnumValueAsString<PCI_CAPABILITY_ID>(_CapabilityID);

        [JsonProperty(Order = 2)]
        public byte Next;
    }

    // Structure size: 2 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_CAPABILITIES_REGISTER {
        private ushort _RawBits;

        [JsonProperty(Order = 1)]
        public byte CapabilityVersion => (byte)(_RawBits & 0xF); // Bits 0-3

        // Switched to an enumeration
        [JsonProperty(Order = 2)]
        public string DeviceType => GetEnumValueAsString<PCI_EXPRESS_DEVICE_TYPE>((_RawBits >> 4) & 0xF); // Bits 4-7

        [JsonProperty(Order = 3)]
        public bool SlotImplemented => ((_RawBits >> 8) & 0x1) == 1; // Bit 8

        [JsonProperty(Order = 4)]
        public byte InterruptMessageNumber => (byte)((_RawBits >> 9) & 0x1F); // Bits 9-13

        [JsonProperty(Order = 5)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved => (byte)(_RawBits >> 14); // Bits 14-15

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 4 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_DEVICE_CAPABILITIES_REGISTER {
        private uint _RawBits;

        [JsonProperty(Order = 1)]
        public byte MaxPayloadSizeSupported => (byte)(_RawBits & 0x7); // Bits 0-2

        [JsonProperty(Order = 2)]
        public byte PhantomFunctionsSupported => (byte)((_RawBits >> 3) & 0x3); // Bits 3-4

        [JsonProperty(Order = 3)]
        public bool ExtendedTagSupported => ((_RawBits >> 5) & 0x1) == 1; // Bit 5

        [JsonProperty(Order = 4)]
        public byte L0sAcceptableLatency => (byte)((_RawBits >> 6) & 0x7); // Bits 6-8

        [JsonProperty(Order = 5)]
        public byte L1AcceptableLatency => (byte)((_RawBits >> 9) & 0x7); // Bits 9-11

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Undefined => (byte)((_RawBits >> 12) & 0x7); // Bits 12-14

        [JsonProperty(Order = 7)]
        public bool RoleBasedErrorReporting => ((_RawBits >> 15) & 0x1) == 1; // Bit 15

        [JsonProperty(Order = 8)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved1 => (byte)((_RawBits >> 16) & 0x3); // Bits 16-17

        [JsonProperty(Order = 9)]
        public byte CapturedSlotPowerLimit => (byte)(_RawBits >> 18); // Bits 18-25

        [JsonProperty(Order = 10)]
        public byte CapturedSlotPowerLimitScale => (byte)((_RawBits >> 26) & 0x3); // Bits 26-27

        [JsonProperty(Order = 11)]
        public bool FunctionLevelResetCapability => ((_RawBits >> 28) & 0x1) == 1; // Bit 28

        [JsonProperty(Order = 12)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved2 => (byte)(_RawBits >> 29); // Bits 29-31

        [UsedImplicitly]
        public bool ShouldSerializeUndefined() => Undefined != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved1() => Reserved1 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved2() => Reserved2 != 0;
    }

    // Structure size: 2 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_DEVICE_CONTROL_REGISTER {
        private ushort _RawBits;

        [JsonProperty(Order = 1)]
        public bool CorrectableErrorEnable => (_RawBits & 0x1) == 1; // Bit 0

        [JsonProperty(Order = 2)]
        public bool NonFatalErrorEnable => ((_RawBits >> 1) & 0x1) == 1; // Bit 1

        [JsonProperty(Order = 3)]
        public bool FatalErrorEnable => ((_RawBits >> 2) & 0x1) == 1; // Bit 2

        [JsonProperty(Order = 4)]
        public bool UnsupportedRequestErrorEnable => ((_RawBits >> 3) & 0x1) == 1; // Bit 3

        [JsonProperty(Order = 5)]
        public bool EnableRelaxedOrder => ((_RawBits >> 4) & 0x1) == 1; // Bit 4

        [JsonProperty(Order = 6)]
        public byte MaxPayloadSize => (byte)((_RawBits >> 5) & 0x7); // Bits 5-7

        [JsonProperty(Order = 7)]
        public bool ExtendedTagEnable => ((_RawBits >> 8) & 0x1) == 1; // Bit 8

        [JsonProperty(Order = 8)]
        public bool PhantomFunctionsEnable => ((_RawBits >> 9) & 0x1) == 1; // Bit 9

        [JsonProperty(Order = 9)]
        public bool AuxPowerEnable => ((_RawBits >> 10) & 0x1) == 1; // Bit 10

        [JsonProperty(Order = 10)]
        public bool NoSnoopEnable => ((_RawBits >> 11) & 0x1) == 1; // Bit 11

        [JsonProperty(Order = 11)]
        public byte MaxReadRequestSize => (byte)((_RawBits >> 12) & 0x7); // Bits 12-14

        [JsonProperty(Order = 12)]
        public bool BridgeConfigRetryEnable => ((_RawBits >> 15) & 0x1) == 1; // Bit 15
    }

    // Structure size: 2 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_DEVICE_STATUS_REGISTER {
        private ushort _RawBits;

        [JsonProperty(Order = 1)]
        public bool CorrectableErrorDetected => (_RawBits & 0x1) == 1; // Bit 0

        [JsonProperty(Order = 2)]
        public bool NonFatalErrorDetected => ((_RawBits >> 1) & 0x1) == 1; // Bit 1

        [JsonProperty(Order = 3)]
        public bool FatalErrorDetected => ((_RawBits >> 2) & 0x1) == 1; // Bit 2

        [JsonProperty(Order = 4)]
        public bool UnsupportedRequestDetected => ((_RawBits >> 3) & 0x1) == 1; // Bit 3

        [JsonProperty(Order = 5)]
        public bool AuxPowerDetected => ((_RawBits >> 4) & 0x1) == 1; // Bit 4

        [JsonProperty(Order = 6)]
        public bool TransactionsPending => ((_RawBits >> 5) & 0x1) == 1; // Bit 5

        [JsonProperty(Order = 7)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Reserved => (ushort)(_RawBits >> 6); // Bits 6-15

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 4 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_LINK_CAPABILITIES_REGISTER {
        private uint _RawBits;

        [JsonProperty(Order = 1)]
        public byte MaximumLinkSpeed => (byte)(_RawBits & 0xF); // Bits 0-3

        [JsonProperty(Order = 2)]
        public byte MaximumLinkWidth => (byte)((_RawBits >> 4) & 0x3F); // Bits 4-9

        [JsonProperty(Order = 3)]
        public byte ActiveStatePMSupport => (byte)((_RawBits >> 10) & 0x3); // Bits 10-11

        [JsonProperty(Order = 4)]
        public byte L0sExitLatency => (byte)((_RawBits >> 12) & 0x7); // Bits 12-14

        [JsonProperty(Order = 5)]
        public byte L1ExitLatency => (byte)((_RawBits >> 15) & 0x7); // Bits 15-17

        [JsonProperty(Order = 6)]
        public bool ClockPowerManagement => ((_RawBits >> 18) & 0x1) == 1; // Bit 18

        [JsonProperty(Order = 7)]
        public bool SurpriseDownErrorReportingCapable => ((_RawBits >> 19) & 0x1) == 1; // Bit 19

        [JsonProperty(Order = 8)]
        public bool DataLinkLayerActiveReportingCapable => ((_RawBits >> 20) & 0x1) == 1; // Bit 20

        [JsonProperty(Order = 9)]
        public bool LinkBandwidthNotificationCapability => ((_RawBits >> 21) & 0x1) == 1; // Bit 21

        [JsonProperty(Order = 10)]
        public bool AspmOptionalityCompliance => ((_RawBits >> 22) & 0x1) == 1; // Bit 22

        [JsonProperty(Order = 11)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved => (byte)((_RawBits >> 23) & 0x1); // Bit 23

        [JsonProperty(Order = 12)]
        public byte PortNumber => (byte)(_RawBits >> 24); // Bits 24-31

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 2 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_LINK_CONTROL_REGISTER {
        private ushort _RawBits;

        [JsonProperty(Order = 1)]
        public byte ActiveStatePMControl => (byte)(_RawBits & 0x3); // Bits 0-1

        [JsonProperty(Order = 2)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved1 => (byte)((_RawBits >> 2) & 0x1); // Bit 2

        [JsonProperty(Order = 3)]
        public bool ReadCompletionBoundary => ((_RawBits >> 3) & 0x1) == 1; // Bit 3

        [JsonProperty(Order = 4)]
        public bool LinkDisable => ((_RawBits >> 4) & 0x1) == 1; // Bit 4

        [JsonProperty(Order = 5)]
        public bool RetrainLink => ((_RawBits >> 5) & 0x1) == 1; // Bit 5

        [JsonProperty(Order = 6)]
        public bool CommonClockConfig => ((_RawBits >> 6) & 0x1) == 1; // Bit 6

        [JsonProperty(Order = 7)]
        public bool ExtendedSynch => ((_RawBits >> 7) & 0x1) == 1; // Bit 7

        [JsonProperty(Order = 8)]
        public bool EnableClockPowerManagement => ((_RawBits >> 8) & 0x1) == 1; // Bit 8

        [JsonProperty(Order = 9)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved2 => (byte)(_RawBits >> 9); // Bit 9-15

        [UsedImplicitly]
        public bool ShouldSerializeReserved1() => Reserved1 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved2() => Reserved2 != 0;
    }

    // Structure size: 2 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_LINK_STATUS_REGISTER {
        private ushort _RawBits;

        [JsonProperty(Order = 1)]
        public byte LinkSpeed => (byte)(_RawBits & 0xF); // Bits 0-3

        [JsonProperty(Order = 2)]
        public byte LinkWidth => (byte)((_RawBits >> 4) & 0x3F); // Bits 4-9

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Undefined => (byte)((_RawBits >> 10) & 0x1); // Bit 10

        [JsonProperty(Order = 4)]
        public bool LinkTraining => ((_RawBits >> 11) & 0x1) == 1; // Bit 11

        [JsonProperty(Order = 5)]
        public bool SlotClockConfig => ((_RawBits >> 12) & 0x1) == 1; // Bit 12

        [JsonProperty(Order = 6)]
        public bool DataLinkLayerActive => ((_RawBits >> 13) & 0x1) == 1; // Bit 13

        [JsonProperty(Order = 7)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved => (byte)(_RawBits >> 14); // Bit 14-15

        [UsedImplicitly]
        public bool ShouldSerializeUndefined() => Undefined != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 4 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_SLOT_CAPABILITIES_REGISTER {
        private uint _RawBits;

        [JsonProperty(Order = 1)]
        public bool AttentionButtonPresent => (_RawBits & 0x1) == 1; // Bit 0

        [JsonProperty(Order = 2)]
        public bool PowerControllerPresent => ((_RawBits >> 1) & 0x1) == 1; // Bit 1

        [JsonProperty(Order = 3)]
        public bool MRLSensorPresent => ((_RawBits >> 2) & 0x1) == 1; // Bit 2

        [JsonProperty(Order = 4)]
        public bool AttentionIndicatorPresent => ((_RawBits >> 3) & 0x1) == 1; // Bit 3

        [JsonProperty(Order = 5)]
        public bool PowerIndicatorPresent => ((_RawBits >> 4) & 0x1) == 1; // Bit 4

        [JsonProperty(Order = 6)]
        public bool HotPlugSurprise => ((_RawBits >> 5) & 0x1) == 1; // Bit 5

        [JsonProperty(Order = 7)]
        public bool HotPlugCapable => ((_RawBits >> 6) & 0x1) == 1; // Bit 6

        [JsonProperty(Order = 8)]
        public byte SlotPowerLimit => (byte)(_RawBits >> 7); // Bits 7-14

        [JsonProperty(Order = 9)]
        public byte SlotPowerLimitScale => (byte)((_RawBits >> 15) & 0x3); // Bits 15-16

        [JsonProperty(Order = 10)]
        public bool ElectromechanicalLockPresent => ((_RawBits >> 17) & 0x1) == 1; // Bit 17

        [JsonProperty(Order = 11)]
        public bool NoCommandCompletedSupport => ((_RawBits >> 18) & 0x1) == 1; // Bit 18

        [JsonProperty(Order = 12)]
        public ushort PhysicalSlotNumber => (ushort)(_RawBits >> 19); // Bits 19-31
    }

    // Structure size: 2 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_SLOT_CONTROL_REGISTER {
        private ushort _RawBits;

        [JsonProperty(Order = 1)]
        public bool AttentionButtonEnable => (_RawBits & 0x1) == 1; // Bit 0

        [JsonProperty(Order = 2)]
        public bool PowerFaultDetectEnable => ((_RawBits >> 1) & 0x1) == 1; // Bit 1

        [JsonProperty(Order = 3)]
        public bool MRLSensorEnable => ((_RawBits >> 2) & 0x1) == 1; // Bit 2

        [JsonProperty(Order = 4)]
        public bool PresenceDetectEnable => ((_RawBits >> 3) & 0x1) == 1; // Bit 3

        [JsonProperty(Order = 5)]
        public bool CommandCompletedEnable => ((_RawBits >> 4) & 0x1) == 1; // Bit 4

        [JsonProperty(Order = 6)]
        public bool HotPlugInterruptEnable => ((_RawBits >> 5) & 0x1) == 1; // Bit 5

        [JsonProperty(Order = 7)]
        public byte AttentionIndicatorControl => (byte)((_RawBits >> 6) & 0x3); // Bits 6-7

        [JsonProperty(Order = 8)]
        public byte PowerIndicatorControl => (byte)((_RawBits >> 8) & 0x3); // Bits 8-9

        [JsonProperty(Order = 9)]
        public bool PowerControllerControl => ((_RawBits >> 10) & 0x1) == 1; // Bit 10

        [JsonProperty(Order = 10)]
        public bool ElectromechanicalLockControl => ((_RawBits >> 11) & 0x1) == 1; // Bit 11

        [JsonProperty(Order = 11)]
        public bool DataLinkStateChangeEnable => ((_RawBits >> 12) & 0x1) == 1; // Bit 12

        [JsonProperty(Order = 12)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved => (byte)(_RawBits >> 13); // Bits 13-15

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 2 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_SLOT_STATUS_REGISTER {
        private ushort _RawBits;

        [JsonProperty(Order = 1)]
        public bool AttentionButtonPressed => (_RawBits & 0x1) == 1; // Bit 0

        [JsonProperty(Order = 2)]
        public bool PowerFaultDetected => ((_RawBits >> 1) & 0x1) == 1; // Bit 1

        [JsonProperty(Order = 3)]
        public bool MRLSensorChanged => ((_RawBits >> 2) & 0x1) == 1; // Bit 2

        [JsonProperty(Order = 4)]
        public bool PresenceDetectChanged => ((_RawBits >> 3) & 0x1) == 1; // Bit 3

        [JsonProperty(Order = 5)]
        public bool CommandCompleted => ((_RawBits >> 4) & 0x1) == 1; // Bit 4

        [JsonProperty(Order = 6)]
        public bool MRLSensorState => ((_RawBits >> 5) & 0x1) == 1; // Bit 5

        [JsonProperty(Order = 7)]
        public bool PresenceDetectState => ((_RawBits >> 6) & 0x1) == 1; // Bit 6

        [JsonProperty(Order = 8)]
        public bool ElectromechanicalLockEngaged => ((_RawBits >> 7) & 0x1) == 1; // Bit 7

        [JsonProperty(Order = 9)]
        public bool DataLinkStateChanged => ((_RawBits >> 8) & 0x1) == 1; // Bit 8

        [JsonProperty(Order = 10)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved => (byte)(_RawBits >> 9); // Bits 9-15

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 2 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_ROOT_CONTROL_REGISTER {
        private ushort _RawBits;

        [JsonProperty(Order = 1)]
        public bool CorrectableSerrEnable => (_RawBits & 0x1) == 1; // Bit 0

        [JsonProperty(Order = 2)]
        public bool NonFatalSerrEnable => ((_RawBits >> 1) & 0x1) == 1; // Bit 1

        [JsonProperty(Order = 3)]
        public bool FatalSerrEnable => ((_RawBits >> 2) & 0x1) == 1; // Bit 2

        [JsonProperty(Order = 4)]
        public bool PMEInterruptEnable => ((_RawBits >> 3) & 0x1) == 1; // Bit 3

        [JsonProperty(Order = 5)]
        public bool CRSSoftwareVisibilityEnable => ((_RawBits >> 4) & 0x1) == 1; // Bit 4

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Reserved => (ushort)(_RawBits >> 5); // Bits 5-15

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 2 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_ROOT_CAPABILITIES_REGISTER {
        private ushort _RawBits;

        [JsonProperty(Order = 1)]
        public bool CRSSoftwareVisibility => (_RawBits & 0x1) == 1; // Bit 0

        [JsonProperty(Order = 2)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Reserved => (ushort)(_RawBits >> 1); // Bits 1-15

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 4 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_ROOT_STATUS_REGISTER {
        private uint _RawBits;

        [JsonProperty(Order = 1)]
        public ushort PMERequestorId => (ushort)_RawBits; // Bits 0-15

        [JsonProperty(Order = 2)]
        public bool PMEStatus => ((_RawBits >> 16) & 0x1) == 1; // Bit 16

        [JsonProperty(Order = 3)]
        public bool PMEPending => ((_RawBits >> 17) & 0x1) == 1; // Bit 17

        [JsonProperty(Order = 4)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Reserved => (ushort)(_RawBits >> 18); // Bits 18-31

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 4 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_DEVICE_CAPABILITIES_2_REGISTER {
        private uint _RawBits;

        [JsonProperty(Order = 1)]
        public ushort CompletionTimeoutRangesSupported => (byte)(_RawBits & 0xF); // Bits 0-3

        [JsonProperty(Order = 2)]
        public bool CompletionTimeoutDisableSupported => ((_RawBits >> 4) & 0x1) == 1; // Bit 4

        [JsonProperty(Order = 3)]
        public bool AriForwardingSupported => ((_RawBits >> 5) & 0x1) == 1; // Bit 5

        [JsonProperty(Order = 4)]
        public bool AtomicOpRoutingSupported => ((_RawBits >> 6) & 0x1) == 1; // Bit 6

        [JsonProperty(Order = 5)]
        public bool AtomicOpCompleterSupported32Bit => ((_RawBits >> 7) & 0x1) == 1; // Bit 7

        [JsonProperty(Order = 6)]
        public bool AtomicOpCompleterSupported64Bit => ((_RawBits >> 8) & 0x1) == 1; // Bit 8

        [JsonProperty(Order = 7)]
        public bool CASCompleterSupported128Bit => ((_RawBits >> 9) & 0x1) == 1; // Bit 9

        [JsonProperty(Order = 8)]
        public bool NoROEnabledPRPRPassing => ((_RawBits >> 10) & 0x1) == 1; // Bit 10

        [JsonProperty(Order = 9)]
        public bool LTRMechanismSupported => ((_RawBits >> 11) & 0x1) == 1; // Bit 11

        [JsonProperty(Order = 10)]
        public byte TPHCompleterSupported => (byte)((_RawBits >> 12) & 0x3); // Bits 12-13

        [JsonProperty(Order = 11)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved1 => (byte)((_RawBits >> 14) & 0xF); // Bits 14-17

        [JsonProperty(Order = 12)]
        public byte OBFFSupported => (byte)((_RawBits >> 18) & 0x3); // Bits 18-19

        [JsonProperty(Order = 13)]
        public bool ExtendedFmtFieldSuported => ((_RawBits >> 20) & 0x1) == 1; // Bit 20

        [JsonProperty(Order = 14)]
        public bool EndEndTLPPrefixSupported => ((_RawBits >> 21) & 0x1) == 1; // Bit 21

        [JsonProperty(Order = 15)]
        public byte MaxEndEndTLPPrefixes => (byte)((_RawBits >> 22) & 0x3); // Bits 22-23

        [JsonProperty(Order = 16)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved2 => (byte)((_RawBits >> 24) & 0xF); // Bits 24-27

        [JsonProperty(Order = 17)]
        public bool DmwrCompleterSupported => ((_RawBits >> 28) & 0x1) == 1; // Bit 28

        [JsonProperty(Order = 18)]
        public byte DmwrLengthsSupported => (byte)((_RawBits >> 29) & 0x3); // Bits 29-30

        [JsonProperty(Order = 19)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved3 => (byte)(_RawBits >> 31); // Bit 31

        [UsedImplicitly]
        public bool ShouldSerializeReserved1() => Reserved1 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved2() => Reserved2 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved3() => Reserved3 != 0;
    }

    // Structure size: 2 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_DEVICE_CONTROL_2_REGISTER {
        private ushort _RawBits;

        [JsonProperty(Order = 1)]
        public ushort CompletionTimeoutValue => (byte)(_RawBits & 0xF); // Bits 0-3

        [JsonProperty(Order = 2)]
        public bool CompletionTimeoutDisable => ((_RawBits >> 4) & 0x1) == 1; // Bit 4

        [JsonProperty(Order = 3)]
        public bool AriForwardingEnable => ((_RawBits >> 5) & 0x1) == 1; // Bit 5

        [JsonProperty(Order = 4)]
        public bool AtomicOpRequesterEnable => ((_RawBits >> 6) & 0x1) == 1; // Bit 6

        [JsonProperty(Order = 5)]
        public bool AtomicOpEgresBlocking => ((_RawBits >> 7) & 0x1) == 1; // Bit 7

        [JsonProperty(Order = 6)]
        public bool IDORequestEnable => ((_RawBits >> 8) & 0x1) == 1; // Bit 8

        [JsonProperty(Order = 7)]
        public bool IDOCompletionEnable => ((_RawBits >> 9) & 0x1) == 1; // Bit 9

        [JsonProperty(Order = 8)]
        public bool LTRMechanismEnable => ((_RawBits >> 10) & 0x1) == 1; // Bit 10

        [JsonProperty(Order = 9)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved => (byte)((_RawBits >> 11) & 0x3); // Bits 11-12

        [JsonProperty(Order = 10)]
        public byte OBFFEnable => (byte)((_RawBits >> 13) & 0x3); // Bits 13-14

        [JsonProperty(Order = 11)]
        public bool EndEndTLPPrefixBlocking => ((_RawBits >> 15) & 0x1) == 1; // Bit 15

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 2 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_DEVICE_STATUS_2_REGISTER {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Reserved;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 4 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_LINK_CAPABILITIES_2_REGISTER {
        private uint _RawBits;

        [JsonProperty(Order = 1)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved1 => (byte)(_RawBits & 0x1); // Bit 0

        [JsonProperty(Order = 2)]
        public byte SupportedLinkSpeedsVector => (byte)((_RawBits >> 1) & 0x7F); // Bits 1-7

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Reserved2 => _RawBits >> 8; // Bits 8-31

        [UsedImplicitly]
        public bool ShouldSerializeReserved1() => Reserved1 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved2() => Reserved2 != 0;
    }

    // Structure size: 2 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_LINK_CONTROL_2_REGISTER {
        private ushort _RawBits;

        [JsonProperty(Order = 1)]
        public ushort TargetLinkSpeed => (byte)(_RawBits & 0xF); // Bits 0-3

        [JsonProperty(Order = 2)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Reserved => (ushort)(_RawBits >> 4); // Bits 4-15

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 2 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_LINK_STATUS_2_REGISTER {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Reserved;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }
}
