#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming
// ReSharper disable MemberCanBePrivate.Global

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.NativeMethods;
using static DecodeWheaRecord.Utilities;


namespace DecodeWheaRecord.Shared {
    internal sealed class WHEA_ERROR_SOURCE_DESCRIPTOR : WheaStruct {
        // Structure size is static
        private const int _NativeSize = 972;
        internal override int GetNativeSize() => _NativeSize;

        internal const int WHEA_ERROR_SOURCE_DESCRIPTOR_VERSION = 10;

        // TODO
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _DescriptorType;

        [JsonProperty(Order = 1)]
        public uint Length;

        [JsonProperty(Order = 2)]
        public uint Version;

        private WHEA_ERROR_SOURCE_TYPE _Type;

        [JsonProperty(Order = 3)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_TYPE), _Type);

        private WHEA_ERROR_SOURCE_STATE _State;

        [JsonProperty(Order = 4)]
        public string State => Enum.GetName(typeof(WHEA_ERROR_SOURCE_STATE), _State);

        [JsonProperty(Order = 5)]
        public uint MaxRawDataLength;

        [JsonProperty(Order = 6)]
        public uint NumRecordsToPreallocate;

        [JsonProperty(Order = 7)]
        public uint MaxSectionsPerRecord;

        [JsonProperty(Order = 8)]
        public uint ErrorSourceId;

        [JsonProperty(Order = 9)]
        public uint PlatformErrorSourceId;

        private WHEA_ERROR_SOURCE_FLAGS _Flags;

        [JsonProperty(Order = 10)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        [JsonProperty(Order = 11)]
        public WHEA_XPF_MCE_DESCRIPTOR XpfMceDescriptor;

        [JsonProperty(Order = 12)]
        public WHEA_XPF_CMC_DESCRIPTOR XpfCmcDescriptor;

        [JsonProperty(Order = 13)]
        public WHEA_XPF_NMI_DESCRIPTOR XpfNmiDescriptor;

        [JsonProperty(Order = 14)]
        public WHEA_IPF_MCA_DESCRIPTOR IpfMcaDescriptor;

        [JsonProperty(Order = 15)]
        public WHEA_IPF_CMC_DESCRIPTOR IpfCmcDescriptor;

        [JsonProperty(Order = 16)]
        public WHEA_IPF_CPE_DESCRIPTOR IpfCpeDescriptor;

        [JsonProperty(Order = 17)]
        public WHEA_AER_ROOTPORT_DESCRIPTOR AerRootportDescriptor;

        [JsonProperty(Order = 18)]
        public WHEA_AER_ENDPOINT_DESCRIPTOR AerEndpointDescriptor;

        [JsonProperty(Order = 19)]
        public WHEA_AER_BRIDGE_DESCRIPTOR AerBridgeDescriptor;

        [JsonProperty(Order = 20)]
        public WHEA_GENERIC_ERROR_DESCRIPTOR GenErrDescriptor;

        [JsonProperty(Order = 21)]
        public WHEA_GENERIC_ERROR_DESCRIPTOR_V2 GenErrDescriptorV2;

        [JsonProperty(Order = 22)]
        public WHEA_DEVICE_DRIVER_DESCRIPTOR DeviceDriverDescriptor;

        public WHEA_ERROR_SOURCE_DESCRIPTOR(IntPtr recordAddr, int initialOffset) {
            DebugBeforeDecode(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR), initialOffset);

            Length = (uint)Marshal.ReadInt32(recordAddr);
            Version = (uint)Marshal.ReadInt32(recordAddr, 4);
            _Type = (WHEA_ERROR_SOURCE_TYPE)Marshal.ReadInt32(recordAddr, 8);
            _State = (WHEA_ERROR_SOURCE_STATE)Marshal.ReadInt32(recordAddr, 12);
            MaxRawDataLength = (uint)Marshal.ReadInt32(recordAddr, 16);
            NumRecordsToPreallocate = (uint)Marshal.ReadInt32(recordAddr, 20);
            MaxSectionsPerRecord = (uint)Marshal.ReadInt32(recordAddr, 24);
            ErrorSourceId = (uint)Marshal.ReadInt32(recordAddr, 28);
            PlatformErrorSourceId = (uint)Marshal.ReadInt32(recordAddr, 32);
            _Flags = (WHEA_ERROR_SOURCE_FLAGS)Marshal.ReadInt32(recordAddr, 36);
            var offset = 40;

            // TODO: Explain
            _DescriptorType = (WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE)Marshal.ReadInt16(recordAddr, offset);

            string cat, msg;
            switch (_Type) {
                case WHEA_ERROR_SOURCE_TYPE.MCE:
                    XpfMceDescriptor = new WHEA_XPF_MCE_DESCRIPTOR(recordAddr + offset, offset);
                    offset += XpfMceDescriptor.GetNativeSize();
                    break;
                case WHEA_ERROR_SOURCE_TYPE.CMC:
                    XpfCmcDescriptor = new WHEA_XPF_CMC_DESCRIPTOR(recordAddr + offset, offset);
                    offset += XpfCmcDescriptor.GetNativeSize();
                    break;
                case WHEA_ERROR_SOURCE_TYPE.NMI:
                    XpfNmiDescriptor = Marshal.PtrToStructure<WHEA_XPF_NMI_DESCRIPTOR>(recordAddr + offset);
                    offset += Marshal.SizeOf<WHEA_XPF_NMI_DESCRIPTOR>();
                    break;
                case WHEA_ERROR_SOURCE_TYPE.IPFMCA:
                    IpfMcaDescriptor = Marshal.PtrToStructure<WHEA_IPF_MCA_DESCRIPTOR>(recordAddr + offset);
                    offset += Marshal.SizeOf<WHEA_IPF_MCA_DESCRIPTOR>();
                    break;
                case WHEA_ERROR_SOURCE_TYPE.IPFCMC:
                    IpfCmcDescriptor = Marshal.PtrToStructure<WHEA_IPF_CMC_DESCRIPTOR>(recordAddr + offset);
                    offset += Marshal.SizeOf<WHEA_IPF_CMC_DESCRIPTOR>();
                    break;
                case WHEA_ERROR_SOURCE_TYPE.IPFCPE:
                    IpfCpeDescriptor = Marshal.PtrToStructure<WHEA_IPF_CPE_DESCRIPTOR>(recordAddr + offset);
                    offset += Marshal.SizeOf<WHEA_IPF_CPE_DESCRIPTOR>();
                    break;
                case WHEA_ERROR_SOURCE_TYPE.PCIe:
                    if (_DescriptorType == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerRootPort) {
                        AerRootportDescriptor = Marshal.PtrToStructure<WHEA_AER_ROOTPORT_DESCRIPTOR>(recordAddr + offset);
                        offset += Marshal.SizeOf<WHEA_AER_ROOTPORT_DESCRIPTOR>();
                    } else if (_DescriptorType == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerEndpoint) {
                        AerEndpointDescriptor = Marshal.PtrToStructure<WHEA_AER_ENDPOINT_DESCRIPTOR>(recordAddr + offset);
                        offset += Marshal.SizeOf<WHEA_AER_ENDPOINT_DESCRIPTOR>();
                    } else if (_DescriptorType == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerBridge) {
                        AerBridgeDescriptor = Marshal.PtrToStructure<WHEA_AER_BRIDGE_DESCRIPTOR>(recordAddr + offset);
                        offset += Marshal.SizeOf<WHEA_AER_BRIDGE_DESCRIPTOR>();
                    } else {
                        cat = $"{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}.{nameof(Type)}";
                        var descriptorType = Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _DescriptorType);
                        msg = $"Error source type is PCIe but descriptor type is invalid: {descriptorType}";
                        ExitWithMessage(msg, cat, 2);
                    }
                    break;
                case WHEA_ERROR_SOURCE_TYPE.Generic:
                    GenErrDescriptor = Marshal.PtrToStructure<WHEA_GENERIC_ERROR_DESCRIPTOR>(recordAddr + offset);
                    offset += Marshal.SizeOf<WHEA_GENERIC_ERROR_DESCRIPTOR>();
                    break;
                case WHEA_ERROR_SOURCE_TYPE.GenericV2:
                    GenErrDescriptorV2 = Marshal.PtrToStructure<WHEA_GENERIC_ERROR_DESCRIPTOR_V2>(recordAddr + offset);
                    offset += Marshal.SizeOf<WHEA_GENERIC_ERROR_DESCRIPTOR_V2>();
                    break;
                case WHEA_ERROR_SOURCE_TYPE.DeviceDriver:
                    DeviceDriverDescriptor = Marshal.PtrToStructure<WHEA_DEVICE_DRIVER_DESCRIPTOR>(recordAddr + offset);
                    offset += Marshal.SizeOf<WHEA_DEVICE_DRIVER_DESCRIPTOR>();
                    break;
                default:
                    cat = $"{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}.{nameof(Type)}";
                    msg = $"Error source type is invalid: {Type}";
                    ExitWithMessage(msg, cat, 2);
                    break;
            }

            // Check we haven't exceeded the maximum possible structure size
            if (offset > _NativeSize) {
                cat = $"{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}";
                msg = $"Number of deserialized bytes is greater than expected maximum structure size: {offset} > {_NativeSize}";
                ExitWithMessage(msg, cat, 2);
            }

            offset = _NativeSize;
            DebugAfterDecode(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR), offset, _NativeSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeXpfMceDescriptor() => _Type == WHEA_ERROR_SOURCE_TYPE.MCE;

        [UsedImplicitly]
        public bool ShouldSerializeXpfCmcDescriptor() => _Type == WHEA_ERROR_SOURCE_TYPE.CMC;

        [UsedImplicitly]
        public bool ShouldSerializeXpfNmiDescriptor() => _Type == WHEA_ERROR_SOURCE_TYPE.NMI;

        [UsedImplicitly]
        public bool ShouldSerializeIpfMcaDescriptor() => _Type == WHEA_ERROR_SOURCE_TYPE.IPFMCA;

        [UsedImplicitly]
        public bool ShouldSerializeIpfCmcDescriptor() => _Type == WHEA_ERROR_SOURCE_TYPE.IPFCMC;

        [UsedImplicitly]
        public bool ShouldSerializeIpfCpeDescriptor() => _Type == WHEA_ERROR_SOURCE_TYPE.IPFCPE;

        [UsedImplicitly]
        public bool ShouldSerializeAerRootportDescriptor() => _Type == WHEA_ERROR_SOURCE_TYPE.PCIe && _DescriptorType == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerRootPort;

        [UsedImplicitly]
        public bool ShouldSerializeAerEndpointDescriptor() => _Type == WHEA_ERROR_SOURCE_TYPE.PCIe && _DescriptorType == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerEndpoint;

        [UsedImplicitly]
        public bool ShouldSerializeAerBridgeDescriptor() => _Type == WHEA_ERROR_SOURCE_TYPE.PCIe && _DescriptorType == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerBridge;

        [UsedImplicitly]
        public bool ShouldSerializeGenErrDescriptor() => _Type == WHEA_ERROR_SOURCE_TYPE.Generic;

        [UsedImplicitly]
        public bool ShouldSerializeGenErrDescriptorV2() => _Type == WHEA_ERROR_SOURCE_TYPE.GenericV2;

        [UsedImplicitly]
        public bool ShouldSerializeDeviceDriverDescriptor() => _Type == WHEA_ERROR_SOURCE_TYPE.DeviceDriver;

        public override void Validate() {
            string msg;

            var expectedLength = Marshal.SizeOf<WHEA_ERROR_SOURCE_DESCRIPTOR>();
            if (Length != expectedLength) {
                msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Expected length of {expectedLength} bytes but Length member is: {Length}";
                ExitWithMessage(msg, code: 2);
            }

            /*
             * The WHEA header defines versions 10 and 11 but it's unclear
             * how they differ. The Microsoft docs state the version should
             * always be set to 10 so for now we just ignore version 11.
             */
            if (Version != WHEA_ERROR_SOURCE_DESCRIPTOR_VERSION) {
                msg =
                    $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Expected version {WHEA_ERROR_SOURCE_DESCRIPTOR_VERSION} but Version member is: {Version}";
                ExitWithMessage(msg, code: 2);
            }

            if (ShouldSerializeXpfMceDescriptor()) {
                if (XpfMceDescriptor.Validate()) return;
                msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type is \"{Type}\" but Type of XpfMceDescriptor is: {XpfMceDescriptor.Type}";
                ExitWithMessage(msg, code: 2);
            }

            if (ShouldSerializeXpfCmcDescriptor()) {
                if (XpfCmcDescriptor.Validate()) return;
                msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type is \"{Type}\" but Type of XpfCmcDescriptor is: {XpfCmcDescriptor.Type}";
                ExitWithMessage(msg, code: 2);
            }

            if (ShouldSerializeXpfNmiDescriptor()) {
                if (XpfNmiDescriptor.Validate()) return;
                msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type is \"{Type}\" but Type of XpfNmiDescriptor is: {XpfNmiDescriptor.Type}";
                ExitWithMessage(msg, code: 2);
            }

            if (ShouldSerializeIpfMcaDescriptor()) {
                if (IpfMcaDescriptor.Validate()) return;
                msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type is \"{Type}\" but Type of IpfMcaDescriptor is: {IpfMcaDescriptor.Type}";
                ExitWithMessage(msg, code: 2);
            }

            if (ShouldSerializeIpfCmcDescriptor()) {
                if (IpfCmcDescriptor.Validate()) return;
                msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type is \"{Type}\" but Type of IpfCmcDescriptor is: {IpfCmcDescriptor.Type}";
                ExitWithMessage(msg, code: 2);
            }

            if (ShouldSerializeIpfCpeDescriptor()) {
                if (IpfCpeDescriptor.Validate()) return;
                msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type is \"{Type}\" but Type of IpfCpeDescriptor is: {IpfCpeDescriptor.Type}";
                ExitWithMessage(msg, code: 2);
            }

            if (_Type == WHEA_ERROR_SOURCE_TYPE.PCIe) {
                if (ShouldSerializeAerRootportDescriptor() || ShouldSerializeAerEndpointDescriptor() || ShouldSerializeAerBridgeDescriptor()) return;
                /*
                 * Using any PCIe AER structure is safe as the Type member
                 * resides at the same offset for all the structures.
                 */
                msg =
                    $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type is \"{Type}\" but Type in all AER structures is invalid: {AerRootportDescriptor.Type}";
                ExitWithMessage(msg, code: 2);
            }

            if (ShouldSerializeGenErrDescriptor()) {
                if (GenErrDescriptor.Validate()) return;
                msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type is \"{Type}\" but Type of GenErrDescriptor is: {GenErrDescriptor.Type}";
                ExitWithMessage(msg, code: 2);
            }

            if (ShouldSerializeGenErrDescriptorV2()) {
                if (GenErrDescriptorV2.Validate()) return;
                msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type is \"{Type}\" but Type of GenErrDescriptorV2 is: {GenErrDescriptorV2.Type}";
                ExitWithMessage(msg, code: 2);
            }

            if (ShouldSerializeDeviceDriverDescriptor()) {
                if (DeviceDriverDescriptor.Validate()) return;
                msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type is \"{Type}\" but Type of DeviceDriverDescriptor is: {DeviceDriverDescriptor.Type}";
                ExitWithMessage(msg, code: 2);
            }

            msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type does not match any known descriptor: {Type}";
            ExitWithMessage(msg, code: 2);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_XPF_MC_BANK_DESCRIPTOR {
        [JsonProperty(Order = 1)]
        public byte BankNumber;

        [JsonProperty(Order = 2)]
        [MarshalAs(UnmanagedType.U1)]
        public bool ClearOnInitialization;

        private WHEA_XPF_MC_BANK_STATUSFORMAT _StatusDataFormat;

        [JsonProperty(Order = 3)]
        public string StatusDataFormat => Enum.GetName(typeof(WHEA_XPF_MC_BANK_STATUSFORMAT), _StatusDataFormat);

        private XPF_MC_BANK_FLAGS _Flags;

        [JsonProperty(Order = 4)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        [JsonProperty(Order = 5)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint ControlMsr;

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint StatusMsr;

        [JsonProperty(Order = 7)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint AddressMsr;

        [JsonProperty(Order = 8)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint MiscMsr;

        [JsonProperty(Order = 9)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ControlData;
    }

    /*
     * Cannot be directly marshalled as a structure due to the fixed-size array
     * having a non-blittable type.
     */
    internal sealed class WHEA_XPF_MCE_DESCRIPTOR : WheaStruct {
        // Structure size is static
        private const int _NativeSize = 920;
        internal override int GetNativeSize() => _NativeSize;

        internal const int WHEA_MAX_MC_BANKS = 32;

        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        public byte Enabled;

        [JsonProperty(Order = 3)]
        public byte NumberOfBanks;

        private XPF_MCE_FLAGS _Flags;

        [JsonProperty(Order = 4)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        [JsonProperty(Order = 5)]
        public ulong MCG_Capability;

        [JsonProperty(Order = 6)]
        public ulong MCG_GlobalControl;

        [JsonProperty(Order = 7)]
        public WHEA_XPF_MC_BANK_DESCRIPTOR[] Banks;

        public WHEA_XPF_MCE_DESCRIPTOR(IntPtr recordAddr, int initialOffset) {
            DebugBeforeDecode(typeof(WHEA_XPF_MCE_DESCRIPTOR), initialOffset);

            _Type = (WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE)Marshal.ReadInt16(recordAddr);
            Enabled = Marshal.ReadByte(recordAddr, 2);
            NumberOfBanks = Marshal.ReadByte(recordAddr, 3);
            _Flags = (XPF_MCE_FLAGS)Marshal.ReadInt32(recordAddr, 4);
            MCG_Capability = (ulong)Marshal.ReadInt64(recordAddr, 8);
            MCG_GlobalControl = (ulong)Marshal.ReadInt64(recordAddr, 16);
            var offset = 24;

            Banks = new WHEA_XPF_MC_BANK_DESCRIPTOR[WHEA_MAX_MC_BANKS];
            for (var i = 0; i < NumberOfBanks; i++) {
                Banks[i] = Marshal.PtrToStructure<WHEA_XPF_MC_BANK_DESCRIPTOR>(recordAddr + offset);
                offset += Marshal.SizeOf<WHEA_XPF_MC_BANK_DESCRIPTOR>();
            }

            // Add any remaining bytes we can ignore
            offset += Marshal.SizeOf<WHEA_XPF_MC_BANK_DESCRIPTOR>() * (WHEA_MAX_MC_BANKS - NumberOfBanks);

            Debug.Assert(offset == _NativeSize, $"{nameof(offset)} != {nameof(_NativeSize)}");
            DebugAfterDecode(typeof(WHEA_XPF_MCE_DESCRIPTOR), offset, _NativeSize);
        }

        public bool Validate() {
            return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.XpfMce;
        }
    }

    /*
     * Cannot be directly marshalled as a structure due to the fixed-size array
     * having a non-blittable type.
     */
    internal sealed class WHEA_XPF_CMC_DESCRIPTOR : WheaStruct {
        // Structure size is static
        private const int _NativeSize = 932;
        internal override int GetNativeSize() => _NativeSize;

        internal const int WHEA_MAX_MC_BANKS = 32;

        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        [MarshalAs(UnmanagedType.U1)]
        public bool Enabled;

        [JsonProperty(Order = 3)]
        public byte NumberOfBanks;

        [JsonProperty(Order = 4)]
        public uint Reserved;

        [JsonProperty(Order = 5)]
        public WHEA_NOTIFICATION_DESCRIPTOR Notify;

        [JsonProperty(Order = 6)]
        public WHEA_XPF_MC_BANK_DESCRIPTOR[] Banks;

        public WHEA_XPF_CMC_DESCRIPTOR(IntPtr recordAddr, int initialOffset) {
            DebugBeforeDecode(typeof(WHEA_XPF_CMC_DESCRIPTOR), initialOffset);

            _Type = (WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE)Marshal.ReadInt16(recordAddr);
            Enabled = Marshal.ReadByte(recordAddr, 2) != 0;
            NumberOfBanks = Marshal.ReadByte(recordAddr, 3);
            Reserved = (uint)Marshal.ReadInt32(recordAddr, 4);
            var offset = 8;

            Notify = Marshal.PtrToStructure<WHEA_NOTIFICATION_DESCRIPTOR>(recordAddr + offset);
            offset += Marshal.SizeOf<WHEA_NOTIFICATION_DESCRIPTOR>();

            Banks = new WHEA_XPF_MC_BANK_DESCRIPTOR[WHEA_MAX_MC_BANKS];
            for (var i = 0; i < NumberOfBanks; i++) {
                Banks[i] = Marshal.PtrToStructure<WHEA_XPF_MC_BANK_DESCRIPTOR>(recordAddr + offset);
                offset += Marshal.SizeOf<WHEA_XPF_MC_BANK_DESCRIPTOR>();
            }

            // Add any remaining bytes we can ignore
            offset += Marshal.SizeOf<WHEA_XPF_MC_BANK_DESCRIPTOR>() * (WHEA_MAX_MC_BANKS - NumberOfBanks);

            Debug.Assert(offset == _NativeSize, $"{nameof(offset)} != {nameof(_NativeSize)}");
            DebugAfterDecode(typeof(WHEA_XPF_CMC_DESCRIPTOR), offset, _NativeSize);
        }

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();

        public bool Validate() {
            return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.XpfCmc;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_XPF_NMI_DESCRIPTOR {
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        [MarshalAs(UnmanagedType.U1)]
        public bool Enabled;

        public bool Validate() {
            return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.XpfNmi;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_IPF_MCA_DESCRIPTOR {
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        public byte Enabled;

        [JsonProperty(Order = 3)]
        public byte Reserved;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();

        public bool Validate() {
            return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.IpfMca;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_IPF_CMC_DESCRIPTOR {
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        public byte Enabled;

        [JsonProperty(Order = 3)]
        public byte Reserved;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();

        public bool Validate() {
            return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.IpfCmc;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_IPF_CPE_DESCRIPTOR {
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        public byte Enabled;

        [JsonProperty(Order = 3)]
        public byte Reserved;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();

        public bool Validate() {
            return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.IpfCpe;
        }
    }

    // TODO: ULONG union
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCI_SLOT_NUMBER {
        private byte _DevFuncNumber;

        [JsonProperty(Order = 1)]
        public byte DeviceNumber => (byte)(_DevFuncNumber & 0x1F); // Bits 0-4

        [JsonProperty(Order = 2)]
        public byte FunctionNumber => (byte)(_DevFuncNumber >> 5); // Bits 5-7

        [JsonProperty(Order = 3)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        public byte[] Reserved;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_AER_ROOTPORT_DESCRIPTOR {
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        [MarshalAs(UnmanagedType.U1)]
        public bool Enabled;

        [JsonProperty(Order = 3)]
        public byte Reserved;

        [JsonProperty(Order = 4)]
        public uint BusNumber;

        [JsonProperty(Order = 5)]
        public WHEA_PCI_SLOT_NUMBER Slot;

        [JsonProperty(Order = 6)]
        public ushort DeviceControl;

        private AER_ROOTPORT_DESCRIPTOR_FLAGS _Flags;

        [JsonProperty(Order = 7)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        [JsonProperty(Order = 8)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint UncorrectableErrorMask;

        [JsonProperty(Order = 9)]
        public uint UncorrectableErrorSeverity;

        [JsonProperty(Order = 10)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint CorrectableErrorMask;

        [JsonProperty(Order = 11)]
        public uint AdvancedCapsAndControl;

        [JsonProperty(Order = 12)]
        public uint RootErrorCommand;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();

        public bool Validate() {
            return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerRootPort;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_AER_ENDPOINT_DESCRIPTOR {
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        [MarshalAs(UnmanagedType.U1)]
        public bool Enabled;

        [JsonProperty(Order = 3)]
        public byte Reserved;

        [JsonProperty(Order = 4)]
        public uint BusNumber;

        [JsonProperty(Order = 5)]
        public WHEA_PCI_SLOT_NUMBER Slot;

        [JsonProperty(Order = 6)]
        public ushort DeviceControl;

        private AER_ENDPOINT_DESCRIPTOR_FLAGS _Flags;

        [JsonProperty(Order = 7)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        [JsonProperty(Order = 8)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint UncorrectableErrorMask;

        [JsonProperty(Order = 9)]
        public uint UncorrectableErrorSeverity;

        [JsonProperty(Order = 10)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint CorrectableErrorMask;

        [JsonProperty(Order = 11)]
        public uint AdvancedCapsAndControl;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();

        public bool Validate() {
            return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerEndpoint;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_AER_BRIDGE_DESCRIPTOR {
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        [MarshalAs(UnmanagedType.U1)]
        public bool Enabled;

        [JsonProperty(Order = 3)]
        public byte Reserved;

        [JsonProperty(Order = 4)]
        public uint BusNumber;

        [JsonProperty(Order = 5)]
        public WHEA_PCI_SLOT_NUMBER Slot;

        [JsonProperty(Order = 6)]
        public ushort DeviceControl;

        private AER_BRIDGE_DESCRIPTOR_FLAGS _Flags;

        [JsonProperty(Order = 7)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        [JsonProperty(Order = 8)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint UncorrectableErrorMask;

        [JsonProperty(Order = 9)]
        public uint UncorrectableErrorSeverity;

        [JsonProperty(Order = 10)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint CorrectableErrorMask;

        [JsonProperty(Order = 11)]
        public uint AdvancedCapsAndControl;

        [JsonProperty(Order = 12)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint SecondaryUncorrectableErrorMask;

        [JsonProperty(Order = 13)]
        public uint SecondaryUncorrectableErrorSev;

        [JsonProperty(Order = 14)]
        public uint SecondaryCapsAndControl;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();

        public bool Validate() {
            return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerBridge;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_GENERIC_ERROR_DESCRIPTOR {
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        public byte Reserved;

        [JsonProperty(Order = 3)]
        public byte Enabled;

        [JsonProperty(Order = 4)]
        public uint ErrStatusBlockLength;

        [JsonProperty(Order = 5)]
        public uint RelatedErrorSourceId;

        // Next five members are equivalent to GEN_ADDR struct
        [JsonProperty(Order = 6)]
        public byte ErrStatusAddressSpaceID;

        [JsonProperty(Order = 7)]
        public byte ErrStatusAddressBitWidth;

        [JsonProperty(Order = 8)]
        public byte ErrStatusAddressBitOffset;

        [JsonProperty(Order = 9)]
        public byte ErrStatusAddressAccessSize;

        [JsonProperty(Order = 10)]
        public long ErrStatusAddress; // TODO: WHEA_PHYSICAL_ADDRESS

        [JsonProperty(Order = 11)]
        public WHEA_NOTIFICATION_DESCRIPTOR Notify;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();

        public bool Validate() {
            return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.Generic;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_GENERIC_ERROR_DESCRIPTOR_V2 {
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        public byte Reserved;

        [JsonProperty(Order = 3)]
        public byte Enabled;

        [JsonProperty(Order = 4)]
        public uint ErrStatusBlockLength;

        [JsonProperty(Order = 5)]
        public uint RelatedErrorSourceId;

        // Next five members are equivalent to GEN_ADDR struct
        [JsonProperty(Order = 6)]
        public byte ErrStatusAddressSpaceID;

        [JsonProperty(Order = 7)]
        public byte ErrStatusAddressBitWidth;

        [JsonProperty(Order = 8)]
        public byte ErrStatusAddressBitOffset;

        [JsonProperty(Order = 9)]
        public byte ErrStatusAddressAccessSize;

        [JsonProperty(Order = 10)]
        public long ErrStatusAddress; // TODO: WHEA_PHYSICAL_ADDRESS

        [JsonProperty(Order = 11)]
        public WHEA_NOTIFICATION_DESCRIPTOR Notify;

        // Next five members are equivalent to GEN_ADDR struct
        [JsonProperty(Order = 12)]
        public byte ReadAckAddressSpaceID;

        [JsonProperty(Order = 13)]
        public byte ReadAckAddressBitWidth;

        [JsonProperty(Order = 14)]
        public byte ReadAckAddressBitOffset;

        [JsonProperty(Order = 15)]
        public byte ReadAckAddressAccessSize;

        [JsonProperty(Order = 16)]
        public long ReadAckAddress; // TODO: WHEA_PHYSICAL_ADDRESS

        [JsonProperty(Order = 17)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ReadAckPreserveMask;

        [JsonProperty(Order = 18)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ReadAckWriteMask;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();

        public bool Validate() {
            return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.GenericV2;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_DEVICE_DRIVER_DESCRIPTOR {
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        [MarshalAs(UnmanagedType.U1)]
        public bool Enabled;

        [JsonProperty(Order = 3)]
        public byte Reserved;

        [JsonProperty(Order = 4)]
        public Guid SourceGuid;

        [JsonProperty(Order = 5)]
        public ushort LogTag;

        [JsonProperty(Order = 6)]
        public ushort Reserved2;

        [JsonProperty(Order = 7)]
        public uint PacketLength;

        [JsonProperty(Order = 8)]
        public uint PacketCount;

        [JsonProperty(Order = 9)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public IntPtr PacketBuffer; // PUCHAR

        [JsonProperty(Order = 10)]
        public WHEA_ERROR_SOURCE_CONFIGURATION_DD Config;

        private Guid _CreatorId;

        [JsonProperty(Order = 11)]
        public string CreatorId => CreatorIds.TryGetValue(_CreatorId, out var CreatorIdValue) ? CreatorIdValue : _CreatorId.ToString();

        [JsonProperty(Order = 12)]
        public Guid PartitionId;

        [JsonProperty(Order = 13)]
        public uint MaxSectionDataLength;

        [JsonProperty(Order = 14)]
        public uint MaxSectionsPerRecord;

        [JsonProperty(Order = 15)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public IntPtr PacketStateBuffer; // PUCHAR

        [JsonProperty(Order = 16)]
        public int OpenHandles;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();

        [UsedImplicitly]
        public static bool ShouldSerializeReserved2() => IsDebugBuild();

        public bool Validate() {
            return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.DeviceDriver;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ERROR_SOURCE_CONFIGURATION_DD {
        // Callback
        // NTSTATUS WHEA_ERROR_SOURCE_INITIALIZE_DEVICE_DRIVER(PVOID Context, ULONG ErrorSourceId)
        [JsonConverter(typeof(HexStringJsonConverter))]
        public IntPtr Initialize;

        // Callback
        // VOID WHEA_ERROR_SOURCE_UNINITIALIZE_DEVICE_DRIVER(PVOID Context)
        [JsonConverter(typeof(HexStringJsonConverter))]
        public IntPtr Uninitialize;

        // Callback
        // NTSTATUS WHEA_ERROR_SOURCE_CORRECT_DEVICE_DRIVER(PVOID ErrorSourceDesc, PULONG MaximumSectionLength)
        [JsonConverter(typeof(HexStringJsonConverter))]
        public IntPtr Correct;
    }

    // @formatter:int_align_fields true

    [Flags]
    internal enum AER_BRIDGE_DESCRIPTOR_FLAGS : ushort {
        UncorrectableErrorMaskRW          = 0x1,
        UncorrectableErrorSeverityRW      = 0x2,
        CorrectableErrorMaskRW            = 0x4,
        AdvancedCapsAndControlRW          = 0x8,
        SecondaryUncorrectableErrorMaskRW = 0x10,
        SecondaryUncorrectableErrorSevRW  = 0x20,
        SecondaryCapsAndControlRW         = 0x40
    }

    [Flags]
    internal enum AER_ENDPOINT_DESCRIPTOR_FLAGS : ushort {
        UncorrectableErrorMaskRW     = 0x1,
        UncorrectableErrorSeverityRW = 0x2,
        CorrectableErrorMaskRW       = 0x4,
        AdvancedCapsAndControlRW     = 0x8
    }

    [Flags]
    internal enum AER_ROOTPORT_DESCRIPTOR_FLAGS : ushort {
        UncorrectableErrorMaskRW     = 0x1,
        UncorrectableErrorSeverityRW = 0x2,
        CorrectableErrorMaskRW       = 0x4,
        AdvancedCapsAndControlRW     = 0x8,
        RootErrorCommandRW           = 0x10
    }

    // From preprocessor definitions (WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_*)
    internal enum WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE : ushort {
        XpfMce       = 0,
        XpfCmc       = 1,
        XpfNmi       = 2,
        IpfMca       = 3,
        IpfCmc       = 4,
        IpfCpe       = 5,
        AerRootPort  = 6,
        AerEndpoint  = 7,
        AerBridge    = 8,
        Generic      = 9,
        GenericV2    = 10,
        DeviceDriver = 11 // TODO: Just a guess as not in the header
    }

    // From preprocessor definitions (WHEA_ERROR_SOURCE_FLAG_*)
    [Flags]
    internal enum WHEA_ERROR_SOURCE_FLAGS : uint {
        FirmwareFirst = 0x1,
        Global        = 0x2,
        GhesAssist    = 0x4,
        DefaultSource = 0x80000000
    }

    internal enum WHEA_ERROR_SOURCE_STATE : uint {
        Stopped       = 1,
        Started       = 2,
        Removed       = 3,
        RemovePending = 4
    }

    // From preprocessor definitions (WHEA_XPF_MC_BANK_STATUSFORMAT_*)
    internal enum WHEA_XPF_MC_BANK_STATUSFORMAT : byte {
        IA32MCA    = 0,
        Intel64MCA = 1,
        AMD64MCA   = 2
    }

    [Flags]
    internal enum XPF_MC_BANK_FLAGS : byte {
        ClearOnInitializationRW = 0x1,
        ControlDataRW           = 0x2
    }

    [Flags]
    internal enum XPF_MCE_FLAGS : uint {
        MCG_CapabilityRW    = 0x1,
        MCG_GlobalControlRW = 0x2
    }

    // @formatter:int_align_fields false
}
