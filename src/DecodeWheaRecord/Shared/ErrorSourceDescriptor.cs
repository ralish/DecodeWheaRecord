#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;


namespace DecodeWheaRecord.Shared {
    internal sealed class WHEA_ERROR_SOURCE_DESCRIPTOR : WheaRecord {
        public override uint GetNativeSize() => Length;

        // Structure size is static
        private const byte ExpectedLength = 32;

        /*
         * The Windows headers also define a version 11 but it's not clear if
         * or where it's used. The Microsoft documentation state the version
         * field should be set to 10, so we'll stick with that.
         */
        private const int WHEA_ERROR_SOURCE_DESCRIPTOR_VERSION = 10;

        /*
         * For WHEA_XPF_MCE_DESCRIPTOR and WHEA_XPF_CMC_DESCRIPTOR structures,
         * the maximum machine check banks in their respective Banks array and
         * the count of elements in the array as it is of static size.
         */
        internal const int WHEA_MAX_MC_BANKS = 32;

        /*
         * All error source descriptors start with a Type field which is an
         * enumeration of possible error source descriptor types. This is not
         * the same as the Type field in this structure, which represents the
         * type of error source. The former is potentially more specific.
         *
         * We marshal the former field as part of this structure (but don't
         * serialize it in JSON output) so we can determine the correct error
         * source descriptor for the PCIe error source, which has different
         * descriptors for endpoint, root port, and bridge device types.
         *
         * This field has also been switched to an enumeration.
         */
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _DescriptorType;
        private string DescriptorType => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _DescriptorType);

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

        // Switched to an enumeration
        private WHEA_ERROR_SOURCE_FLAGS _Flags;

        [JsonProperty(Order = 10)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        /*
         * The next 12 fields contain the error source descriptor for the type
         * of error source as determined by the Type field. The Windows headers
         * define them in a union structure but we directly embed them and
         * and marshal only the correct one.
         */

        [JsonProperty(Order = 11)]
        public WHEA_XPF_MCE_DESCRIPTOR XpfMceDescriptor;

        [JsonProperty(Order = 11)]
        public WHEA_XPF_CMC_DESCRIPTOR XpfCmcDescriptor;

        [JsonProperty(Order = 11)]
        public WHEA_XPF_NMI_DESCRIPTOR XpfNmiDescriptor;

        [JsonProperty(Order = 11)]
        public WHEA_IPF_DESCRIPTOR IpfMcaDescriptor;

        [JsonProperty(Order = 11)]
        public WHEA_IPF_DESCRIPTOR IpfCmcDescriptor;

        [JsonProperty(Order = 11)]
        public WHEA_IPF_DESCRIPTOR IpfCpeDescriptor;

        [JsonProperty(Order = 11)]
        public WHEA_AER_ROOTPORT_DESCRIPTOR AerRootportDescriptor;

        [JsonProperty(Order = 11)]
        public WHEA_AER_ENDPOINT_DESCRIPTOR AerEndpointDescriptor;

        [JsonProperty(Order = 11)]
        public WHEA_AER_BRIDGE_DESCRIPTOR AerBridgeDescriptor;

        [JsonProperty(Order = 11)]
        public WHEA_GENERIC_ERROR_DESCRIPTOR GenErrDescriptor;

        [JsonProperty(Order = 11)]
        public WHEA_GENERIC_ERROR_DESCRIPTOR_V2 GenErrDescriptorV2;

        [JsonProperty(Order = 11)]
        public WHEA_DEVICE_DRIVER_DESCRIPTOR DeviceDriverDescriptor;

        public WHEA_ERROR_SOURCE_DESCRIPTOR(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR), structOffset, ExpectedLength, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            Length = (uint)Marshal.ReadInt32(structAddr);

            if (Length != ExpectedLength) {
                throw new InvalidDataException($"Expected {nameof(Length)} to be {ExpectedLength} but found: {Length}");
            }

            Version = (uint)Marshal.ReadInt32(structAddr, 4);

            if (Version != WHEA_ERROR_SOURCE_DESCRIPTOR_VERSION) {
                throw new InvalidDataException($"Expected {nameof(Version)} to be {WHEA_ERROR_SOURCE_DESCRIPTOR_VERSION} but found: {Version}");
            }

            _Type = (WHEA_ERROR_SOURCE_TYPE)Marshal.ReadInt32(structAddr, 8);
            _State = (WHEA_ERROR_SOURCE_STATE)Marshal.ReadInt32(structAddr, 12);
            MaxRawDataLength = (uint)Marshal.ReadInt32(structAddr, 16);
            NumRecordsToPreallocate = (uint)Marshal.ReadInt32(structAddr, 20);
            MaxSectionsPerRecord = (uint)Marshal.ReadInt32(structAddr, 24);
            ErrorSourceId = (uint)Marshal.ReadInt32(structAddr, 28);
            PlatformErrorSourceId = (uint)Marshal.ReadInt32(structAddr, 32);
            _Flags = (WHEA_ERROR_SOURCE_FLAGS)Marshal.ReadInt32(structAddr, 36);

            bytesRemaining -= 40;
            const uint descriptorStructOffset = 40;

            // ReSharper disable once SwitchStatementHandlesSomeKnownEnumValuesWithDefault
            switch (_Type) {
                case WHEA_ERROR_SOURCE_TYPE.MCE:
                    XpfMceDescriptor = new WHEA_XPF_MCE_DESCRIPTOR(recordAddr, descriptorStructOffset, bytesRemaining);
                    break;
                case WHEA_ERROR_SOURCE_TYPE.CMC:
                    XpfCmcDescriptor = new WHEA_XPF_CMC_DESCRIPTOR(recordAddr, descriptorStructOffset, bytesRemaining);
                    break;
                case WHEA_ERROR_SOURCE_TYPE.NMI:
                    XpfNmiDescriptor = new WHEA_XPF_NMI_DESCRIPTOR(recordAddr, descriptorStructOffset, bytesRemaining);
                    break;
                case WHEA_ERROR_SOURCE_TYPE.IPFMCA:
                    IpfMcaDescriptor = new WHEA_IPF_DESCRIPTOR(recordAddr, descriptorStructOffset, bytesRemaining);
                    break;
                case WHEA_ERROR_SOURCE_TYPE.IPFCMC:
                    IpfCmcDescriptor = new WHEA_IPF_DESCRIPTOR(recordAddr, descriptorStructOffset, bytesRemaining);
                    break;
                case WHEA_ERROR_SOURCE_TYPE.IPFCPE:
                    IpfCpeDescriptor = new WHEA_IPF_DESCRIPTOR(recordAddr, descriptorStructOffset, bytesRemaining);
                    break;
                case WHEA_ERROR_SOURCE_TYPE.PCIe:
                    _DescriptorType = (WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE)Marshal.ReadInt16(recordAddr, (int)descriptorStructOffset);

                    // ReSharper disable once SwitchStatementHandlesSomeKnownEnumValuesWithDefault
                    switch (_DescriptorType) {
                        case WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerRootPort:
                            AerRootportDescriptor = new WHEA_AER_ROOTPORT_DESCRIPTOR(recordAddr, descriptorStructOffset, bytesRemaining);
                            break;
                        case WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerEndpoint:
                            AerEndpointDescriptor = new WHEA_AER_ENDPOINT_DESCRIPTOR(recordAddr, descriptorStructOffset, bytesRemaining);
                            break;
                        case WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerBridge:
                            AerBridgeDescriptor = new WHEA_AER_BRIDGE_DESCRIPTOR(recordAddr, descriptorStructOffset, bytesRemaining);
                            break;
                        default:
                            throw new InvalidDataException($"{Type} is PCIe but error source descriptor type is not a valid PCIe type: {DescriptorType}");
                    }

                    break;
                case WHEA_ERROR_SOURCE_TYPE.Generic:
                    GenErrDescriptor = new WHEA_GENERIC_ERROR_DESCRIPTOR(recordAddr, descriptorStructOffset, bytesRemaining);
                    break;
                case WHEA_ERROR_SOURCE_TYPE.GenericV2:
                    GenErrDescriptorV2 = new WHEA_GENERIC_ERROR_DESCRIPTOR_V2(recordAddr, descriptorStructOffset, bytesRemaining);
                    break;
                case WHEA_ERROR_SOURCE_TYPE.DeviceDriver:
                    DeviceDriverDescriptor = new WHEA_DEVICE_DRIVER_DESCRIPTOR(recordAddr, descriptorStructOffset, bytesRemaining);
                    break;
                default:
                    throw new InvalidDataException($"{nameof(Type)} is unknown or invalid: {Type}");
            }

            FinalizeRecord(recordAddr, Length);
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
        public bool ShouldSerializeAerRootportDescriptor() =>
            _Type == WHEA_ERROR_SOURCE_TYPE.PCIe && _DescriptorType == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerRootPort;

        [UsedImplicitly]
        public bool ShouldSerializeAerEndpointDescriptor() =>
            _Type == WHEA_ERROR_SOURCE_TYPE.PCIe && _DescriptorType == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerEndpoint;

        [UsedImplicitly]
        public bool ShouldSerializeAerBridgeDescriptor() =>
            _Type == WHEA_ERROR_SOURCE_TYPE.PCIe && _DescriptorType == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerBridge;

        [UsedImplicitly]
        public bool ShouldSerializeGenErrDescriptor() => _Type == WHEA_ERROR_SOURCE_TYPE.Generic;

        [UsedImplicitly]
        public bool ShouldSerializeGenErrDescriptorV2() => _Type == WHEA_ERROR_SOURCE_TYPE.GenericV2;

        [UsedImplicitly]
        public bool ShouldSerializeDeviceDriverDescriptor() => _Type == WHEA_ERROR_SOURCE_TYPE.DeviceDriver;
    }

    // Structure size: 28 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_XPF_MC_BANK_DESCRIPTOR {
        [JsonProperty(Order = 1)]
        public byte BankNumber;

        [JsonProperty(Order = 2)]
        [MarshalAs(UnmanagedType.U1)]
        public bool ClearOnInitialization;

        // Switched to an enumeration
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

    internal sealed class WHEA_XPF_MCE_DESCRIPTOR : WheaRecord {
        private const uint StructSize = 920;
        public override uint GetNativeSize() => StructSize;

        // Switched to an enumeration
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        public bool Enabled; // UCHAR

        [JsonProperty(Order = 3)]
        public byte NumberOfBanks;

        private XPF_MCE_FLAGS _Flags;

        [JsonProperty(Order = 4)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        [JsonProperty(Order = 5)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MCG_Capability;

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MCG_GlobalControl;

        [JsonProperty(Order = 7)]
        public WHEA_XPF_MC_BANK_DESCRIPTOR[] Banks = new WHEA_XPF_MC_BANK_DESCRIPTOR[WHEA_ERROR_SOURCE_DESCRIPTOR.WHEA_MAX_MC_BANKS];

        public WHEA_XPF_MCE_DESCRIPTOR(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_XPF_MCE_DESCRIPTOR), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _Type = (WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE)Marshal.ReadInt16(structAddr);

            if (_Type != WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.XpfMce) {
                var expectedErrSrc = Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.XpfMce);
                var msg = $"{nameof(Type)} does not match the descriptor: {Type} != {expectedErrSrc}";
                throw new InvalidDataException(msg);
            }

            Enabled = Marshal.ReadByte(recordAddr, 2) != 0;
            NumberOfBanks = Marshal.ReadByte(recordAddr, 3);

            if (NumberOfBanks > WHEA_ERROR_SOURCE_DESCRIPTOR.WHEA_MAX_MC_BANKS) {
                var msg = $"{nameof(NumberOfBanks)} is greater than maximum allowed: {NumberOfBanks} > {WHEA_ERROR_SOURCE_DESCRIPTOR.WHEA_MAX_MC_BANKS}";
                throw new InvalidDataException(msg);
            }

            _Flags = (XPF_MCE_FLAGS)Marshal.ReadInt32(recordAddr, 4);
            MCG_Capability = (ulong)Marshal.ReadInt64(recordAddr, 8);
            MCG_GlobalControl = (ulong)Marshal.ReadInt64(recordAddr, 16);

            if (NumberOfBanks > 0) {
                var elementSize = (uint)Marshal.SizeOf<WHEA_XPF_MC_BANK_DESCRIPTOR>();
                var offset = (uint)24;

                for (var i = 0; i < NumberOfBanks; i++) {
                    Banks[i] = Marshal.PtrToStructure<WHEA_XPF_MC_BANK_DESCRIPTOR>(recordAddr + (int)offset);
                    offset += elementSize;
                }
            }

            FinalizeRecord(recordAddr, StructSize);
        }
    }

    internal sealed class WHEA_XPF_CMC_DESCRIPTOR : WheaRecord {
        private const uint StructSize = 932;
        public override uint GetNativeSize() => StructSize;

        // Switched to an enumeration
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        public bool Enabled;

        [JsonProperty(Order = 3)]
        public byte NumberOfBanks;

        [JsonProperty(Order = 4)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Reserved;

        [JsonProperty(Order = 5)]
        public WHEA_NOTIFICATION_DESCRIPTOR Notify;

        [JsonProperty(Order = 6)]
        public WHEA_XPF_MC_BANK_DESCRIPTOR[] Banks = new WHEA_XPF_MC_BANK_DESCRIPTOR[WHEA_ERROR_SOURCE_DESCRIPTOR.WHEA_MAX_MC_BANKS];

        public WHEA_XPF_CMC_DESCRIPTOR(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_XPF_CMC_DESCRIPTOR), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _Type = (WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE)Marshal.ReadInt16(structAddr);

            if (_Type != WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.XpfCmc) {
                var expectedErrSrc = Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.XpfCmc);
                var msg = $"{nameof(Type)} does not match the descriptor: {Type} != {expectedErrSrc}";
                throw new InvalidDataException(msg);
            }

            Enabled = Marshal.ReadByte(recordAddr, 2) != 0;
            NumberOfBanks = Marshal.ReadByte(recordAddr, 3);

            if (NumberOfBanks > WHEA_ERROR_SOURCE_DESCRIPTOR.WHEA_MAX_MC_BANKS) {
                var msg = $"{nameof(NumberOfBanks)} is greater than maximum allowed: {NumberOfBanks} > {WHEA_ERROR_SOURCE_DESCRIPTOR.WHEA_MAX_MC_BANKS}";
                throw new InvalidDataException(msg);
            }

            Reserved = (uint)Marshal.ReadInt32(recordAddr, 4);

            if (Reserved != 0) {
                WarnOutput($"{nameof(Reserved)} is non-zero.", SectionType.Name);
            }

            Notify = Marshal.PtrToStructure<WHEA_NOTIFICATION_DESCRIPTOR>(recordAddr + 8);

            if (NumberOfBanks > 0) {
                var elementSize = (uint)Marshal.SizeOf<WHEA_XPF_MC_BANK_DESCRIPTOR>();
                var offset = (uint)24;

                for (var i = 0; i < NumberOfBanks; i++) {
                    Banks[i] = Marshal.PtrToStructure<WHEA_XPF_MC_BANK_DESCRIPTOR>(recordAddr + (int)offset);
                    offset += elementSize;
                }
            }

            FinalizeRecord(recordAddr, StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    internal sealed class WHEA_XPF_NMI_DESCRIPTOR : WheaRecord {
        private const uint StructSize = 3;
        public override uint GetNativeSize() => StructSize;

        // Switched to an enumeration
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        public bool Enabled;

        public WHEA_XPF_NMI_DESCRIPTOR(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_XPF_NMI_DESCRIPTOR), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _Type = (WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE)Marshal.ReadInt16(structAddr);

            if (_Type != WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.XpfNmi) {
                var expectedErrSrc = Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.XpfNmi);
                var msg = $"{nameof(Type)} does not match the descriptor: {Type} != {expectedErrSrc}";
                throw new InvalidDataException(msg);
            }

            Enabled = Marshal.ReadByte(recordAddr, 2) != 0;

            FinalizeRecord(recordAddr, StructSize);
        }
    }

    /*
     * The Windows headers define separate structures for the MCA, CMC, and CPE
     * error source descriptors for the Itanium platform, but they are
     * identical. Do the obvious thing and just reuse this structure.
     */
    internal sealed class WHEA_IPF_DESCRIPTOR : WheaRecord {
        private const uint StructSize = 4;
        public override uint GetNativeSize() => StructSize;

        // Switched to an enumeration
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        public bool Enabled; // UCHAR

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved;

        public WHEA_IPF_DESCRIPTOR(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_IPF_DESCRIPTOR), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _Type = (WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE)Marshal.ReadInt16(structAddr);

            if (_Type != WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.IpfMca &&
                _Type != WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.IpfCmc &&
                _Type != WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.IpfCpe) {
                var errSrcIpfMca = Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.IpfMca);
                var errSrcIpfCmc = Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.IpfCmc);
                var errSrcIpfCpe = Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.IpfCpe);
                var msg = $"{nameof(Type)} does not match the descriptor: {Type} != ({errSrcIpfMca} || {errSrcIpfCmc} || {errSrcIpfCpe})";
                throw new InvalidDataException(msg);
            }

            Enabled = Marshal.ReadByte(recordAddr, 2) != 0;
            Reserved = Marshal.ReadByte(recordAddr, 3);

            if (Reserved != 0) {
                WarnOutput($"{nameof(Reserved)} is non-zero.", SectionType.Name);
            }

            FinalizeRecord(recordAddr, StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCI_SLOT_NUMBER {
        private uint _RawBits;

        [JsonProperty(Order = 1)]
        public byte DeviceNumber => (byte)(_RawBits & 0x1F); // Bits 0-4

        [JsonProperty(Order = 2)]
        public byte FunctionNumber => (byte)((_RawBits >> 5) & 0x7); // Bits 5-7

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Reserved => _RawBits >> 8; // Bits 8-31

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    internal sealed class WHEA_AER_ROOTPORT_DESCRIPTOR : WheaRecord {
        private const uint StructSize = 36;
        public override uint GetNativeSize() => StructSize;

        // Switched to an enumeration
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        public bool Enabled;

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
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

        public WHEA_AER_ROOTPORT_DESCRIPTOR(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_AER_ROOTPORT_DESCRIPTOR), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _Type = (WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE)Marshal.ReadInt16(structAddr);

            if (_Type != WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerRootPort) {
                var expectedErrSrc = Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerRootPort);
                var msg = $"{nameof(Type)} does not match the descriptor: {Type} != {expectedErrSrc}";
                throw new InvalidDataException(msg);
            }

            Enabled = Marshal.ReadByte(recordAddr, 2) != 0;
            Reserved = Marshal.ReadByte(recordAddr, 3);

            if (Reserved != 0) {
                WarnOutput($"{nameof(Reserved)} is non-zero.", SectionType.Name);
            }

            BusNumber = (uint)Marshal.ReadInt32(recordAddr, 4);
            Slot = Marshal.PtrToStructure<WHEA_PCI_SLOT_NUMBER>(recordAddr + 8);
            DeviceControl = (ushort)Marshal.ReadInt16(recordAddr, 12);
            _Flags = (AER_ROOTPORT_DESCRIPTOR_FLAGS)Marshal.ReadInt16(recordAddr, 14);
            UncorrectableErrorMask = (uint)Marshal.ReadInt32(recordAddr, 16);
            UncorrectableErrorSeverity = (uint)Marshal.ReadInt32(recordAddr, 20);
            CorrectableErrorMask = (uint)Marshal.ReadInt32(recordAddr, 24);
            AdvancedCapsAndControl = (uint)Marshal.ReadInt32(recordAddr, 28);
            RootErrorCommand = (uint)Marshal.ReadInt32(recordAddr, 32);

            FinalizeRecord(recordAddr, StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    internal sealed class WHEA_AER_ENDPOINT_DESCRIPTOR : WheaRecord {
        private const uint StructSize = 32;
        public override uint GetNativeSize() => StructSize;

        // Switched to an enumeration
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        public bool Enabled;

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
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

        public WHEA_AER_ENDPOINT_DESCRIPTOR(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_AER_ENDPOINT_DESCRIPTOR), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _Type = (WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE)Marshal.ReadInt16(structAddr);

            if (_Type != WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerEndpoint) {
                var expectedErrSrc = Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerEndpoint);
                var msg = $"{nameof(Type)} does not match the descriptor: {Type} != {expectedErrSrc}";
                throw new InvalidDataException(msg);
            }

            Enabled = Marshal.ReadByte(recordAddr, 2) != 0;
            Reserved = Marshal.ReadByte(recordAddr, 3);

            if (Reserved != 0) {
                WarnOutput($"{nameof(Reserved)} is non-zero.", SectionType.Name);
            }

            BusNumber = (uint)Marshal.ReadInt32(recordAddr, 4);
            Slot = Marshal.PtrToStructure<WHEA_PCI_SLOT_NUMBER>(recordAddr + 8);
            DeviceControl = (ushort)Marshal.ReadInt16(recordAddr, 12);
            _Flags = (AER_ENDPOINT_DESCRIPTOR_FLAGS)Marshal.ReadInt16(recordAddr, 14);
            UncorrectableErrorMask = (uint)Marshal.ReadInt32(recordAddr, 16);
            UncorrectableErrorSeverity = (uint)Marshal.ReadInt32(recordAddr, 20);
            CorrectableErrorMask = (uint)Marshal.ReadInt32(recordAddr, 24);
            AdvancedCapsAndControl = (uint)Marshal.ReadInt32(recordAddr, 28);

            FinalizeRecord(recordAddr, StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    internal sealed class WHEA_AER_BRIDGE_DESCRIPTOR : WheaRecord {
        private const uint StructSize = 44;
        public override uint GetNativeSize() => StructSize;

        // Switched to an enumeration
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        public bool Enabled;

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
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

        public WHEA_AER_BRIDGE_DESCRIPTOR(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_AER_BRIDGE_DESCRIPTOR), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _Type = (WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE)Marshal.ReadInt16(structAddr);

            if (_Type != WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerBridge) {
                var expectedErrSrc = Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerBridge);
                var msg = $"{nameof(Type)} does not match the descriptor: {Type} != {expectedErrSrc}";
                throw new InvalidDataException(msg);
            }

            Enabled = Marshal.ReadByte(recordAddr, 2) != 0;
            Reserved = Marshal.ReadByte(recordAddr, 3);

            if (Reserved != 0) {
                WarnOutput($"{nameof(Reserved)} is non-zero.", SectionType.Name);
            }

            BusNumber = (uint)Marshal.ReadInt32(recordAddr, 4);
            Slot = Marshal.PtrToStructure<WHEA_PCI_SLOT_NUMBER>(recordAddr + 8);
            DeviceControl = (ushort)Marshal.ReadInt16(recordAddr, 12);
            _Flags = (AER_BRIDGE_DESCRIPTOR_FLAGS)Marshal.ReadInt16(recordAddr, 14);
            UncorrectableErrorMask = (uint)Marshal.ReadInt32(recordAddr, 16);
            UncorrectableErrorSeverity = (uint)Marshal.ReadInt32(recordAddr, 20);
            CorrectableErrorMask = (uint)Marshal.ReadInt32(recordAddr, 24);
            AdvancedCapsAndControl = (uint)Marshal.ReadInt32(recordAddr, 28);
            SecondaryUncorrectableErrorMask = (uint)Marshal.ReadInt32(recordAddr, 32);
            SecondaryUncorrectableErrorSev = (uint)Marshal.ReadInt32(recordAddr, 36);
            SecondaryCapsAndControl = (uint)Marshal.ReadInt32(recordAddr, 40);

            FinalizeRecord(recordAddr, StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    internal sealed class WHEA_GENERIC_ERROR_DESCRIPTOR : WheaRecord {
        private const uint StructSize = 52;
        public override uint GetNativeSize() => StructSize;

        // Switched to an enumeration
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved;

        [JsonProperty(Order = 3)]
        public bool Enabled; // UCHAR

        [JsonProperty(Order = 4)]
        public uint ErrStatusBlockLength;

        [JsonProperty(Order = 5)]
        public uint RelatedErrorSourceId;

        // Next five fields are equivalent to a GEN_ADDR structure
        [JsonProperty(Order = 6)]
        public byte ErrStatusAddressSpaceID;

        [JsonProperty(Order = 7)]
        public byte ErrStatusAddressBitWidth;

        [JsonProperty(Order = 8)]
        public byte ErrStatusAddressBitOffset;

        [JsonProperty(Order = 9)]
        public byte ErrStatusAddressAccessSize;

        [JsonProperty(Order = 10)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ErrStatusAddress; // TODO: WHEA_PHYSICAL_ADDRESS

        [JsonProperty(Order = 11)]
        public WHEA_NOTIFICATION_DESCRIPTOR Notify;

        public WHEA_GENERIC_ERROR_DESCRIPTOR(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_GENERIC_ERROR_DESCRIPTOR), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _Type = (WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE)Marshal.ReadInt16(structAddr);

            if (_Type != WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.Generic) {
                var expectedErrSrc = Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.Generic);
                var msg = $"{nameof(Type)} does not match the descriptor: {Type} != {expectedErrSrc}";
                throw new InvalidDataException(msg);
            }

            Enabled = Marshal.ReadByte(recordAddr, 2) != 0;
            Reserved = Marshal.ReadByte(recordAddr, 3);

            if (Reserved != 0) {
                WarnOutput($"{nameof(Reserved)} is non-zero.", SectionType.Name);
            }

            ErrStatusBlockLength = (uint)Marshal.ReadInt32(recordAddr, 4);
            RelatedErrorSourceId = (uint)Marshal.ReadInt32(recordAddr, 8);
            ErrStatusAddressSpaceID = Marshal.ReadByte(recordAddr, 12);
            ErrStatusAddressBitWidth = Marshal.ReadByte(recordAddr, 13);
            ErrStatusAddressBitOffset = Marshal.ReadByte(recordAddr, 14);
            ErrStatusAddressAccessSize = Marshal.ReadByte(recordAddr, 15);
            ErrStatusAddress = (ulong)Marshal.ReadInt64(recordAddr, 16);
            Notify = Marshal.PtrToStructure<WHEA_NOTIFICATION_DESCRIPTOR>(recordAddr + 24);

            FinalizeRecord(recordAddr, StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    internal sealed class WHEA_GENERIC_ERROR_DESCRIPTOR_V2 : WheaRecord {
        private const uint StructSize = 80;
        public override uint GetNativeSize() => StructSize;

        // Switched to an enumeration
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved;

        [JsonProperty(Order = 3)]
        public bool Enabled; // UCHAR

        [JsonProperty(Order = 4)]
        public uint ErrStatusBlockLength;

        [JsonProperty(Order = 5)]
        public uint RelatedErrorSourceId;

        // Next five fields are equivalent to a GEN_ADDR structure
        [JsonProperty(Order = 6)]
        public byte ErrStatusAddressSpaceID;

        [JsonProperty(Order = 7)]
        public byte ErrStatusAddressBitWidth;

        [JsonProperty(Order = 8)]
        public byte ErrStatusAddressBitOffset;

        [JsonProperty(Order = 9)]
        public byte ErrStatusAddressAccessSize;

        [JsonProperty(Order = 10)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ErrStatusAddress; // TODO: WHEA_PHYSICAL_ADDRESS

        [JsonProperty(Order = 11)]
        public WHEA_NOTIFICATION_DESCRIPTOR Notify;

        // Next five fields are equivalent to a GEN_ADDR structure
        [JsonProperty(Order = 12)]
        public byte ReadAckAddressSpaceID;

        [JsonProperty(Order = 13)]
        public byte ReadAckAddressBitWidth;

        [JsonProperty(Order = 14)]
        public byte ReadAckAddressBitOffset;

        [JsonProperty(Order = 15)]
        public byte ReadAckAddressAccessSize;

        [JsonProperty(Order = 16)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ReadAckAddress; // TODO: WHEA_PHYSICAL_ADDRESS

        [JsonProperty(Order = 17)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ReadAckPreserveMask;

        [JsonProperty(Order = 18)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ReadAckWriteMask;

        public WHEA_GENERIC_ERROR_DESCRIPTOR_V2(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_GENERIC_ERROR_DESCRIPTOR_V2), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _Type = (WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE)Marshal.ReadInt16(structAddr);

            if (_Type != WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.GenericV2) {
                var expectedErrSrc = Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.GenericV2);
                var msg = $"{nameof(Type)} does not match the descriptor: {Type} != {expectedErrSrc}";
                throw new InvalidDataException(msg);
            }

            Enabled = Marshal.ReadByte(recordAddr, 2) != 0;
            Reserved = Marshal.ReadByte(recordAddr, 3);

            if (Reserved != 0) {
                WarnOutput($"{nameof(Reserved)} is non-zero.", SectionType.Name);
            }

            ErrStatusBlockLength = (uint)Marshal.ReadInt32(recordAddr, 4);
            RelatedErrorSourceId = (uint)Marshal.ReadInt32(recordAddr, 8);
            ErrStatusAddressSpaceID = Marshal.ReadByte(recordAddr, 12);
            ErrStatusAddressBitWidth = Marshal.ReadByte(recordAddr, 13);
            ErrStatusAddressBitOffset = Marshal.ReadByte(recordAddr, 14);
            ErrStatusAddressAccessSize = Marshal.ReadByte(recordAddr, 15);
            ErrStatusAddress = (ulong)Marshal.ReadInt64(recordAddr, 16);
            Notify = Marshal.PtrToStructure<WHEA_NOTIFICATION_DESCRIPTOR>(recordAddr + 24);
            ReadAckAddressSpaceID = Marshal.ReadByte(recordAddr, 52);
            ReadAckAddressBitWidth = Marshal.ReadByte(recordAddr, 53);
            ReadAckAddressBitOffset = Marshal.ReadByte(recordAddr, 54);
            ReadAckAddressAccessSize = Marshal.ReadByte(recordAddr, 55);
            ReadAckAddress = (ulong)Marshal.ReadInt64(recordAddr, 56);
            ReadAckPreserveMask = (ulong)Marshal.ReadInt64(recordAddr, 64);
            ReadAckWriteMask = (ulong)Marshal.ReadInt64(recordAddr, 72);

            FinalizeRecord(recordAddr, StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    internal sealed class WHEA_DEVICE_DRIVER_DESCRIPTOR : WheaRecord {
        private uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        // Size of the entire structure assuming 32-bit pointer size
        private const uint StructSizePtr32 = 92;

        // Size of the entire structure assuming 64-bit pointer size
        private const uint StructSizePtr64 = 112;

        // Switched to an enumeration
        private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

        [JsonProperty(Order = 2)]
        public bool Enabled;

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved;

        [JsonProperty(Order = 4)]
        public Guid SourceGuid;

        [JsonProperty(Order = 5)]
        public ushort LogTag;

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
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
        public string CreatorId => WheaGuids.CreatorIds.TryGetValue(_CreatorId, out var creatorId) ? creatorId : _CreatorId.ToString();

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

        public WHEA_DEVICE_DRIVER_DESCRIPTOR(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_DEVICE_DRIVER_DESCRIPTOR), structOffset, GetStructSize(), bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;
            var isPtrSize64 = IntPtr.Size == 8;

            _Type = (WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE)Marshal.ReadInt16(structAddr);

            if (_Type != WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.DeviceDriver) {
                var expectedErrSrc = Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.DeviceDriver);
                var msg = $"{nameof(Type)} does not match the descriptor: {Type} != {expectedErrSrc}";
                throw new InvalidDataException(msg);
            }

            Enabled = Marshal.ReadByte(recordAddr, 2) != 0;
            Reserved = Marshal.ReadByte(recordAddr, 3);

            if (Reserved != 0) {
                WarnOutput($"{nameof(Reserved)} is non-zero.", SectionType.Name);
            }

            SourceGuid = Marshal.PtrToStructure<Guid>(recordAddr + 4);
            LogTag = (ushort)Marshal.ReadInt16(recordAddr, 20);
            Reserved2 = (ushort)Marshal.ReadInt16(recordAddr, 22);

            if (Reserved2 != 0) {
                WarnOutput($"{nameof(Reserved2)} is non-zero.", SectionType.Name);
            }

            PacketLength = (uint)Marshal.ReadInt32(recordAddr, 24);
            PacketCount = (uint)Marshal.ReadInt32(recordAddr, 28);
            PacketBuffer = Marshal.ReadIntPtr(PacketBuffer);
            Config = Marshal.PtrToStructure<WHEA_ERROR_SOURCE_CONFIGURATION_DD>(recordAddr + (isPtrSize64 ? 36 : 32));
            _CreatorId = Marshal.PtrToStructure<Guid>(recordAddr + (isPtrSize64 ? 60 : 44));
            PartitionId = Marshal.PtrToStructure<Guid>(recordAddr + (isPtrSize64 ? 76 : 60));
            MaxSectionDataLength = (uint)Marshal.ReadInt32(recordAddr, isPtrSize64 ? 92 : 76);
            MaxSectionsPerRecord = (uint)Marshal.ReadInt32(recordAddr, isPtrSize64 ? 96 : 80);
            PacketStateBuffer = Marshal.ReadIntPtr(recordAddr, isPtrSize64 ? 100 : 84);
            OpenHandles = Marshal.ReadInt32(recordAddr, isPtrSize64 ? 108 : 88);

            _StructSize = GetStructSize();
            FinalizeRecord(recordAddr, _StructSize);
        }

        private static uint GetStructSize() => IntPtr.Size == 8 ? StructSizePtr64 : StructSizePtr32;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved2() => Reserved2 != 0;
    }

    // Structure size: 12 bytes (32-bit pointers) / 24 bytes (64-bit pointers)
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ERROR_SOURCE_CONFIGURATION_DD {
        // Callback function pointer
        // NTSTATUS WHEA_ERROR_SOURCE_INITIALIZE_DEVICE_DRIVER(PVOID Context, ULONG ErrorSourceId)
        [JsonConverter(typeof(HexStringJsonConverter))]
        public IntPtr Initialize;

        // Callback function pointer
        // VOID WHEA_ERROR_SOURCE_UNINITIALIZE_DEVICE_DRIVER(PVOID Context)
        [JsonConverter(typeof(HexStringJsonConverter))]
        public IntPtr Uninitialize;

        // Callback function pointer
        // NTSTATUS WHEA_ERROR_SOURCE_CORRECT_DEVICE_DRIVER(PVOID ErrorSourceDesc, PULONG MaximumSectionLength)
        [JsonConverter(typeof(HexStringJsonConverter))]
        public IntPtr Correct;
    }

    // @formatter:int_align_fields true

    // From WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE preprocessor definitions
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

    internal enum WHEA_ERROR_SOURCE_STATE : uint {
        Stopped       = 1,
        Started       = 2,
        Removed       = 3,
        RemovePending = 4
    }

    // From WHEA_ERROR_SOURCE_FLAG preprocessor definitions
    [Flags]
    internal enum WHEA_ERROR_SOURCE_FLAGS : uint {
        FirmwareFirst = 0x1,
        Global        = 0x2,
        GhesAssist    = 0x4,
        DefaultSource = 0x80000000
    }

    // From WHEA_XPF_MC_BANK_STATUSFORMAT preprocessor definitions
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

    [Flags]
    internal enum AER_ROOTPORT_DESCRIPTOR_FLAGS : ushort {
        UncorrectableErrorMaskRW     = 0x1,
        UncorrectableErrorSeverityRW = 0x2,
        CorrectableErrorMaskRW       = 0x4,
        AdvancedCapsAndControlRW     = 0x8,
        RootErrorCommandRW           = 0x10
    }

    [Flags]
    internal enum AER_ENDPOINT_DESCRIPTOR_FLAGS : ushort {
        UncorrectableErrorMaskRW     = 0x1,
        UncorrectableErrorSeverityRW = 0x2,
        CorrectableErrorMaskRW       = 0x4,
        AdvancedCapsAndControlRW     = 0x8
    }

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

    // @formatter:int_align_fields false
}
