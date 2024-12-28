#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.Linq;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Hardware;
using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors.UEFI {
    internal sealed class WHEA_PCIEXPRESS_ERROR_SECTION : WheaErrorRecord {
        private const uint StructSize = 208;
        public override uint GetNativeSize() => StructSize;

        private const uint ExpCapBufferSize = 60;
        private const uint AerInfoBufferSize = 96;

        private WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS _ValidBits;

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        private WHEA_PCIEXPRESS_DEVICE_TYPE _PortType;

        [JsonProperty(Order = 2)]
        public string PortType => Enum.GetName(typeof(WHEA_PCIEXPRESS_DEVICE_TYPE), _PortType);

        // Supported version of the PCIe specification
        [JsonProperty(Order = 3)]
        public WHEA_PCIEXPRESS_VERSION Version;

        [JsonProperty(Order = 4)]
        public WHEA_PCIEXPRESS_COMMAND_STATUS CommandStatus;

        [JsonProperty(Order = 5)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Reserved;

        [JsonProperty(Order = 6)]
        public WHEA_PCIEXPRESS_DEVICE_ID DeviceId;

        [JsonProperty(Order = 7)]
        public ulong DeviceSerialNumber;

        [JsonProperty(Order = 8)]
        public WHEA_PCIEXPRESS_BRIDGE_CONTROL_STATUS BridgeControlStatus;

        [JsonProperty(Order = 9)]
        public PCI_EXPRESS_CAPABILITY ExpressCapability;

        [JsonProperty(Order = 10)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] ExpCapUnusedBytes;

        [JsonProperty(Order = 11)]
        public PCI_EXPRESS_AER_CAPABILITY AerInfo;

        [JsonProperty(Order = 12)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] AerInfoUnusedBytes;

        public WHEA_PCIEXPRESS_ERROR_SECTION(IntPtr recordAddr, uint sectionOffset, uint bytesRemaining) :
            base(typeof(WHEA_PCIEXPRESS_ERROR_SECTION), sectionOffset, StructSize, bytesRemaining) {
            WheaPciExpressErrorSection(recordAddr, sectionOffset);
        }

        public WHEA_PCIEXPRESS_ERROR_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(WHEA_PCIEXPRESS_ERROR_SECTION), StructSize, bytesRemaining) {
            WheaPciExpressErrorSection(recordAddr, sectionDsc.SectionOffset);
        }

        private void WheaPciExpressErrorSection(IntPtr recordAddr, uint sectionOffset) {
            var logCat = SectionType.Name;
            var sectionAddr = recordAddr + (int)sectionOffset;

            _ValidBits = (WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS)Marshal.ReadInt64(sectionAddr);
            _PortType = (WHEA_PCIEXPRESS_DEVICE_TYPE)Marshal.ReadInt32(sectionAddr, 8);
            Version = Marshal.PtrToStructure<WHEA_PCIEXPRESS_VERSION>(sectionAddr + 12);
            CommandStatus = Marshal.PtrToStructure<WHEA_PCIEXPRESS_COMMAND_STATUS>(sectionAddr + 16);
            Reserved = (uint)Marshal.ReadInt32(sectionAddr, 20);
            DeviceId = Marshal.PtrToStructure<WHEA_PCIEXPRESS_DEVICE_ID>(sectionAddr + 24);
            DeviceSerialNumber = (ulong)Marshal.ReadInt64(sectionAddr, 40);
            BridgeControlStatus = Marshal.PtrToStructure<WHEA_PCIEXPRESS_BRIDGE_CONTROL_STATUS>(sectionAddr + 48);

            ExpressCapability = Marshal.PtrToStructure<PCI_EXPRESS_CAPABILITY>(sectionAddr + 52);
            var ExpCapStructSize = Marshal.SizeOf<PCI_EXPRESS_CAPABILITY>();
            var ExpCapBytesRemaining = ExpCapBufferSize - (uint)ExpCapStructSize;
            if (ExpCapBytesRemaining != 0) {
                ExpCapUnusedBytes = new byte[ExpCapBytesRemaining];
                Marshal.Copy(sectionAddr + 52, ExpCapUnusedBytes, ExpCapStructSize, (int)ExpCapBytesRemaining);

                if (ExpCapUnusedBytes.Any(element => element != 0)) {
                    WarnOutput($"{nameof(ExpCapUnusedBytes)} has non-zero bytes.", logCat);
                }
            }

            // TODO: PCI_EXPRESS_ROOTPORT_AER_CAPABILITY? Others?
            AerInfo = Marshal.PtrToStructure<PCI_EXPRESS_AER_CAPABILITY>(sectionAddr + 112);
            var AerInfoStructSize = Marshal.SizeOf<PCI_EXPRESS_AER_CAPABILITY>();
            var AerInfoBytesRemaining = AerInfoBufferSize - (uint)AerInfoStructSize;
            if (AerInfoBytesRemaining != 0) {
                AerInfoUnusedBytes = new byte[AerInfoBytesRemaining];
                Marshal.Copy(sectionAddr + 112, AerInfoUnusedBytes, AerInfoStructSize, (int)AerInfoBytesRemaining);

                if (AerInfoUnusedBytes.Any(element => element != 0)) {
                    WarnOutput($"{nameof(AerInfoUnusedBytes)} has non-zero bytes.", logCat);
                }
            }

            FinalizeRecord(recordAddr, StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializePortType() => (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.PortType) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeVersion() => (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.Version) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeCommandStatus() => (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.CommandStatus) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;

        [UsedImplicitly]
        public bool ShouldSerializeDeviceId() => (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.DeviceId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeDeviceSerialNumber() => (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.DeviceSerialNumber) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeBridgeControlStatus() => (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.BridgeControlStatus) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeExpressCapability() => (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.ExpressCapability) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeExpCapUnusedBytes() =>
            ShouldSerializeExpressCapability() && ExpCapUnusedBytes != null && ExpCapUnusedBytes.Any(element => element != 0);

        [UsedImplicitly]
        public bool ShouldSerializeAerInfo() => (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.AerInfo) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeAerInfoUnusedBytes() =>
            ShouldSerializeAerInfo() && AerInfoUnusedBytes != null && AerInfoUnusedBytes.Any(element => element != 0);
    }

    // Structure size: 4 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCIEXPRESS_BRIDGE_CONTROL_STATUS {
        public ushort BridgeSecondaryStatus;
        public ushort BridgeControl;
    }

    // Structure size: 4 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCIEXPRESS_COMMAND_STATUS {
        public ushort Command;
        public ushort Status;
    }

    // Structure size: 24 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCIEXPRESS_DEVICE_ID {
        [JsonProperty(Order = 1)]
        public ushort VendorID;

        [JsonProperty(Order = 2)]
        public ushort DeviceID;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        private byte[] _ClassCode;

        [JsonProperty(Order = 3)]
        public uint ClassCode => (uint)(_ClassCode[0] + (_ClassCode[1] << 8) + (_ClassCode[2] << 16));

        [JsonProperty(Order = 4)]
        public byte FunctionNumber;

        [JsonProperty(Order = 5)]
        public byte DeviceNumber;

        [JsonProperty(Order = 6)]
        public ushort Segment;

        [JsonProperty(Order = 7)]
        public byte PrimaryBusNumber;

        [JsonProperty(Order = 8)]
        public byte SecondaryBusNumber;

        private ushort _SlotNumber;

        [JsonProperty(Order = 9)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved1 => (byte)(_SlotNumber & 0x7); // Bits 0-2

        [JsonProperty(Order = 10)]
        public ushort SlotNumber => (ushort)(_SlotNumber >> 3); // Bits 3-15

        [JsonProperty(Order = 11)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Reserved2;

        [UsedImplicitly]
        public bool ShouldSerializeReserved1() => Reserved1 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved2() => Reserved2 != 0;
    }

    // Structure size: 4 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCIEXPRESS_VERSION {
        public byte MinorVersion;
        public byte MajorVersion;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Reserved;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // @formatter:int_align_fields true

    [Flags]
    internal enum WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS : ulong {
        PortType = 0x1,
        Version = 0x2,
        CommandStatus = 0x4,
        DeviceId = 0x8,
        DeviceSerialNumber = 0x10,
        BridgeControlStatus = 0x20,
        ExpressCapability = 0x40,
        AerInfo = 0x80
    }

    // @formatter:int_align_fields false
}
