#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.NativeMethods;
using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors {
    /*
     * In retrospect this could probably be directly marshalled as a structure,
     * but supporting the PCI_EXPRESS_CAPABILITY and PCI_EXPRESS_AER_CAPABILITY
     * structures may change that.
     */
    internal sealed class WHEA_PCIEXPRESS_ERROR_SECTION : WheaErrorRecord {
        // Structure size is static
        private const uint _StructSize = 208;
        public override uint GetNativeSize() => _StructSize;

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
        public uint Reserved;

        [JsonProperty(Order = 6)]
        public WHEA_PCIEXPRESS_DEVICE_ID DeviceId;

        [JsonProperty(Order = 7)]
        public ulong DeviceSerialNumber;

        [JsonProperty(Order = 8)]
        public WHEA_PCIEXPRESS_BRIDGE_CONTROL_STATUS BridgeControlStatus;

        [JsonProperty(Order = 9)]
        public byte[] ExpressCapability; // TODO: PCI_EXPRESS_CAPABILITY

        [JsonProperty(Order = 10)]
        public byte[] AerInfo; // TODO: PCI_EXPRESS_AER_CAPABILITY

        private void WheaPciExpressErrorSection(IntPtr recordAddr, uint sectionOffset) {
            var sectionAddr = recordAddr + (int)sectionOffset;

            _ValidBits = (WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS)Marshal.ReadInt64(sectionAddr);
            _PortType = (WHEA_PCIEXPRESS_DEVICE_TYPE)Marshal.ReadInt32(sectionAddr, 8);
            var offset = 12;

            Version = Marshal.PtrToStructure<WHEA_PCIEXPRESS_VERSION>(sectionAddr + offset);
            offset += Marshal.SizeOf<WHEA_PCIEXPRESS_VERSION>();

            CommandStatus = Marshal.PtrToStructure<WHEA_PCIEXPRESS_COMMAND_STATUS>(sectionAddr + offset);
            offset += Marshal.SizeOf<WHEA_PCIEXPRESS_COMMAND_STATUS>();

            Reserved = (uint)Marshal.ReadInt32(sectionAddr, offset);
            offset += 4;

            DeviceId = Marshal.PtrToStructure<WHEA_PCIEXPRESS_DEVICE_ID>(sectionAddr + offset);
            offset += Marshal.SizeOf<WHEA_PCIEXPRESS_DEVICE_ID>();

            DeviceSerialNumber = (ulong)Marshal.ReadInt64(sectionAddr, offset);
            offset += 8;

            BridgeControlStatus = Marshal.PtrToStructure<WHEA_PCIEXPRESS_BRIDGE_CONTROL_STATUS>(sectionAddr + offset);
            offset += Marshal.SizeOf<WHEA_PCIEXPRESS_BRIDGE_CONTROL_STATUS>();

            ExpressCapability = new byte[60];
            Marshal.Copy(sectionAddr + offset, ExpressCapability, 0, 60);
            offset += 60;

            AerInfo = new byte[96];
            Marshal.Copy(sectionAddr + offset, AerInfo, 0, 96);

            FinalizeRecord(recordAddr, _StructSize);
        }

        public WHEA_PCIEXPRESS_ERROR_SECTION(IntPtr recordAddr, uint sectionOffset, uint bytesRemaining) :
            base(typeof(WHEA_PCIEXPRESS_ERROR_SECTION), sectionOffset, _StructSize, bytesRemaining) {
            WheaPciExpressErrorSection(recordAddr, sectionOffset);
        }

        public WHEA_PCIEXPRESS_ERROR_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(WHEA_PCIEXPRESS_ERROR_SECTION), _StructSize, bytesRemaining) {
            WheaPciExpressErrorSection(recordAddr, sectionDsc.SectionOffset);
        }

        [UsedImplicitly]
        public bool ShouldSerializePortType() =>
            (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.PortType) ==
            WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.PortType;

        [UsedImplicitly]
        public bool ShouldSerializeVersion() =>
            (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.Version) ==
            WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.Version;

        [UsedImplicitly]
        public bool ShouldSerializeCommandStatus() =>
            (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.CommandStatus) ==
            WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.CommandStatus;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();

        [UsedImplicitly]
        public bool ShouldSerializeDeviceId() =>
            (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.DeviceId) ==
            WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.DeviceId;

        [UsedImplicitly]
        public bool ShouldSerializeDeviceSerialNumber() =>
            (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.DeviceSerialNumber) ==
            WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.DeviceSerialNumber;

        [UsedImplicitly]
        public bool ShouldSerializeBridgeControlStatus() =>
            (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.BridgeControlStatus) ==
            WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.BridgeControlStatus;

        [UsedImplicitly]
        public bool ShouldSerializeExpressCapability() =>
            (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.ExpressCapability) ==
            WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.ExpressCapability;

        [UsedImplicitly]
        public bool ShouldSerializeAerInfo() =>
            (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.AerInfo) ==
            WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.AerInfo;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCIEXPRESS_BRIDGE_CONTROL_STATUS {
        public ushort BridgeSecondaryStatus;
        public ushort BridgeControl;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCIEXPRESS_COMMAND_STATUS {
        public ushort Command;
        public ushort Status;
    }

    /*
     * Originally defined as a structure of which three fields are ULONGs as
     * bitfields. This structure has the same in memory format but is simpler
     * to interact with.
     */
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
        public byte Reserved1 => (byte)(_SlotNumber & 0xFFF8); // Bits 0-2

        [JsonProperty(Order = 10)]
        public ushort SlotNumber => (ushort)(_SlotNumber >> 3); // Bits 3-15

        [JsonProperty(Order = 11)]
        public byte Reserved2;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved1() => IsDebugBuild();

        [UsedImplicitly]
        public static bool ShouldSerializeReserved2() => IsDebugBuild();
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCIEXPRESS_VERSION {
        public byte MinorVersion;
        public byte MajorVersion;
        public ushort Reserved;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();
    }

    // @formatter:int_align_fields true

    [Flags]
    internal enum WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS : ulong {
        PortType            = 0x1,
        Version             = 0x2,
        CommandStatus       = 0x4,
        DeviceId            = 0x8,
        DeviceSerialNumber  = 0x10,
        BridgeControlStatus = 0x20,
        ExpressCapability   = 0x40,
        AerInfo             = 0x80
    }

    // @formatter:int_align_fields false
}
