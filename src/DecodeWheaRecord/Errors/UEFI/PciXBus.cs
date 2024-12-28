#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors.UEFI {
    // Structure size: 72 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCIXBUS_ERROR_SECTION : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_PCIXBUS_ERROR_SECTION>();

        private WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS _ValidBits;

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        [JsonProperty(Order = 2)]
        public WHEA_ERROR_STATUS ErrorStatus;

        // Switched to an enumeration
        private WHEA_PCIXBUS_ERROR_TYPE _ErrorType;

        [JsonProperty(Order = 3)]
        public string ErrorType => Enum.GetName(typeof(WHEA_PCIXBUS_ERROR_TYPE), _ErrorType);

        [JsonProperty(Order = 4)]
        public WHEA_PCIXBUS_ID BusId;

        [JsonProperty(Order = 5)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Reserved;

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong BusAddress;

        [JsonProperty(Order = 7)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong BusData;

        [JsonProperty(Order = 8)]
        public WHEA_PCIXBUS_COMMAND BusCommand;

        [JsonProperty(Order = 9)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong RequesterId;

        [JsonProperty(Order = 10)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong CompleterId;

        [JsonProperty(Order = 11)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong TargetId;

        [UsedImplicitly]
        public bool ShouldSerializeErrorStatus() => (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.ErrorStatus) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeErrorType() => (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.ErrorType) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeBusId() => (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.BusId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;

        [UsedImplicitly]
        public bool ShouldSerializeBusAddress() => (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.BusAddress) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeBusData() => (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.BusData) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeBusCommand() => (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.BusCommand) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeRequesterId() => (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.RequesterId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeCompleterId() => (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.CompleterId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeTargetId() => (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.TargetId) != 0;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCIXBUS_COMMAND {
        private ulong _RawBits;

        [JsonProperty(Order = 1)]
        public ulong Command => _RawBits & 0xFFFFFFFFFFFFFF; // Bits 0 - 55

        [JsonProperty(Order = 2)]
        public bool PCIXCommand => (_RawBits >> 56 & 0x1) == 1; // Bit 56

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved => (byte)(_RawBits >> 57); // Bits 57-63

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 2 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCIXBUS_ID {
        public byte BusNumber;
        public byte BusSegment;
    }

    // @formatter:int_align_fields true

    [Flags]
    internal enum WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS : ulong {
        ErrorStatus = 0x1,
        ErrorType = 0x2,
        BusId = 0x4,
        BusAddress = 0x8,
        BusData = 0x10,
        BusCommand = 0x20,
        RequesterId = 0x40,
        CompleterId = 0x80,
        TargetId = 0x100
    }

    // From PCIXBUS_ERRTYPE preprocessor definitions
    internal enum WHEA_PCIXBUS_ERROR_TYPE : ushort {
        Unknown = 0,
        DataParity = 1,
        System = 2,
        MasterAbort = 3,
        BusTimeout = 4,
        MasterDataParity = 5,
        AddressParity = 6,
        CommandParity = 7
    }

    // @formatter:int_align_fields false
}
