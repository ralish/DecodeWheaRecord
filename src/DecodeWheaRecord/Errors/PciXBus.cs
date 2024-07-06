#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.NativeMethods;
using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors {
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCIXBUS_ERROR_SECTION : WheaRecord {
        private WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS _ValidBits;

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        [JsonProperty(Order = 2)]
        public WHEA_ERROR_STATUS ErrorStatus;

        private WHEA_PCIXBUS_ERROR_TYPE _ErrorType;

        [JsonProperty(Order = 3)]
        public string ErrorType => Enum.GetName(typeof(WHEA_PCIXBUS_ERROR_TYPE), _ErrorType);

        [JsonProperty(Order = 4)]
        public WHEA_PCIXBUS_ID BusId;

        [JsonProperty(Order = 5)]
        public uint Reserved;

        [JsonProperty(Order = 6)]
        public ulong BusAddress;

        [JsonProperty(Order = 7)]
        public ulong BusData;

        [JsonProperty(Order = 8)]
        public WHEA_PCIXBUS_COMMAND BusCommand;

        [JsonProperty(Order = 9)]
        public ulong RequesterId;

        [JsonProperty(Order = 10)]
        public ulong CompleterId;

        [JsonProperty(Order = 11)]
        public ulong TargetId;

        [UsedImplicitly]
        public bool ShouldSerializeErrorStatus() => (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.ErrorStatus) ==
                                                    WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.ErrorStatus;

        [UsedImplicitly]
        public bool ShouldSerializeErrorType() => (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.ErrorType) ==
                                                  WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.ErrorType;

        [UsedImplicitly]
        public bool ShouldSerializeBusId() => (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.BusId) ==
                                              WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.BusId;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();

        [UsedImplicitly]
        public bool ShouldSerializeBusAddress() => (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.BusAddress) ==
                                                   WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.BusAddress;

        [UsedImplicitly]
        public bool ShouldSerializeBusData() => (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.BusData) ==
                                                WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.BusData;

        [UsedImplicitly]
        public bool ShouldSerializeBusCommand() => (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.BusCommand) ==
                                                   WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.BusCommand;

        [UsedImplicitly]
        public bool ShouldSerializeRequesterId() => (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.RequesterId) ==
                                                    WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.RequesterId;

        [UsedImplicitly]
        public bool ShouldSerializeCompleterId() => (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.CompleterId) ==
                                                    WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.CompleterId;

        [UsedImplicitly]
        public bool ShouldSerializeTargetId() => (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.TargetId) ==
                                                 WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.TargetId;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCIXBUS_COMMAND {
        private ulong _Command;

        [JsonProperty(Order = 1)]
        public ulong Command => _Command & 0xFF00000000000000; // Bits 0 - 55

        [JsonProperty(Order = 2)]
        public string Flags => GetEnabledFlagsAsString((WHEA_PCIXBUS_COMMAND_FLAGS)(_Command >> 56)); // Bits 56-63
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCIXBUS_ID {
        public byte BusNumber;
        public byte BusSegment;
    }

    // @formatter:int_align_fields true

    // Originally defined in the WHEA_PCIXBUS_COMMAND structure
    [Flags]
    internal enum WHEA_PCIXBUS_COMMAND_FLAGS : byte {
        PCIXCommand = 0x1
    }

    [Flags]
    internal enum WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS : ulong {
        ErrorStatus = 0x1,
        ErrorType   = 0x2,
        BusId       = 0x4,
        BusAddress  = 0x8,
        BusData     = 0x10,
        BusCommand  = 0x20,
        RequesterId = 0x40,
        CompleterId = 0x80,
        TargetId    = 0x100
    }

    // From preprocessor definitions (PCIXBUS_ERRTYPE_*)
    internal enum WHEA_PCIXBUS_ERROR_TYPE : ushort {
        Unknown          = 0,
        DataParity       = 1,
        System           = 2,
        MasterAbort      = 3,
        BusTimeout       = 4,
        MasterDataParity = 5,
        AddressParity    = 6,
        CommandParity    = 7
    }

    // @formatter:int_align_fields false
}
