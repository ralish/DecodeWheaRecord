#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.Linq;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Descriptors;
using DecodeWheaRecord.Internal;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

/*
 * Module       Version             Arch(s)         Function(s)
 * AzPshedPi    11.0.2404.15001     AMD64           PshedPiGetMemoryErrorSections
 * ntoskrnl     10.0.26100.2605     AMD64           HalpCreateMcaMemoryErrorRecord
 */
namespace DecodeWheaRecord.Errors.Microsoft {
    internal sealed class WHEA_MEMORY_ERROR_EXT_SECTION_INTEL : WheaRecord {
        private const uint StructSize = 166;
        public override uint GetNativeSize() => StructSize;

        private WHEA_MEMORY_ERROR_EXT_SECTION_FLAGS _Flags;

        [JsonProperty(Order = 1)]
        public string Flags => GetEnumFlagsAsString(_Flags);

        private WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS _ValidBits;

        [JsonProperty(Order = 2)]
        public string ValidBits => GetEnumFlagsAsString(_ValidBits);

        [JsonProperty(Order = 3)]
        public WHEA_MEMORY_HARDWARE_ADDRESS_INTEL HardwareAddress;

        [JsonProperty(Order = 4)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] Reserved;

        public WHEA_MEMORY_ERROR_EXT_SECTION_INTEL(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_MEMORY_ERROR_EXT_SECTION_INTEL), structOffset, StructSize, bytesRemaining) {
            WheaMemoryErrorExtSectionIntel(recordAddr, structOffset);
        }

        public WHEA_MEMORY_ERROR_EXT_SECTION_INTEL(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(typeof(WHEA_MEMORY_ERROR_EXT_SECTION_INTEL), sectionDsc, StructSize, bytesRemaining) {
            WheaMemoryErrorExtSectionIntel(recordAddr, sectionDsc.SectionOffset);
        }

        private void WheaMemoryErrorExtSectionIntel(IntPtr recordAddr, uint structOffset) {
            var structAddr = recordAddr + (int)structOffset;

            _Flags = (WHEA_MEMORY_ERROR_EXT_SECTION_FLAGS)Marshal.ReadInt64(structAddr);
            _ValidBits = (WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS)Marshal.ReadInt64(structAddr + 8);

            // The offset of +8 is correct (see the comment in the structure)
            HardwareAddress = PtrToStructure<WHEA_MEMORY_HARDWARE_ADDRESS_INTEL>(structAddr + 8);

            Marshal.Copy(structAddr + 126, Reserved, 0, 40);

            FinalizeRecord(recordAddr, StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved.Any(element => element != 0);
    }

    // Structure size: 110 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_MEMORY_HARDWARE_ADDRESS_INTEL {
        /*
         * We want to preserve the original structure of the ... structure, but
         * it needs the ValidBits field present in the parent structure for the
         * ShouldSerialize() methods. To avoid manual marshalling to compensate
         * for that we'll be a bit cheeky:
         *
         * - Add a "copy" of ValidBits to the start of the structure
         * - Marshal the structure offset by -8 bytes from its address
         *
         * This exploits the adjacency of the ValidBits field in the parent
         * structure, marshalling it twice but including it in this structure.
         */
        private WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS _ValidBits;

        private WHEA_MEMORY_DEFINITION _MemDef;

        [JsonProperty(Order = 1)]
        public string MemDef => GetEnumValueAsString<WHEA_MEMORY_DEFINITION>(_MemDef);

        [JsonProperty(Order = 2)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong SystemAddress;

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong SpareSystemAddress;

        [JsonProperty(Order = 4)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong DevicePhysicalAddress;

        [JsonProperty(Order = 5)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ChannelAddress;

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong RankAddress;

        [JsonProperty(Order = 7)]
        public byte ProcessorSocketId;

        [JsonProperty(Order = 8)]
        public byte MemoryControllerId;

        [JsonProperty(Order = 9)]
        public byte TargetId;

        [JsonProperty(Order = 10)]
        public byte LogicalChannelId;

        [JsonProperty(Order = 11)]
        public byte ChannelId;

        [JsonProperty(Order = 12)]
        public byte SubChannelId;

        [JsonProperty(Order = 13)]
        public byte PhysicalRankId;

        [JsonProperty(Order = 14)]
        public byte DimmSlotId;

        [JsonProperty(Order = 15)]
        public byte DimmRankId;

        [JsonProperty(Order = 16)]
        public byte Bank;

        [JsonProperty(Order = 17)]
        public byte BankGroup;

        [JsonProperty(Order = 18)]
        public uint Row;

        [JsonProperty(Order = 19)]
        public uint Column;

        [JsonProperty(Order = 20)]
        public byte LockStepRank;

        [JsonProperty(Order = 21)]
        public byte LockStepPhysicalRank;

        [JsonProperty(Order = 22)]
        public byte LockStepBank;

        [JsonProperty(Order = 23)]
        public byte LockStepBankGroup;

        [JsonProperty(Order = 24)]
        public byte ChipSelect;

        [JsonProperty(Order = 25)]
        public byte Node;

        [JsonProperty(Order = 26)]
        public byte ChipId;

        [JsonProperty(Order = 26)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 40)]
        public byte[] Reserved;

        [UsedImplicitly]
        public bool ShouldSerializeMemDef() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.MemDef) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeSystemAddress() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.SystemAddress) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeSpareSystemAddress() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.SpareSystemAddress) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeDevicePhysicalAddress() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.DevicePhysicalAddress) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeChannelAddress() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.ChannelAddress) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeRankAddress() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.RankAddress) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeProcessorSocketId() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.ProcessorSocketId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeMemoryControllerId() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.MemoryControllerId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeTargetId() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.TargetId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeLogicalChannelId() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.LogicalChannelId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeChannelId() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.ChannelId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeSubChannelId() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.SubChannelId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializePhysicalRankId() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.PhysicalRankId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeDimmSlotId() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.DimmSlotId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeDimmRankId() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.DimmRankId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeBank() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.Bank) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeBankGroup() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.BankGroup) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeRow() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.Row) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeColumn() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.Column) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeLockStepRank() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.LockStepRank) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeLockStepPhysicalRank() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.LockStepPhysicalRank) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeLockStepBank() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.LockStepBank) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeLockStepBankGroup() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.LockStepBankGroup) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeChipSelect() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.ChipSelect) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeNode() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.Node) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeChipId() => (_ValidBits & WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS.ChipId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved.Any(element => element != 0);
    }

    // @formatter:int_align_fields true

    [Flags]
    internal enum WHEA_MEMORY_ERROR_EXT_SECTION_FLAGS : ulong {
        AddressTranslationByPrmSuccess         = 0x1,
        AddressTranslationByPrmFailed          = 0x2,
        AddressTranslationByPrmNotSupported    = 0x4,
        AddressTranslationByPluginSuccess      = 0x8,
        AddressTranslationByPluginFailed       = 0x10,
        AddressTranslationByPluginNotSupported = 0x20
    }

    [Flags]
    internal enum WHEA_MEMORY_ERROR_EXT_SECTION_INTEL_VALIDBITS : ulong {
        MemDef                = 0x1,
        SystemAddress         = 0x2,
        SpareSystemAddress    = 0x4,
        DevicePhysicalAddress = 0x8,
        ChannelAddress        = 0x10,
        RankAddress           = 0x20,
        ProcessorSocketId     = 0x40,
        MemoryControllerId    = 0x80,
        TargetId              = 0x100,
        LogicalChannelId      = 0x200,
        ChannelId             = 0x400,
        SubChannelId          = 0x800,
        PhysicalRankId        = 0x1000,
        DimmSlotId            = 0x2000,
        DimmRankId            = 0x4000,
        Bank                  = 0x8000,
        BankGroup             = 0x10000,
        Row                   = 0x20000,
        Column                = 0x40000,
        LockStepRank          = 0x80000,
        LockStepPhysicalRank  = 0x100000,
        LockStepBank          = 0x200000,
        LockStepBankGroup     = 0x400000,
        ChipSelect            = 0x800000,
        Node                  = 0x1000000,
        ChipId                = 0x2000000
    }

    internal enum WHEA_MEMORY_DEFINITION : uint {
        Undefined           = 0,
        FarMemory           = 1,
        NearMemory          = 2,
        HighBandwidthMemory = 3
    }

    // @formatter:int_align_fields false
}
