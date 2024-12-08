#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Runtime.InteropServices;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.NativeMethods;
using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors {
    /*
     * Cannot be directly marshalled as a structure due to the presence of
     * additional fields, the inclusion of which is determined based on the
     * structure size as set in the associated section descriptor.
     */
    internal sealed class WHEA_MEMORY_ERROR_SECTION : WheaErrorRecord {
        // Size up to and including the ErrorType field
        private const uint BaseStructSize = 73; // Not a typo

        // Size up to and including the ModuleHandle field
        private const uint StructSizeWin1803 = 80;

        private uint _NativeSize;
        public override uint GetNativeSize() => _NativeSize;

        private WHEA_MEMORY_ERROR_SECTION_VALIDBITS _ValidBits;

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        [JsonProperty(Order = 2)]
        public WHEA_ERROR_STATUS ErrorStatus;

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong PhysicalAddress;

        [JsonProperty(Order = 4)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong PhysicalAddressMask;

        [JsonProperty(Order = 5)]
        public ushort Node;

        [JsonProperty(Order = 6)]
        public ushort Card;

        [JsonProperty(Order = 7)]
        public ushort Module;

        [JsonProperty(Order = 8)]
        public ushort Bank;

        [JsonProperty(Order = 9)]
        public ushort Device;

        [JsonProperty(Order = 10)]
        public ushort Row;

        [JsonProperty(Order = 11)]
        public ushort Column;

        [JsonProperty(Order = 12)]
        public ushort BitPosition;

        [JsonProperty(Order = 13)]
        public ulong RequesterId;

        [JsonProperty(Order = 14)]
        public ulong ResponderId;

        [JsonProperty(Order = 15)]
        public ulong TargetId;

        private WHEA_MEMORY_ERROR_TYPE _ErrorType;

        [JsonProperty(Order = 16)]
        public string ErrorType => GetEnabledFlagsAsString(_ErrorType);

        // From Windows 10, version 1803
        [JsonProperty(Order = 17)]
        public byte Extended;

        // From Windows 10, version 1803
        [JsonProperty(Order = 18)]
        public ushort RankNumber;

        // From Windows 10, version 1803
        [JsonProperty(Order = 19)]
        public ushort CardHandle;

        // From Windows 10, version 1803
        [JsonProperty(Order = 20)]
        public ushort ModuleHandle;

        // TODO: Additional validation on Row and ExtendedRow in ValidBits
        // TODO: BankAddress, BankGroup, and ChipIdentification in ValidBits

        private void WheaMemoryErrorSection(IntPtr recordAddr, uint sectionOffset, uint sectionLength) {
            var sectionAddr = recordAddr + (int)sectionOffset;

            uint expectedStructSize;

            switch (sectionLength) {
                case BaseStructSize:
                    expectedStructSize = BaseStructSize;
                    break;
                case StructSizeWin1803:
                    expectedStructSize = StructSizeWin1803;
                    break;
                default:
                    var errMsg = $"Unexpected length: {sectionLength}";
                    throw new InvalidDataException(errMsg);
            }

            _ValidBits = (WHEA_MEMORY_ERROR_SECTION_VALIDBITS)Marshal.ReadInt64(sectionAddr);
            var offset = 8;

            ErrorStatus = Marshal.PtrToStructure<WHEA_ERROR_STATUS>(sectionAddr + offset);
            offset += Marshal.SizeOf<WHEA_ERROR_STATUS>();

            PhysicalAddress = (ulong)Marshal.ReadInt64(sectionAddr, offset);
            PhysicalAddressMask = (ulong)Marshal.ReadInt64(sectionAddr, offset + 8);
            Node = (ushort)Marshal.ReadInt16(sectionAddr, offset + 16);
            Card = (ushort)Marshal.ReadInt16(sectionAddr, offset + 18);
            Module = (ushort)Marshal.ReadInt16(sectionAddr, offset + 20);
            Bank = (ushort)Marshal.ReadInt16(sectionAddr, offset + 22);
            Device = (ushort)Marshal.ReadInt16(sectionAddr, offset + 24);
            Row = (ushort)Marshal.ReadInt16(sectionAddr, offset + 26);
            Column = (ushort)Marshal.ReadInt16(sectionAddr, offset + 28);
            BitPosition = (ushort)Marshal.ReadInt16(sectionAddr, offset + 30);
            RequesterId = (ulong)Marshal.ReadInt64(sectionAddr, offset + 32);
            ResponderId = (ulong)Marshal.ReadInt64(sectionAddr, offset + 40);
            TargetId = (ulong)Marshal.ReadInt64(sectionAddr, offset + 48);
            _ErrorType = (WHEA_MEMORY_ERROR_TYPE)Marshal.ReadByte(sectionAddr, offset + 56);
            offset += 57;

            if (expectedStructSize >= StructSizeWin1803) {
                Extended = Marshal.ReadByte(sectionAddr, offset);
                RankNumber = (ushort)Marshal.ReadInt16(sectionAddr, offset + 1);
                CardHandle = (ushort)Marshal.ReadInt16(sectionAddr, offset + 3);
                ModuleHandle = (ushort)Marshal.ReadInt16(sectionAddr, offset + 5);
                offset += 7;
            }

            _NativeSize = (uint)offset;
            FinalizeRecord(recordAddr, _NativeSize);
        }

        public WHEA_MEMORY_ERROR_SECTION(IntPtr recordAddr, uint sectionOffset, uint bytesRemaining) :
            base(typeof(WHEA_MEMORY_ERROR_SECTION), sectionOffset, BaseStructSize, BaseStructSize, bytesRemaining) {
            /*
             * The only case where this error record is embedded in another
             * is the WHEA_ERROR_PACKET_V1 structure. As that structure only
             * applies to Windows Server 2008 and Windows Vista SP1+, it must
             * be the original variant without the Windows 10 v1803 fields.
             *
             * As there are fields in the WHEA_ERROR_PACKET_V1 structure after
             * any embedded WHEA_MEMORY_ERROR_SECTION structure, we need to be
             * a little clever about how many bytes we tell the constructor are
             * remaining. Either there's enough, and we cap "bytesRemaining" to
             * the size of the original structure, or there aren't and we just
             * pass through the provided value. The latter case is fine as the
             * constructor will throw an exception due to the invalid length.
             */
            WheaMemoryErrorSection(recordAddr, sectionOffset, bytesRemaining >= BaseStructSize ? BaseStructSize : bytesRemaining);
        }

        public WHEA_MEMORY_ERROR_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(WHEA_MEMORY_ERROR_SECTION), BaseStructSize, bytesRemaining) {
            WheaMemoryErrorSection(recordAddr, sectionDsc.SectionOffset, sectionDsc.SectionLength);
        }

        [UsedImplicitly]
        public bool ShouldSerializeErrorStatus() =>
            (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ErrorStatus) ==
            WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ErrorStatus;

        [UsedImplicitly]
        public bool ShouldSerializePhysicalAddress() =>
            (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.PhysicalAddress) ==
            WHEA_MEMORY_ERROR_SECTION_VALIDBITS.PhysicalAddress;

        [UsedImplicitly]
        public bool ShouldSerializePhysicalAddressMask() =>
            (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.PhysicalAddressMask) ==
            WHEA_MEMORY_ERROR_SECTION_VALIDBITS.PhysicalAddressMask;

        [UsedImplicitly]
        public bool ShouldSerializeNode() =>
            (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Node) ==
            WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Node;

        [UsedImplicitly]
        public bool ShouldSerializeCard() =>
            (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Card) ==
            WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Card;

        [UsedImplicitly]
        public bool ShouldSerializeModule() =>
            (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Module) ==
            WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Module;

        [UsedImplicitly]
        public bool ShouldSerializeBank() =>
            (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Bank) ==
            WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Bank;

        [UsedImplicitly]
        public bool ShouldSerializeDevice() =>
            (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Device) ==
            WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Device;

        [UsedImplicitly]
        public bool ShouldSerializeRow() =>
            (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Row) == WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Row ||
            (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ExtendedRow) == WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ExtendedRow;

        [UsedImplicitly]
        public bool ShouldSerializeColumn() =>
            (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Column) ==
            WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Column;

        [UsedImplicitly]
        public bool ShouldSerializeBitPosition() =>
            (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.BitPosition) ==
            WHEA_MEMORY_ERROR_SECTION_VALIDBITS.BitPosition;

        [UsedImplicitly]
        public bool ShouldSerializeRequesterId() =>
            (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.RequesterId) ==
            WHEA_MEMORY_ERROR_SECTION_VALIDBITS.RequesterId;

        [UsedImplicitly]
        public bool ShouldSerializeResponderId() =>
            (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ResponderId) ==
            WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ResponderId;

        [UsedImplicitly]
        public bool ShouldSerializeTargetId() =>
            (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.TargetId) ==
            WHEA_MEMORY_ERROR_SECTION_VALIDBITS.TargetId;

        [UsedImplicitly]
        public bool ShouldSerializeErrorType() =>
            (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ErrorType) ==
            WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ErrorType;

        [UsedImplicitly]
        public bool ShouldSerializeExtended() =>
            (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ExtendedRow) ==
            WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ExtendedRow;

        [UsedImplicitly]
        public bool ShouldSerializeRankNumber() =>
            (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.RankNumber) ==
            WHEA_MEMORY_ERROR_SECTION_VALIDBITS.RankNumber;

        [UsedImplicitly]
        public bool ShouldSerializeCardHandle() =>
            (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.CardHandle) ==
            WHEA_MEMORY_ERROR_SECTION_VALIDBITS.CardHandle;

        [UsedImplicitly]
        public bool ShouldSerializeModuleHandle() =>
            (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ModuleHandle) ==
            WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ModuleHandle;
    }

    // @formatter:int_align_fields true

    [Flags]
    internal enum WHEA_MEMORY_ERROR_SECTION_VALIDBITS : ulong {
        ErrorStatus         = 0x1,
        PhysicalAddress     = 0x2,
        PhysicalAddressMask = 0x4,
        Node                = 0x8,
        Card                = 0x10,
        Module              = 0x20,
        Bank                = 0x40,
        Device              = 0x80,
        Row                 = 0x100,
        Column              = 0x200,
        BitPosition         = 0x400,
        RequesterId         = 0x800,
        ResponderId         = 0x1000,
        TargetId            = 0x2000,
        ErrorType           = 0x4000,
        RankNumber          = 0x8000,
        CardHandle          = 0x10000,
        ModuleHandle        = 0x20000,
        ExtendedRow         = 0x40000,
        BankGroup           = 0x80000,
        BankAddress         = 0x100000,
        ChipIdentification  = 0x200000
    }

    // From preprocessor definitions (WHEA_MEMERRTYPE_*)
    internal enum WHEA_MEMORY_ERROR_TYPE : byte {
        Unknown           = 0,
        NoError           = 1,
        SingleBitECC      = 2,
        MultiBitECC       = 3,
        SingleSymChipKill = 4,
        MultiSymChipKill  = 5,
        MasterAbort       = 6,
        TargetAbort       = 7,
        ParityError       = 8,
        WatchdogTimeout   = 9,
        InvalidAddress    = 10,
        MirrorBroken      = 11,
        MemorySparing     = 12
    }

    // @formatter:int_align_fields false
}
