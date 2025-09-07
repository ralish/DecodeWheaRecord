// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Descriptors;
using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

/*
 * Module       Version             Arch(s)         Function(s)
 * AzPshedPi    11.0.2404.15001     AMD64           AmdPluginFinalizeErrorRecord
 *                                  AMD64           PshedPiGetMemoryErrorSections
 *                                  AMD64           PshedPIHsxFinalizeErrorRec
 *                                  AMD64           PshedPiIcxFinalizeErrorRec
 *                                  AMD64           PshedPISkxFinalizeErrorRec
 *                                  AMD64           PshedPiSprFinalizeErrorRec
 *                                  AMD64           PshedPiValidateMemoryError
 * ntoskrnl     10.0.26100.2605     AMD64           HalpAddErrorEntryToPacket
 *                                  AMD64           HalpCreateMcaMemoryErrorRecord
 *                                  AMD64 / Arm64   HalpGenericErrorSourceRecovery
 *                                  AMD64 / Arm64   WheapPersistPageForMemoryError
 *                                  AMD64 / Arm64   WheapPredictiveFailureAnalysis
 * RADARM       10.0.26100.1        Arm64           RadArmSeaCreateErrorRecord
 *                                  Arm64           RadArmSeaRecover
 */
namespace DecodeWheaRecord.Errors.UEFI {
    internal sealed class WHEA_MEMORY_ERROR_SECTION : WheaRecord {
        private uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        // Size up to and including the ErrorType field
        internal const uint MinStructSize = 73;

        // Size up to and including the ModuleHandle field
        private const uint ExtendedStructSize = 80;

        private WHEA_MEMORY_ERROR_SECTION_VALIDBITS _ValidBits;

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnumFlagsAsString(_ValidBits);

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

        // Only with extended structure
        [JsonProperty(Order = 8)]
        public byte BankAddress => (byte)Bank;

        // Only with extended structure
        [JsonProperty(Order = 9)]
        public byte BankGroup => (byte)(Bank >> 8);

        [JsonProperty(Order = 10)]
        public ushort Device;

        [JsonProperty(Order = 11)]
        public ushort Row;

        // Only with extended structure
        [JsonProperty(Order = 11)]
        public uint ExtendedRow => ((Extended & (uint)0x3) << 16) + Row;

        [JsonProperty(Order = 12)]
        public ushort Column;

        [JsonProperty(Order = 13)]
        public ushort BitPosition;

        [JsonProperty(Order = 14)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong RequesterId;

        [JsonProperty(Order = 15)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ResponderId;

        [JsonProperty(Order = 16)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong TargetId;

        // Switched to an enumeration
        private WHEA_MEMORY_ERROR_TYPE _ErrorType;

        [JsonProperty(Order = 17)]
        public string ErrorType => GetEnumFlagsAsString(_ErrorType);

        /*
         * Extended fields
         */

        /*
         * This field contains bits which are either interpreted as stand-alone
         * new fields or are added as high-order bits to existing fields. There
         * is no corresponding ShouldSerialize method as multiple new flags are
         * present in ValidBits to support this field. Each supporting property
         * instead has its own ShouldSerialize method.
         */
        private byte Extended;

        [JsonProperty(Order = 18)]
        public uint ChipIdentification => (uint)(Extended >> 5);

        [JsonProperty(Order = 19)]
        public ushort RankNumber;

        [JsonProperty(Order = 20)]
        public ushort CardHandle;

        [JsonProperty(Order = 21)]
        public ushort ModuleHandle;

        public WHEA_MEMORY_ERROR_SECTION(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_MEMORY_ERROR_SECTION), structOffset, MinStructSize, bytesRemaining) {
            WheaMemoryErrorSection(recordAddr, structOffset, bytesRemaining);
        }

        public WHEA_MEMORY_ERROR_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(typeof(WHEA_MEMORY_ERROR_SECTION), sectionDsc, MinStructSize, bytesRemaining) {
            WheaMemoryErrorSection(recordAddr, sectionDsc.SectionOffset, sectionDsc.SectionLength);
        }

        private void WheaMemoryErrorSection(IntPtr recordAddr, uint structOffset, uint bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _StructSize = bytesRemaining >= ExtendedStructSize ? ExtendedStructSize : MinStructSize;
            _ValidBits = (WHEA_MEMORY_ERROR_SECTION_VALIDBITS)Marshal.ReadInt64(structAddr);

            if (HasExtendedFields()) {
                if (ShouldSerializeRow() && ShouldSerializeExtendedRow()) {
                    throw new InvalidDataException($"The {nameof(Row)} and {nameof(ExtendedRow)} flags in {nameof(ValidBits)} cannot both be set.");
                }

                if (ShouldSerializeBank()) {
                    if (ShouldSerializeBankGroup() || ShouldSerializeBankAddress()) {
                        var msg = $"The {nameof(Bank)} flag cannot be set with the {nameof(BankGroup)} or {nameof(BankAddress)} flags in {nameof(ValidBits)}.";
                        throw new InvalidDataException(msg);
                    }
                } else {
                    if (ShouldSerializeBankAddress() != ShouldSerializeBankGroup()) {
                        WarnOutput($"Only one of the {nameof(BankGroup)} and {nameof(BankAddress)} flags in {nameof(ValidBits)} is set.", StructType.Name);
                    }
                }
            }

            ErrorStatus = PtrToStructure<WHEA_ERROR_STATUS>(structAddr + 8);
            PhysicalAddress = (ulong)Marshal.ReadInt64(structAddr, 16);
            PhysicalAddressMask = (ulong)Marshal.ReadInt64(structAddr, 24);
            Node = (ushort)Marshal.ReadInt16(structAddr, 32);
            Card = (ushort)Marshal.ReadInt16(structAddr, 34);
            Module = (ushort)Marshal.ReadInt16(structAddr, 36);
            Bank = (ushort)Marshal.ReadInt16(structAddr, 38);
            Device = (ushort)Marshal.ReadInt16(structAddr, 40);
            Row = (ushort)Marshal.ReadInt16(structAddr, 42);
            Column = (ushort)Marshal.ReadInt16(structAddr, 44);
            BitPosition = (ushort)Marshal.ReadInt16(structAddr, 46);
            RequesterId = (ulong)Marshal.ReadInt64(structAddr, 48);
            ResponderId = (ulong)Marshal.ReadInt64(structAddr, 56);
            TargetId = (ulong)Marshal.ReadInt64(structAddr, 64);
            _ErrorType = (WHEA_MEMORY_ERROR_TYPE)Marshal.ReadByte(structAddr, 72);

            if (HasExtendedFields()) {
                Extended = Marshal.ReadByte(structAddr, 73);
                RankNumber = (ushort)Marshal.ReadInt16(structAddr, 74);
                CardHandle = (ushort)Marshal.ReadInt16(structAddr, 76);
                ModuleHandle = (ushort)Marshal.ReadInt16(structAddr, 78);
            }

            FinalizeRecord(recordAddr, _StructSize);
        }

        private bool HasExtendedFields() => _StructSize >= ExtendedStructSize;

        [UsedImplicitly]
        public bool ShouldSerializeErrorStatus() => (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ErrorStatus) != 0;

        [UsedImplicitly]
        public bool ShouldSerializePhysicalAddress() => (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.PhysicalAddress) != 0;

        [UsedImplicitly]
        public bool ShouldSerializePhysicalAddressMask() => (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.PhysicalAddressMask) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeNode() => (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Node) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeCard() => (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Card) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeModule() => (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Module) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeBank() => (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Bank) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeBankAddress() => HasExtendedFields() && (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.BankAddress) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeBankGroup() => HasExtendedFields() && (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.BankGroup) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeDevice() => (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Device) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeRow() => (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Row) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeExtendedRow() => HasExtendedFields() && (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ExtendedRow) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeColumn() => (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Column) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeBitPosition() => (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.BitPosition) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeRequesterId() => (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.RequesterId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeResponderId() => (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ResponderId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeTargetId() => (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.TargetId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeErrorType() => (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ErrorType) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeChipIdentification() => HasExtendedFields() && (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ChipIdentification) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeRankNumber() => HasExtendedFields() && (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.RankNumber) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeCardHandle() => HasExtendedFields() && (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.CardHandle) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeModuleHandle() => HasExtendedFields() && (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ModuleHandle) != 0;
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

    // From WHEA_MEMERRTYPE preprocessor definitions
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
