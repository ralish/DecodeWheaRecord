#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Runtime.InteropServices;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

/*
 * Vanilla Windows doesn't appear to have any functionality to report this
 * error. The only implementation I've found is in the Azure PSHED plugin.
 */
namespace DecodeWheaRecord.Errors.Microsoft {
    internal sealed class WHEA_MEMORY_CORRECTABLE_ERROR_SECTION : WheaRecord {
        private uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        // At least the header
        private const uint MinStructSize = WHEA_MEMORY_CORRECTABLE_ERROR_HEADER.StructSize;

        [JsonProperty(Order = 1)]
        public WHEA_MEMORY_CORRECTABLE_ERROR_HEADER Header;

        [JsonProperty(Order = 2)]
        public WHEA_MEMORY_CORRECTABLE_ERROR_DATA[] Data;

        public WHEA_MEMORY_CORRECTABLE_ERROR_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(WHEA_MEMORY_CORRECTABLE_ERROR_SECTION), MinStructSize, bytesRemaining) {
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            Header = new WHEA_MEMORY_CORRECTABLE_ERROR_HEADER(recordAddr, sectionDsc.SectionOffset, bytesRemaining);
            var offset = MinStructSize;

            if (Header.Count != 0) {
                var elementSize = (uint)Marshal.SizeOf<WHEA_MEMORY_CORRECTABLE_ERROR_DATA>();

                if (MinStructSize + Header.Count * elementSize > sectionDsc.SectionLength) {
                    var msg = "Calculated size is greater than in section descriptor: " +
                              $"{MinStructSize} + {Header.Count} * {elementSize} > {sectionDsc.SectionLength}";
                    throw new InvalidDataException(msg);
                }

                Data = new WHEA_MEMORY_CORRECTABLE_ERROR_DATA[Header.Count];

                for (var i = 0; i < Header.Count; i++) {
                    Data[i] = Marshal.PtrToStructure<WHEA_MEMORY_CORRECTABLE_ERROR_DATA>(sectionAddr + (int)offset);
                    offset += elementSize;
                }
            }

            _StructSize = offset;
            FinalizeRecord(recordAddr, _StructSize);
        }
    }

    internal sealed class WHEA_MEMORY_CORRECTABLE_ERROR_HEADER : WheaRecord {
        internal const uint StructSize = 4;
        public override uint GetNativeSize() => StructSize;

        /*
         * Verified from the Azure PSHED plugin implementation
         * Function: PshedPiReportMemoryCorrectableErrorSummary
         */
        private const ushort ExpectedVersion = 1;

        [JsonProperty(Order = 1)]
        public ushort Version;

        [JsonProperty(Order = 2)]
        public ushort Count;

        public WHEA_MEMORY_CORRECTABLE_ERROR_HEADER(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_MEMORY_CORRECTABLE_ERROR_HEADER), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            Version = (ushort)Marshal.ReadInt16(structAddr);

            if (Version != ExpectedVersion) {
                var msg = $"Expected {nameof(Version)} to be {ExpectedVersion} but found: {Version}";
                throw new InvalidDataException(msg);
            }

            Count = (ushort)Marshal.ReadInt16(structAddr, 2);

            if (Count == 0) {
                var msg = $"{nameof(Count)} Expected at least one correctable memory error entry.";
                WarnOutput(msg, SectionType.Name);
            }

            FinalizeRecord(recordAddr, StructSize);
        }
    }

    // Structure size: 24 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_MEMORY_CORRECTABLE_ERROR_DATA {
        private WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS _ValidBits;

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        [JsonProperty(Order = 2)]
        public uint SocketId;

        [JsonProperty(Order = 3)]
        public uint ChannelId;

        [JsonProperty(Order = 4)]
        public uint DimmSlot;

        [JsonProperty(Order = 5)]
        public uint CorrectableErrorCount;

        [UsedImplicitly]
        public bool ShouldSerializeSocketId() => (_ValidBits & WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.SocketId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeChannelId() => (_ValidBits & WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.ChannelId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeDimmSlot() => (_ValidBits & WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.DimmSlot) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeCorrectableErrorCount() => (_ValidBits & WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.CorrectableErrorCount) != 0;
    }

    // @formatter:int_align_fields true

    [Flags]
    internal enum WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS : ulong {
        SocketId              = 0x1,
        ChannelId             = 0x2,
        DimmSlot              = 0x4,
        CorrectableErrorCount = 0x8
    }

    // @formatter:int_align_fields false
}
