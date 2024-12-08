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

namespace DecodeWheaRecord.Errors {
    /*
     * Cannot be directly marshalled as a structure due to the usage of a
     * variable length array, resulting in a non-static structure size.
     */
    internal sealed class WHEA_MEMORY_CORRECTABLE_ERROR_SECTION : WheaErrorRecord {
        // Header field must be present
        private static uint BaseStructSize = (uint)Marshal.SizeOf<WHEA_MEMORY_CORRECTABLE_ERROR_HEADER>();

        private uint _NativeSize;
        public override uint GetNativeSize() => _NativeSize;

        [JsonProperty(Order = 1)]
        public WHEA_MEMORY_CORRECTABLE_ERROR_HEADER Header;

        [JsonProperty(Order = 2)]
        public WHEA_MEMORY_CORRECTABLE_ERROR_DATA[] Data;

        public WHEA_MEMORY_CORRECTABLE_ERROR_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(WHEA_MEMORY_CORRECTABLE_ERROR_SECTION), BaseStructSize, bytesRemaining) {
            var logCat = SectionType.Name;
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            Header = Marshal.PtrToStructure<WHEA_MEMORY_CORRECTABLE_ERROR_HEADER>(sectionAddr);
            var offset = Marshal.SizeOf<WHEA_MEMORY_CORRECTABLE_ERROR_HEADER>();

            if (Header.Count != 0) {
                var elementSize = Marshal.SizeOf<WHEA_MEMORY_CORRECTABLE_ERROR_DATA>();
                var arraySize = Header.Count * elementSize;

                if (BaseStructSize + arraySize != sectionDsc.SectionLength) {
                    var errMsg = $"Length does not equal expected length: {BaseStructSize} + {arraySize} != {sectionDsc.SectionLength}";
                    throw new InvalidDataException(errMsg);
                }

                Data = new WHEA_MEMORY_CORRECTABLE_ERROR_DATA[Header.Count];
                for (var i = 0; i < Header.Count; i++) {
                    Data[i] = Marshal.PtrToStructure<WHEA_MEMORY_CORRECTABLE_ERROR_DATA>(sectionAddr + offset + i * elementSize);
                }
                offset += Header.Count * elementSize;
            } else {
                WarnOutput("Expected at least one structure (count in header is zero).", logCat);
            }

            _NativeSize = (uint)offset;
            FinalizeRecord(recordAddr, _NativeSize);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_MEMORY_CORRECTABLE_ERROR_HEADER {
        public ushort Version; // TODO: Description & validation
        public ushort Count;   // TODO: Description & validation
    }

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
        public bool ShouldSerializeSocketId() =>
            (_ValidBits & WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.SocketId) ==
            WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.SocketId;

        [UsedImplicitly]
        public bool ShouldSerializeChannelId() =>
            (_ValidBits & WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.ChannelId) ==
            WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.ChannelId;

        [UsedImplicitly]
        public bool ShouldSerializeDimmSlot() =>
            (_ValidBits & WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.DimmSlot) ==
            WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.DimmSlot;

        [UsedImplicitly]
        public bool ShouldSerializeCorrectableErrorCount() =>
            (_ValidBits & WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.CorrectableErrorCount) ==
            WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.CorrectableErrorCount;
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
