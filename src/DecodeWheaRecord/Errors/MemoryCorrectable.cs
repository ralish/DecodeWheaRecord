#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Global
// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming
// ReSharper disable MemberCanBePrivate.Global

using System;
using System.Runtime.InteropServices;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.NativeMethods;
using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors {
    internal sealed class WHEA_MEMORY_CORRECTABLE_ERROR_SECTION : WheaRecord {
        private int _NativeSize;
        internal override int GetNativeSize() => _NativeSize;

        [JsonProperty(Order = 1)]
        public WHEA_MEMORY_CORRECTABLE_ERROR_HEADER Header;

        [JsonProperty(Order = 2)]
        public WHEA_MEMORY_CORRECTABLE_ERROR_DATA[] Data;

        public WHEA_MEMORY_CORRECTABLE_ERROR_SECTION(IntPtr recordAddr, WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc) {
            DebugOutputPre(typeof(WHEA_MEMORY_CORRECTABLE_ERROR_SECTION), sectionDsc);
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            Header = Marshal.PtrToStructure<WHEA_MEMORY_CORRECTABLE_ERROR_HEADER>(sectionAddr);
            var offset = Marshal.SizeOf<WHEA_MEMORY_CORRECTABLE_ERROR_HEADER>();

            if (Header.Count != 0) {
                var elementSize = Marshal.SizeOf<WHEA_MEMORY_CORRECTABLE_ERROR_DATA>();
                Data = new WHEA_MEMORY_CORRECTABLE_ERROR_DATA[Header.Count];
                for (var i = 0; i < Header.Count; i++) {
                    Data[i] = Marshal.PtrToStructure<WHEA_MEMORY_CORRECTABLE_ERROR_DATA>(sectionAddr + offset + (i * elementSize));
                }

                offset += Header.Count * elementSize;
            }

            _NativeSize = offset;
            DebugOutputPost(typeof(WHEA_MEMORY_CORRECTABLE_ERROR_SECTION), sectionDsc, _NativeSize);
        }
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
        public bool ShouldSerializeChannelId() => (_ValidBits & WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.ChannelId) ==
                                                  WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.ChannelId;

        [UsedImplicitly]
        public bool ShouldSerializeCorrectableErrorCount() => (_ValidBits & WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.CorrectableErrorCount) ==
                                                              WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.CorrectableErrorCount;

        [UsedImplicitly]
        public bool ShouldSerializeDimmSlot() => (_ValidBits & WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.DimmSlot) ==
                                                 WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.DimmSlot;

        [UsedImplicitly]
        public bool ShouldSerializeSocketId() => (_ValidBits & WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.SocketId) ==
                                                 WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.SocketId;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_MEMORY_CORRECTABLE_ERROR_HEADER {
        // TODO: Description & validation
        public ushort Version;

        // TODO: Description & validation
        public ushort Count;
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
