#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

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
    internal sealed class WHEA_PCIE_CORRECTABLE_ERROR_SECTION : WheaRecord {
        internal const ushort WHEA_PCIE_CORRECTABLE_ERROR_SECTION_COUNT_SIZE = 32;

        private int _NativeSize;
        internal override int GetNativeSize() => _NativeSize;

        [JsonProperty(Order = 1)]
        public WHEA_PCIE_CORRECTABLE_ERROR_SECTION_HEADER Header;

        [JsonProperty(Order = 2)]
        public WHEA_PCIE_CORRECTABLE_ERROR_DEVICES[] Devices;

        public WHEA_PCIE_CORRECTABLE_ERROR_SECTION(IntPtr recordAddr, WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc) {
            DebugOutputPre(typeof(WHEA_PCIE_CORRECTABLE_ERROR_SECTION), sectionDsc);
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            Header = Marshal.PtrToStructure<WHEA_PCIE_CORRECTABLE_ERROR_SECTION_HEADER>(sectionAddr);
            var offset = Marshal.SizeOf<WHEA_PCIE_CORRECTABLE_ERROR_SECTION_HEADER>();

            var elementSize = Marshal.SizeOf<WHEA_PCIE_CORRECTABLE_ERROR_DEVICES>();
            Devices = new WHEA_PCIE_CORRECTABLE_ERROR_DEVICES[Header.Count];
            for (var i = 0; i < Header.Count; i++) {
                Devices[i] = Marshal.PtrToStructure<WHEA_PCIE_CORRECTABLE_ERROR_DEVICES>(sectionAddr + offset + (i * elementSize));
            }

            offset += Header.Count * elementSize;

            _NativeSize = offset;
            DebugOutputPost(typeof(WHEA_PCIE_CORRECTABLE_ERROR_SECTION), sectionDsc, _NativeSize);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCIE_CORRECTABLE_ERROR_SECTION_HEADER {
        // TODO: Description & validation
        public ushort Version;

        // TODO: Description & validation
        public ushort Count;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCIE_CORRECTABLE_ERROR_DEVICES {
        private WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS _ValidBits;

        // TODO: Add remaining ShouldSerialize methods
        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        [JsonProperty(Order = 2)]
        public WHEA_PCIE_ADDRESS Address;

        [JsonProperty(Order = 3)]
        public uint Mask;

        [JsonProperty(Order = 4)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = WHEA_PCIE_CORRECTABLE_ERROR_SECTION.WHEA_PCIE_CORRECTABLE_ERROR_SECTION_COUNT_SIZE)]
        public uint[] CorrectableErrorCount;

        [UsedImplicitly]
        public bool ShouldSerializeMask() => (_ValidBits & WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS.Mask) ==
                                             WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS.Mask;

        [UsedImplicitly]
        public bool ShouldSerializeCorrectableErrorCount() => (_ValidBits & WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS.CorrectableErrorCount) ==
                                                              WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS.CorrectableErrorCount;
    }

    // @formatter:int_align_fields true

    [Flags]
    internal enum WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS : ulong {
        Segment               = 0x1,
        Bus                   = 0x2,
        Device                = 0x4,
        Function              = 0x8,
        Mask                  = 0x10,
        CorrectableErrorCount = 0x20
    }

    // @formatter:int_align_fields false
}
