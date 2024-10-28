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
    internal sealed class WHEA_PMEM_ERROR_SECTION : WheaRecord {
        internal const int WHEA_PMEM_ERROR_SECTION_LOCATION_INFO_SIZE = 64;
        internal const int WHEA_PMEM_ERROR_SECTION_MAX_PAGES = 50;

        private int _NativeSize;
        internal override int GetNativeSize() => _NativeSize;

        private WHEA_PMEM_ERROR_SECTION_VALIDBITS _ValidBits;

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        [JsonProperty(Order = 2)]
        public byte[] LocationInfo; // TODO

        [JsonProperty(Order = 3)]
        public WHEA_ERROR_STATUS ErrorStatus;

        [JsonProperty(Order = 4)]
        public uint NFITHandle;

        [JsonProperty(Order = 5)]
        public uint PageRangeCount;

        [JsonProperty(Order = 6)]
        public WHEA_PMEM_PAGE_RANGE[] PageRange;

        private void WheaPmemErrorSection(IntPtr sectionAddr) {
            _ValidBits = (WHEA_PMEM_ERROR_SECTION_VALIDBITS)Marshal.ReadInt64(sectionAddr);
            var offset = 8;

            LocationInfo = new byte[WHEA_PMEM_ERROR_SECTION_LOCATION_INFO_SIZE];
            Marshal.Copy(sectionAddr + offset, LocationInfo, 0, WHEA_PMEM_ERROR_SECTION_LOCATION_INFO_SIZE);
            offset += WHEA_PMEM_ERROR_SECTION_LOCATION_INFO_SIZE;

            ErrorStatus = Marshal.PtrToStructure<WHEA_ERROR_STATUS>(sectionAddr + offset);
            offset += Marshal.SizeOf<WHEA_ERROR_STATUS>();

            NFITHandle = (uint)Marshal.ReadInt32(sectionAddr, offset);
            PageRangeCount = (uint)Marshal.ReadInt32(sectionAddr, offset + 4);
            offset += 8;

            if (PageRangeCount > WHEA_PMEM_ERROR_SECTION_MAX_PAGES) {
                var msg =
                    $"[{nameof(WHEA_PMEM_ERROR_SECTION)}] {nameof(PageRangeCount)} is greater than the maximum allowed: {WHEA_PMEM_ERROR_SECTION_MAX_PAGES}";
            } else if (PageRangeCount > 0) {
                var elementSize = Marshal.SizeOf<WHEA_PMEM_PAGE_RANGE>();
                PageRange = new WHEA_PMEM_PAGE_RANGE[PageRangeCount];
                for (var i = 0; i < PageRangeCount; i++) {
                    PageRange[i] = Marshal.PtrToStructure<WHEA_PMEM_PAGE_RANGE>(sectionAddr + offset + (i * elementSize));
                }

                offset += (int)PageRangeCount * elementSize;
            }

            _NativeSize = offset;
        }

        public WHEA_PMEM_ERROR_SECTION(IntPtr sectionAddr) => WheaPmemErrorSection(sectionAddr);

        public WHEA_PMEM_ERROR_SECTION(IntPtr recordAddr, WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc) {
            DebugOutputPre(typeof(WHEA_PMEM_ERROR_SECTION), sectionDsc);

            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;
            WheaPmemErrorSection(sectionAddr);

            DebugOutputPost(typeof(WHEA_PMEM_ERROR_SECTION), sectionDsc, _NativeSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeLocationInfo() => (_ValidBits & WHEA_PMEM_ERROR_SECTION_VALIDBITS.LocationInfo) ==
                                                     WHEA_PMEM_ERROR_SECTION_VALIDBITS.LocationInfo;

        [UsedImplicitly]
        public bool ShouldSerializeErrorStatus() => (_ValidBits & WHEA_PMEM_ERROR_SECTION_VALIDBITS.ErrorStatus) ==
                                                    WHEA_PMEM_ERROR_SECTION_VALIDBITS.ErrorStatus;

        [UsedImplicitly]
        public bool ShouldSerializeNFITHandle() => (_ValidBits & WHEA_PMEM_ERROR_SECTION_VALIDBITS.NFITHandle) ==
                                                   WHEA_PMEM_ERROR_SECTION_VALIDBITS.NFITHandle;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PMEM_PAGE_RANGE {
        public ulong StartingPfn;
        public ulong PageCount;
        public ulong MarkedBadBitmap;
    }

    // @formatter:int_align_fields true

    [Flags]
    internal enum WHEA_PMEM_ERROR_SECTION_VALIDBITS : ulong {
        ErrorStatus  = 0x1,
        NFITHandle   = 0x2,
        LocationInfo = 0x4
    }

    // @formatter:int_align_fields false
}
