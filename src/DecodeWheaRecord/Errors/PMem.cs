#pragma warning disable CS0649 // Field is never assigned to

// ReSharper disable InconsistentNaming
// ReSharper disable MemberCanBePrivate.Global

using System;
using System.IO;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors {
    /*
     * Cannot be directly marshalled as a structure due to the usage of a
     * variable length array, resulting in a non-static structure size.
     */
    internal sealed class WHEA_PMEM_ERROR_SECTION : WheaErrorRecord {
        // Size up to and including the PageRangeCount field
        private const uint BaseStructSize = 88;

        private uint _NativeSize;
        public override uint GetNativeSize() => _NativeSize;

        internal const int WHEA_PMEM_ERROR_SECTION_LOCATION_INFO_SIZE = 64;
        internal const int WHEA_PMEM_ERROR_SECTION_MAX_PAGES = 50;

        private WHEA_PMEM_ERROR_SECTION_VALIDBITS _ValidBits;

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        [JsonProperty(Order = 2)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] LocationInfo; // TODO: Deserialize

        [JsonProperty(Order = 3)]
        public WHEA_ERROR_STATUS ErrorStatus;

        [JsonProperty(Order = 4)]
        public uint NFITHandle; // NVDIMM Firmware Interface Table

        [JsonProperty(Order = 5)]
        public uint PageRangeCount;

        [JsonProperty(Order = 6)]
        public WHEA_PMEM_PAGE_RANGE[] PageRange;

        private void WheaPmemErrorSection(IntPtr recordAddr, uint sectionOffset) {
            var sectionAddr = recordAddr + (int)sectionOffset;

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
                var msg = $"{nameof(PageRangeCount)} is greater than the maximum allowed of {WHEA_PMEM_ERROR_SECTION_MAX_PAGES}: {PageRangeCount}";
                throw new InvalidDataException(msg);
            }

            if (PageRangeCount > 0) {
                var elementSize = Marshal.SizeOf<WHEA_PMEM_PAGE_RANGE>();
                PageRange = new WHEA_PMEM_PAGE_RANGE[PageRangeCount];
                for (var i = 0; i < PageRangeCount; i++) {
                    PageRange[i] = Marshal.PtrToStructure<WHEA_PMEM_PAGE_RANGE>(sectionAddr + offset + i * elementSize);
                }
                offset += (int)PageRangeCount * elementSize;
            }

            _NativeSize = (uint)offset;
            FinalizeRecord(recordAddr, _NativeSize);
        }

        public WHEA_PMEM_ERROR_SECTION(IntPtr recordAddr, uint sectionOffset, uint bytesRemaining) :
            base(typeof(WHEA_PMEM_ERROR_SECTION), sectionOffset, BaseStructSize, bytesRemaining) {
            WheaPmemErrorSection(recordAddr, sectionOffset);
        }

        public WHEA_PMEM_ERROR_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(WHEA_PMEM_ERROR_SECTION), BaseStructSize, bytesRemaining) {
            WheaPmemErrorSection(recordAddr, sectionDsc.SectionOffset);
        }

        [UsedImplicitly]
        public bool ShouldSerializeLocationInfo() =>
            (_ValidBits & WHEA_PMEM_ERROR_SECTION_VALIDBITS.LocationInfo) ==
            WHEA_PMEM_ERROR_SECTION_VALIDBITS.LocationInfo;

        [UsedImplicitly]
        public bool ShouldSerializeErrorStatus() =>
            (_ValidBits & WHEA_PMEM_ERROR_SECTION_VALIDBITS.ErrorStatus) ==
            WHEA_PMEM_ERROR_SECTION_VALIDBITS.ErrorStatus;

        [UsedImplicitly]
        public bool ShouldSerializeNFITHandle() =>
            (_ValidBits & WHEA_PMEM_ERROR_SECTION_VALIDBITS.NFITHandle) ==
            WHEA_PMEM_ERROR_SECTION_VALIDBITS.NFITHandle;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PMEM_PAGE_RANGE {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong StartingPfn;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong PageCount;

        [JsonConverter(typeof(HexStringJsonConverter))]
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
