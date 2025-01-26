#pragma warning disable CS0649 // Field is never assigned to

// ReSharper disable ClassNeverInstantiated.Global
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
 * ntoskrnl     10.0.26100.2605     AMD64 / ARM64   HalpGenericErrorSourceRecovery
 * scmbus       10.0.26100.2605     AMD64           ScmBusArsReportWheaBadRanges
 */
namespace DecodeWheaRecord.Errors.Microsoft {
    internal sealed class WHEA_PMEM_ERROR_SECTION : WheaRecord {
        private uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        // Size up to and including the PageRangeCount field
        private const uint MinStructSize = 88;

        // Size of the LocationInfo array
        private const int WHEA_PMEM_ERROR_SECTION_LOCATION_INFO_SIZE = 64;

        // Maximum count of pages in the PageRange array
        private const int WHEA_PMEM_ERROR_SECTION_MAX_PAGES = 50;

        private WHEA_PMEM_ERROR_SECTION_VALIDBITS _ValidBits;

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnumFlagsAsString(_ValidBits);

        [JsonProperty(Order = 2)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] LocationInfo = new byte[WHEA_PMEM_ERROR_SECTION_LOCATION_INFO_SIZE]; // TODO: Deserialize

        [JsonProperty(Order = 3)]
        public WHEA_ERROR_STATUS ErrorStatus;

        [JsonProperty(Order = 4)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint NFITHandle;

        [JsonProperty(Order = 5)]
        public uint PageRangeCount;

        [JsonProperty(Order = 6)]
        public WHEA_PMEM_PAGE_RANGE[] PageRange;

        public WHEA_PMEM_ERROR_SECTION(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_PMEM_ERROR_SECTION), structOffset, MinStructSize, bytesRemaining) {
            WheaPmemErrorSection(recordAddr, structOffset, bytesRemaining);
        }

        public WHEA_PMEM_ERROR_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(typeof(WHEA_PMEM_ERROR_SECTION), sectionDsc, MinStructSize, bytesRemaining) {
            WheaPmemErrorSection(recordAddr, sectionDsc.SectionOffset, sectionDsc.SectionLength);
        }

        private void WheaPmemErrorSection(IntPtr recordAddr, uint structOffset, uint bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _ValidBits = (WHEA_PMEM_ERROR_SECTION_VALIDBITS)Marshal.ReadInt64(structAddr);
            Marshal.Copy(structAddr + 8, LocationInfo, 0, WHEA_PMEM_ERROR_SECTION_LOCATION_INFO_SIZE);
            ErrorStatus = PtrToStructure<WHEA_ERROR_STATUS>(structAddr + 72);
            NFITHandle = (uint)Marshal.ReadInt32(structAddr, 80);
            PageRangeCount = (uint)Marshal.ReadInt32(structAddr, 84);
            var offset = MinStructSize;

            if (PageRangeCount > WHEA_PMEM_ERROR_SECTION_MAX_PAGES) {
                var checkCalc = $"{PageRangeCount} > {WHEA_PMEM_ERROR_SECTION_MAX_PAGES}";
                throw new InvalidDataException($"{nameof(PageRangeCount)} is greater than maximum allowed: {checkCalc}");
            }

            if (PageRangeCount > 0) {
                var elementSize = (uint)Marshal.SizeOf<WHEA_PMEM_PAGE_RANGE>();

                if (MinStructSize + PageRangeCount * elementSize > bytesRemaining) {
                    var checkCalc = $"{MinStructSize} + {PageRangeCount} * {elementSize} > {bytesRemaining}";
                    throw new InvalidDataException($"Expected size is greater than bytes remaining: {checkCalc}");
                }

                PageRange = new WHEA_PMEM_PAGE_RANGE[PageRangeCount];
                for (var i = 0; i < PageRangeCount; i++) {
                    PageRange[i] = PtrToStructure<WHEA_PMEM_PAGE_RANGE>(structAddr + (int)offset);
                    offset += elementSize;
                }
            } else {
                WarnOutput($"{nameof(PageRangeCount)} Expected at least one page range entry.", StructType.Name);
            }

            _StructSize = offset;
            FinalizeRecord(recordAddr, _StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeLocationInfo() => (_ValidBits & WHEA_PMEM_ERROR_SECTION_VALIDBITS.LocationInfo) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeErrorStatus() => (_ValidBits & WHEA_PMEM_ERROR_SECTION_VALIDBITS.ErrorStatus) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeNFITHandle() => (_ValidBits & WHEA_PMEM_ERROR_SECTION_VALIDBITS.NFITHandle) != 0;
    }

    // Structure size: 24 bytes
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
