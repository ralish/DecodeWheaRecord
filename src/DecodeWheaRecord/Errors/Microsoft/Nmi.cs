// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Descriptors;
using DecodeWheaRecord.Internal;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

/*
 * Module       Version             Arch(s)         Function(s)
 * ntoskrnl     10.0.26100.2605     AMD64 / Arm64   HalBugCheckSystem
 *                                  AMD64 / Arm64   HalpCreateNMIErrorRecord
 */
namespace DecodeWheaRecord.Errors.Microsoft {
    internal sealed class WHEA_NMI_ERROR_SECTION : WheaRecord {
        private const uint StructSize = 12;
        public override uint GetNativeSize() => StructSize;

        /*
         * On x86 and AMD64 only the first byte is set and the data it contains
         * is close to useless. Other architectures may return more useful data
         * in both quantity and quality.
         */
        [JsonProperty(Order = 1)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] Data = new byte[8];

        private WHEA_NMI_ERROR_SECTION_FLAGS _Flags;

        [JsonProperty(Order = 2)]
        public string Flags => GetEnumFlagsAsString(_Flags);

        public WHEA_NMI_ERROR_SECTION(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_NMI_ERROR_SECTION), structOffset, StructSize, bytesRemaining) {
            WheaNmiErrorSection(recordAddr, structOffset);
        }

        public WHEA_NMI_ERROR_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(typeof(WHEA_NMI_ERROR_SECTION), sectionDsc, StructSize, bytesRemaining) {
            WheaNmiErrorSection(recordAddr, sectionDsc.SectionOffset);
        }

        private void WheaNmiErrorSection(IntPtr recordAddr, uint structOffset) {
            var structAddr = recordAddr + (int)structOffset;

            Marshal.Copy(structAddr, Data, 0, 8);
            _Flags = (WHEA_NMI_ERROR_SECTION_FLAGS)Marshal.ReadInt32(structAddr, 8);

            FinalizeRecord(recordAddr, StructSize);
        }
    }

    // @formatter:int_align_fields true

    [Flags]
    internal enum WHEA_NMI_ERROR_SECTION_FLAGS : uint {
        HypervisorError = 0x1
    }

    // @formatter:int_align_fields false
}
