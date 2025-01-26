// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Descriptors;
using DecodeWheaRecord.Internal;

using Newtonsoft.Json;

/*
 * Module       Version             Arch(s)         Function(s)
 * ntoskrnl     10.0.26100.2605     Arm64           HalpWheaSeiCreateErrorRecord
 */
namespace DecodeWheaRecord.Errors.Microsoft {
    internal sealed class WHEA_SEI_SECTION : WheaRecord {
        private const uint StructSize = 12;
        public override uint GetNativeSize() => StructSize;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Esr;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Far;

        public WHEA_SEI_SECTION(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_SEI_SECTION), structOffset, StructSize, bytesRemaining) {
            WheaSeiSection(recordAddr, structOffset);
        }

        public WHEA_SEI_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(typeof(WHEA_SEI_SECTION), sectionDsc, StructSize, bytesRemaining) {
            WheaSeiSection(recordAddr, sectionDsc.SectionOffset);
        }

        private void WheaSeiSection(IntPtr recordAddr, uint structOffset) {
            var structAddr = recordAddr + (int)structOffset;

            Esr = (uint)Marshal.ReadInt32(structAddr);
            Far = (ulong)Marshal.ReadInt64(structAddr, 4);

            FinalizeRecord(recordAddr, StructSize);
        }
    }
}
