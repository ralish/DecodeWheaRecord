// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Descriptors;
using DecodeWheaRecord.Internal;

using Newtonsoft.Json;

/*
 * Module       Version             Arch(s)         Function(s)
 * ntoskrnl     10.0.26100.2605     Arm64           HalpWheaSeaCreateErrorRecord
 * RADARM       10.0.26100.1        Arm64           RadArmSeaCreateErrorRecord
 *                                  Arm64           RadArmSeaRecover
 */
namespace DecodeWheaRecord.Errors.Microsoft {
    internal sealed class WHEA_SEA_SECTION : WheaRecord {
        private const uint StructSize = 21;
        public override uint GetNativeSize() => StructSize;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Esr;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Far;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Par;

        public bool WasKernel;

        public WHEA_SEA_SECTION(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_SEA_SECTION), structOffset, StructSize, bytesRemaining) {
            WheaSeaSection(recordAddr, structOffset);
        }

        public WHEA_SEA_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(typeof(WHEA_SEA_SECTION), sectionDsc, StructSize, bytesRemaining) {
            WheaSeaSection(recordAddr, sectionDsc.SectionOffset);
        }

        private void WheaSeaSection(IntPtr recordAddr, uint structOffset) {
            var structAddr = recordAddr + (int)structOffset;

            Esr = (uint)Marshal.ReadInt32(structAddr);
            Far = (ulong)Marshal.ReadInt64(structAddr, 4);
            Par = (ulong)Marshal.ReadInt64(structAddr, 12);
            WasKernel = Marshal.ReadByte(structAddr, 20) != 0;

            FinalizeRecord(recordAddr, StructSize);
        }
    }
}
