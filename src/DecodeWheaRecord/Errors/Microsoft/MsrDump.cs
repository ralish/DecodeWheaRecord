// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Descriptors;
using DecodeWheaRecord.Internal;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

/*
 * Module       Version             Arch(s)         Function(s)
 * IPMIDrv      10.0.26100.2454     AMD64 / Arm64   BmcWheaCreateErrorRecord
 *
 * On Windows Server 2025 the reporting of this error is performed by the inbox
 * IPMI driver (IPMIDrv.sys). Dumping out of the MSRs is handled by a bugcheck
 * callback which writes them to the SEL. When the system has rebooted they're
 * read out of the SEL and the error submitted to WHEA.
 */
namespace DecodeWheaRecord.Errors.Microsoft {
    internal sealed class WHEA_MSR_DUMP_SECTION : WheaRecord {
        public override uint GetNativeSize() => MsrDumpLength;

        // Size up to and including the MsrDumpLength field
        private const uint MinStructSize = 5;

        [JsonProperty(Order = 1)]
        public byte MsrDumpBuffer; // TODO: What does this indicate?

        [JsonProperty(Order = 2)]
        public uint MsrDumpLength;

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] MsrDumpData; // TODO: Deserialize

        public WHEA_MSR_DUMP_SECTION(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_MSR_DUMP_SECTION), structOffset, MinStructSize, bytesRemaining) {
            WheaMsrDumpSection(recordAddr, structOffset, bytesRemaining);
        }

        public WHEA_MSR_DUMP_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(typeof(WHEA_MSR_DUMP_SECTION), sectionDsc, MinStructSize, bytesRemaining) {
            WheaMsrDumpSection(recordAddr, sectionDsc.SectionOffset, sectionDsc.SectionLength);
        }

        private void WheaMsrDumpSection(IntPtr recordAddr, uint structOffset, uint bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            MsrDumpBuffer = Marshal.ReadByte(structAddr);
            MsrDumpLength = (uint)Marshal.ReadInt32(structAddr, 1);

            if (MinStructSize + MsrDumpLength > bytesRemaining) {
                var checkCalc = $"{MinStructSize} + {MsrDumpLength} > {bytesRemaining}";
                throw new InvalidDataException($"Expected size is greater than bytes remaining: {checkCalc}");
            }

            if (MsrDumpLength > 0) {
                MsrDumpData = new byte[MsrDumpLength];
                Marshal.Copy(structAddr + (int)MinStructSize, MsrDumpData, 0, (int)MsrDumpLength);
            } else {
                WarnOutput($"{nameof(MsrDumpLength)} Expected a non-zero MSR dump length.", StructType.Name);
            }

            FinalizeRecord(recordAddr, MsrDumpLength);
        }
    }
}
