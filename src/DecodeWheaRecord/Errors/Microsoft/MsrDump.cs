// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

/*
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

        public WHEA_MSR_DUMP_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(WHEA_MSR_DUMP_SECTION), MinStructSize, bytesRemaining) {
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            MsrDumpBuffer = Marshal.ReadByte(sectionAddr);
            MsrDumpLength = (uint)Marshal.ReadInt32(sectionAddr, 1);

            if (MinStructSize + MsrDumpLength > sectionDsc.SectionLength) {
                var msg = $"Calculated size is greater than in section descriptor: {MinStructSize} + {MsrDumpLength} > {sectionDsc.SectionLength}";
                throw new InvalidDataException(msg);
            }

            if (MsrDumpLength > 0) {
                MsrDumpData = new byte[MsrDumpLength];
                Marshal.Copy(sectionAddr, MsrDumpData, (int)MinStructSize, (int)MsrDumpLength);
            } else {
                WarnOutput($"{nameof(MsrDumpLength)} Expected a non-zero MSR dump length.", SectionType.Name);
            }

            FinalizeRecord(recordAddr, MsrDumpLength);
        }
    }
}
