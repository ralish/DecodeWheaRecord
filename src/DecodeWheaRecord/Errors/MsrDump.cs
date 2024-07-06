// ReSharper disable FieldCanBeMadeReadOnly.Global
// ReSharper disable InconsistentNaming
// ReSharper disable MemberCanBePrivate.Global

using System;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using static DecodeWheaRecord.NativeMethods;
using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors {
    internal sealed class WHEA_MSR_DUMP_SECTION : WheaRecord {
        internal override int GetNativeSize() => (int)MsrDumpLength;

        [JsonProperty(Order = 1)]
        public byte MsrDumpBuffer;

        // TODO: Description & validation
        [JsonProperty(Order = 2)]
        public uint MsrDumpLength;

        [JsonProperty(Order = 3)]
        public byte[] MsrDumpData;

        public WHEA_MSR_DUMP_SECTION(IntPtr recordAddr, WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc) {
            DebugOutputPre(typeof(WHEA_MSR_DUMP_SECTION), sectionDsc);
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            MsrDumpBuffer = Marshal.ReadByte(sectionAddr);
            MsrDumpLength = (uint)Marshal.ReadInt32(sectionAddr, 1);
            const int offset = 5;

            var msrDumpDataLen = MsrDumpLength - offset;
            if (msrDumpDataLen > 0) {
                MsrDumpData = new byte[msrDumpDataLen];
                Marshal.Copy(sectionAddr + offset, MsrDumpData, 0, (int)msrDumpDataLen);
            }

            DebugOutputPost(typeof(WHEA_MSR_DUMP_SECTION), sectionDsc, (int)MsrDumpLength);
        }
    }
}
