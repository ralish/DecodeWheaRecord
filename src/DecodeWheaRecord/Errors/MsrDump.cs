// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Errors {
    /*
     * Cannot be directly marshalled as a structure due to the usage of a
     * variable length array, resulting in a non-static structure size.
     */
    internal sealed class WHEA_MSR_DUMP_SECTION : WheaErrorRecord {
        // Size up to and including the MsrDumpLength field
        private const uint BaseStructSize = 5;

        public override uint GetNativeSize() => MsrDumpLength;

        [JsonProperty(Order = 1)]
        public byte MsrDumpBuffer;

        [JsonProperty(Order = 2)]
        public uint MsrDumpLength; // TODO: Description & validation

        [JsonProperty(Order = 3)]
        public byte[] MsrDumpData; // TODO: Output as hex

        public WHEA_MSR_DUMP_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(WHEA_MSR_DUMP_SECTION), BaseStructSize, bytesRemaining) {
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            MsrDumpBuffer = Marshal.ReadByte(sectionAddr);
            MsrDumpLength = (uint)Marshal.ReadInt32(sectionAddr, 1);

            var msrDumpDataLen = MsrDumpLength - BaseStructSize;
            if (msrDumpDataLen > 0) {
                MsrDumpData = new byte[msrDumpDataLen];
                Marshal.Copy(sectionAddr + (int)BaseStructSize, MsrDumpData, 0, (int)msrDumpDataLen);
            }

            FinalizeRecord(recordAddr, MsrDumpLength);
        }
    }
}
