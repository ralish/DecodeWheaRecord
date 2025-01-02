#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Errors {
    internal sealed class UnsupportedError : WheaRecord {
        private uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        [JsonProperty(Order = 1)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        private byte[] Data;

        public UnsupportedError(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(UnsupportedError), 0, bytesRemaining) {
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            Data = new byte[sectionDsc.SectionLength];
            Marshal.Copy(sectionAddr, Data, 0, (int)sectionDsc.SectionLength);

            FinalizeRecord(recordAddr, _StructSize);
        }
    }
}
