#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Descriptors;
using DecodeWheaRecord.Internal;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Errors {
    internal sealed class UnsupportedError : WheaRecord {
        private readonly uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        [JsonProperty(Order = 1)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        private byte[] Data;

        public UnsupportedError(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(typeof(UnsupportedError), sectionDsc, 0, bytesRemaining) {
            var structAddr = recordAddr + (int)sectionDsc.SectionOffset;

            Data = new byte[sectionDsc.SectionLength];
            Marshal.Copy(structAddr, Data, 0, (int)sectionDsc.SectionLength);

            _StructSize = sectionDsc.SectionLength;
            FinalizeRecord(recordAddr, _StructSize);
        }
    }
}
