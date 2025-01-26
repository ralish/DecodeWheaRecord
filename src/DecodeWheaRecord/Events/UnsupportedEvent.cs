#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Events {
    internal sealed class UnsupportedEvent : WheaRecord {
        private readonly uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        [JsonProperty(Order = 1)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        private byte[] Data;

        public UnsupportedEvent(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(UnsupportedEvent), structOffset, 1, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            Data = new byte[bytesRemaining];
            Marshal.Copy(structAddr, Data, 0, (int)bytesRemaining);

            _StructSize = bytesRemaining;
            FinalizeRecord(recordAddr, _StructSize);
        }
    }
}
