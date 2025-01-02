#pragma warning disable CS0649 // Field is never assigned to

// ReSharper disable InconsistentNaming

using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Events {
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ETW_OVERFLOW_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_ETW_OVERFLOW_EVENT>();

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong RecordId;
    }
}
