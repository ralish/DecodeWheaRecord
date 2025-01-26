#pragma warning disable CS0649 // Field is never assigned to

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable InconsistentNaming

using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Events.Software {
    /*
     * Entry ID:        EtwOverFlow
     * Module:          Unknown
     * Version:         Unknown
     * Function(s):     Unknown
     * Notes:           Unable to locate the responsible function in Windows
     *                  Server 2025.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ETW_OVERFLOW_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_ETW_OVERFLOW_EVENT>(); // 8 bytes

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong RecordId;
    }
}
