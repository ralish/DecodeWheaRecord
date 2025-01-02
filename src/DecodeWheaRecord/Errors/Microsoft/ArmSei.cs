#pragma warning disable CS0649  // Field is never assigned to

// ReSharper disable InconsistentNaming

using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Errors.Microsoft {
    // Structure size: 12 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_SEI_SECTION : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_SEI_SECTION>();

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Esr;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Far;
    }
}
