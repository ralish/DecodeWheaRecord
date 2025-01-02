#pragma warning disable CS0649 // Field is never assigned to

// ReSharper disable InconsistentNaming

using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Errors.Microsoft {
    // Structure size: 21 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_SEA_SECTION : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_SEA_SECTION>();

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Esr;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Far;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Par;

        [MarshalAs(UnmanagedType.U1)]
        public bool WasKernel;
    }
}
