#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors.Microsoft {
    // Structure size: 12 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_NMI_ERROR_SECTION : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_NMI_ERROR_SECTION>();

        /*
         * On x86 and AMD64 only the first byte is set and the data it contains
         * is near useless. Other architectures may return more useful data.
         */
        [JsonProperty(Order = 1)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Data;

        private WHEA_NMI_ERROR_SECTION_FLAGS _Flags;

        [JsonProperty(Order = 2)]
        public string Flags => GetEnabledFlagsAsString(_Flags);
    }

    // @formatter:int_align_fields true

    [Flags]
    internal enum WHEA_NMI_ERROR_SECTION_FLAGS : uint {
        HypervisorError = 0x1
    }

    // @formatter:int_align_fields false
}
