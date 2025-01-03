#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Events.Todo {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEA_PSHED_PI_TRACE_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_PSHED_PI_TRACE_EVENT>();

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        private string _Buffer;

        [JsonProperty(Order = 1)]
        public string Buffer => _Buffer.Trim('\0');
    }


}
