// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors {
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class MU_TELEMETRY_SECTION : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<MU_TELEMETRY_SECTION>();

        [JsonProperty(Order = 1)]
        public Guid ComponentID;

        [JsonProperty(Order = 2)]
        public Guid SubComponentID;

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Reserved;

        [JsonProperty(Order = 4)]
        public uint ErrorStatusValue;

        [JsonProperty(Order = 5)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong AdditionalInfo1;

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong AdditionalInfo2;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();
    }
}