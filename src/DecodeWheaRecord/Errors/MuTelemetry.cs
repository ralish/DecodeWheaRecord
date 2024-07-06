#pragma warning disable CS0649 // Field is never assigned to

using System;
using System.Runtime.InteropServices;

using JetBrains.Annotations;

using static DecodeWheaRecord.NativeMethods;
using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors {
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class MU_TELEMETRY_SECTION : WheaRecord {
        public Guid ComponentID;
        public Guid SubComponentID;
        public uint Reserved;
        public uint ErrorStatusValue;
        public ulong AdditionalInfo1;
        public ulong AdditionalInfo2;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();
    }
}
