#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Shared;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Events {
    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogCpuBusesInitFailedEvent
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT>(); // 4 bytes

        private NtStatus _Status;

        [JsonProperty(Order = 1)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipIsRunningInGuest
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PSHED_PI_CPUID : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_PSHED_PI_CPUID>(); // 20 bytes

        public uint CpuVendor;
        public uint CpuFamily;
        public uint CpuModel;
        public uint CpuStepping;
        public uint NumBanks;
    }
}