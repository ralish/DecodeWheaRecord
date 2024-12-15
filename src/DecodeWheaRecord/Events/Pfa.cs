#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Events {
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PFA_MEMORY_OFFLINED : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PFA_MEMORY_OFFLINED>();

        private WHEAP_PFA_OFFLINE_DECISION_TYPE _DecisionType;

        [JsonProperty(Order = 1)]
        public string DecisionType => Enum.GetName(typeof(WHEAP_PFA_OFFLINE_DECISION_TYPE), _DecisionType);

        [JsonProperty(Order = 2)]
        [MarshalAs(UnmanagedType.U1)]
        public bool ImmediateSuccess;

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Page;

        [JsonProperty(Order = 4)]
        [MarshalAs(UnmanagedType.U1)]
        public bool NotifyVid;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PFA_MEMORY_POLICY : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PFA_MEMORY_POLICY>();

        public uint RegistryKeysPresent;

        [MarshalAs(UnmanagedType.U1)]
        public bool DisableOffline;

        [MarshalAs(UnmanagedType.U1)]
        public bool PersistOffline;

        [MarshalAs(UnmanagedType.U1)]
        public bool PfaDisabled;

        public uint PageCount;
        public uint ErrorThreshold;
        public uint TimeOut;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PFA_MEMORY_REMOVE_MONITOR : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PFA_MEMORY_REMOVE_MONITOR>();

        private WHEA_PFA_REMOVE_TRIGGER _RemoveTrigger;

        [JsonProperty(Order = 1)]
        public string RemoveTrigger => Enum.GetName(typeof(WHEA_PFA_REMOVE_TRIGGER), _RemoveTrigger);

        [JsonProperty(Order = 2)]
        public uint TimeInList;

        [JsonProperty(Order = 3)]
        public uint ErrorCount;

        [JsonProperty(Order = 4)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Page;
    }

    // @formatter:int_align_fields true

    internal enum WHEA_PFA_REMOVE_TRIGGER : uint {
        ErrorThreshold = 1,
        Timeout        = 2,
        Capacity       = 3
    }

    internal enum WHEAP_PFA_OFFLINE_DECISION_TYPE : uint {
        PredictiveFailure = 1,
        UncorrectedError  = 2
    }

    // @formatter:int_align_fields false
}
