#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Descriptors {
    /*
     * Structure size: 28 bytes
     *
     * The original structure contains a union with many embedded structures
     * which correspond to different notification source types, as defined in
     * the WHEA_NOTIFICATION_TYPE enumeration. All the structures are the same
     * except for the Polled type, which contains only the first field.
     *
     * Instead of defining numerous duplicate structures we directly embed the
     * fields and serialize only those which apply to the notification source
     * type per the Type field.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_NOTIFICATION_DESCRIPTOR {
        // Switched to an enumeration
        private WHEA_NOTIFICATION_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => GetEnumValueAsString<WHEA_NOTIFICATION_TYPE>(_Type);

        [JsonProperty(Order = 2)]
        public byte Length;

        private WHEA_NOTIFICATION_FLAGS _Flags;

        [JsonProperty(Order = 3)]
        public string Flags => GetEnumFlagsAsString(_Flags);

        /*
         * Subsequent fields were previously part of structures defined in the
         * earlier referenced union.
         */

        [JsonProperty(Order = 4)]
        public uint PollInterval;

        [JsonProperty(Order = 5)]
        public uint Vector;

        [JsonProperty(Order = 6)]
        public uint SwitchToPollingThreshold;

        [JsonProperty(Order = 7)]
        public uint SwitchToPollingWindow;

        [JsonProperty(Order = 8)]
        public uint ErrorThreshold;

        [JsonProperty(Order = 9)]
        public uint ErrorThresholdWindow;

        private bool IsPolled() => _Type == WHEA_NOTIFICATION_TYPE.Polled;

        [UsedImplicitly]
        public bool ShouldSerializeVector() => !IsPolled();

        [UsedImplicitly]
        public bool ShouldSerializeSwitchToPollingThreshold() => !IsPolled();

        [UsedImplicitly]
        public bool ShouldSerializeSwitchToPollingWindow() => !IsPolled();

        [UsedImplicitly]
        public bool ShouldSerializeErrorThreshold() => !IsPolled();

        [UsedImplicitly]
        public bool ShouldSerializeErrorThresholdWindow() => !IsPolled();
    }

    // @formatter:int_align_fields true

    // From WHEA_NOTIFICATION_TYPE preprocessor definitions
    internal enum WHEA_NOTIFICATION_TYPE : byte {
        Polled                = 0,
        ExternalInterrupt     = 1,
        LocalInterrupt        = 2,
        Sci                   = 3,
        Nmi                   = 4,
        Cmci                  = 5,
        Mce                   = 6,
        GpioSignal            = 7,
        Armv8Sea              = 8,
        Armv8Sei              = 9,
        ExternalInterruptGsiv = 10,
        Sdei                  = 11
    }

    [Flags]
    internal enum WHEA_NOTIFICATION_FLAGS : ushort {
        PollIntervalRW             = 0x1,
        SwitchToPollingThresholdRW = 0x2,
        SwitchToPollingWindowRW    = 0x4,
        ErrorThresholdRW           = 0x8,
        ErrorThresholdWindowRW     = 0x10
    }

    // @formatter:int_align_fields false
}
