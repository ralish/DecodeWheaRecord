#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Events.Hardware {
    /*
     * Entry ID:        CreateGenericRecord
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheapCreateRecordFromGenericErrorData
     */
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEAP_CREATE_GENERIC_RECORD_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_CREATE_GENERIC_RECORD_EVENT>(); // 40 bytes

        [JsonProperty(Order = 1)]
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WHEA_EVENT_LOG_ENTRY.WHEA_ERROR_TEXT_LEN)]
        public string Error;

        [JsonProperty(Order = 2)]
        public uint EntryCount;

        private NtStatus _Status;

        [JsonProperty(Order = 3)]
        public string Status => GetEnumValueAsString<NtStatus>(_Status);
    }

    /*
     * Entry ID:        DrvErrSrcInvalid & DrvHandleBusy
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheaRemoveErrorSourceDeviceDriver
     *                  WheapInitErrorReportDeviceDriver
     * Header flags:    Driver, LogSel, RawSel
     */
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEAP_DEVICE_DRV_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_DEVICE_DRV_EVENT>(); // 32 bytes

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WHEA_EVENT_LOG_ENTRY.WHEA_ERROR_TEXT_LEN)]
        public string Function;
    }

    /*
     * Entry ID:        StartedReportHwError
     * Module:          Unknown
     * Version:         Unknown
     * Function(s):     Unknown
     * Header flags:    LogSel
     * Notes:           Unable to locate the responsible function in Windows
     *                  Server 2025, though WheaSelLogErrorPkt(...) appears to
     *                  process the created event as it is exclusively called
     *                  by WheaSelLogEvent(...) for this event ID.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_STARTED_REPORT_HW_ERROR : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_STARTED_REPORT_HW_ERROR>(); // 4 bytes (x86), 8 bytes (x64)

        [JsonConverter(typeof(HexStringJsonConverter))]
        public IntPtr ErrorPacket; // PWHEA_ERROR_PACKET
    }
}
