#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using JetBrains.Annotations;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Events.Hardware {
    /*
     * Module:          pshed.dll
     * Version:         10.0.26100.1150
     * Function(s):     PshedpLogGasErrorEvent
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_GAS_ERROR_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_GAS_ERROR_EVENT>(); // 4 bytes

        private WHEA_GAS_ERRORS _Error;

        [JsonProperty(Order = 1)]
        public string Error => Enum.GetName(typeof(WHEA_GAS_ERRORS), _Error);
    }

    /*
     * Module:          pshed.dll
     * Version:         10.0.26100.1150
     * Function(s):     PshedpClearErrorRecordERST
     *                  PshedpInjectErrorEINJ
     *                  PshedpReadErrorRecordERST
     */
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEAP_ACPI_TIMEOUT_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_ACPI_TIMEOUT_EVENT>(); // 64 bytes

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        private string _TableType;

        [JsonProperty(Order = 1)]
        public string TableType => _TableType.Trim('\0');

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        private string _TableRequest;

        [JsonProperty(Order = 2)]
        public string TableRequest => _TableRequest.Trim('\0');
    }

    /*
     * Module:          pshed.dll
     * Version:         10.0.26100.1150
     * Function(s):     PshedpInitXPFCMCErrorSource
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_BAD_HEST_NOTIFY_DATA_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_BAD_HEST_NOTIFY_DATA_EVENT>(); // 32 bytes

        public ushort SourceId;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Reserved;

        public WHEA_NOTIFICATION_DESCRIPTOR NotifyDesc;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    /*
     * Module:          pshed.dll
     * Version:         10.0.26100.1150
     * Function(s):     PshedpValidateErrorSourceArray
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_ERR_SRC_ARRAY_INVALID_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_ERR_SRC_ARRAY_INVALID_EVENT>(); // 12 bytes

        public uint ErrorSourceCount;
        public uint ReportedLength;
        public uint ExpectedLength;
    }

    /*
     * Module:          pshed.dll
     * Version:         10.0.26100.1150
     * Function(s):     PshedpValidateErrorSource
     */
    internal sealed class WHEAP_ERR_SRC_INVALID_EVENT : WheaRecord {
        private const uint StructSize = 1004;
        public override uint GetNativeSize() => StructSize;

        public WHEA_ERROR_SOURCE_DESCRIPTOR ErrDescriptor;
        public string Error;

        public WHEAP_ERR_SRC_INVALID_EVENT(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEAP_ERR_SRC_INVALID_EVENT), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            ErrDescriptor = new WHEA_ERROR_SOURCE_DESCRIPTOR(recordAddr, structOffset, bytesRemaining);
            Error = Marshal.PtrToStringAnsi(structAddr + 972, Shared.WHEA_ERROR_TEXT_LEN);

            FinalizeRecord(recordAddr, StructSize);
        }
    }

    /*
     * Module:          pshed.dll
     * Version:         10.0.26100.1150
     * Function(s):     PshedpIsWheaOscImplemented
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_OSC_IMPLEMENTED : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_OSC_IMPLEMENTED>(); // 2 bytes

        [MarshalAs(UnmanagedType.U1)]
        public bool OscImplemented;

        [MarshalAs(UnmanagedType.U1)]
        public bool DebugChecked;
    }

    /*
     * Module:          pshed.dll
     * Version:         10.0.26100.1150
     * Function(s):     PshedpProcessEINJ
     */
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEAP_PROCESS_EINJ_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_PROCESS_EINJ_EVENT>(); // 73 bytes

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        private string _Error;

        [JsonProperty(Order = 1)]
        public string Error => _Error.Trim('\0');

        [JsonProperty(Order = 2)]
        [MarshalAs(UnmanagedType.U1)]
        public bool InjectionActionTableValid;

        [JsonProperty(Order = 3)]
        public uint BeginInjectionInstructionCount;

        [JsonProperty(Order = 4)]
        public uint GetTriggerErrorActionTableInstructionCount;

        [JsonProperty(Order = 5)]
        public uint SetErrorTypeInstructionCount;

        [JsonProperty(Order = 6)]
        public uint GetErrorTypeInstructionCount;

        [JsonProperty(Order = 7)]
        public uint EndOperationInstructionCount;

        [JsonProperty(Order = 8)]
        public uint ExecuteOperationInstructionCount;

        [JsonProperty(Order = 9)]
        public uint CheckBusyStatusInstructionCount;

        [JsonProperty(Order = 10)]
        public uint GetCommandStatusInstructionCount;

        [JsonProperty(Order = 11)]
        public uint SetErrorTypeWithAddressInstructionCount;

        [JsonProperty(Order = 12)]
        public uint GetExecuteOperationTimingsInstructionCount;
    }

    /*
     * Module:          pshed.dll
     * Version:         10.0.26100.1150
     * Function(s):     PshedpProcessHEST
     */
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEAP_PROCESS_HEST_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_PROCESS_HEST_EVENT>(); // 101 bytes

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        private string _Error;

        [JsonProperty(Order = 1)]
        public string Error => _Error.Trim('\0');

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        private string _EntryType;

        [JsonProperty(Order = 2)]
        public string EntryType => _EntryType.Trim('\0');

        [JsonProperty(Order = 3)]
        public uint EntryIndex;

        [JsonProperty(Order = 4)]
        [MarshalAs(UnmanagedType.U1)]
        public bool HestValid;

        [JsonProperty(Order = 5)]
        public uint CmcCount;

        [JsonProperty(Order = 6)]
        public uint MceCount;

        [JsonProperty(Order = 7)]
        public uint NmiCount;

        [JsonProperty(Order = 8)]
        public uint AerRootCount;

        [JsonProperty(Order = 9)]
        public uint AerBridgeCount;

        [JsonProperty(Order = 10)]
        public uint AerEndPointCount;

        [JsonProperty(Order = 11)]
        public uint GenericV1Count;

        [JsonProperty(Order = 12)]
        public uint GenericV2Count;
    }

    // @formatter:int_align_fields true

    internal enum WHEA_GAS_ERRORS : uint {
        None                     = 0,
        UnexpectedAddressSpaceId = 1,
        InvalidStructFields      = 2,
        InvalidAccessSize        = 3
    }

    // @formatter:int_align_fields false
}
