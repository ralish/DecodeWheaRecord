#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Errors;
using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Events {
    /*
     * HalpCmciHandler -> CmcSwitchToPolling (0 bytes)
     * KiBugCheckProgressCpusFrozen -> CpusFrozen (0 bytes)
     * WheaRemoveErrorSourceDeviceDriver -> DrvHandleBusy (32 bytes)
     * WheaReportHwError -> EarlyError (0 bytes)
     * WheapTrackPendingPage -> PageOfflinePendMax (0 bytes)
     *
     * TODO -> hal (now krnl)
     * HalpCmcLogPollingTimeoutEvent -> CmcPollingTimeout (24 bytes)
     * HalpCmcWorkerRoutine
     *
     * TODO -> krnl
     * PspVsmLogBugCheckCallback -> SELBugCheckStackDump (256 bytes)
     * WheapCreateRecordFromGenericErrorData -> CreateGenericRecord
     * WheaPersistentBadPageToRegistry -> BadPageLimitReached
     * WheapExecuteRowFailureCheck -> SrasTableEntries
     * WheapInitErrorReportDeviceDriver -> DrvErrSrcInvalid, DrvHandleBusy
     * WheapLogInitEvent -> WheaInit
     *
     * AzPshedPi.sys
     * PshedPiHsxFindRootBusNumbers -> AzccRootBusSearchErr
     * PshedPipReportAllPcieErrorSummary -> PcieSummaryFailed (25 bytes)
     * PshedPipWriteSelEvent -> ??? (16 bytes)
     * WheapLogSRASTableBadDataEvent -> SrasTableBadData (0 bytes)
     */


    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_FOUND_ERROR_IN_BANK_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_FOUND_ERROR_IN_BANK_EVENT>();

        public uint EpIndex;
        public uint Bank;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MciStatus;

        public uint ErrorType;
    }



    #region WHEA Event Log Entry: Constants

    internal static class Shared {
        internal const int WCS_RAS_REGISTER_NAME_MAX_LENGTH = 32;
        internal const int WHEA_ERROR_TEXT_LEN = 32;
    }

    #endregion

    #region WHEA Event Log Entry: Enumerations

    // @formatter:int_align_fields true

    internal enum WHEA_REGISTRY_ERRORS : uint {
        None                    = 0,
        FailedToCreateWheaKey   = 1,
        FailedToCreatePolicyKey = 2,
        FailedToOpenHandle      = 3
    }

    internal enum WHEA_THROTTLE_TYPE : uint {
        Pcie   = 0,
        Memory = 1
    }

    // @formatter:int_align_fields false

    #endregion

    #region WHEA Event Log Entry: Structures

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_AZCC_ROOT_BUS_ERR_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_AZCC_ROOT_BUS_ERR_EVENT>();

        [MarshalAs(UnmanagedType.U1)]
        public bool MaxBusCountPassed;

        [MarshalAs(UnmanagedType.U1)]
        public bool InvalidBusMSR;
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     KiMcheckAlternateReturn
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_SRAR_DETAIL_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_SRAR_DETAIL_EVENT>(); // 17 bytes

        [JsonProperty(Order = 1)]
        public uint RecoveryContextFlags;

        [JsonProperty(Order = 2)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong RecoveryContextPa;

        private NtStatus _PageOfflineStatus;

        [JsonProperty(Order = 3)]
        public string PageOfflineStatus => Enum.GetName(typeof(NtStatus), _PageOfflineStatus);

        [JsonProperty(Order = 4)]
        [MarshalAs(UnmanagedType.U1)]
        public bool KernelConsumerError;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ACPI_HEADER {
        public uint Signature;
        public uint Length;
        public byte Revision;
        public byte Checksum;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] OemId;

        public ulong OemTableId;
        public uint OemRevision;
        public uint CreatorId;
        public uint CreatorRevision;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class SIGNAL_REG_VALUE {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Shared.WCS_RAS_REGISTER_NAME_MAX_LENGTH)]
        public byte[] RegName;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint MsrAddr;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Value;
    }

    /*
     * Cannot be directly marshalled as a structure due to non-static size
     * resulting from the variable length array member.
     */
    internal sealed class EFI_ACPI_RAS_SIGNAL_TABLE : WheaStruct {
        private int _NativeSize;
        internal override int GetNativeSize() => _NativeSize;

        [JsonProperty(Order = 1)]
        public WHEA_ACPI_HEADER Header;

        [JsonProperty(Order = 2)]
        public uint NumberRecord;

        [JsonProperty(Order = 3)]
        public SIGNAL_REG_VALUE[] Entries;

        public EFI_ACPI_RAS_SIGNAL_TABLE(IntPtr recordAddr) {
            Header = Marshal.PtrToStructure<WHEA_ACPI_HEADER>(recordAddr);
            var offset = Marshal.SizeOf<WHEA_ACPI_HEADER>();

            NumberRecord = (uint)Marshal.ReadInt32(recordAddr, offset);
            offset += 4;

            if (NumberRecord > 0) {
                Entries = new SIGNAL_REG_VALUE[NumberRecord];
                for (var i = 0; i < NumberRecord; i++) {
                    Entries[i] = Marshal.PtrToStructure<SIGNAL_REG_VALUE>(recordAddr + offset);
                    offset += Marshal.SizeOf<SIGNAL_REG_VALUE>();
                }
            }

            _NativeSize = offset;
        }
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     WheapLogSRASTable
     *
     * Cannot be directly marshalled as a structure due to non-static size
     * resulting from the variable length array member.
     */
    internal sealed class WHEA_SRAS_TABLE_ENTRIES_EVENT : WheaStruct {
        private int _NativeSize;
        internal override int GetNativeSize() => _NativeSize;

        [JsonProperty(Order = 1)]
        public uint LogNumber;

        [JsonProperty(Order = 2)]
        public uint NumberSignals;

        [JsonProperty(Order = 1)]
        public EFI_ACPI_RAS_SIGNAL_TABLE[] Data;

        public WHEA_SRAS_TABLE_ENTRIES_EVENT(IntPtr recordAddr) {
            LogNumber = (uint)Marshal.ReadInt32(recordAddr);
            NumberSignals = (uint)Marshal.ReadInt32(recordAddr, 4);
            var offset = 8;

            if (NumberSignals > 0) {
                Data = new EFI_ACPI_RAS_SIGNAL_TABLE[NumberSignals];
                for (var i = 0; i < NumberSignals; i++) {
                    Data[i] = new EFI_ACPI_RAS_SIGNAL_TABLE(recordAddr + offset);
                    offset += Data[i].GetNativeSize();
                }
            }

            _NativeSize = offset;
        }
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     WheapLogSRASTableErrorEvent
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_SRAS_TABLE_ERROR : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_SRAS_TABLE_ERROR>(); // 0 bytes
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     WheapLogSRASTableNotFound
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_SRAS_TABLE_NOT_FOUND : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_SRAS_TABLE_NOT_FOUND>(); // 0 bytes
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogAddErrorSourceFailedEvent
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_THROTTLE_ADD_ERR_SRC_FAILED_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_THROTTLE_ADD_ERR_SRC_FAILED_EVENT>(); // 0 bytes
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheaAddErrorSource
     *                  WheaRemoveErrorSource
     */
    internal sealed class WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT>(); // 977 bytes

        [JsonProperty(Order = 1)]
        public WHEA_ERROR_SOURCE_DESCRIPTOR Descriptor;

        private NtStatus _Status;

        [JsonProperty(Order = 2)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);

        [JsonProperty(Order = 3)]
        public bool IsRemove;

        public WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT(IntPtr recordAddr, int initialOffset) {
            DebugBeforeDecode(typeof(WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT), initialOffset);

            Descriptor = new WHEA_ERROR_SOURCE_DESCRIPTOR(recordAddr, 0);
            var offset = Descriptor.GetNativeSize();

            _Status = (NtStatus)Marshal.ReadInt32(recordAddr, offset);
            IsRemove = Marshal.ReadByte(recordAddr, offset + 4) != 0;
            offset += 5;

            //DebugAfterDecode(typeof(WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT), offset, _NativeSize);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_ATTEMPT_RECOVERY_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_ATTEMPT_RECOVERY_EVENT>();

        [JsonProperty(Order = 1)]
        public WHEA_ERROR_RECORD_HEADER ErrorHeader; // TODO: Verify

        [JsonProperty(Order = 2)]
        [MarshalAs(UnmanagedType.U1)]
        public bool ArchitecturalRecovery;

        [JsonProperty(Order = 3)]
        [MarshalAs(UnmanagedType.U1)]
        public bool PshedRecovery;

        private NtStatus _Status;

        [JsonProperty(Order = 4)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_CMCI_IMPLEMENTED_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_CMCI_IMPLEMENTED_EVENT>();

        [MarshalAs(UnmanagedType.U1)]
        public bool CmciAvailable;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_CMCI_INITERR_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_CMCI_INITERR_EVENT>();

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Msr;

        public uint Type;
        public uint Bank;
        public uint EpIndex;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_CMCI_RESTART_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_CMCI_RESTART_EVENT>();

        public uint CmciRestoreAttempts;
        public uint MaxCmciRestoreLimit;
        public uint MaxCorrectedErrorsFound;
        public uint MaxCorrectedErrorLimit;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEAP_CREATE_GENERIC_RECORD_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_CREATE_GENERIC_RECORD_EVENT>();

        [JsonProperty(Order = 1)]
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        public string Error;

        [JsonProperty(Order = 2)]
        public uint EntryCount;

        private NtStatus _Status;

        [JsonProperty(Order = 3)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipWriteDeviceDriverSelEntry
     */
    // TODO: Missing 4 bytes?
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEAP_DEVICE_DRV_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_DEVICE_DRV_EVENT>();

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        public string Function;
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheaReportHwError
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_DROPPED_CORRECTED_ERROR_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_DROPPED_CORRECTED_ERROR_EVENT>(); // 8bytes

        private WHEA_ERROR_SOURCE_TYPE _ErrorSourceType;

        [JsonProperty(Order = 1)]
        public string ErrorSourceType => Enum.GetName(typeof(WHEA_ERROR_SOURCE_TYPE), _ErrorSourceType);

        [JsonProperty(Order = 2)]
        public uint ErrorSourceId;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_ERROR_CLEARED_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_ERROR_CLEARED_EVENT>();

        public uint EpIndex;
        public uint Bank;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_ERROR_RECORD_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_ERROR_RECORD_EVENT>();

        /*
         * TODO
         * How is this a pointer to an error record in the context of a
         * hex-encoded serialized record? Need a sample record to inspect.
         */
        //PWHEA_ERROR_RECORD Record;
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     HalpInitGenericErrorSourceEntry
     *                  HalpInitGenericErrorSourceEntryV2
     */
    // TODO: Alongside MCE, CMC, and NMI (processor?)
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEAP_GENERIC_ERR_MEM_MAP_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_GENERIC_ERR_MEM_MAP_EVENT>(); // 48 bytes

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        public string MapReason;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong PhysicalAddress;

        public ulong Length;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_STARTED_REPORT_HW_ERROR : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_STARTED_REPORT_HW_ERROR>();

        /*
         * TODO
         * How is this a pointer to an error record in the context of a
         * hex-encoded serialized record? Need a sample record to inspect.
         */
        //PWHEA_ERROR_PACKET ErrorPacket;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_STUCK_ERROR_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_STUCK_ERROR_EVENT>();

        public uint EpIndex;
        public uint Bank;
        public ulong MciStatus;
    }

    #endregion
}
