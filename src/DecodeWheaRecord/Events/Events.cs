#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Errors;
using DecodeWheaRecord.Shared;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.NativeMethods;
using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Events {
    #region WHEA Event Log Entry: Constants

    internal static class Shared {
        internal const int WCS_RAS_REGISTER_NAME_MAX_LENGTH = 32;
        internal const int WHEA_ERROR_TEXT_LEN = 32;
    }

    #endregion

    #region WHEA Event Log Entry: Enumerations

    // @formatter:int_align_fields true

    internal enum PSHED_PI_ERR_READING_PCIE_OVERRIDES : uint {
        NoErr        = 0,
        NoMemory     = 1,
        QueryErr     = 2,
        BadSize      = 3,
        BadSignature = 4,
        NoCapOffset  = 5,
        NotBinary    = 6
    }

    internal enum WHEA_GAS_ERRORS : uint {
        None                     = 0,
        UnexpectedAddressSpaceId = 1,
        InvalidStructFields      = 2,
        InvalidAccessSize        = 3
    }

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

    internal enum WHEAP_DPC_ERROR_EVENT_TYPE : uint {
        NoErr        = 0,
        BusNotFound  = 1,
        DpcedSubtree = 2,
        DeviceIdBad  = 3,
        ResetFailed  = 4,
        NoChildren   = 5
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

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_AZCC_ROOT_BUS_LIST_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_AZCC_ROOT_BUS_LIST_EVENT>();

        public uint RootBusCount;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public uint[] RootBuses;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_AZCC_SET_POISON_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_AZCC_SET_POISON_EVENT>();

        public uint Bus;

        [MarshalAs(UnmanagedType.U1)]
        public bool ReadSuccess;

        [MarshalAs(UnmanagedType.U1)]
        public bool WriteSuccess;

        [MarshalAs(UnmanagedType.U1)]
        public bool IsEnable;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ETW_OVERFLOW_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_ETW_OVERFLOW_EVENT>();

        public ulong RecordId;
    }

    // Deliberately empty (no payload)
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_FAILED_ADD_DEFECT_LIST_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_FAILED_ADD_DEFECT_LIST_EVENT>();
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_GAS_ERROR_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_GAS_ERROR_EVENT>();

        private WHEA_GAS_ERRORS _Error;

        [JsonProperty(Order = 1)]
        public string Error => Enum.GetName(typeof(WHEA_GAS_ERRORS), _Error);
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT>();

        private NtStatus _Status;

        [JsonProperty(Order = 1)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_OFFLINE_DONE_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_OFFLINE_DONE_EVENT>();

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Address;
    }

    // Deliberately empty (no payload)
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_REGISTER_KEY_NOTIFICATION_FAILED_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_REGISTER_KEY_NOTIFICATION_FAILED_EVENT>();
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_REGISTRY_ERROR_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_REGISTRY_ERROR_EVENT>();

        private WHEA_REGISTRY_ERRORS _RegErr;

        [JsonProperty(Order = 1)]
        public string RegErr => Enum.GetName(typeof(WHEA_REGISTRY_ERRORS), _RegErr);

        [JsonProperty(Order = 2)]
        public uint Status;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEA_REGNOTIFY_POLICY_CHANGE_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_REGNOTIFY_POLICY_CHANGE_EVENT>();

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        public string PolicyName;

        public uint PolicyIndex;
        public uint PolicyValue;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_SEL_BUGCHECK_PROGRESS : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_SEL_BUGCHECK_PROGRESS>();

        public uint BugCheckCode;
        public uint BugCheckProgressSummary;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_SRAR_DETAIL_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_SRAR_DETAIL_EVENT>();

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

    // Deliberately empty (no payload)
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_SRAS_TABLE_ERROR : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_SRAS_TABLE_ERROR>();
    }

    // Deliberately empty (no payload)
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_SRAS_TABLE_NOT_FOUND : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_SRAS_TABLE_NOT_FOUND>();
    }

    // Deliberately empty (no payload)
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_THROTTLE_ADD_ERR_SRC_FAILED_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_THROTTLE_ADD_ERR_SRC_FAILED_EVENT>();
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT>();

        public uint SocketId;
        public uint ChannelId;
        public uint DimmSlot;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_THROTTLE_PCIE_ADD_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_THROTTLE_PCIE_ADD_EVENT>();

        [JsonProperty(Order = 1)]
        public WHEA_PCIE_ADDRESS Address;

        [JsonProperty(Order = 2)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Mask;

        [JsonProperty(Order = 3)]
        [MarshalAs(UnmanagedType.U1)]
        public bool Updated;

        private NtStatus _Status;

        [JsonProperty(Order = 4)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_THROTTLE_PCIE_REMOVE_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_THROTTLE_PCIE_REMOVE_EVENT>();

        public WHEA_PCIE_ADDRESS Address;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Mask;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_THROTTLE_REG_DATA_IGNORED_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_THROTTLE_REG_DATA_IGNORED_EVENT>();

        private WHEA_THROTTLE_TYPE _ThrottleType;

        [JsonProperty(Order = 1)]
        public string ThrottleType => Enum.GetName(typeof(WHEA_THROTTLE_TYPE), _ThrottleType);
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT>();

        private WHEA_THROTTLE_TYPE _ThrottleType;

        [JsonProperty(Order = 1)]
        public string ThrottleType => Enum.GetName(typeof(WHEA_THROTTLE_TYPE), _ThrottleType);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEAP_ACPI_TIMEOUT_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_ACPI_TIMEOUT_EVENT>();

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        public string TableType;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        public string TableRequest;
    }

    internal sealed class WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT : WheaStruct {
        private int _NativeSize;
        internal override int GetNativeSize() => _NativeSize;

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

            _NativeSize = offset;
            DebugAfterDecode(typeof(WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT), offset, _NativeSize);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_ATTEMPT_RECOVERY_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_BAD_HEST_NOTIFY_DATA_EVENT>();

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
    internal sealed class WHEAP_BAD_HEST_NOTIFY_DATA_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_BAD_HEST_NOTIFY_DATA_EVENT>();

        public ushort SourceId;
        public ushort Reserved;
        public WHEA_NOTIFICATION_DESCRIPTOR NotifyDesc; // TODO: Verify

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_CLEARED_POISON_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_CLEARED_POISON_EVENT>();

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong PhysicalAddress;
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

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEAP_DEVICE_DRV_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_DEVICE_DRV_EVENT>();

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        public string Function;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_DPC_ERROR_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_DPC_ERROR_EVENT>();

        private WHEAP_DPC_ERROR_EVENT_TYPE _ErrType;

        [JsonProperty(Order = 1)]
        public string ErrType => Enum.GetName(typeof(WHEAP_DPC_ERROR_EVENT_TYPE), _ErrType);

        [JsonProperty(Order = 2)]
        public uint Bus;

        [JsonProperty(Order = 3)]
        public uint Device;

        [JsonProperty(Order = 4)]
        public uint Function;

        [JsonProperty(Order = 5)]
        public ushort DeviceId;

        [JsonProperty(Order = 6)]
        public ushort VendorId;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_DROPPED_CORRECTED_ERROR_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_DROPPED_CORRECTED_ERROR_EVENT>();

        private WHEA_ERROR_SOURCE_TYPE _ErrorSourceType;

        [JsonProperty(Order = 1)]
        public string ErrorSourceType => Enum.GetName(typeof(WHEA_ERROR_SOURCE_TYPE), _ErrorSourceType);

        [JsonProperty(Order = 2)]
        public uint ErrorSourceId;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_EDPC_ENABLED_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_EDPC_ENABLED_EVENT>();

        [MarshalAs(UnmanagedType.U1)]
        public bool eDPCEnabled;

        [MarshalAs(UnmanagedType.U1)]
        public bool eDPCRecovEnabled;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_ERR_SRC_ARRAY_INVALID_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_ERR_SRC_ARRAY_INVALID_EVENT>();

        public uint ErrorSourceCount;
        public uint ReportedLength;
        public uint ExpectedLength;
    }

    internal sealed class WHEAP_ERR_SRC_INVALID_EVENT : WheaStruct {
        private int _NativeSize;
        internal override int GetNativeSize() => _NativeSize;

        [JsonProperty(Order = 1)]
        public WHEA_ERROR_SOURCE_DESCRIPTOR ErrDescriptor;

        [JsonProperty(Order = 2)]
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        public string Error;

        public WHEAP_ERR_SRC_INVALID_EVENT(IntPtr recordAddr, int initialOffset) {
            DebugBeforeDecode(typeof(WHEAP_ERR_SRC_INVALID_EVENT), initialOffset);

            ErrDescriptor = new WHEA_ERROR_SOURCE_DESCRIPTOR(recordAddr, 0);
            var offset = ErrDescriptor.GetNativeSize();

            Error = Marshal.PtrToStringAnsi(recordAddr + offset, Shared.WHEA_ERROR_TEXT_LEN);
            offset += Shared.WHEA_ERROR_TEXT_LEN;

            _NativeSize = offset;
            DebugAfterDecode(typeof(WHEAP_ERR_SRC_INVALID_EVENT), offset, _NativeSize);
        }
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

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_FOUND_ERROR_IN_BANK_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_FOUND_ERROR_IN_BANK_EVENT>();

        public uint EpIndex;
        public uint Bank;
        public ulong MciStatus;
        public uint ErrorType;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEAP_GENERIC_ERR_MEM_MAP_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_GENERIC_ERR_MEM_MAP_EVENT>();

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        public string MapReason;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong PhysicalAddress;

        public ulong Length;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_OSC_IMPLEMENTED : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_OSC_IMPLEMENTED>();

        [MarshalAs(UnmanagedType.U1)]
        public bool OscImplemented;

        [MarshalAs(UnmanagedType.U1)]
        public bool DebugChecked;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PCIE_CONFIG_INFO : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PCIE_CONFIG_INFO>();

        public uint Segment;
        public uint Bus;
        public uint Device;
        public uint Function;
        public uint Offset;
        public uint Length;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Value;

        public byte Succeeded; // TODO: Possibly should be a boolean?

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        public byte[] Reserved;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PCIE_OVERRIDE_INFO : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PCIE_OVERRIDE_INFO>();

        public uint Segment;
        public uint Bus;
        public uint Device;
        public uint Function;
        public byte ValidBits; // TODO: Where are these defined?

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        public byte[] Reserved;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint UncorrectableErrorMask;

        public uint UncorrectableErrorSeverity;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint CorrectableErrorMask;

        public uint CapAndControl;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PCIE_READ_OVERRIDES_ERR : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PCIE_READ_OVERRIDES_ERR>();

        private PSHED_PI_ERR_READING_PCIE_OVERRIDES _FailureReason;

        [JsonProperty(Order = 1)]
        public string FailureReason => Enum.GetName(typeof(PSHED_PI_ERR_READING_PCIE_OVERRIDES), _FailureReason);

        private NtStatus _FailureStatus;

        [JsonProperty(Order = 2)]
        public string FailureStatus => Enum.GetName(typeof(NtStatus), _FailureStatus);
    }

    // Deliberately empty (no payload)
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PLUGIN_DEFECT_LIST_CORRUPT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PLUGIN_DEFECT_LIST_CORRUPT>();
    }

    // Deliberately empty (no payload)
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PLUGIN_DEFECT_LIST_FULL_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PLUGIN_DEFECT_LIST_FULL_EVENT>();
    }

    // Deliberately empty (no payload)
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PLUGIN_DEFECT_LIST_UEFI_VAR_FAILED : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PLUGIN_DEFECT_LIST_UEFI_VAR_FAILED>();
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEAP_PROCESS_EINJ_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PROCESS_EINJ_EVENT>();

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        public string Error;

        [MarshalAs(UnmanagedType.U1)]
        public bool InjectionActionTableValid;

        public uint BeginInjectionInstructionCount;
        public uint GetTriggerErrorActionTableInstructionCount;
        public uint SetErrorTypeInstructionCount;
        public uint GetErrorTypeInstructionCount;
        public uint EndOperationInstructionCount;
        public uint ExecuteOperationInstructionCount;
        public uint CheckBusyStatusInstructionCount;
        public uint GetCommandStatusInstructionCount;
        public uint SetErrorTypeWithAddressInstructionCount;
        public uint GetExecuteOperationTimingsInstructionCount;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEAP_PROCESS_HEST_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PROCESS_HEST_EVENT>();

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        public string Error;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Shared.WHEA_ERROR_TEXT_LEN)]
        public string EntryType;

        public uint EntryIndex;

        [MarshalAs(UnmanagedType.U1)]
        public bool HestValid;

        public uint CmcCount;
        public uint MceCount;
        public uint NmiCount;
        public uint AerRootCount;
        public uint AerBridgeCount;
        public uint AerEndPointCount;
        public uint GenericV1Count;
        public uint GenericV2Count;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_PROMOTED_AER_ERROR_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_PROMOTED_AER_ERROR_EVENT>();

        private WHEA_ERROR_SEVERITY _ErrorSeverity;

        [JsonProperty(Order = 1)]
        public string ErrorSeverity => Enum.GetName(typeof(WHEA_ERROR_SEVERITY), _ErrorSeverity);

        [JsonProperty(Order = 2)]
        public uint ErrorHandlerType;

        [JsonProperty(Order = 3)]
        public uint ErrorSourceId;

        [JsonProperty(Order = 4)]
        public uint RootErrorCommand;

        [JsonProperty(Order = 5)]
        public uint RootErrorStatus;

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint DeviceAssociationBitmap;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_ROW_FAILURE_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_ROW_FAILURE_EVENT>();

        public uint LowOrderPage;  // TODO: PFN_NUMBER
        public uint HighOrderPage; // TODO: PFN_NUMBER
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_SPURIOUS_AER_EVENT : WheaStruct {
        internal override int GetNativeSize() => Marshal.SizeOf<WHEAP_SPURIOUS_AER_EVENT>();

        private WHEA_ERROR_SEVERITY _ErrorSeverity;

        [JsonProperty(Order = 1)]
        public string ErrorSeverity => Enum.GetName(typeof(WHEA_ERROR_SEVERITY), _ErrorSeverity);

        private WHEA_PCIEXPRESS_DEVICE_TYPE _ErrorHandlerType;

        [JsonProperty(Order = 2)]
        public string ErrorHandlerType => Enum.GetName(typeof(WHEA_PCIEXPRESS_DEVICE_TYPE), _ErrorHandlerType);

        [JsonProperty(Order = 3)]
        public uint SpuriousErrorSourceId;

        [JsonProperty(Order = 4)]
        public uint RootErrorCommand;

        [JsonProperty(Order = 5)]
        public uint RootErrorStatus;

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint DeviceAssociationBitmap;

        public override void Validate() {
            if (_ErrorHandlerType != WHEA_PCIEXPRESS_DEVICE_TYPE.RootPort &&
                _ErrorHandlerType != WHEA_PCIEXPRESS_DEVICE_TYPE.DownstreamSwitchPort &&
                _ErrorHandlerType != WHEA_PCIEXPRESS_DEVICE_TYPE.RootComplexEventCollector) {
                var cat = $"{nameof(WHEAP_SPURIOUS_AER_EVENT)}.{nameof(ErrorHandlerType)}";
                DebugOutput("Not RootPort, DownstreamSwitchPort, or RootComplexEventCollector.", cat);
            }
        }
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
