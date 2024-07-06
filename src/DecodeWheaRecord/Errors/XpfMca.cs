#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming
// ReSharper disable MemberCanBePrivate.Global

using System;
using System.Runtime.InteropServices;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.NativeMethods;
using static DecodeWheaRecord.Utilities;


namespace DecodeWheaRecord.Errors {
    internal sealed class WHEA_XPF_MCA_SECTION : WheaRecord {
        internal const int WHEA_AMD_EXT_REG_NUM = 10;
        internal const int WHEA_XPF_MCA_EXBANK_COUNT = 32;
        internal const int WHEA_XPF_MCA_EXTREG_MAX_COUNT = 24;

        private int _NativeSize;
        internal override int GetNativeSize() => _NativeSize;

        [JsonProperty(Order = 1)]
        public uint VersionNumber;

        private WHEA_CPU_VENDOR _CpuVendor;

        [JsonProperty(Order = 2)]
        public string CpuVendor => Enum.GetName(typeof(WHEA_CPU_VENDOR), _CpuVendor);

        [JsonProperty(Order = 3)]
        public long Timestamp; // LARGE_INTEGER

        [JsonProperty(Order = 4)]
        public uint ProcessorNumber;

        private MCG_STATUS _GlobalStatus;

        [JsonProperty(Order = 5)]
        public string GlobalStatus => GetEnabledFlagsAsString(_GlobalStatus);

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong InstructionPointer;

        [JsonProperty(Order = 7)]
        public uint BankNumber;

        /*
         * The next three fields were originally a single field named Status
         * with type MCI_STATUS. This type was a union of the three possible
         * structures subject to the CPU architecture of the system. Directly
         * defining all three structures in the parent structure helps to make
         * the serialization slightly easier to deal with.
         */

        [JsonProperty(Order = 8)]
        public MCI_STATUS_BITS_COMMON CommonBits;

        [JsonProperty(Order = 9)]
        public MCI_STATUS_AMD_BITS AmdBits;

        [JsonProperty(Order = 10)]
        public MCI_STATUS_INTEL_BITS IntelBits;

        [JsonProperty(Order = 11)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Address;

        [JsonProperty(Order = 12)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Misc;

        [JsonProperty(Order = 13)]
        public uint ExtendedRegisterCount;

        [JsonProperty(Order = 14)]
        public uint ApicId;

        [JsonProperty(Order = 15)]
        public ulong[] ExtendedRegisters;

        [JsonProperty(Order = 16)]
        public WHEA_AMD_EXTENDED_REGISTERS AMDExtendedRegisters;

        [JsonProperty(Order = 17)]
        public MCG_CAP GlobalCapability;

        [JsonProperty(Order = 18)]
        public XPF_RECOVERY_INFO RecoveryInfo;

        [JsonProperty(Order = 19)]
        public uint ExBankCount;

        [JsonProperty(Order = 20)]
        public uint[] BankNumberEx;

        /*
         * The next three fields were originally a single field named StatusEx
         * with type MCI_STATUS[]. This type was a union of the three possible
         * structures subject to the CPU architecture of the system. Directly
         * defining all three structures in the parent structure helps to make
         * the serialization slightly easier to deal with.
         */

        [JsonProperty(Order = 21)]
        public MCI_STATUS_BITS_COMMON[] StatusExCommon;

        [JsonProperty(Order = 22)]
        public MCI_STATUS_AMD_BITS[] StatusExAmd;

        [JsonProperty(Order = 23)]
        public MCI_STATUS_INTEL_BITS[] StatusExIntel;

        [JsonProperty(Order = 24)]
        public ulong[] AddressEx;

        [JsonProperty(Order = 25)]
        public ulong[] MiscEx;

        public WHEA_XPF_MCA_SECTION(IntPtr recordAddr, WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc) {
            DebugOutputPre(typeof(WHEA_XPF_MCA_SECTION), sectionDsc);
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            VersionNumber = (uint)Marshal.ReadInt32(sectionAddr);
            _CpuVendor = (WHEA_CPU_VENDOR)Marshal.ReadInt32(sectionAddr, 4);
            Timestamp = Marshal.ReadInt64(sectionAddr, 8);
            ProcessorNumber = (uint)Marshal.ReadInt32(sectionAddr, 16);
            _GlobalStatus = (MCG_STATUS)Marshal.ReadInt64(sectionAddr, 20);
            InstructionPointer = (ulong)Marshal.ReadInt64(sectionAddr, 28);
            BankNumber = (uint)Marshal.ReadInt32(sectionAddr, 36);
            var offset = 40;

            switch (_CpuVendor) {
                case WHEA_CPU_VENDOR.Amd:
                    AmdBits = Marshal.PtrToStructure<MCI_STATUS_AMD_BITS>(sectionAddr + offset);
                    break;
                case WHEA_CPU_VENDOR.Intel:
                    IntelBits = Marshal.PtrToStructure<MCI_STATUS_INTEL_BITS>(sectionAddr + offset);
                    break;
                case WHEA_CPU_VENDOR.Other:
                    CommonBits = Marshal.PtrToStructure<MCI_STATUS_BITS_COMMON>(sectionAddr + offset);
                    break;
            }

            // AMD & Intel structures have the same size
            offset += Marshal.SizeOf<MCI_STATUS_BITS_COMMON>();

            Address = (ulong)Marshal.ReadInt64(sectionAddr, offset);
            Misc = (ulong)Marshal.ReadInt64(sectionAddr, offset + 8);
            ExtendedRegisterCount = (uint)Marshal.ReadInt32(sectionAddr, offset + 16);
            ApicId = (uint)Marshal.ReadInt32(sectionAddr, offset + 20);
            offset += 24;

            switch (_CpuVendor) {
                case WHEA_CPU_VENDOR.Amd:
                    AMDExtendedRegisters = Marshal.PtrToStructure<WHEA_AMD_EXTENDED_REGISTERS>(sectionAddr + offset);
                    break;
                case WHEA_CPU_VENDOR.Intel:
                    var numExtRegs = ExtendedRegisterCount <= WHEA_XPF_MCA_EXTREG_MAX_COUNT ? ExtendedRegisterCount : WHEA_XPF_MCA_EXTREG_MAX_COUNT;
                    var extRegsTmp = new long[WHEA_XPF_MCA_EXTREG_MAX_COUNT];
                    ExtendedRegisters = new ulong[WHEA_XPF_MCA_EXTREG_MAX_COUNT];

                    Marshal.Copy(sectionAddr + offset, extRegsTmp, 0, (int)numExtRegs);
                    for (var i = 0; i < numExtRegs; i++) {
                        ExtendedRegisters[i] = (ulong)extRegsTmp[i];
                    }

                    break;
                case WHEA_CPU_VENDOR.Other:
                    // TODO: Should ExtendedRegisters be populated?
                    break;
            }

            // AMD structure has the same size
            offset += sizeof(ulong) * WHEA_XPF_MCA_EXTREG_MAX_COUNT;

            GlobalCapability = Marshal.PtrToStructure<MCG_CAP>(sectionAddr + offset);
            offset += Marshal.SizeOf<MCG_CAP>();

            if (VersionNumber >= 3) {
                RecoveryInfo = Marshal.PtrToStructure<XPF_RECOVERY_INFO>(sectionAddr + offset);
                offset += Marshal.SizeOf<XPF_RECOVERY_INFO>();
            }

            if (VersionNumber >= 4) {
                ExBankCount = (uint)Marshal.ReadInt32(sectionAddr, offset);
                offset += 4;

                var bankNumberExTmp = new int[WHEA_XPF_MCA_EXBANK_COUNT];
                BankNumberEx = new uint[WHEA_XPF_MCA_EXBANK_COUNT];

                Marshal.Copy(sectionAddr + offset, bankNumberExTmp, 0, WHEA_XPF_MCA_EXBANK_COUNT);
                for (var i = 0; i < WHEA_XPF_MCA_EXBANK_COUNT; i++) {
                    BankNumberEx[i] = (uint)bankNumberExTmp[i];
                }

                offset += sizeof(uint) * WHEA_XPF_MCA_EXBANK_COUNT;

                // AMD & Intel structures have the same size
                var elementSize = Marshal.SizeOf<MCI_STATUS_BITS_COMMON>();
                switch (_CpuVendor) {
                    case WHEA_CPU_VENDOR.Amd:
                        StatusExAmd = new MCI_STATUS_AMD_BITS[WHEA_XPF_MCA_EXBANK_COUNT];
                        for (var i = 0; i < WHEA_XPF_MCA_EXBANK_COUNT; i++) {
                            StatusExAmd[i] = Marshal.PtrToStructure<MCI_STATUS_AMD_BITS>(sectionAddr + offset + (i * elementSize));
                        }

                        break;
                    case WHEA_CPU_VENDOR.Intel:
                        StatusExIntel = new MCI_STATUS_INTEL_BITS[WHEA_XPF_MCA_EXBANK_COUNT];
                        for (var i = 0; i < WHEA_XPF_MCA_EXBANK_COUNT; i++) {
                            StatusExIntel[i] = Marshal.PtrToStructure<MCI_STATUS_INTEL_BITS>(sectionAddr + offset + (i * elementSize));
                        }

                        break;
                    case WHEA_CPU_VENDOR.Other:
                        StatusExCommon = new MCI_STATUS_BITS_COMMON[WHEA_XPF_MCA_EXBANK_COUNT];
                        for (var i = 0; i < WHEA_XPF_MCA_EXBANK_COUNT; i++) {
                            StatusExCommon[i] = Marshal.PtrToStructure<MCI_STATUS_BITS_COMMON>(sectionAddr + offset + (i * elementSize));
                        }

                        break;
                }

                offset += elementSize * WHEA_XPF_MCA_EXBANK_COUNT;

                var addressExTmp = new long[WHEA_XPF_MCA_EXBANK_COUNT];
                AddressEx = new ulong[WHEA_XPF_MCA_EXBANK_COUNT];

                Marshal.Copy(sectionAddr + offset, addressExTmp, 0, WHEA_XPF_MCA_EXBANK_COUNT);
                for (var i = 0; i < WHEA_XPF_MCA_EXBANK_COUNT; i++) {
                    AddressEx[i] = (ulong)addressExTmp[i];
                }

                offset += sizeof(ulong) * WHEA_XPF_MCA_EXBANK_COUNT;

                var miscExTmp = new long[WHEA_XPF_MCA_EXBANK_COUNT];
                MiscEx = new ulong[WHEA_XPF_MCA_EXBANK_COUNT];

                Marshal.Copy(sectionAddr + offset, miscExTmp, 0, WHEA_XPF_MCA_EXBANK_COUNT);
                for (var i = 0; i < WHEA_XPF_MCA_EXBANK_COUNT; i++) {
                    MiscEx[i] = (ulong)miscExTmp[i];
                }

                offset += sizeof(ulong) * WHEA_XPF_MCA_EXBANK_COUNT;
            }

            _NativeSize = offset;
            DebugOutputPost(typeof(WHEA_XPF_MCA_SECTION), sectionDsc, _NativeSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeCommonBits() => _CpuVendor == WHEA_CPU_VENDOR.Other;

        [UsedImplicitly]
        public bool ShouldSerializeAmdBits() => _CpuVendor == WHEA_CPU_VENDOR.Amd;

        [UsedImplicitly]
        public bool ShouldSerializeIntelBits() => _CpuVendor == WHEA_CPU_VENDOR.Intel;

        [UsedImplicitly]
        public bool ShouldSerializeExtendedRegisters() => _CpuVendor == WHEA_CPU_VENDOR.Intel;

        [UsedImplicitly]
        public bool ShouldSerializeAMDExtendedRegisters() => _CpuVendor == WHEA_CPU_VENDOR.Amd;

        [UsedImplicitly]
        public bool ShouldSerializeRecoveryInfo() => VersionNumber >= 3;

        [UsedImplicitly]
        public bool ShouldSerializeExBankCount() => VersionNumber >= 4;

        [UsedImplicitly]
        public bool ShouldSerializeBankNumberEx() => VersionNumber >= 4;

        [UsedImplicitly]
        public bool ShouldSerializeStatusExCommon() => VersionNumber >= 4 && ShouldSerializeCommonBits();

        [UsedImplicitly]
        public bool ShouldSerializeStatusExAmd() => VersionNumber >= 4 && ShouldSerializeAmdBits();

        [UsedImplicitly]
        public bool ShouldSerializeStatusExIntel() => VersionNumber >= 4 && ShouldSerializeIntelBits();

        [UsedImplicitly]
        public bool ShouldSerializeAddressEx() => VersionNumber >= 4;

        [UsedImplicitly]
        public bool ShouldSerializeMiscEx() => VersionNumber >= 4;
    }

    /*
     * Originally defined as a ULONG64 bitfield. This structure has the same in
     * memory format but is simpler to interact with.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class MCG_CAP {
        private MCG_CAP_FLAGS _Flags;

        [JsonProperty(Order = 1)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        [JsonProperty(Order = 2)]
        public byte CountField => (byte)_Flags;

        [JsonProperty(Order = 3)]
        public byte ExtendedRegisterCount => (byte)((uint)_Flags >> 15);
    }

    /*
     * Originally defined as a ULONG64 bitfield. This structure has the same in
     * memory format but is simpler to interact with.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class MCI_STATUS_BITS_COMMON {
        [JsonProperty(Order = 1)]
        public ushort McaErrorCode;

        [JsonProperty(Order = 2)]
        public ushort ModelErrorCode;

        private MCI_STATUS_BITS_COMMON_FLAGS _Flags;

        [JsonProperty(Order = 3)]
        public string Flags => GetEnabledFlagsAsString(_Flags);
    }

    /*
     * Originally defined as a ULONG64 bitfield. This structure has the same in
     * memory format but is simpler to interact with.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class MCI_STATUS_AMD_BITS {
        [JsonProperty(Order = 1)]
        public ushort McaErrorCode;

        [JsonProperty(Order = 2)]
        public ushort ModelErrorCode;

        private MCI_STATUS_AMD_BITS_FLAGS _Flags;

        [JsonProperty(Order = 3)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        [JsonProperty(Order = 4)]
        public ushort ImplementationSpecific1 => (ushort)((uint)_Flags >> 12 & 0xFFF);

        [JsonProperty(Order = 5)]
        public ushort ImplementationSpecific2 => (ushort)((uint)_Flags & 0x7FF);
    }

    /*
     * Originally defined as a ULONG64 bitfield. This structure has the same in
     * memory format but is simpler to interact with.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class MCI_STATUS_INTEL_BITS {
        [JsonProperty(Order = 1)]
        public ushort McaErrorCode;

        [JsonProperty(Order = 2)]
        public ushort ModelErrorCode;

        private MCI_STATUS_INTEL_BITS_FLAGS _Flags;

        [JsonProperty(Order = 3)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        [JsonProperty(Order = 4)]
        public byte OtherInfo => (byte)((uint)_Flags & 0x1F);

        [JsonProperty(Order = 5)]
        public ushort CorrectedErrorCount => (ushort)((uint)_Flags >> 5 & 0x7FFF);

        [JsonProperty(Order = 6)]
        public byte ThresholdErrorStatus => (byte)((uint)_Flags >> 20 & 0x3);
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_AMD_EXTENDED_REGISTERS {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong IPID;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong SYND;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong CONFIG;

        public ulong DESTAT;
        public ulong DEADDR;
        public ulong MISC1;
        public ulong MISC2;
        public ulong MISC3;
        public ulong MISC4;
        public ulong RasCap;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = WHEA_XPF_MCA_SECTION.WHEA_XPF_MCA_EXTREG_MAX_COUNT - WHEA_XPF_MCA_SECTION.WHEA_AMD_EXT_REG_NUM)]
        public ulong[] Reserved;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class XPF_RECOVERY_INFO {
        private XPF_RECOVERY_INFO_FAILURE_REASON_FLAGS _FailureReason;

        [JsonProperty(Order = 1)]
        public string FailureReason => GetEnabledFlagsAsString(_FailureReason);

        private XPF_RECOVERY_INFO_ACTION_FLAGS _Action;

        [JsonProperty(Order = 2)]
        public string Action => GetEnabledFlagsAsString(_Action);

        [JsonProperty(Order = 3)]
        [MarshalAs(UnmanagedType.U1)]
        public bool ActionRequired;

        [JsonProperty(Order = 4)]
        [MarshalAs(UnmanagedType.U1)]
        public bool RecoverySucceeded;

        [JsonProperty(Order = 5)]
        [MarshalAs(UnmanagedType.U1)]
        public bool RecoveryKernel;

        [JsonProperty(Order = 6)]
        public byte Reserved;

        [JsonProperty(Order = 7)]
        public ushort Reserved2;

        [JsonProperty(Order = 8)]
        public ushort Reserved3;

        [JsonProperty(Order = 9)]
        public uint Reserved4;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();

        [UsedImplicitly]
        public static bool ShouldSerializeReserved2() => IsDebugBuild();

        [UsedImplicitly]
        public static bool ShouldSerializeReserved3() => IsDebugBuild();

        [UsedImplicitly]
        public static bool ShouldSerializeReserved4() => IsDebugBuild();
    }

    // @formatter:int_align_fields true

    // Originally defined in the MCG_CAP structure
    [Flags]
    internal enum MCG_CAP_FLAGS : ulong {
        ControlMsrPresent              = 0x100,
        ExtendedMsrsPresent            = 0x200,
        SignalingExtensionPresent      = 0x400,
        ThresholdErrorStatusPresent    = 0x800,
        SoftwareErrorRecoverySupported = 0x1000000,
        EnhancedMachineCheckCapability = 0x2000000,
        ExtendedErrorLogging           = 0x4000000,
        LocalMachineCheckException     = 0x8000000
    }

    [Flags]
    internal enum MCG_STATUS : ulong {
        RestartIpValid         = 0x1,
        ErrorIpValid           = 0x2,
        MachineCheckInProgress = 0x4,
        LocalMceValid          = 0x8
    }

    // Originally defined in the MCI_STATUS_BITS_COMMON structure
    [Flags]
    internal enum MCI_STATUS_BITS_COMMON_FLAGS : uint {
        ContextCorrupt   = 0x2000000,
        AddressValid     = 0x4000000,
        MiscValid        = 0x8000000,
        ErrorEnabled     = 0x10000000,
        UncorrectedError = 0x20000000,
        StatusOverFlow   = 0x40000000,
        Valid            = 0x80000000
    }

    // Originally defined in the MCI_STATUS_AMD_BITS structure
    [Flags]
    internal enum MCI_STATUS_AMD_BITS_FLAGS : uint {
        Poison           = 0x800,
        Deferred         = 0x1000,
        ContextCorrupt   = 0x2000000,
        AddressValid     = 0x4000000,
        MiscValid        = 0x8000000,
        ErrorEnabled     = 0x10000000,
        UncorrectedError = 0x20000000,
        StatusOverFlow   = 0x40000000,
        Valid            = 0x80000000
    }

    // Originally defined in the MCI_STATUS_INTEL_BITS structure
    [Flags]
    internal enum MCI_STATUS_INTEL_BITS_FLAGS : uint {
        FirmwareUpdateError = 0x20,
        ActionRequired      = 0x800000,
        Signalling          = 0x1000000,
        ContextCorrupt      = 0x2000000,
        AddressValid        = 0x4000000,
        MiscValid           = 0x8000000,
        ErrorEnabled        = 0x10000000,
        UncorrectedError    = 0x20000000,
        StatusOverFlow      = 0x40000000,
        Valid               = 0x80000000
    }

    internal enum WHEA_CPU_VENDOR : uint {
        Other = 0,
        Intel = 1,
        Amd   = 2
    }

    // Originally defined in the XPF_RECOVERY_INFO structure
    [Flags]
    internal enum XPF_RECOVERY_INFO_ACTION_FLAGS : uint {
        RecoveryAttempted = 0x1,
        HvHandled         = 0x2,
    }

    // Originally defined in the XPF_RECOVERY_INFO structure
    [Flags]
    internal enum XPF_RECOVERY_INFO_FAILURE_REASON_FLAGS : uint {
        NotSupported             = 0x1,
        Overflow                 = 0x2,
        ContextCorrupt           = 0x4,
        RestartIpErrorIpNotValid = 0x8,
        NoRecoveryContext        = 0x10,
        MiscOrAddrNotValid       = 0x20,
        InvalidAddressMode       = 0x40,
        HighIrql                 = 0x80,
        InterruptsDisabled       = 0x100,
        SwapBusy                 = 0x200,
        StackOverflow            = 0x400
    }

    // @formatter:int_align_fields false
}
