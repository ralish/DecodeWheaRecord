#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming
// ReSharper disable MemberCanBePrivate.Global

using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors {
    internal sealed class WHEA_XPF_MCA_SECTION : WheaErrorRecord {
        private uint _NativeSize;
        public override uint GetNativeSize() => _NativeSize;

        // Size up to and including the GlobalCapability field
        private const uint BaseStructSize = 272;

        // Maximum count of extended registers in ExtendedRegisters array
        internal const int WHEA_XPF_MCA_EXTREG_MAX_COUNT = 24;

        // Number of AMD extended registers in WHEA_AMD_EXTENDED_REGISTERS
        internal const int WHEA_AMD_EXT_REG_NUM = 10;

        // Count of MCA banks in each "Ex" array in the Version 4 structure
        internal const int WHEA_XPF_MCA_EXBANK_COUNT = 32;

        [JsonProperty(Order = 1)]
        public uint VersionNumber;

        private WHEA_CPU_VENDOR _CpuVendor;

        [JsonProperty(Order = 2)]
        public string CpuVendor => Enum.GetName(typeof(WHEA_CPU_VENDOR), _CpuVendor);

        [JsonProperty(Order = 3)]
        public long Timestamp; // TODO: LARGE_INTEGER

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
         * The next three fields contain MCI status information where some of
         * the bits are interpreted dependent on the CPU vendor. The Windows
         * headers define a union with a "common" structure in addition to AMD
         * and Intel variants. We directly embed the different structure types
         * and marshal the correct one.
         *
         * Original type: MCI_STATUS
         */

        [JsonProperty(Order = 8)]
        public MCI_STATUS_BITS_COMMON CommonBits;

        [JsonProperty(Order = 8)]
        public MCI_STATUS_AMD_BITS AmdBits;

        [JsonProperty(Order = 8)]
        public MCI_STATUS_INTEL_BITS IntelBits;

        [JsonProperty(Order = 9)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Address;

        [JsonProperty(Order = 10)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Misc;

        [JsonProperty(Order = 11)]
        public uint ExtendedRegisterCount;

        [JsonProperty(Order = 12)]
        public uint ApicId;

        /*
         * The next two fields comprise what was originally an embedded union
         * which contains either a vendor-agnostic array of extended register
         * values or an AMD-specific variant. As per the earlier comment, we
         * directly embed the the different types and marshal the correct one.
         */

        [JsonProperty(Order = 13, ItemConverterType = typeof(HexStringJsonConverter))]
        public ulong[] ExtendedRegisters;

        [JsonProperty(Order = 13)]
        public WHEA_AMD_EXTENDED_REGISTERS AMDExtendedRegisters;

        [JsonProperty(Order = 14)]
        public MCG_CAP GlobalCapability;

        /*
         * Version 3 fields
         */

        [JsonProperty(Order = 15)]
        public XPF_RECOVERY_INFO RecoveryInfo;

        /*
         * Version 4 fields
         */

        [JsonProperty(Order = 16)]
        public uint ExBankCount;

        [JsonProperty(Order = 17)]
        public uint[] BankNumberEx;

        /*
         * See the earlier comment pertaining to the CommonBits, AmdBits, and
         * IntelBits fields. The same applies here except these fields are an
         * array of the common or vendor-specific MCI status information type.
         */

        [JsonProperty(Order = 18)]
        public MCI_STATUS_BITS_COMMON[] StatusExCommon;

        [JsonProperty(Order = 18)]
        public MCI_STATUS_AMD_BITS[] StatusExAmd;

        [JsonProperty(Order = 18)]
        public MCI_STATUS_INTEL_BITS[] StatusExIntel;

        [JsonProperty(Order = 19, ItemConverterType = typeof(HexStringJsonConverter))]
        public ulong[] AddressEx;

        [JsonProperty(Order = 20, ItemConverterType = typeof(HexStringJsonConverter))]
        public ulong[] MiscEx;

        public WHEA_XPF_MCA_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(WHEA_XPF_MCA_SECTION), BaseStructSize, bytesRemaining) {
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            VersionNumber = (uint)Marshal.ReadInt32(sectionAddr);

            _CpuVendor = (WHEA_CPU_VENDOR)Marshal.ReadInt32(sectionAddr, 4);
            if (string.IsNullOrEmpty(CpuVendor)) {
                throw new InvalidDataException($"{nameof(CpuVendor)} is unknown or invalid: {_CpuVendor}");
            }

            Timestamp = Marshal.ReadInt64(sectionAddr, 8);
            ProcessorNumber = (uint)Marshal.ReadInt32(sectionAddr, 16);
            _GlobalStatus = (MCG_STATUS)Marshal.ReadInt64(sectionAddr, 20);
            InstructionPointer = (ulong)Marshal.ReadInt64(sectionAddr, 28);
            BankNumber = (uint)Marshal.ReadInt32(sectionAddr, 36);

            // ReSharper disable once SwitchStatementHandlesSomeKnownEnumValuesWithDefault
            switch (_CpuVendor) {
                case WHEA_CPU_VENDOR.Amd:
                    AmdBits = Marshal.PtrToStructure<MCI_STATUS_AMD_BITS>(sectionAddr + 40);
                    break;
                case WHEA_CPU_VENDOR.Intel:
                    IntelBits = Marshal.PtrToStructure<MCI_STATUS_INTEL_BITS>(sectionAddr + 40);
                    break;
                case WHEA_CPU_VENDOR.Other:
                    CommonBits = Marshal.PtrToStructure<MCI_STATUS_BITS_COMMON>(sectionAddr + 40);
                    break;
            }

            Address = (ulong)Marshal.ReadInt64(sectionAddr, 48);
            Misc = (ulong)Marshal.ReadInt64(sectionAddr, 56);
            ExtendedRegisterCount = (uint)Marshal.ReadInt32(sectionAddr, 64);
            ApicId = (uint)Marshal.ReadInt32(sectionAddr, 68);

            // ReSharper disable once SwitchStatementHandlesSomeKnownEnumValuesWithDefault
            switch (_CpuVendor) {
                case WHEA_CPU_VENDOR.Amd:
                    AMDExtendedRegisters = Marshal.PtrToStructure<WHEA_AMD_EXTENDED_REGISTERS>(sectionAddr + 72);
                    break;
                case WHEA_CPU_VENDOR.Intel:
                    var numExtRegs = ExtendedRegisterCount <= WHEA_XPF_MCA_EXTREG_MAX_COUNT ? ExtendedRegisterCount : WHEA_XPF_MCA_EXTREG_MAX_COUNT;
                    var extRegsTmp = new long[WHEA_XPF_MCA_EXTREG_MAX_COUNT];
                    ExtendedRegisters = new ulong[WHEA_XPF_MCA_EXTREG_MAX_COUNT];

                    Marshal.Copy(sectionAddr + 72, extRegsTmp, 0, (int)numExtRegs);
                    for (var i = 0; i < numExtRegs; i++) {
                        ExtendedRegisters[i] = (ulong)extRegsTmp[i];
                    }

                    break;
                case WHEA_CPU_VENDOR.Other:
                    // TODO: Should ExtendedRegisters be populated?
                    break;
            }

            GlobalCapability = Marshal.PtrToStructure<MCG_CAP>(sectionAddr + 264);
            var offset = 272;

            if (VersionNumber >= 3) {
                RecoveryInfo = Marshal.PtrToStructure<XPF_RECOVERY_INFO>(sectionAddr + offset);
                offset += Marshal.SizeOf<XPF_RECOVERY_INFO>(); // 292 bytes
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
                offset += 4 * WHEA_XPF_MCA_EXBANK_COUNT;

                // AMD & Intel structures have the same size
                var elementSize = Marshal.SizeOf<MCI_STATUS_BITS_COMMON>();
                // ReSharper disable once SwitchStatementHandlesSomeKnownEnumValuesWithDefault
                switch (_CpuVendor) {
                    case WHEA_CPU_VENDOR.Amd:
                        StatusExAmd = new MCI_STATUS_AMD_BITS[WHEA_XPF_MCA_EXBANK_COUNT];
                        for (var i = 0; i < WHEA_XPF_MCA_EXBANK_COUNT; i++) {
                            StatusExAmd[i] = Marshal.PtrToStructure<MCI_STATUS_AMD_BITS>(sectionAddr + offset + i * elementSize);
                        }

                        break;
                    case WHEA_CPU_VENDOR.Intel:
                        StatusExIntel = new MCI_STATUS_INTEL_BITS[WHEA_XPF_MCA_EXBANK_COUNT];
                        for (var i = 0; i < WHEA_XPF_MCA_EXBANK_COUNT; i++) {
                            StatusExIntel[i] = Marshal.PtrToStructure<MCI_STATUS_INTEL_BITS>(sectionAddr + offset + i * elementSize);
                        }

                        break;
                    case WHEA_CPU_VENDOR.Other:
                        StatusExCommon = new MCI_STATUS_BITS_COMMON[WHEA_XPF_MCA_EXBANK_COUNT];
                        for (var i = 0; i < WHEA_XPF_MCA_EXBANK_COUNT; i++) {
                            StatusExCommon[i] = Marshal.PtrToStructure<MCI_STATUS_BITS_COMMON>(sectionAddr + offset + i * elementSize);
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
                offset += 8 * WHEA_XPF_MCA_EXBANK_COUNT;

                var miscExTmp = new long[WHEA_XPF_MCA_EXBANK_COUNT];
                MiscEx = new ulong[WHEA_XPF_MCA_EXBANK_COUNT];

                Marshal.Copy(sectionAddr + offset, miscExTmp, 0, WHEA_XPF_MCA_EXBANK_COUNT);
                for (var i = 0; i < WHEA_XPF_MCA_EXBANK_COUNT; i++) {
                    MiscEx[i] = (ulong)miscExTmp[i];
                }
                offset += 8 * WHEA_XPF_MCA_EXBANK_COUNT; // 1192 bytes
            }

            _NativeSize = (uint)offset;
            FinalizeRecord(recordAddr, _NativeSize);
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

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class MCG_CAP {
        private ulong _RawBits;

        [JsonProperty(Order = 1)]
        public byte CountField => (byte)_RawBits; // Bits 0-7

        [JsonProperty(Order = 2)]
        public bool ControlMsrPresent => ((_RawBits >> 8) & 0x1) == 1; // Bit 8

        [JsonProperty(Order = 3)]
        public bool ExtendedMsrsPresent => ((_RawBits >> 9) & 0x1) == 1; // Bit 9

        [JsonProperty(Order = 4)]
        public bool SignalingExtensionPresent => ((_RawBits >> 10) & 0x1) == 1; // Bit 10

        [JsonProperty(Order = 5)]
        public bool ThresholdErrorStatusPresent => ((_RawBits >> 11) & 0x1) == 1; // Bit 11

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved => (byte)((_RawBits >> 12) & 0xF); // Bits 12-15

        [JsonProperty(Order = 7)]
        public byte ExtendedRegisterCount => (byte)(_RawBits >> 16); // Bits 16-23

        [JsonProperty(Order = 8)]
        public bool SoftwareErrorRecoverySupported => ((_RawBits >> 24) & 0x1) == 1; // Bit 24

        [JsonProperty(Order = 9)]
        public bool EnhancedMachineCheckCapability => ((_RawBits >> 25) & 0x1) == 1; // Bit 25

        [JsonProperty(Order = 10)]
        public bool ExtendedErrorLogging => ((_RawBits >> 26) & 0x1) == 1; // Bit 26

        [JsonProperty(Order = 11)]
        public bool LocalMachineCheckException => ((_RawBits >> 27) & 0x1) == 1; // Bit 27

        [JsonProperty(Order = 12)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Reserved2 => _RawBits >> 28; // Bit 28-63

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved2() => Reserved != 0;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class MCI_STATUS_BITS_COMMON {
        private ulong _RawBits;

        [JsonProperty(Order = 1)]
        public ushort McaErrorCode => (ushort)_RawBits; // Bits 0-15

        [JsonProperty(Order = 2)]
        public ushort ModelErrorCode => (ushort)(_RawBits >> 16); // Bits 16-31

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Reserved => (uint)((_RawBits >> 32) & 0x1FFFFFF); // Bits 32-56

        [JsonProperty(Order = 4)]
        public bool ContextCorrupt => ((_RawBits >> 57) & 0x1) == 1; // Bit 57

        [JsonProperty(Order = 5)]
        public bool AddressValid => ((_RawBits >> 58) & 0x1) == 1; // Bit 58

        [JsonProperty(Order = 6)]
        public bool MiscValid => ((_RawBits >> 59) & 0x1) == 1; // Bit 59

        [JsonProperty(Order = 7)]
        public bool ErrorEnabled => ((_RawBits >> 60) & 0x1) == 1; // Bit 60

        [JsonProperty(Order = 8)]
        public bool UncorrectedError => ((_RawBits >> 61) & 0x1) == 1; // Bit 61

        [JsonProperty(Order = 9)]
        public bool StatusOverFlow => ((_RawBits >> 62) & 0x1) == 1; // Bit 62

        [JsonProperty(Order = 10)]
        public bool Valid => ((_RawBits >> 63) & 0x1) == 1; // Bit 63

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class MCI_STATUS_AMD_BITS {
        private ulong _RawBits;

        [JsonProperty(Order = 1)]
        public ushort McaErrorCode => (ushort)_RawBits; // Bits 0-15

        [JsonProperty(Order = 2)]
        public ushort ModelErrorCode => (ushort)(_RawBits >> 16); // Bits 16-31

        [JsonProperty(Order = 3)]
        public ushort ImplementationSpecific2 => (ushort)((_RawBits >> 32) & 0x7FF); // Bits 32-42

        [JsonProperty(Order = 4)]
        public bool Poison => ((_RawBits >> 43) & 0x1) == 1; // Bit 43

        [JsonProperty(Order = 5)]
        public bool Deferred => ((_RawBits >> 44) & 0x1) == 1; // Bit 44

        [JsonProperty(Order = 6)]
        public ushort ImplementationSpecific1 => (ushort)((_RawBits >> 45) & 0xFFF); // Bits 45-56

        [JsonProperty(Order = 7)]
        public bool ContextCorrupt => ((_RawBits >> 57) & 0x1) == 1; // Bit 57

        [JsonProperty(Order = 8)]
        public bool AddressValid => ((_RawBits >> 58) & 0x1) == 1; // Bit 58

        [JsonProperty(Order = 9)]
        public bool MiscValid => ((_RawBits >> 59) & 0x1) == 1; // Bit 59

        [JsonProperty(Order = 10)]
        public bool ErrorEnabled => ((_RawBits >> 60) & 0x1) == 1; // Bit 60

        [JsonProperty(Order = 11)]
        public bool UncorrectedError => ((_RawBits >> 61) & 0x1) == 1; // Bit 61

        [JsonProperty(Order = 12)]
        public bool StatusOverFlow => ((_RawBits >> 62) & 0x1) == 1; // Bit 62

        [JsonProperty(Order = 13)]
        public bool Valid => ((_RawBits >> 63) & 0x1) == 1; // Bit 63
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class MCI_STATUS_INTEL_BITS {
        private ulong _RawBits;

        [JsonProperty(Order = 1)]
        public ushort McaErrorCode => (ushort)_RawBits; // Bits 0-15

        [JsonProperty(Order = 2)]
        public ushort ModelErrorCode => (ushort)(_RawBits >> 16); // Bits 16-31

        [JsonProperty(Order = 3)]
        public byte OtherInfo => (byte)((_RawBits >> 32) & 0x1F); // Bits 32-36

        [JsonProperty(Order = 4)]
        public bool FirmwareUpdateError => ((_RawBits >> 37) & 0x1) == 1; // Bit 37

        [JsonProperty(Order = 5)]
        public ushort CorrectedErrorCount => (ushort)((_RawBits >> 38) & 0x7FFF); // Bits 38-52

        [JsonProperty(Order = 6)]
        public byte ThresholdErrorStatus => (byte)((_RawBits >> 53) & 0x3); // Bits 53-54

        [JsonProperty(Order = 7)]
        public bool ActionRequired => ((_RawBits >> 55) & 0x1) == 1; // Bit 55

        [JsonProperty(Order = 8)]
        public bool Signalling => ((_RawBits >> 56) & 0x1) == 1; // Bit 56

        [JsonProperty(Order = 9)]
        public bool ContextCorrupt => ((_RawBits >> 57) & 0x1) == 1; // Bit 57

        [JsonProperty(Order = 10)]
        public bool AddressValid => ((_RawBits >> 58) & 0x1) == 1; // Bit 58

        [JsonProperty(Order = 11)]
        public bool MiscValid => ((_RawBits >> 59) & 0x1) == 1; // Bit 59

        [JsonProperty(Order = 12)]
        public bool ErrorEnabled => ((_RawBits >> 60) & 0x1) == 1; // Bit 60

        [JsonProperty(Order = 13)]
        public bool UncorrectedError => ((_RawBits >> 61) & 0x1) == 1; // Bit 61

        [JsonProperty(Order = 14)]
        public bool StatusOverFlow => ((_RawBits >> 62) & 0x1) == 1; // Bit 62

        [JsonProperty(Order = 15)]
        public bool Valid => ((_RawBits >> 63) & 0x1) == 1; // Bit 63
    }

    // Structure size: 192 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_AMD_EXTENDED_REGISTERS {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong IPID;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong SYND;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong CONFIG;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong DESTAT;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong DEADDR;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MISC1;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MISC2;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MISC3;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MISC4;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong RasCap;

        [JsonProperty(ItemConverterType = typeof(HexStringJsonConverter))]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = WHEA_XPF_MCA_SECTION.WHEA_XPF_MCA_EXTREG_MAX_COUNT - WHEA_XPF_MCA_SECTION.WHEA_AMD_EXT_REG_NUM)]
        public ulong[] Reserved;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved.Any(element => element != 0);
    }

    // Structure size: 20 bytes
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
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved;

        [JsonProperty(Order = 7)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Reserved2;

        [JsonProperty(Order = 8)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Reserved3;

        [JsonProperty(Order = 9)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Reserved4;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved2() => Reserved2 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved3() => Reserved3 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved4() => Reserved4 != 0;
    }

    // @formatter:int_align_fields true

    internal enum WHEA_CPU_VENDOR : uint {
        Other = 0,
        Intel = 1,
        Amd   = 2
    }

    [Flags]
    internal enum MCG_STATUS : ulong {
        RestartIpValid         = 0x1,
        ErrorIpValid           = 0x2,
        MachineCheckInProgress = 0x4,
        LocalMceValid          = 0x8
    }

    // Originally defined in a structure embedded in XPF_RECOVERY_INFO
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

    // Originally defined in a structure embedded in XPF_RECOVERY_INFO
    [Flags]
    internal enum XPF_RECOVERY_INFO_ACTION_FLAGS : uint {
        RecoveryAttempted = 0x1,
        HvHandled         = 0x2
    }

    // @formatter:int_align_fields false
}
