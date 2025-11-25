#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Descriptors;
using DecodeWheaRecord.Internal;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

/*
 * Module       Version             Arch(s)         Function(s)
 * AzPshedPi    11.0.2404.15001     AMD64           AmdPluginFinalizeErrorRecord
 *                                  AMD64           PshedPiGetMemoryErrorSections
 *                                  AMD64           PshedPIHsxFinalizeErrorRec
 *                                  AMD64           PshedPiIcxFinalizeErrorRec
 *                                  AMD64           PshedPISkxFinalizeErrorRec
 * ntoskrnl     10.0.26100.2605     AMD64           HalBugCheckSystem
 *                                  AMD64           HalpCreateMcaMemoryErrorRecord
 *                                  AMD64           HalpCreateMcaProcessorErrorRecord
 *                                  AMD64           KiAltContextProcessorMcheckAltReturn
 *                                  AMD64           KiMcheckAlternateReturn
 *                                  AMD64 / Arm64   WheapReportLiveDump
 * pshed        10.0.26100.1150     AMD64           PshedpPopulateRecoverySection
 */
namespace DecodeWheaRecord.Errors.Microsoft {
    internal sealed class WHEA_XPF_MCA_SECTION : WheaRecord {
        private uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        // Size up to and including the ExtendedRegisters field
        private const uint StructSizeV1 = 264;

        /*
         * Size up to and including the ExtendedRegisters field. This is the
         * original v2 structure where the only difference is the Reserved2
         * field was replaced with the ApicId field.
         */
        private const uint StructSizeV2R1 = 264;

        /*
         * Size up to and including the GlobalCapability field. This is a later
         * "revision" of the v2 structure which added the AMD-specific variant
         * of the ExtendedRegisters field *and* the GlobalCapability field.
         */
        private const uint StructSizeV2R2 = 272;

        // Size up to and including the RecoveryInfo field
        private const uint StructSizeV3 = 292;

        // Size up to and including the MiscEx field
        private const uint StructSizeV4 = 1192;

        // Maximum count of extended registers in the ExtendedRegisters array
        internal const int WHEA_XPF_MCA_EXTREG_MAX_COUNT = 24;

        // Count of MCA banks in each "Ex" array in the Version 4 structure
        private const int WHEA_XPF_MCA_EXBANK_COUNT = 32;

        [JsonProperty(Order = 1)]
        public uint VersionNumber;

        private WHEA_CPU_VENDOR _CpuVendor;

        [JsonProperty(Order = 2)]
        public string CpuVendor => GetEnumValueAsString<WHEA_CPU_VENDOR>(_CpuVendor);

        [JsonProperty(Order = 3)]
        public long Timestamp; // LARGE_INTEGER

        [JsonProperty(Order = 4)]
        public uint ProcessorNumber;

        private MCG_STATUS _GlobalStatus;

        [JsonProperty(Order = 5)]
        public string GlobalStatus => GetEnumFlagsAsString(_GlobalStatus);

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

        // Version 1 only
        [JsonProperty(Order = 12)]
        public uint Reserved2;

        // Version 2 and later
        [JsonProperty(Order = 12)]
        public uint ApicId;

        /*
         * The v1 and original v2 structures only support the vendor-agnostic
         * array of extended register values. The later "revision" of the v2
         * structure added an AMD-specific variant of the extended registers
         * field as part of a union, along with the GlobalCapability field.
         *
         * This means we have to rely on the structure size provided in the
         * section descriptor to determine if the AMD-specific variant of the
         * extended register values may be present, which also implies the
         * presence of the GlobalCapability field (for Intel or AMD).
         *
         * As with the MCI_STATUS union above, we directly embed both fields
         * and marshal the correct one.
         */

        [JsonProperty(Order = 13, ItemConverterType = typeof(HexStringJsonConverter))]
        public ulong[] ExtendedRegisters;

        [JsonProperty(Order = 13)]
        public WHEA_AMD_EXTENDED_REGISTERS AMDExtendedRegisters;

        /*
         * Version 2 fields (rev2 only)
         *
         * The GlobalCapability field was added in a later "revision" of the v2
         * structure. See the earlier comment on the ExtendedRegisters union
         * for more details.
         */

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

        public WHEA_XPF_MCA_SECTION(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_XPF_MCA_SECTION), structOffset, StructSizeV1, bytesRemaining) {
            WheaXpfMcaSection(recordAddr, structOffset, bytesRemaining);
        }

        public WHEA_XPF_MCA_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(typeof(WHEA_XPF_MCA_SECTION), sectionDsc, StructSizeV1, bytesRemaining) {
            WheaXpfMcaSection(recordAddr, sectionDsc.SectionOffset, sectionDsc.SectionLength);
        }

        private void WheaXpfMcaSection(IntPtr recordAddr, uint structOffset, uint bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            VersionNumber = (uint)Marshal.ReadInt32(structAddr);

            switch (VersionNumber) {
                case 1:
                    _StructSize = StructSizeV1;
                    break;
                case 2:
                    _StructSize = bytesRemaining >= StructSizeV2R2 ? StructSizeV2R2 : StructSizeV2R1;
                    break;
                case 3:
                    _StructSize = StructSizeV3;
                    break;
                case 4:
                    _StructSize = StructSizeV4;
                    break;
                default:
                    throw new InvalidDataException($"{nameof(VersionNumber)} is unknown or invalid: {VersionNumber}");
            }

            if (_StructSize > bytesRemaining) {
                var checkCalc = $"{_StructSize} > {bytesRemaining}";
                throw new InvalidDataException($"Expected size is greater than bytes remaining: {checkCalc}");
            }

            _CpuVendor = (WHEA_CPU_VENDOR)Marshal.ReadInt32(structAddr, 4);

            if (string.IsNullOrEmpty(CpuVendor)) {
                throw new InvalidDataException($"{nameof(CpuVendor)} is unknown or invalid: {CpuVendor}");
            }

            Timestamp = Marshal.ReadInt64(structAddr, 8);
            ProcessorNumber = (uint)Marshal.ReadInt32(structAddr, 16);
            _GlobalStatus = (MCG_STATUS)Marshal.ReadInt64(structAddr, 20);
            InstructionPointer = (ulong)Marshal.ReadInt64(structAddr, 28);
            BankNumber = (uint)Marshal.ReadInt32(structAddr, 36);

            // ReSharper disable once SwitchStatementHandlesSomeKnownEnumValuesWithDefault
            switch (_CpuVendor) {
                case WHEA_CPU_VENDOR.Amd:
                    AmdBits = PtrToStructure<MCI_STATUS_AMD_BITS>(structAddr + 40);
                    break;
                case WHEA_CPU_VENDOR.Intel:
                    IntelBits = PtrToStructure<MCI_STATUS_INTEL_BITS>(structAddr + 40);
                    break;
                case WHEA_CPU_VENDOR.Other:
                    CommonBits = PtrToStructure<MCI_STATUS_BITS_COMMON>(structAddr + 40);
                    break;
            }

            Address = (ulong)Marshal.ReadInt64(structAddr, 48);
            Misc = (ulong)Marshal.ReadInt64(structAddr, 56);
            ExtendedRegisterCount = (uint)Marshal.ReadInt32(structAddr, 64);

            if (VersionNumber >= 2) {
                ApicId = (uint)Marshal.ReadInt32(structAddr, 68);
            } else {
                Reserved2 = (uint)Marshal.ReadInt32(structAddr, 68);
            }

            var serializeAmdExtRegs = _CpuVendor == WHEA_CPU_VENDOR.Amd && _StructSize >= StructSizeV2R2;
            if (serializeAmdExtRegs) {
                if (ExtendedRegisterCount > WHEA_AMD_EXTENDED_REGISTERS.WHEA_AMD_EXT_REG_NUM) {
                    var checkCalc = $"{ExtendedRegisterCount} > {WHEA_AMD_EXTENDED_REGISTERS.WHEA_AMD_EXT_REG_NUM}";
                    throw new InvalidDataException($"{nameof(ExtendedRegisterCount)} is invalid for AMD CPU: {checkCalc}");
                }

                AMDExtendedRegisters = PtrToStructure<WHEA_AMD_EXTENDED_REGISTERS>(structAddr + 72);
            } else {
                if (ExtendedRegisterCount > WHEA_XPF_MCA_EXTREG_MAX_COUNT) {
                    var checkCalc = $"{ExtendedRegisterCount} > {WHEA_XPF_MCA_EXTREG_MAX_COUNT}";
                    throw new InvalidDataException($"{nameof(ExtendedRegisterCount)} is greater than maximum allowed for Intel CPU: {checkCalc}");
                }

                var extendedRegistersSigned = new long[ExtendedRegisterCount];
                Marshal.Copy(structAddr + 72, extendedRegistersSigned, 0, (int)ExtendedRegisterCount);
                ExtendedRegisters = new ulong[ExtendedRegisterCount];
                for (var i = 0; i < ExtendedRegisterCount; i++) {
                    ExtendedRegisters[i] = (ulong)extendedRegistersSigned[i];
                }
            }

            if (_StructSize >= StructSizeV2R2) {
                GlobalCapability = PtrToStructure<MCG_CAP>(structAddr + 264);
            }

            if (VersionNumber >= 3) {
                RecoveryInfo = PtrToStructure<XPF_RECOVERY_INFO>(structAddr + 272);
            }

            if (VersionNumber >= 4) {
                ExBankCount = (uint)Marshal.ReadInt32(structAddr, 292);

                var bankNumberExSigned = new int[WHEA_XPF_MCA_EXBANK_COUNT];
                Marshal.Copy(structAddr + 296, bankNumberExSigned, 0, WHEA_XPF_MCA_EXBANK_COUNT);
                BankNumberEx = new uint[WHEA_XPF_MCA_EXBANK_COUNT];
                for (var i = 0; i < WHEA_XPF_MCA_EXBANK_COUNT; i++) {
                    BankNumberEx[i] = (uint)bankNumberExSigned[i];
                }

                var elementSize = Marshal.SizeOf<MCI_STATUS_BITS_COMMON>();
                // ReSharper disable once SwitchStatementHandlesSomeKnownEnumValuesWithDefault
                switch (_CpuVendor) {
                    case WHEA_CPU_VENDOR.Amd:
                        StatusExAmd = new MCI_STATUS_AMD_BITS[WHEA_XPF_MCA_EXBANK_COUNT];
                        for (var i = 0; i < WHEA_XPF_MCA_EXBANK_COUNT; i++) {
                            StatusExAmd[i] = PtrToStructure<MCI_STATUS_AMD_BITS>(structAddr + 424 + i * elementSize);
                        }

                        break;
                    case WHEA_CPU_VENDOR.Intel:
                        StatusExIntel = new MCI_STATUS_INTEL_BITS[WHEA_XPF_MCA_EXBANK_COUNT];
                        for (var i = 0; i < WHEA_XPF_MCA_EXBANK_COUNT; i++) {
                            StatusExIntel[i] = PtrToStructure<MCI_STATUS_INTEL_BITS>(structAddr + 424 + i * elementSize);
                        }

                        break;
                    case WHEA_CPU_VENDOR.Other:
                        StatusExCommon = new MCI_STATUS_BITS_COMMON[WHEA_XPF_MCA_EXBANK_COUNT];
                        for (var i = 0; i < WHEA_XPF_MCA_EXBANK_COUNT; i++) {
                            StatusExCommon[i] = PtrToStructure<MCI_STATUS_BITS_COMMON>(structAddr + 424 + i * elementSize);
                        }

                        break;
                }

                var addressExSigned = new long[WHEA_XPF_MCA_EXBANK_COUNT];
                Marshal.Copy(structAddr + 680, addressExSigned, 0, WHEA_XPF_MCA_EXBANK_COUNT);
                AddressEx = new ulong[WHEA_XPF_MCA_EXBANK_COUNT];
                for (var i = 0; i < WHEA_XPF_MCA_EXBANK_COUNT; i++) {
                    AddressEx[i] = (ulong)addressExSigned[i];
                }

                var miscExSigned = new long[WHEA_XPF_MCA_EXBANK_COUNT];
                Marshal.Copy(structAddr + 936, miscExSigned, 0, WHEA_XPF_MCA_EXBANK_COUNT);
                MiscEx = new ulong[WHEA_XPF_MCA_EXBANK_COUNT];
                for (var i = 0; i < WHEA_XPF_MCA_EXBANK_COUNT; i++) {
                    MiscEx[i] = (ulong)miscExSigned[i];
                }
            }

            FinalizeRecord(recordAddr, _StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeReserved2() => VersionNumber == 1 && Reserved2 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeApicId() => VersionNumber >= 2;

        [UsedImplicitly]
        public bool ShouldSerializeGlobalCapability() => _StructSize >= StructSizeV2R2;

        [UsedImplicitly]
        public bool ShouldSerializeRecoveryInfo() => VersionNumber >= 3;

        [UsedImplicitly]
        public bool ShouldSerializeExBankCount() => VersionNumber >= 4;

        [UsedImplicitly]
        public bool ShouldSerializeBankNumberEx() => VersionNumber >= 4;

        [UsedImplicitly]
        public bool ShouldSerializeStatusExCommon() => VersionNumber >= 4 && CommonBits != null;

        [UsedImplicitly]
        public bool ShouldSerializeStatusExAmd() => VersionNumber >= 4 && AmdBits != null;

        [UsedImplicitly]
        public bool ShouldSerializeStatusExIntel() => VersionNumber >= 4 && IntelBits != null;

        [UsedImplicitly]
        public bool ShouldSerializeAddressEx() => VersionNumber >= 4;

        [UsedImplicitly]
        public bool ShouldSerializeMiscEx() => VersionNumber >= 4;
    }

    // Structure size: 8 bytes
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

    // Structure size: 8 bytes
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

    // Structure size: 8 bytes
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

    // Structure size: 8 bytes
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
        // Number of AMD extended registers
        internal const int WHEA_AMD_EXT_REG_NUM = 10;

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
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = WHEA_XPF_MCA_SECTION.WHEA_XPF_MCA_EXTREG_MAX_COUNT - WHEA_AMD_EXT_REG_NUM)]
        public ulong[] Reserved;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved.Any(element => element != 0);
    }

    // Structure size: 20 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class XPF_RECOVERY_INFO {
        private XPF_RECOVERY_INFO_FAILURE_REASON_FLAGS _FailureReason;

        [JsonProperty(Order = 1)]
        public string FailureReason => GetEnumFlagsAsString(_FailureReason);

        private XPF_RECOVERY_INFO_ACTION_FLAGS _Action;

        [JsonProperty(Order = 2)]
        public string Action => GetEnumFlagsAsString(_Action);

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
