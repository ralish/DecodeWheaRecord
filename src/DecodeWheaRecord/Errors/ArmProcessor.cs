#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly
#pragma warning disable IDE1006 // Naming rule violation

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming
// ReSharper disable PrivateFieldCanBeConvertedToLocalVariable

using System;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;

using DecodeWheaRecord.Internal;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors {
    internal sealed class WHEA_ARM_PROCESSOR_ERROR_SECTION : WheaErrorRecord {
        // Size up to and including the PSCIState field
        private const uint MinStructSize = 40;

        /*
         * Per UEFI Specification R2.11
         *
         * This might be a documentation error as the backing field is 16-bits
         * wide. The ContextInformationStructures field is the same width and
         * is not limited to the maximum value of an unsigned byte.
         */
        private const byte MaxErrorInformationStructures = 255;

        // Per UEFI Specification R2.11
        private const byte MaxErrorAffinityLevel = 3;

        public override uint GetNativeSize() => SectionLength;

        private WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS _ValidBits;

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        [JsonProperty(Order = 2)]
        public ushort ErrorInformationStructures;

        [JsonProperty(Order = 3)]
        public ushort ContextInformationStructures;

        // Total size of the error section
        [JsonProperty(Order = 4)]
        public uint SectionLength;

        [JsonProperty(Order = 5)]
        public byte ErrorAffinityLevel;

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] Reserved = new byte[3];

        [JsonProperty(Order = 7)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MPIDR_EL1;

        [JsonProperty(Order = 8)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MIDR_EL1;

        [JsonProperty(Order = 9)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint RunningState;

        [JsonProperty(Order = 10)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint PSCIState;

        /*
         * The original structure has one additional field typed as a variable
         * length byte array. We've expanded it into three separate arrays that
         * correspond to the error information structures, context information
         * structures, and vendor specific error information.
         */

        [JsonProperty(Order = 11)]
        public WHEA_ARM_PROCESSOR_ERROR_INFORMATION[] ErrorInformation;

        [JsonProperty(Order = 12)]
        public WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER[] ContextInformation;

        [JsonProperty(Order = 13)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] VendorInformation;

        public WHEA_ARM_PROCESSOR_ERROR_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(WHEA_ARM_PROCESSOR_ERROR_SECTION), MinStructSize, bytesRemaining) {
            var logCat = SectionType.Name;
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            _ValidBits = (WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS)Marshal.ReadInt32(sectionAddr);

            ErrorInformationStructures = (ushort)Marshal.ReadInt16(sectionAddr, 4);
            if (ErrorInformationStructures == 0) {
                WarnOutput($"{nameof(ErrorInformationStructures)} is zero (expected at least one structure).", logCat);
            } else if (ErrorInformationStructures > MaxErrorInformationStructures) {
                WarnOutput($"{nameof(ErrorInformationStructures)} is greater than maximum allowed of {MaxErrorInformationStructures}.", logCat);
            }

            ContextInformationStructures = (ushort)Marshal.ReadInt16(sectionAddr, 6);

            SectionLength = (uint)Marshal.ReadInt32(sectionAddr, 8);
            if (SectionLength < MinStructSize) {
                throw new InvalidDataException($"{nameof(SectionLength)} is less than minimum expected bytes: {SectionLength} < {MinStructSize}");
            }
            if (SectionLength > sectionDsc.SectionLength) {
                throw new InvalidDataException($"{nameof(SectionLength)} is greater than in section descriptor: {SectionLength} > {sectionDsc.SectionLength}");
            }

            ErrorAffinityLevel = Marshal.ReadByte(sectionAddr, 12);
            if (ShouldSerializeErrorAffinityLevel() && ErrorAffinityLevel > MaxErrorAffinityLevel) {
                WarnOutput($"{nameof(ErrorAffinityLevel)} above maximum of {MaxErrorAffinityLevel}.", logCat);
            }

            Marshal.Copy(sectionAddr + 13, Reserved, 0, 3);
            if (Reserved.Any(element => element != 0)) {
                WarnOutput($"{nameof(Reserved)} has non-zero bytes.", logCat);
            }

            MPIDR_EL1 = (ulong)Marshal.ReadInt64(sectionAddr, 16);
            MIDR_EL1 = (ulong)Marshal.ReadInt64(sectionAddr, 24);
            RunningState = (uint)Marshal.ReadInt32(sectionAddr, 32);

            PSCIState = (uint)Marshal.ReadInt32(sectionAddr, 36);
            // PSCIState should be zero when bit 0 of RunningState is set
            if (ShouldSerializeRunningState() && (RunningState & 0x1) == 1 && PSCIState != 0) {
                WarnOutput($"{nameof(PSCIState)} is non-zero but {nameof(RunningState)} indicates it should be zero.", logCat);
            }

            var offset = 40;

            ErrorInformation = new WHEA_ARM_PROCESSOR_ERROR_INFORMATION[ErrorInformationStructures];
            if (ErrorInformationStructures > 0) {
                for (var i = 0; i < ErrorInformationStructures; i++) {
                    ErrorInformation[i] = new WHEA_ARM_PROCESSOR_ERROR_INFORMATION(recordAddr,
                                                                                   sectionDsc.SectionOffset + (uint)offset,
                                                                                   SectionLength - (uint)offset);
                    offset += (int)ErrorInformation[i].GetNativeSize();
                }
            }

            ContextInformation = new WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER[ContextInformationStructures];
            if (ContextInformationStructures > 0) {
                for (var i = 0; i < ContextInformationStructures; i++) {
                    ContextInformation[i] = new WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER(recordAddr,
                                                                                                    sectionDsc.SectionOffset + (uint)offset,
                                                                                                    SectionLength - (uint)offset);

                    // Padding for when the size is not a multiple of 16 bytes
                    var ctxInfoStructSize = ContextInformation[i].GetNativeSize();
                    var ctxInfoStructPad = ctxInfoStructSize % 16;
                    offset += (int)(ctxInfoStructSize + ctxInfoStructPad);
                }
            }

            // Any remaining data is vendor specific information
            if (offset < SectionLength) {
                if (ShouldSerializeVendorInformation()) {
                    VendorInformation = new byte[SectionLength - offset];
                    Marshal.Copy(recordAddr + offset, VendorInformation, 0, VendorInformation.Length);
                } else {
                    WarnOutput($"Number of bytes marshalled less than {nameof(SectionLength)}: {SectionLength - offset} > {SectionLength}", logCat);
                }
            }

            FinalizeRecord(recordAddr, SectionLength);
        }

        [UsedImplicitly]
        public bool ShouldSerializeErrorAffinityLevel() => (_ValidBits & WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.AffinityLevel) != 0;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();

        [UsedImplicitly]
        public bool ShouldSerializeMPIDR_EL1() => (_ValidBits & WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.MPIDR) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeRunningState() => (_ValidBits & WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.RunningState) != 0;

        // Valid when bit 0 of RunningState is unset
        [UsedImplicitly]
        public bool ShouldSerializePSCIState() => ShouldSerializeRunningState() && (RunningState & 0x1) == 0;

        [UsedImplicitly]
        public bool ShouldSerializeVendorInformation() => (_ValidBits & WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.VendorSpecificInfo) != 0;
    }

    internal sealed class WHEA_ARM_PROCESSOR_ERROR_INFORMATION : WheaErrorRecord {
        // Per UEFI Specification R2.11
        private const byte ExpectedVersion = 0;

        // Structure size is static
        private const byte ExpectedLength = 32;

        public override uint GetNativeSize() => Length;

        [JsonProperty(Order = 1)]
        public byte Version;

        [JsonProperty(Order = 2)]
        public byte Length;

        private WHEA_ARM_PROCESSOR_ERROR_INFORMATION_VALID_BITS _ValidationBit;

        [JsonProperty(Order = 3)]
        public string ValidationBit => GetEnabledFlagsAsString(_ValidationBit);

        // Switched to an enumeration
        private WHEA_ARM_PROCESSOR_ERROR_INFORMATION_TYPE _Type;

        [JsonProperty(Order = 4)]
        public string Type => Enum.GetName(typeof(WHEA_ARM_PROCESSOR_ERROR_INFORMATION_TYPE), _Type);

        // Values 0 and 1 are special so serialize a string for extra info
        private ushort _MultipleError;

        [JsonProperty(Order = 5)]
        public string MultipleError;

        // Switched to an enumeration
        private WHEA_ARM_PROCESSOR_ERROR_INFORMATION_FLAGS _Flags;

        [JsonProperty(Order = 6)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        /*
         * The next four fields contain the error information for the type of
         * error as determined by the Type field. The Windows headers define
         * them in a union structure but we directly embed them and marshal
         * only the correct one when marshalling this structure.
         *
         * Original type: WHEA_ARM_PROCESSOR_ERROR
         */

        [JsonProperty(Order = 7)]
        public WHEA_ARM_CACHE_ERROR CacheError;

        [JsonProperty(Order = 7)]
        public WHEA_ARM_TLB_ERROR TlbError;

        [JsonProperty(Order = 7)]
        public WHEA_ARM_BUS_ERROR BusError;

        // Micro-architecture error structures are vendor specific
        [JsonProperty(Order = 7)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MaeError;

        [JsonProperty(Order = 8)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong VirtualFaultAddress;

        [JsonProperty(Order = 9)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong PhysicalFaultAddress;

        public WHEA_ARM_PROCESSOR_ERROR_INFORMATION(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_ARM_PROCESSOR_ERROR_INFORMATION), structOffset, ExpectedLength, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            Version = Marshal.ReadByte(structAddr);
            if (Version != ExpectedVersion) {
                throw new InvalidDataException($"Expected {nameof(Version)} to be {ExpectedVersion} but found: {Version}");
            }

            Length = Marshal.ReadByte(structAddr, 1);
            if (Length != ExpectedLength) {
                throw new InvalidDataException($"Expected {nameof(Length)} to be {ExpectedLength} but found: {Length}");
            }

            _ValidationBit = (WHEA_ARM_PROCESSOR_ERROR_INFORMATION_VALID_BITS)Marshal.ReadInt16(structAddr, 2);
            _Type = (WHEA_ARM_PROCESSOR_ERROR_INFORMATION_TYPE)Marshal.ReadByte(structAddr, 4);

            _MultipleError = (ushort)Marshal.ReadInt16(structAddr, 5);
            if (ShouldSerializeMultipleError()) {
                switch (_MultipleError) {
                    case 0:
                        MultipleError = "Single error";
                        break;
                    case 1:
                        MultipleError = "Multiple errors";
                        break;
                    default:
                        MultipleError = $"{_MultipleError} errors";
                        break;
                }
            }

            _Flags = (WHEA_ARM_PROCESSOR_ERROR_INFORMATION_FLAGS)Marshal.ReadByte(structAddr, 7);

            if (ShouldSerializeErrorInformation()) {
                var errInfoStructAddr = structAddr + 8;
                switch (_Type) {
                    case WHEA_ARM_PROCESSOR_ERROR_INFORMATION_TYPE.Cache:
                        CacheError = Marshal.PtrToStructure<WHEA_ARM_CACHE_ERROR>(errInfoStructAddr);
                        break;
                    case WHEA_ARM_PROCESSOR_ERROR_INFORMATION_TYPE.TLB:
                        TlbError = Marshal.PtrToStructure<WHEA_ARM_TLB_ERROR>(errInfoStructAddr);
                        break;
                    case WHEA_ARM_PROCESSOR_ERROR_INFORMATION_TYPE.Bus:
                        BusError = Marshal.PtrToStructure<WHEA_ARM_BUS_ERROR>(errInfoStructAddr);
                        break;
                    case WHEA_ARM_PROCESSOR_ERROR_INFORMATION_TYPE.MAE:
                        MaeError = (ulong)Marshal.ReadInt64(errInfoStructAddr);
                        break;
                    default:
                        throw new InvalidDataException($"{nameof(Type)} is unknown or invalid: {Type}");
                }
            }

            VirtualFaultAddress = (ulong)Marshal.ReadInt64(structAddr, 16);
            PhysicalFaultAddress = (ulong)Marshal.ReadInt64(structAddr, 24);

            FinalizeRecord(recordAddr, Length);
        }

        [UsedImplicitly]
        public bool ShouldSerializeMultipleError() => (_ValidationBit & WHEA_ARM_PROCESSOR_ERROR_INFORMATION_VALID_BITS.MultipleError) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeFlags() => (_ValidationBit & WHEA_ARM_PROCESSOR_ERROR_INFORMATION_VALID_BITS.Flags) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeErrorInformation() => (_ValidationBit & WHEA_ARM_PROCESSOR_ERROR_INFORMATION_VALID_BITS.ErrorInformation) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeVirtualFaultAddress() => (_ValidationBit & WHEA_ARM_PROCESSOR_ERROR_INFORMATION_VALID_BITS.VirtualFaultAddress) != 0;

        [UsedImplicitly]
        public bool ShouldSerializePhysicalFaultAddress() => (_ValidationBit & WHEA_ARM_PROCESSOR_ERROR_INFORMATION_VALID_BITS.PhysicalFaultAddress) != 0;
    }

    // Originally a 64-bits wide bitfield
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ARM_CACHE_ERROR {
        private ulong _RawBits;

        private WHEA_ARM_CACHE_ERROR_VALID_BITS _ValidationBit => (WHEA_ARM_CACHE_ERROR_VALID_BITS)_RawBits; // Bits 0-15

        [JsonProperty(Order = 1)]
        public string ValidationBit => GetEnabledFlagsAsString(_ValidationBit);

        // Switched to an enumeration
        [JsonProperty(Order = 2)]
        public string TransactionType => Enum.GetName(typeof(WHEA_ARM_CACHE_ERROR_TRANSACTION_TYPE), (byte)((_RawBits >> 16) & 0x3)); // Bits 16-17

        // Switched to an enumeration
        [JsonProperty(Order = 3)]
        public string Operation => Enum.GetName(typeof(WHEA_ARM_CACHE_ERROR_OPERATION), (byte)((_RawBits >> 18) & 0xF)); // Bits 18-21

        [JsonProperty(Order = 4)]
        public byte Level => (byte)((_RawBits >> 22) & 0x7); // Bits 22-24

        [JsonProperty(Order = 5)]
        public bool ProcessorContextCorrupt => ((_RawBits >> 25) & 0x1) == 1; // Bit 25

        [JsonProperty(Order = 6)]
        public bool Corrected => ((_RawBits >> 26) & 0x1) == 1; // Bit 26

        [JsonProperty(Order = 7)]
        public bool PrecisePC => ((_RawBits >> 27) & 0x1) == 1; // Bit 27

        [JsonProperty(Order = 8)]
        public bool RestartablePC => ((_RawBits >> 28) & 0x1) == 1; // Bit 28

        [UsedImplicitly]
        public bool ShouldSerializeTransactionType() => (_ValidationBit & WHEA_ARM_CACHE_ERROR_VALID_BITS.TransactionType) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeOperation() => (_ValidationBit & WHEA_ARM_CACHE_ERROR_VALID_BITS.Operation) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeLevel() => (_ValidationBit & WHEA_ARM_CACHE_ERROR_VALID_BITS.Level) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeProcessorContextCorrupt() => (_ValidationBit & WHEA_ARM_CACHE_ERROR_VALID_BITS.ProcessorContextCorrupt) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeCorrected() => (_ValidationBit & WHEA_ARM_CACHE_ERROR_VALID_BITS.Corrected) != 0;

        [UsedImplicitly]
        public bool ShouldSerializePrecisePC() => (_ValidationBit & WHEA_ARM_CACHE_ERROR_VALID_BITS.PrecisePC) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeRestartablePC() => (_ValidationBit & WHEA_ARM_CACHE_ERROR_VALID_BITS.RestartablePC) != 0;
    }

    // Originally a 64-bits wide bitfield
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ARM_TLB_ERROR {
        private ulong _RawBits;

        private WHEA_ARM_TLB_ERROR_VALID_BITS _ValidationBit => (WHEA_ARM_TLB_ERROR_VALID_BITS)_RawBits; // Bits 0-15

        [JsonProperty(Order = 1)]
        public string ValidationBit => GetEnabledFlagsAsString(_ValidationBit);

        // Switched to an enumeration
        [JsonProperty(Order = 2)]
        public string TransactionType => Enum.GetName(typeof(WHEA_ARM_TLB_ERROR_TRANSACTION_TYPE), (byte)((_RawBits >> 16) & 0x3)); // Bits 16-17

        // Switched to an enumeration
        [JsonProperty(Order = 3)]
        public string Operation => Enum.GetName(typeof(WHEA_ARM_TLB_ERROR_OPERATION), (byte)((_RawBits >> 18) & 0xF)); // Bits 18-21

        [JsonProperty(Order = 4)]
        public byte Level => (byte)((_RawBits >> 22) & 0x7); // Bits 22-24

        [JsonProperty(Order = 5)]
        public bool ProcessorContextCorrupt => ((_RawBits >> 25) & 0x1) == 1; // Bit 25

        [JsonProperty(Order = 6)]
        public bool Corrected => ((_RawBits >> 26) & 0x1) == 1; // Bit 26

        [JsonProperty(Order = 7)]
        public bool PrecisePC => ((_RawBits >> 27) & 0x1) == 1; // Bit 27

        [JsonProperty(Order = 8)]
        public bool RestartablePC => ((_RawBits >> 28) & 0x1) == 1; // Bit 28

        [UsedImplicitly]
        public bool ShouldSerializeTransactionType() => (_ValidationBit & WHEA_ARM_TLB_ERROR_VALID_BITS.TransactionType) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeOperation() => (_ValidationBit & WHEA_ARM_TLB_ERROR_VALID_BITS.Operation) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeLevel() => (_ValidationBit & WHEA_ARM_TLB_ERROR_VALID_BITS.Level) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeProcessorContextCorrupt() => (_ValidationBit & WHEA_ARM_TLB_ERROR_VALID_BITS.ProcessorContextCorrupt) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeCorrected() => (_ValidationBit & WHEA_ARM_TLB_ERROR_VALID_BITS.Corrected) != 0;

        [UsedImplicitly]
        public bool ShouldSerializePrecisePC() => (_ValidationBit & WHEA_ARM_TLB_ERROR_VALID_BITS.PrecisePC) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeRestartablePC() => (_ValidationBit & WHEA_ARM_TLB_ERROR_VALID_BITS.RestartablePC) != 0;
    }

    // Originally a 64-bits wide bitfield
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ARM_BUS_ERROR {
        private ulong _RawBits;

        private WHEA_ARM_BUS_ERROR_VALID_BITS _ValidationBit => (WHEA_ARM_BUS_ERROR_VALID_BITS)_RawBits; // Bits 0-15

        [JsonProperty(Order = 1)]
        public string ValidationBit => GetEnabledFlagsAsString(_ValidationBit);

        // Switched to an enumeration
        [JsonProperty(Order = 2)]
        public string TransactionType => Enum.GetName(typeof(WHEA_ARM_BUS_ERROR_TRANSACTION_TYPE), (byte)((_RawBits >> 16) & 0x3)); // Bits 16-17

        // Switched to an enumeration
        [JsonProperty(Order = 3)]
        public string Operation => Enum.GetName(typeof(WHEA_ARM_BUS_ERROR_OPERATION), (byte)((_RawBits >> 18) & 0xF)); // Bits 18-21

        [JsonProperty(Order = 4)]
        public byte Level => (byte)((_RawBits >> 22) & 0x7); // Bits 22-24

        [JsonProperty(Order = 5)]
        public bool ProcessorContextCorrupt => ((_RawBits >> 25) & 0x1) == 1; // Bit 25

        [JsonProperty(Order = 6)]
        public bool Corrected => ((_RawBits >> 26) & 0x1) == 1; // Bit 26

        [JsonProperty(Order = 7)]
        public bool PrecisePC => ((_RawBits >> 27) & 0x1) == 1; // Bit 27

        [JsonProperty(Order = 8)]
        public bool RestartablePC => ((_RawBits >> 28) & 0x1) == 1; // Bit 28

        // Switched to an enumeration
        [JsonProperty(Order = 9)]
        public string ParticipationType => Enum.GetName(typeof(WHEA_ARM_BUS_ERROR_PARTICIPATION_TYPE), (byte)((_RawBits >> 29) & 0x3)); // Bits 29-30

        [JsonProperty(Order = 10)]
        public bool Timeout => ((_RawBits >> 31) & 0x1) == 1; // Bit 31

        // Switched to an enumeration
        [JsonProperty(Order = 11)]
        public string AddressSpace => Enum.GetName(typeof(WHEA_ARM_BUS_ERROR_ADDRESS_SPACE), (byte)((_RawBits >> 32) & 0x3)); // Bits 32-33

        // Future: Defined in the ARM specification
        [JsonProperty(Order = 12)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort MemoryAccessAttributes => (ushort)((_RawBits >> 34) & 0x1FF); // Bits 34-42

        // Switched to an enumeration
        [JsonProperty(Order = 13)]
        public string AccessMode => Enum.GetName(typeof(WHEA_ARM_BUS_ERROR_ACCESS_MODE), (byte)((_RawBits >> 42) & 0x1)); // Bit 43

        [UsedImplicitly]
        public bool ShouldSerializeTransactionType() => (_ValidationBit & WHEA_ARM_BUS_ERROR_VALID_BITS.TransactionType) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeOperation() => (_ValidationBit & WHEA_ARM_BUS_ERROR_VALID_BITS.Operation) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeLevel() => (_ValidationBit & WHEA_ARM_BUS_ERROR_VALID_BITS.Level) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeProcessorContextCorrupt() => (_ValidationBit & WHEA_ARM_BUS_ERROR_VALID_BITS.ProcessorContextCorrupt) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeCorrected() => (_ValidationBit & WHEA_ARM_BUS_ERROR_VALID_BITS.Corrected) != 0;

        [UsedImplicitly]
        public bool ShouldSerializePrecisePC() => (_ValidationBit & WHEA_ARM_BUS_ERROR_VALID_BITS.PrecisePC) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeRestartablePC() => (_ValidationBit & WHEA_ARM_BUS_ERROR_VALID_BITS.RestartablePC) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeParticipationType() => (_ValidationBit & WHEA_ARM_BUS_ERROR_VALID_BITS.ParticipationType) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeTimeOut() => (_ValidationBit & WHEA_ARM_BUS_ERROR_VALID_BITS.Timeout) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeAddressSpace() => (_ValidationBit & WHEA_ARM_BUS_ERROR_VALID_BITS.AddressSpace) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeMemoryAccessAttributes() => (_ValidationBit & WHEA_ARM_BUS_ERROR_VALID_BITS.MemoryAttributes) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeAccessMode() => (_ValidationBit & WHEA_ARM_BUS_ERROR_VALID_BITS.AccessMode) != 0;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER : WheaErrorRecord {
        // Size up to and including the RegisterArraySize field
        private const uint MinStructSize = 8;

        // Per UEFI Specification R2.11
        private const ushort ExpectedVersion = 0;

        private uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        [JsonProperty(Order = 1)]
        public ushort Version;

        // Switched to an enumeration
        private WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE _RegisterContextType;

        [JsonProperty(Order = 2)]
        public string RegisterContextType =>
            Enum.GetName(typeof(WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE), _RegisterContextType);

        [JsonProperty(Order = 3)]
        public uint RegisterArraySize;

        /*
         * The original structure has one additional field typed as a variable
         * length byte array. We've expanded it into separate fields typed to
         * the matching structures from the RegisterContextType enumeration.
         */

        [JsonProperty(Order = 4)]
        public WHEA_ARMV8_AARCH32_GPRS AArch32GPR;

        [JsonProperty(Order = 4)]
        public WHEA_ARMV8_AARCH32_EL1_CSR AArch32EL1;

        [JsonProperty(Order = 4)]
        public WHEA_ARMV8_AARCH32_EL2_CSR AArch32EL2;

        [JsonProperty(Order = 4)]
        public WHEA_ARMV8_AARCH32_SECURE_CSR AArch32Secure;

        [JsonProperty(Order = 4)]
        public WHEA_ARMV8_AARCH64_GPRS AArch64GPR;

        [JsonProperty(Order = 4)]
        public WHEA_ARMV8_AARCH64_EL1_CSR AArch64EL1;

        [JsonProperty(Order = 4)]
        public WHEA_ARMV8_AARCH64_EL2_CSR AArch64EL2;

        [JsonProperty(Order = 4)]
        public WHEA_ARMV8_AARCH64_EL3_CSR AArch64EL3;

        [JsonProperty(Order = 4)]
        public WHEA_ARM_MISR_CSR AArchMisc;

        [JsonProperty(Order = 4)]
        public WHEA_ARMV8_AARCH64_TT128 AArch64TT128;

        public WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER), structOffset, MinStructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            Version = (ushort)Marshal.ReadInt16(structAddr);
            if (Version != ExpectedVersion) {
                throw new InvalidDataException($"Expected {nameof(Version)} to be {ExpectedVersion} but found: {Version}");
            }

            _RegisterContextType = (WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE)Marshal.ReadInt16(structAddr, 2);
            RegisterArraySize = (uint)Marshal.ReadInt32(structAddr, 4);

            var ctxInfoStructAddr = structAddr + (int)MinStructSize;
            int ctxInfoStructSize;

            switch (_RegisterContextType) {
                case WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE.AArch32GPR:
                    AArch32GPR = Marshal.PtrToStructure<WHEA_ARMV8_AARCH32_GPRS>(ctxInfoStructAddr);
                    ctxInfoStructSize = Marshal.SizeOf<WHEA_ARMV8_AARCH32_GPRS>();
                    break;
                case WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE.AArch32EL1:
                    AArch32EL1 = Marshal.PtrToStructure<WHEA_ARMV8_AARCH32_EL1_CSR>(ctxInfoStructAddr);
                    ctxInfoStructSize = Marshal.SizeOf<WHEA_ARMV8_AARCH32_EL1_CSR>();
                    break;
                case WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE.AArch32EL2:
                    AArch32EL2 = Marshal.PtrToStructure<WHEA_ARMV8_AARCH32_EL2_CSR>(ctxInfoStructAddr);
                    ctxInfoStructSize = Marshal.SizeOf<WHEA_ARMV8_AARCH32_EL2_CSR>();
                    break;
                case WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE.AArch32Secure:
                    AArch32Secure = Marshal.PtrToStructure<WHEA_ARMV8_AARCH32_SECURE_CSR>(ctxInfoStructAddr);
                    ctxInfoStructSize = Marshal.SizeOf<WHEA_ARMV8_AARCH32_SECURE_CSR>();
                    break;
                case WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE.AArch64GPR:
                    AArch64GPR = Marshal.PtrToStructure<WHEA_ARMV8_AARCH64_GPRS>(ctxInfoStructAddr);
                    ctxInfoStructSize = Marshal.SizeOf<WHEA_ARMV8_AARCH64_GPRS>();
                    break;
                case WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE.AArch64EL1:
                    AArch64EL1 = Marshal.PtrToStructure<WHEA_ARMV8_AARCH64_EL1_CSR>(ctxInfoStructAddr);
                    ctxInfoStructSize = Marshal.SizeOf<WHEA_ARMV8_AARCH64_EL1_CSR>();
                    break;
                case WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE.AArch64EL2:
                    AArch64EL2 = Marshal.PtrToStructure<WHEA_ARMV8_AARCH64_EL2_CSR>(ctxInfoStructAddr);
                    ctxInfoStructSize = Marshal.SizeOf<WHEA_ARMV8_AARCH64_EL2_CSR>();
                    break;
                case WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE.AArch64EL3:
                    AArch64EL3 = Marshal.PtrToStructure<WHEA_ARMV8_AARCH64_EL3_CSR>(ctxInfoStructAddr);
                    ctxInfoStructSize = Marshal.SizeOf<WHEA_ARMV8_AARCH64_EL3_CSR>();
                    break;
                case WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE.AArchMisc:
                    AArchMisc = Marshal.PtrToStructure<WHEA_ARM_MISR_CSR>(ctxInfoStructAddr);
                    ctxInfoStructSize = Marshal.SizeOf<WHEA_ARM_MISR_CSR>();
                    break;
                case WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE.AArch64TT128:
                    AArch64TT128 = new WHEA_ARMV8_AARCH64_TT128(recordAddr, structOffset + MinStructSize, bytesRemaining - MinStructSize);
                    ctxInfoStructSize = (int)AArch64TT128.GetNativeSize();
                    break;
                default:
                    throw new InvalidDataException($"{nameof(RegisterContextType)} is unknown or invalid: {RegisterContextType}");
            }

            if (RegisterArraySize != ctxInfoStructSize) {
                throw new InvalidDataContractException($"Register context size does not equal expected size: {ctxInfoStructSize} != {RegisterArraySize}");
            }

            _StructSize = MinStructSize + RegisterArraySize;
            FinalizeRecord(recordAddr, _StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeAArch32GPR => _RegisterContextType == WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE.AArch32GPR;

        [UsedImplicitly]
        public bool ShouldSerializeAArch32EL1 => _RegisterContextType == WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE.AArch32EL1;

        [UsedImplicitly]
        public bool ShouldSerializeAArch32EL2 => _RegisterContextType == WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE.AArch32EL2;

        [UsedImplicitly]
        public bool ShouldSerializeAArch32Secure =>
            _RegisterContextType == WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE.AArch32Secure;

        [UsedImplicitly]
        public bool ShouldSerializeAArch64GPR => _RegisterContextType == WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE.AArch64GPR;

        [UsedImplicitly]
        public bool ShouldSerializeAArch64EL1 => _RegisterContextType == WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE.AArch64EL1;

        [UsedImplicitly]
        public bool ShouldSerializeAArch64EL2 => _RegisterContextType == WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE.AArch64EL2;

        [UsedImplicitly]
        public bool ShouldSerializeAArch64EL3 => _RegisterContextType == WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE.AArch64EL3;

        [UsedImplicitly]
        public bool ShouldSerializeAArchMisc => _RegisterContextType == WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE.AArchMisc;

        [UsedImplicitly]
        public bool ShouldSerializeAArch64TT128 =>
            _RegisterContextType == WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE.AArch64TT128;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ARMV8_AARCH32_GPRS {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint R0;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint R1;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint R2;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint R3;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint R4;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint R5;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint R6;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint R7;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint R8;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint R9;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint R10;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint R11;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint R12;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint R13; // SP

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint R14; // LR

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint R15; // PC
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ARMV8_AARCH32_EL1_CSR {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint DFAR;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint DFSR;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint IFAR;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint ISR;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint MAIR0;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint MAIR1;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint MIDR;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint MPIDR;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint NMRR;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint PRRR;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint SCTLR; // NS

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint SPSR;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint SPSR_abt;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint SPSR_fiq;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint SPSR_irq;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint SPSR_svc;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint SPSR_und;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint TPIDRPRW;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint TPIDRURO;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint TPIDRURW;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint TTBCR;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint TTBR0;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint TTBR1;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint DACR;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ARMV8_AARCH32_EL2_CSR {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint ELR_hyp;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint HAMAIR0;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint HAMAIR1;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint HCR;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint HCR2;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint HDFAR;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint HIFAR;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint HPFAR;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint HSR;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint HTCR;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint HTPIDR;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint HTTBR;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint SPSR_hyp;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint VTCR;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint VTTBR;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint DACR32_EL2;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ARMV8_AARCH32_SECURE_CSR {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint SCTLR; // S

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint SPSR_mon;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ARMV8_AARCH64_GPRS {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X0;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X1;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X2;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X3;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X4;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X5;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X6;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X7;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X8;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X9;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X10;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X11;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X12;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X13;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X14;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X15;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X16;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X17;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X18;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X19;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X20;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X21;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X22;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X23;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X24;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X25;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X26;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X27;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X28;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X29;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong X30;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong SP;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ARMV8_AARCH64_EL1_CSR {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ELR_EL1;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ESR_EL2;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong FAR_EL1;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ISR_EL1;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MAIR_EL1;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MIDR_EL1;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MPIDR_EL1;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong SCTLR_EL1;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong SP_EL0;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong SP_EL1;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong SPSR_EL1;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong TCR_EL1;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong TPIDR_EL0;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong TPIDR_EL1;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong TPIDRRO_EL0;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong TTBR0_EL1;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong TTBR1_EL1;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ARMV8_AARCH64_EL2_CSR {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ELR_EL2;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ESR_EL2;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong FAR_EL2;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong HACR_EL2;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong HCR_EL2;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong HPFAR_EL2;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MAIR_EL2;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong SCTLR_EL2;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong SP_EL2;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong SPSR_EL2;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong TCR_EL2;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong TPIDR_EL2;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong TTBR0_EL2;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong VTR_EL2;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong VTTBR_EL2;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ARMV8_AARCH64_EL3_CSR {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ELR_EL3;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ESR_EL3;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong FAR_EL3;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MAIR_EL3;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong SCTLR_EL3;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong SP_EL3;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong SPSR_EL3;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong TCR_EL3;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong TPIDR_EL3;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong TTBR0_EL3;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ARM_MISR_CSR {
        // Switched to a 16-bits wide bitfield
        public WHEA_ARM_MISR_CSR_MRS_ENCODING MRSEncoding;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Value;
    }

    // Not in the Windows headers and derived from UEFI Specification R2.11
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ARM_MISR_CSR_MRS_ENCODING {
        public ushort _RawBits;

        [JsonProperty(Order = 1)]
        public byte Op2 => (byte)(_RawBits & 0x7); // Bits 0-2

        [JsonProperty(Order = 2)]
        public byte CRm => (byte)((_RawBits >> 3) & 0xF); // Bits 3-6

        [JsonProperty(Order = 3)]
        public byte CRn => (byte)((_RawBits >> 7) & 0x7); // Bits 7-10

        [JsonProperty(Order = 4)]
        public byte Op1 => (byte)((_RawBits >> 11) & 0x7); // Bits 11-13

        [JsonProperty(Order = 5)]
        public bool O0 => ((_RawBits >> 14) & 0x1) != 0; // Bit 14
    }

    /*
     * Not in the Windows headers and derived from UEFI Specification R2.11
     *
     * This implementation assumes the processor is running in little-endian
     * mode. While ARMv8 can run in big-endian mode, Windows on ARM64 always
     * runs in little-endian mode so this feels like a safe assumption.
     */
    internal sealed class WHEA_ARMV8_AARCH64_TT128 : WheaErrorRecord {
        // Structure size is static
        private const uint StructSize = 96;

        public override uint GetNativeSize() => StructSize;

        private ulong _TTBR0_EL1_Low;
        private ulong _TTBR0_EL1_High;

        [JsonProperty(Order = 1)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public BigInteger _TTBR0_EL1;

        private ulong _TTBR0_EL2_Low;
        private ulong _TTBR0_EL2_High;

        [JsonProperty(Order = 1)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public BigInteger _TTBR0_EL2;

        private ulong _TTBR0_EL3_Low;
        private ulong _TTBR0_EL3_High;

        [JsonProperty(Order = 1)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public BigInteger _TTBR0_EL3;

        private ulong _TTBR1_EL1_Low;
        private ulong _TTBR1_EL1_High;

        [JsonProperty(Order = 1)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public BigInteger _TTBR1_EL1;

        private ulong _TTBR1_EL2_Low;
        private ulong _TTBR1_EL2_High;

        [JsonProperty(Order = 1)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public BigInteger _TTBR1_EL2;

        private ulong _VTTBR_EL2_Low;
        private ulong _VTTBR_EL2_High;

        [JsonProperty(Order = 1)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public BigInteger _VTTBR_EL2;

        public WHEA_ARMV8_AARCH64_TT128(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_ARMV8_AARCH64_TT128), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _TTBR0_EL1_Low = (ulong)Marshal.ReadInt64(structAddr);
            _TTBR0_EL1_High = (ulong)Marshal.ReadInt64(structAddr, 8);
            _TTBR0_EL1 = (new BigInteger(_TTBR0_EL1_High) << 64) + _TTBR0_EL1_Low;

            _TTBR0_EL2_Low = (ulong)Marshal.ReadInt64(structAddr, 16);
            _TTBR0_EL2_High = (ulong)Marshal.ReadInt64(structAddr, 24);
            _TTBR0_EL2 = (new BigInteger(_TTBR0_EL2_High) << 64) + _TTBR0_EL2_Low;

            _TTBR0_EL3_Low = (ulong)Marshal.ReadInt64(structAddr, 32);
            _TTBR0_EL3_High = (ulong)Marshal.ReadInt64(structAddr, 40);
            _TTBR0_EL3 = (new BigInteger(_TTBR0_EL3_High) << 64) + _TTBR0_EL3_Low;

            _TTBR1_EL1_Low = (ulong)Marshal.ReadInt64(structAddr, 48);
            _TTBR1_EL1_High = (ulong)Marshal.ReadInt64(structAddr, 56);
            _TTBR1_EL1 = (new BigInteger(_TTBR1_EL1_High) << 64) + _TTBR1_EL1_Low;

            _TTBR1_EL2_Low = (ulong)Marshal.ReadInt64(structAddr, 64);
            _TTBR1_EL2_High = (ulong)Marshal.ReadInt64(structAddr, 72);
            _TTBR1_EL2 = (new BigInteger(_TTBR1_EL2_High) << 64) + _TTBR1_EL2_Low;

            _VTTBR_EL2_Low = (ulong)Marshal.ReadInt64(structAddr, 80);
            _VTTBR_EL2_High = (ulong)Marshal.ReadInt64(structAddr, 88);
            _VTTBR_EL2 = (new BigInteger(_VTTBR_EL2_High) << 64) + _VTTBR_EL2_Low;

            FinalizeRecord(recordAddr, StructSize);
        }
    }

    // @formatter:int_align_fields true

    [Flags]
    internal enum WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS : uint {
        MPIDR              = 0x1,
        AffinityLevel      = 0x2,
        RunningState       = 0x4,
        VendorSpecificInfo = 0x8
    }

    [Flags]
    internal enum WHEA_ARM_PROCESSOR_ERROR_INFORMATION_VALID_BITS : ushort {
        MultipleError        = 0x1,
        Flags                = 0x2,
        ErrorInformation     = 0x4,
        VirtualFaultAddress  = 0x8,
        PhysicalFaultAddress = 0x10
    }

    // Not in the Windows headers and derived from UEFI Specification R2.11
    internal enum WHEA_ARM_PROCESSOR_ERROR_INFORMATION_TYPE : byte {
        Cache = 0,
        TLB   = 1,
        Bus   = 2,
        MAE   = 3
    }

    // Not in the Windows headers and derived from UEFI Specification R2.11
    [Flags]
    internal enum WHEA_ARM_PROCESSOR_ERROR_INFORMATION_FLAGS : byte {
        FirstErrorCaptured = 0x1,
        LastErrorCaptured  = 0x2,
        Propagated         = 0x4,
        Overflow           = 0x8
    }

    [Flags]
    internal enum WHEA_ARM_CACHE_ERROR_VALID_BITS : ushort {
        TransactionType         = 0x1,
        Operation               = 0x2,
        Level                   = 0x4,
        ProcessorContextCorrupt = 0x8,
        Corrected               = 0x10,
        PrecisePC               = 0x20,
        RestartablePC           = 0x40
    }

    // Not in the Windows headers and derived from UEFI Specification R2.11
    internal enum WHEA_ARM_CACHE_ERROR_TRANSACTION_TYPE : byte {
        Instruction = 0,
        DataAccess  = 1,
        Generic     = 2
    }

    // Not in the Windows headers and derived from UEFI Specification R2.11
    internal enum WHEA_ARM_CACHE_ERROR_OPERATION : byte {
        Generic          = 0,
        GenericRead      = 1,
        GenericWrite     = 2,
        DataRead         = 3,
        DataWrite        = 4,
        InstructionFetch = 5,
        Prefetch         = 6,
        Eviction         = 7,
        Snooping         = 8,
        Snooped          = 9,
        Management       = 10
    }

    [Flags]
    internal enum WHEA_ARM_TLB_ERROR_VALID_BITS : ushort {
        TransactionType         = 0x1,
        Operation               = 0x2,
        Level                   = 0x4,
        ProcessorContextCorrupt = 0x8,
        Corrected               = 0x10,
        PrecisePC               = 0x20,
        RestartablePC           = 0x40
    }

    // Not in the Windows headers and derived from UEFI Specification R2.11
    internal enum WHEA_ARM_TLB_ERROR_TRANSACTION_TYPE : byte {
        Instruction = 0,
        DataAccess  = 1,
        Generic     = 2
    }

    // Not in the Windows headers and derived from UEFI Specification R2.11
    internal enum WHEA_ARM_TLB_ERROR_OPERATION : byte {
        Generic              = 0,
        GenericRead          = 1,
        GenericWrite         = 2,
        DataRead             = 3,
        DataWrite            = 4,
        InstructionFetch     = 5,
        Prefetch             = 6,
        LocalManagementOp    = 7,
        ExternalManagementOp = 8
    }

    [Flags]
    internal enum WHEA_ARM_BUS_ERROR_VALID_BITS : ushort {
        TransactionType         = 0x1,
        Operation               = 0x2,
        Level                   = 0x4,
        ProcessorContextCorrupt = 0x8,
        Corrected               = 0x10,
        PrecisePC               = 0x20,
        RestartablePC           = 0x40,
        ParticipationType       = 0x80,
        Timeout                 = 0x100,
        AddressSpace            = 0x200,
        MemoryAttributes        = 0x400,
        AccessMode              = 0x800
    }

    // Not in the Windows headers and derived from UEFI Specification R2.11
    internal enum WHEA_ARM_BUS_ERROR_TRANSACTION_TYPE : byte {
        Instruction = 0,
        DataAccess  = 1,
        Generic     = 2
    }

    // Not in the Windows headers and derived from UEFI Specification R2.11
    internal enum WHEA_ARM_BUS_ERROR_OPERATION : byte {
        Generic          = 0,
        GenericRead      = 1,
        GenericWrite     = 2,
        DataRead         = 3,
        DataWrite        = 4,
        InstructionFetch = 5,
        Prefetch         = 6
    }

    // Not in the Windows headers and derived from UEFI Specification R2.11
    internal enum WHEA_ARM_BUS_ERROR_PARTICIPATION_TYPE : byte {
        ProcessorOriginated = 0,
        ProcessorResponded  = 1,
        ProcessorObserved   = 2,
        Generic             = 3
    }

    // Not in the Windows headers and derived from UEFI Specification R2.11
    internal enum WHEA_ARM_BUS_ERROR_ADDRESS_SPACE : byte {
        External = 0,
        Internal = 1,
        Device   = 2
    }

    // Not in the Windows headers and derived from UEFI Specification R2.11
    internal enum WHEA_ARM_BUS_ERROR_ACCESS_MODE : byte {
        Secure = 0,
        Normal = 1
    }

    // Not in the Windows headers and derived from UEFI Specification R2.11
    internal enum WHEA_ARM_PROCESSOR_ERROR_CONTEXT_INFORMATION_HEADER_REGISTER_CONTEXT_TYPE : ushort {
        AArch32GPR    = 0,
        AArch32EL1    = 1,
        AArch32EL2    = 2,
        AArch32Secure = 3,
        AArch64GPR    = 4,
        AArch64EL1    = 5,
        AArch64EL2    = 6,
        AArch64EL3    = 7,
        AArchMisc     = 8,
        AArch64TT128  = 9
    }

    // @formatter:int_align_fields false
}