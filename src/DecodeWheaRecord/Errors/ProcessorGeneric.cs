#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors {
    /*
     * Attempting to directly marshal as a structure results in serialization
     * issues with Newtonsoft.Json, though I suspect the real issue is in the
     * marshaller itself. The cause is sure to be related to the handling of
     * the CPUVersion field, which has a different layout subject to the CPU.
     */
    internal sealed class WHEA_PROCESSOR_GENERIC_ERROR_SECTION : WheaErrorRecord {
        // Structure size is static
        private const uint _StructSize = 192;
        public override uint GetNativeSize() => _StructSize;

        private WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS _ValidBits;

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        private WHEA_PROCESSOR_GENERIC_TYPE _ProcessorType;

        [JsonProperty(Order = 2)]
        public string ProcessorType => Enum.GetName(typeof(WHEA_PROCESSOR_GENERIC_TYPE), _ProcessorType);

        private WHEA_PROCESSOR_GENERIC_ISA_TYPE _InstructionSet;

        [JsonProperty(Order = 3)]
        public string InstructionSet => Enum.GetName(typeof(WHEA_PROCESSOR_GENERIC_ISA_TYPE), _InstructionSet);

        private WHEA_PROCESSOR_GENERIC_ERROR_TYPE _ErrorType;

        [JsonProperty(Order = 4)]
        public string ErrorType => Enum.GetName(typeof(WHEA_PROCESSOR_GENERIC_ERROR_TYPE), _ErrorType);

        private WHEA_PROCESSOR_GENERIC_OP_TYPE _Operation;

        [JsonProperty(Order = 5)]
        public string Operation => Enum.GetName(typeof(WHEA_PROCESSOR_GENERIC_OP_TYPE), _Operation);

        private WHEA_PROCESSOR_GENERIC_ERROR_SECTION_FLAGS _Flags;

        [JsonProperty(Order = 6)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        [JsonProperty(Order = 7)]
        public byte Level;

        [JsonProperty(Order = 8)]
        public ushort Reserved;

        [JsonProperty(Order = 9)]
        public WHEA_PROCESSOR_FAMILY_INFO CPUVersion; // TODO: ARM & Itanium

        [JsonProperty(Order = 10)]
        public string CPUBrandString; // TODO: ARM & Itanium

        [JsonProperty(Order = 11)]
        public ulong ProcessorId; // TODO: ARM & Itanium

        [JsonProperty(Order = 12)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong TargetAddress;

        [JsonProperty(Order = 13)]
        public ulong RequesterId;

        [JsonProperty(Order = 14)]
        public ulong ResponderId;

        [JsonProperty(Order = 15)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong InstructionPointer;

        private void WheaProcessorGenericErrorSection(IntPtr recordAddr, uint sectionOffset, uint bytesRemaining) {
            var sectionAddr = recordAddr + (int)sectionOffset;

            _ValidBits = (WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS)Marshal.ReadInt64(sectionAddr);
            _ProcessorType = (WHEA_PROCESSOR_GENERIC_TYPE)Marshal.ReadByte(sectionAddr, 8);
            _InstructionSet = (WHEA_PROCESSOR_GENERIC_ISA_TYPE)Marshal.ReadByte(sectionAddr, 9);
            _ErrorType = (WHEA_PROCESSOR_GENERIC_ERROR_TYPE)Marshal.ReadByte(sectionAddr, 10);
            _Operation = (WHEA_PROCESSOR_GENERIC_OP_TYPE)Marshal.ReadByte(sectionAddr, 11);
            _Flags = (WHEA_PROCESSOR_GENERIC_ERROR_SECTION_FLAGS)Marshal.ReadByte(sectionAddr, 12);
            Level = Marshal.ReadByte(sectionAddr, 13);
            Reserved = (ushort)Marshal.ReadInt16(sectionAddr, 14);
            var offset = 16;

            CPUVersion = new WHEA_PROCESSOR_FAMILY_INFO(recordAddr,
                                                        SectionDsc.SectionOffset + (uint)offset,
                                                        bytesRemaining - (uint)offset,
                                                        ShouldSerializeNativeModelId());
            offset += (int)CPUVersion.GetNativeSize();

            CPUBrandString = Marshal.PtrToStringAnsi(sectionAddr + offset, 128);
            offset += 128;

            ProcessorId = (ulong)Marshal.ReadInt64(sectionAddr, offset);
            TargetAddress = (ulong)Marshal.ReadInt64(sectionAddr, offset + 8);
            RequesterId = (ulong)Marshal.ReadInt64(sectionAddr, offset + 16);
            ResponderId = (ulong)Marshal.ReadInt64(sectionAddr, offset + 24);
            InstructionPointer = (ulong)Marshal.ReadInt64(sectionAddr, offset + 32);

            FinalizeRecord(recordAddr, _StructSize);
        }

        public WHEA_PROCESSOR_GENERIC_ERROR_SECTION(IntPtr recordAddr, uint sectionOffset, uint bytesRemaining) :
            base(typeof(WHEA_PROCESSOR_GENERIC_ERROR_SECTION), sectionOffset, _StructSize, bytesRemaining) {
            WheaProcessorGenericErrorSection(recordAddr, sectionOffset, bytesRemaining);
        }

        public WHEA_PROCESSOR_GENERIC_ERROR_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(WHEA_PROCESSOR_GENERIC_ERROR_SECTION), _StructSize, bytesRemaining) {
            WheaProcessorGenericErrorSection(recordAddr, sectionDsc.SectionOffset, bytesRemaining);
        }

        [UsedImplicitly]
        public bool ShouldSerializeProcessorType() =>
            (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.ProcessorType) ==
            WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.ProcessorType;

        [UsedImplicitly]
        public bool ShouldSerializeInstructionSet() =>
            (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.InstructionSet) ==
            WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.InstructionSet;

        [UsedImplicitly]
        public bool ShouldSerializeErrorType() =>
            (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.ErrorType) ==
            WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.ErrorType;

        [UsedImplicitly]
        public bool ShouldSerializeOperation() =>
            (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.Operation) ==
            WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.Operation;

        [UsedImplicitly]
        public bool ShouldSerializeFlags() =>
            (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.Flags) ==
            WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.Flags;

        [UsedImplicitly]
        public bool ShouldSerializeLevel() =>
            (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.Level) ==
            WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.Level;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();

        [UsedImplicitly]
        public bool ShouldSerializeCPUVersion() {
            if ((_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.CPUVersion) !=
                WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.CPUVersion) {
                return false;
            }

            return ShouldSerializeProcessorType() && _ProcessorType == WHEA_PROCESSOR_GENERIC_TYPE.XPF;
        }

        [UsedImplicitly]
        public bool ShouldSerializeCPUBrandString() =>
            (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.CPUBrandString) ==
            WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.CPUBrandString;

        [UsedImplicitly]
        public bool ShouldSerializeProcessorId() =>
            (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.ProcessorId) ==
            WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.ProcessorId;

        [UsedImplicitly]
        public bool ShouldSerializeTargetAddress() =>
            (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.TargetAddress) ==
            WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.TargetAddress;

        [UsedImplicitly]
        public bool ShouldSerializeRequesterId() =>
            (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.RequesterId) ==
            WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.RequesterId;

        [UsedImplicitly]
        public bool ShouldSerializeResponderId() =>
            (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.ResponderId) ==
            WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.ResponderId;

        [UsedImplicitly]
        public bool ShouldSerializeInstructionPointer() =>
            (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.InstructionPointer) ==
            WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.InstructionPointer;

        /*
         * Only used internally to support marshalling of the
         * WHEA_PROCESSOR_FAMILY_INFO structure.
         */
        private bool ShouldSerializeNativeModelId() {
            return (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.NativeModelId) ==
                   WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.NativeModelId;
        }
    }

    /*
     * Originally defined as a structure with the first ULONG field being a
     * bitfield. This structure has the same in memory format but is simpler
     * to interact with.
     *
     * Cannot be directly marshalled as a structure as the validity of the
     * NativeModelId field is determined by the ValidBits field of the parent
     * encapsulating structure. When marshalling this structure the validity
     * information is stored which changes the memory layout.
     */
    internal sealed class WHEA_PROCESSOR_FAMILY_INFO : WheaErrorRecord {
        // Structure size is static
        private const uint _StructSize = 8;
        public override uint GetNativeSize() => _StructSize;

        private bool _serializeNativeModelId;

        private uint _ProcInfo;

        [JsonProperty(Order = 1)]
        public byte Stepping => (byte)(_ProcInfo & 0xF); // Bits 0-3

        [JsonProperty(Order = 2)]
        public byte Model => (byte)((_ProcInfo & 0xF0) >> 4); // Bits 4-7

        [JsonProperty(Order = 3)]
        public byte Family => (byte)((_ProcInfo & 0xF00) >> 8); // Bits 8-11

        [JsonProperty(Order = 4)]
        public byte ProcessorType => (byte)((_ProcInfo & 0x3000) >> 12); // Bits 12-13

        [JsonProperty(Order = 5)]
        public byte Reserved1 => (byte)((_ProcInfo & 0xC000) >> 14); // Bits 14-15

        [JsonProperty(Order = 6)]
        public byte ExtendedModel => (byte)((_ProcInfo & 0xF0000) >> 16); // Bits 16-19

        [JsonProperty(Order = 7)]
        public byte ExtendedFamily => (byte)((_ProcInfo & 0xFF00000) >> 20); // Bits 20-27

        [JsonProperty(Order = 8)]
        public byte Reserved2 => (byte)(_ProcInfo >> 28); // Bits 28-31

        [JsonProperty(Order = 9)]
        public uint NativeModelId;

        public WHEA_PROCESSOR_FAMILY_INFO(IntPtr recordAddr, uint procFamilyInfoOffset, uint bytesRemaining, bool serializeNativeModelId) :
            base(typeof(WHEA_PROCESSOR_FAMILY_INFO), procFamilyInfoOffset, _StructSize, bytesRemaining) {
            var procFamilyInfoAddr = recordAddr + (int)procFamilyInfoOffset;

            _ProcInfo = (uint)Marshal.ReadInt32(procFamilyInfoAddr);
            NativeModelId = (uint)Marshal.ReadInt32(procFamilyInfoAddr, 4);

            _serializeNativeModelId = serializeNativeModelId;

            FinalizeRecord(recordAddr, _StructSize);
        }

        [UsedImplicitly]
        public static bool ShouldSerializeReserved1() => IsDebugBuild();

        [UsedImplicitly]
        public static bool ShouldSerializeReserved2() => IsDebugBuild();

        [UsedImplicitly]
        public bool ShouldSerializeNativeModelId() => _serializeNativeModelId;
    }

    // @formatter:int_align_fields true

    // From preprocessor definitions (GENPROC_FLAGS_*)
    [Flags]
    internal enum WHEA_PROCESSOR_GENERIC_ERROR_SECTION_FLAGS : byte {
        Restartable = 0x1,
        PreciseIP   = 0x2,
        Overflow    = 0x4,
        Corrected   = 0x8
    }

    [Flags]
    internal enum WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS : ulong {
        ProcessorType      = 0x1,
        InstructionSet     = 0x2,
        ErrorType          = 0x4,
        Operation          = 0x8,
        Flags              = 0x10,
        Level              = 0x20,
        CPUVersion         = 0x40,
        CPUBrandString     = 0x80,
        ProcessorId        = 0x100,
        TargetAddress      = 0x200,
        RequesterId        = 0x400,
        ResponderId        = 0x800,
        InstructionPointer = 0x1000,
        NativeModelId      = 0x2000
    }

    // From preprocessor definitions (GENPROC_PROCERRTYPE_*)
    internal enum WHEA_PROCESSOR_GENERIC_ERROR_TYPE : byte {
        Unknown = 0,
        Cache   = 1,
        TLB     = 2,
        Bus     = 4,
        MAE     = 8
    }

    // From preprocessor definitions (GENPROC_PROCISA_*)
    internal enum WHEA_PROCESSOR_GENERIC_ISA_TYPE : byte {
        X86   = 0,
        IPF   = 1,
        X64   = 2,
        ARM32 = 4,
        ARM64 = 8
    }

    // From preprocessor definitions (GENPROC_OP_*)
    internal enum WHEA_PROCESSOR_GENERIC_OP_TYPE : byte {
        Generic        = 0,
        DataRead       = 1,
        DataWrite      = 2,
        InstructionExe = 3
    }

    // From preprocessor definitions (GENPROC_PROCTYPE_*)
    internal enum WHEA_PROCESSOR_GENERIC_TYPE : byte {
        XPF = 0,
        IPF = 1,
        ARM = 2
    }

    // @formatter:int_align_fields false
}
