#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors.UEFI {
    internal sealed class WHEA_PROCESSOR_GENERIC_ERROR_SECTION : WheaErrorRecord {
        private const uint StructSize = 192;
        public override uint GetNativeSize() => StructSize;

        private const uint CPUBrandStringSize = 128;

        private WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS _ValidBits;

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        // Switched to an enumeration
        private WHEA_PROCESSOR_GENERIC_PROC_TYPE _ProcessorType;

        [JsonProperty(Order = 2)]
        public string ProcessorType => Enum.GetName(typeof(WHEA_PROCESSOR_GENERIC_PROC_TYPE), _ProcessorType);

        // Switched to an enumeration
        private WHEA_PROCESSOR_GENERIC_ISA_TYPE _InstructionSet;

        [JsonProperty(Order = 3)]
        public string InstructionSet => Enum.GetName(typeof(WHEA_PROCESSOR_GENERIC_ISA_TYPE), _InstructionSet);

        // Switched to an enumeration
        private WHEA_PROCESSOR_GENERIC_ERROR_TYPE _ErrorType;

        [JsonProperty(Order = 4)]
        public string ErrorType => Enum.GetName(typeof(WHEA_PROCESSOR_GENERIC_ERROR_TYPE), _ErrorType);

        // Switched to an enumeration
        private WHEA_PROCESSOR_GENERIC_OP_TYPE _Operation;

        [JsonProperty(Order = 5)]
        public string Operation => Enum.GetName(typeof(WHEA_PROCESSOR_GENERIC_OP_TYPE), _Operation);

        // Switched to an enumeration
        private WHEA_PROCESSOR_GENERIC_ERROR_SECTION_FLAGS _Flags;

        [JsonProperty(Order = 6)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        [JsonProperty(Order = 7)]
        public byte Level;

        [JsonProperty(Order = 8)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Reserved;

        // For when the processor type can't be determined (possible?)
        [JsonProperty(Order = 9)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong CPUVersion;

        [JsonProperty(Order = 9)]
        public WHEA_PROCESSOR_FAMILY_INFO CPUVersionXPF;

        // Future: Decode the returned CPUID data
        [JsonProperty(Order = 9)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong CPUVersionIPF;

        // Future: Decode the returned MIDR_EL1 data
        [JsonProperty(Order = 9)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong CPUVersionARM;

        // For when the processor type can't be determined (possible?)
        [JsonProperty(Order = 10)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] CPUBrandString;

        private string _CPUBrandStringXPF;

        [JsonProperty(Order = 10)]
        public string CPUBrandStringXPF => _CPUBrandStringXPF.Trim('\0');

        // Future: Decode the returned PAL_BRAND_INFO data
        [JsonProperty(Order = 10)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] CPUBrandStringIPF;

        // Optional for ARM processors
        private byte[] _CPUBrandStringARM;

        [JsonProperty(Order = 10)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] CPUBrandStringARM => _CPUBrandStringARM.Any(element => element != 0) ? _CPUBrandStringARM : new byte[] { 0 };

        // For when the processor type can't be determined (possible?)
        [JsonProperty(Order = 11)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ProcessorId;

        // Local APIC ID register
        private ulong _ProcessorIdXPF;

        // Although the field is 64-bits the Local APIC ID is 32-bits
        [JsonProperty(Order = 11)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint ProcessorIdXPF => (uint)_ProcessorIdXPF;

        // Future: Decode the returned LID register
        [JsonProperty(Order = 11)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ProcessorIdIPF;

        // Future: Decode the returned MPIDR_EL1 register
        [JsonProperty(Order = 11)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ProcessorIdARM;

        [JsonProperty(Order = 12)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong TargetAddress;

        [JsonProperty(Order = 13)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong RequesterId;

        [JsonProperty(Order = 14)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ResponderId;

        [JsonProperty(Order = 15)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong InstructionPointer;

        public WHEA_PROCESSOR_GENERIC_ERROR_SECTION(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_PROCESSOR_GENERIC_ERROR_SECTION), structOffset, StructSize, bytesRemaining) {
            WheaProcessorGenericErrorSection(recordAddr, structOffset, bytesRemaining);
        }

        public WHEA_PROCESSOR_GENERIC_ERROR_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(WHEA_PROCESSOR_GENERIC_ERROR_SECTION), StructSize, bytesRemaining) {
            WheaProcessorGenericErrorSection(recordAddr, sectionDsc.SectionOffset, bytesRemaining);
        }

        private void WheaProcessorGenericErrorSection(IntPtr recordAddr, uint structOffset, uint bytesRemaining) {
            var logCat = SectionType.Name;
            var sectionAddr = recordAddr + (int)structOffset;

            _ValidBits = (WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS)Marshal.ReadInt64(sectionAddr);
            _ProcessorType = (WHEA_PROCESSOR_GENERIC_PROC_TYPE)Marshal.ReadByte(sectionAddr, 8);
            _InstructionSet = (WHEA_PROCESSOR_GENERIC_ISA_TYPE)Marshal.ReadByte(sectionAddr, 9);
            _ErrorType = (WHEA_PROCESSOR_GENERIC_ERROR_TYPE)Marshal.ReadByte(sectionAddr, 10);
            _Operation = (WHEA_PROCESSOR_GENERIC_OP_TYPE)Marshal.ReadByte(sectionAddr, 11);
            _Flags = (WHEA_PROCESSOR_GENERIC_ERROR_SECTION_FLAGS)Marshal.ReadByte(sectionAddr, 12);
            Level = Marshal.ReadByte(sectionAddr, 13);

            Reserved = (ushort)Marshal.ReadInt16(sectionAddr, 14);
            if (Reserved != 0) {
                WarnOutput($"{nameof(Reserved)} is non-zero.", logCat);
            }

            if (ShouldSerializeProcessorType()) {
                switch (_ProcessorType) {
                    case WHEA_PROCESSOR_GENERIC_PROC_TYPE.XPF:
                        CPUVersionXPF = new WHEA_PROCESSOR_FAMILY_INFO(recordAddr,
                                                                       structOffset + 16,
                                                                       bytesRemaining - 16,
                                                                       ShouldSerializeNativeModelId());

                        _CPUBrandStringXPF = Marshal.PtrToStringAnsi(sectionAddr + 24, (int)CPUBrandStringSize);
                        _ProcessorIdXPF = (ulong)Marshal.ReadInt64(sectionAddr, 24 + (int)CPUBrandStringSize);
                        break;
                    case WHEA_PROCESSOR_GENERIC_PROC_TYPE.IPF:
                        CPUVersionIPF = (ulong)Marshal.ReadInt64(sectionAddr, 16);

                        CPUBrandStringIPF = new byte[CPUBrandStringSize];
                        Marshal.Copy(sectionAddr + 24, CPUBrandStringIPF, 0, CPUBrandStringIPF.Length);

                        ProcessorIdIPF = (ulong)Marshal.ReadInt64(sectionAddr, 24 + (int)CPUBrandStringSize);
                        break;
                    case WHEA_PROCESSOR_GENERIC_PROC_TYPE.ARM:
                        CPUVersionARM = (ulong)Marshal.ReadInt64(sectionAddr, 16);

                        _CPUBrandStringARM = new byte[CPUBrandStringSize];
                        Marshal.Copy(sectionAddr + 24, _CPUBrandStringARM, 0, _CPUBrandStringARM.Length);

                        ProcessorIdARM = (ulong)Marshal.ReadInt64(sectionAddr, 24 + (int)CPUBrandStringSize);
                        break;
                    default:
                        throw new InvalidDataException($"{nameof(ProcessorType)} is unknown or invalid: {_ProcessorType}");
                }
            } else {
                CPUVersion = (ulong)Marshal.ReadInt64(sectionAddr, 16);
                if (ShouldSerializeCPUVersion()) {
                    WarnOutput($"{nameof(CPUVersion)} will be output raw as {nameof(ProcessorType)} is not marked valid.", logCat);
                }

                CPUBrandString = new byte[CPUBrandStringSize];
                Marshal.Copy(sectionAddr + 24, CPUBrandString, 0, CPUBrandString.Length);
                if (ShouldSerializeCPUBrandString()) {
                    WarnOutput($"{nameof(CPUBrandString)} will be output raw as {nameof(ProcessorType)} is not marked valid.", logCat);
                }

                ProcessorId = (ulong)Marshal.ReadInt64(sectionAddr, 24 + (int)CPUBrandStringSize);
                if (ShouldSerializeProcessorId()) {
                    WarnOutput($"{nameof(ProcessorId)} will be output raw as {nameof(ProcessorType)} is not marked valid.", logCat);
                }
            }

            TargetAddress = (ulong)Marshal.ReadInt64(sectionAddr, 160);
            RequesterId = (ulong)Marshal.ReadInt64(sectionAddr, 168);
            ResponderId = (ulong)Marshal.ReadInt64(sectionAddr, 176);
            InstructionPointer = (ulong)Marshal.ReadInt64(sectionAddr, 184);

            FinalizeRecord(recordAddr, StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeProcessorType() => (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.ProcessorType) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeInstructionSet() => (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.InstructionSet) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeErrorType() => (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.ErrorType) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeOperation() => (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.Operation) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeFlags() => (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.Flags) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeLevel() => (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.Level) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;

        private bool IsCPUVersionValid() => (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.CPUVersion) != 0;

        private bool SerializeCPUVersionByType() => IsCPUVersionValid() && ShouldSerializeProcessorType();

        [UsedImplicitly]
        public bool ShouldSerializeCPUVersion() => IsCPUVersionValid() && !ShouldSerializeProcessorType();

        [UsedImplicitly]
        public bool ShouldSerializeCPUVersionXPF() => SerializeCPUVersionByType() && _ProcessorType == WHEA_PROCESSOR_GENERIC_PROC_TYPE.XPF;

        [UsedImplicitly]
        public bool ShouldSerializeCPUVersionIPF() => SerializeCPUVersionByType() && _ProcessorType == WHEA_PROCESSOR_GENERIC_PROC_TYPE.IPF;

        [UsedImplicitly]
        public bool ShouldSerializeCPUVersionARM() => SerializeCPUVersionByType() && _ProcessorType == WHEA_PROCESSOR_GENERIC_PROC_TYPE.ARM;

        private bool IsCPUBrandStringValid() => (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.CPUBrandString) != 0;

        private bool SerializeCPUBrandStringByType() => IsCPUBrandStringValid() && ShouldSerializeProcessorType();

        [UsedImplicitly]
        public bool ShouldSerializeCPUBrandString() => IsCPUBrandStringValid() && !ShouldSerializeProcessorType();

        [UsedImplicitly]
        public bool ShouldSerializeCPUBrandStringXPF() => SerializeCPUBrandStringByType() && _ProcessorType == WHEA_PROCESSOR_GENERIC_PROC_TYPE.XPF;

        [UsedImplicitly]
        public bool ShouldSerializeCPUBrandStringIPF() => SerializeCPUBrandStringByType() && _ProcessorType == WHEA_PROCESSOR_GENERIC_PROC_TYPE.IPF;

        [UsedImplicitly]
        public bool ShouldSerializeCPUBrandStringARM() => SerializeCPUBrandStringByType() && _ProcessorType == WHEA_PROCESSOR_GENERIC_PROC_TYPE.ARM;

        private bool IsProcessorIdValid() => (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.ProcessorId) != 0;

        private bool SerializeProcessorIdByType() => IsProcessorIdValid() && ShouldSerializeProcessorType();

        [UsedImplicitly]
        public bool ShouldSerializeProcessorId() => IsProcessorIdValid() && !ShouldSerializeProcessorType();

        [UsedImplicitly]
        public bool ShouldSerializeProcessorIdXPF() => SerializeProcessorIdByType() && _ProcessorType == WHEA_PROCESSOR_GENERIC_PROC_TYPE.XPF;

        [UsedImplicitly]
        public bool ShouldSerializeProcessorIdIPF() => SerializeProcessorIdByType() && _ProcessorType == WHEA_PROCESSOR_GENERIC_PROC_TYPE.IPF;

        [UsedImplicitly]
        public bool ShouldSerializeProcessorIdARM() => SerializeProcessorIdByType() && _ProcessorType == WHEA_PROCESSOR_GENERIC_PROC_TYPE.ARM;

        [UsedImplicitly]
        public bool ShouldSerializeTargetAddress() => (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.TargetAddress) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeRequesterId() => (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.RequesterId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeResponderId() => (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.ResponderId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeInstructionPointer() => (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.InstructionPointer) != 0;

        // Supports marshalling of the WHEA_PROCESSOR_FAMILY_INFO structure
        private bool ShouldSerializeNativeModelId() => (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.NativeModelId) != 0;
    }

    internal sealed class WHEA_PROCESSOR_FAMILY_INFO : WheaErrorRecord {
        private const uint StructSize = 8;
        public override uint GetNativeSize() => StructSize;

        private bool _serializeNativeModelId;

        private uint _ProcInfo;

        [JsonProperty(Order = 1)]
        public byte Stepping => (byte)(_ProcInfo & 0xF); // Bits 0-3

        [JsonProperty(Order = 2)]
        public byte Model => (byte)(_ProcInfo >> 4 & 0xF); // Bits 4-7

        [JsonProperty(Order = 3)]
        public byte Family => (byte)(_ProcInfo >> 8 & 0xF); // Bits 8-11

        [JsonProperty(Order = 4)]
        public byte ProcessorType => (byte)(_ProcInfo >> 12 & 0x3); // Bits 12-13

        [JsonProperty(Order = 5)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved1 => (byte)(_ProcInfo >> 14 & 0x3); // Bits 14-15

        [JsonProperty(Order = 6)]
        public byte ExtendedModel => (byte)(_ProcInfo >> 16 & 0xF); // Bits 16-19

        [JsonProperty(Order = 7)]
        public byte ExtendedFamily => (byte)(_ProcInfo >> 20); // Bits 20-27

        [JsonProperty(Order = 8)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved2 => (byte)(_ProcInfo >> 28); // Bits 28-31

        [JsonProperty(Order = 9)]
        public uint NativeModelId;

        public WHEA_PROCESSOR_FAMILY_INFO(IntPtr recordAddr, uint structOffset, uint bytesRemaining, bool serializeNativeModelId) :
            base(typeof(WHEA_PROCESSOR_FAMILY_INFO), structOffset, StructSize, bytesRemaining) {
            var logCat = SectionType.Name;
            var structAddr = recordAddr + (int)structOffset;

            _ProcInfo = (uint)Marshal.ReadInt32(structAddr);

            if (Reserved1 != 0) {
                WarnOutput($"{nameof(Reserved1)} is non-zero.", logCat);
            }

            if (Reserved2 != 0) {
                WarnOutput($"{nameof(Reserved2)} is non-zero.", logCat);
            }

            NativeModelId = (uint)Marshal.ReadInt32(structAddr, 4);

            _serializeNativeModelId = serializeNativeModelId;

            FinalizeRecord(recordAddr, StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeReserved1() => Reserved1 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved2() => Reserved2 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeNativeModelId() => _serializeNativeModelId;
    }

    // @formatter:int_align_fields true

    [Flags]
    internal enum WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS : ulong {
        ProcessorType = 0x1,
        InstructionSet = 0x2,
        ErrorType = 0x4,
        Operation = 0x8,
        Flags = 0x10,
        Level = 0x20,
        CPUVersion = 0x40,
        CPUBrandString = 0x80,
        ProcessorId = 0x100,
        TargetAddress = 0x200,
        RequesterId = 0x400,
        ResponderId = 0x800,
        InstructionPointer = 0x1000,
        NativeModelId = 0x2000 // Not in UEFI specification
    }

    // From GENPROC_PROCTYPE preprocessor definitions
    internal enum WHEA_PROCESSOR_GENERIC_PROC_TYPE : byte {
        XPF = 0,
        IPF = 1,
        ARM = 2
    }

    // From GENPROC_PROCISA preprocessor definitions
    internal enum WHEA_PROCESSOR_GENERIC_ISA_TYPE : byte {
        X86 = 0,
        IPF = 1,
        X64 = 2,
        ARM32 = 3, // Windows headers incorrectly set to 4
        ARM64 = 4  // Windows headers incorrectly set to 8
    }

    // From GENPROC_PROCERRTYPE preprocessor definitions
    internal enum WHEA_PROCESSOR_GENERIC_ERROR_TYPE : byte {
        Unknown = 0,
        Cache = 1,
        TLB = 2,
        Bus = 4,
        MAE = 8
    }

    // From GENPROC_OP preprocessor definitions
    internal enum WHEA_PROCESSOR_GENERIC_OP_TYPE : byte {
        Generic = 0,
        DataRead = 1,
        DataWrite = 2,
        InstructionExe = 3
    }

    // From GENPROC_FLAGS preprocessor definitions
    [Flags]
    internal enum WHEA_PROCESSOR_GENERIC_ERROR_SECTION_FLAGS : byte {
        Restartable = 0x1,
        PreciseIP = 0x2,
        Overflow = 0x4,
        Corrected = 0x8
    }

    // @formatter:int_align_fields false
}
