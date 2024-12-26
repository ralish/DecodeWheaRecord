#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly
#pragma warning disable IDE1006 // Naming rule violation

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors {
    /*
     * Cannot be directly marshalled as a structure due to the usage of
     * variable length arrays, resulting in a non-static structure size.
     */
    internal sealed class WHEA_XPF_PROCESSOR_ERROR_SECTION : WheaErrorRecord {
        // Size up to and including the CpuId field
        private const uint BaseStructSize = 64;

        private uint _NativeSize;
        public override uint GetNativeSize() => _NativeSize;

        /*
         * Processor check info types
         */
        internal static readonly Guid WHEA_BUSCHECK_GUID = Guid.Parse("1cf3f8b3-c5b1-49a2-aa59-5eef92ffa63c");
        internal static readonly Guid WHEA_CACHECHECK_GUID = Guid.Parse("a55701f5-e3ef-43de-ac72-249b573fad2c");
        internal static readonly Guid WHEA_MSCHECK_GUID = Guid.Parse("48ab7f57-dc34-4f6c-a7d3-b0b5b0a74314");
        internal static readonly Guid WHEA_TLBCHECK_GUID = Guid.Parse("fc06b535-5e1f-4562-9f25-0a3b9adb63c3");

        internal static readonly Dictionary<Guid, string> CheckInfoTypes = new Dictionary<Guid, string> {
            { WHEA_BUSCHECK_GUID, "Bus" },
            { WHEA_CACHECHECK_GUID, "Cache" },
            { WHEA_MSCHECK_GUID, "Microarchitecture-specific" },
            { WHEA_TLBCHECK_GUID, "Translation Lookaside Buffer" }
        };

        /*
         * Originally defined as a ULONGLONG bitfield, except only two bits are
         * flags with the remaining non-reserved bits composed of two 6-bit
         * integers. The actual flags are defined in a structure with the
         * original WHEA_XPF_PROCESSOR_ERROR_SECTION_VALIDBITS name.
         */
        private ulong _RawValidBits;

        private WHEA_XPF_PROCESSOR_ERROR_SECTION_VALIDBITS _ValidBits => (WHEA_XPF_PROCESSOR_ERROR_SECTION_VALIDBITS)(_RawValidBits & 0x3); // Bits 0-1

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        [JsonProperty(Order = 2)]
        public byte ProcInfoCount => (byte)((_RawValidBits >> 2) & 0x3F); // Bits 2-7

        [JsonProperty(Order = 3)]
        public byte ContextInfoCount => (byte)((_RawValidBits >> 8) & 0x3F); // Bits 8-13

        [JsonProperty(Order = 4)]
        public ulong LocalAPICId;

        [JsonProperty(Order = 5)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] CpuId; // TODO: Deserialize

        [JsonProperty(Order = 6)]
        public WHEA_XPF_PROCINFO[] ProcInfo;

        [JsonProperty(Order = 7)]
        public WHEA_XPF_CONTEXT_INFO[] ContextInfo;

        public WHEA_XPF_PROCESSOR_ERROR_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(WHEA_XPF_PROCESSOR_ERROR_SECTION), BaseStructSize, bytesRemaining) {
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            _RawValidBits = (ulong)Marshal.ReadInt64(sectionAddr);
            LocalAPICId = (ulong)Marshal.ReadInt64(sectionAddr, 8);
            var offset = 16;

            CpuId = new byte[48];
            Marshal.Copy(sectionAddr + offset, CpuId, 0, 48);
            offset += 48;

            if (ProcInfoCount > 0) {
                ProcInfo = new WHEA_XPF_PROCINFO[ProcInfoCount];
                for (var i = 0; i < ProcInfoCount; i++) {
                    ProcInfo[i] = new WHEA_XPF_PROCINFO(recordAddr,
                                                        sectionDsc.SectionOffset + (uint)offset,
                                                        sectionDsc.SectionLength - (uint)offset);
                    offset += (int)ProcInfo[i].GetNativeSize();
                }
            }

            if (ContextInfoCount > 0) {
                ContextInfo = new WHEA_XPF_CONTEXT_INFO[ContextInfoCount];
                for (var i = 0; i < ContextInfoCount; i++) {
                    ContextInfo[i] = new WHEA_XPF_CONTEXT_INFO(recordAddr,
                                                               sectionDsc.SectionOffset + (uint)offset,
                                                               sectionDsc.SectionLength - (uint)offset);
                    offset += (int)ContextInfo[i].GetNativeSize();
                }
            }

            _NativeSize = (uint)offset;
            FinalizeRecord(recordAddr, _NativeSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeLocalAPICId() =>
            (_ValidBits & WHEA_XPF_PROCESSOR_ERROR_SECTION_VALIDBITS.LocalAPICId) ==
            WHEA_XPF_PROCESSOR_ERROR_SECTION_VALIDBITS.LocalAPICId;

        [UsedImplicitly]
        public bool ShouldSerializeCpuId() =>
            (_ValidBits & WHEA_XPF_PROCESSOR_ERROR_SECTION_VALIDBITS.CpuId) ==
            WHEA_XPF_PROCESSOR_ERROR_SECTION_VALIDBITS.CpuId;

        [UsedImplicitly]
        public bool ShouldSerializeProcInfo() => ProcInfo != null && ProcInfo.Length != 0;

        [UsedImplicitly]
        public bool ShouldSerializeContextInfo() => ContextInfo != null && ContextInfo.Length != 0;
    }

    /*
     * Attempting to directly marshal as a structure results in serialization
     * issues with Newtonsoft.Json, though I suspect the real issue is in the
     * marshaller itself. The cause is sure to be related to the handling of
     * the *Check fields which was originally defined as a union of structures.
     */
    internal sealed class WHEA_XPF_PROCINFO : WheaErrorRecord {
        // Structure size is static
        private const uint _StructSize = 64;
        public override uint GetNativeSize() => _StructSize;

        private Guid _CheckInfoId;

        [JsonProperty(Order = 1)]
        public string CheckInfoId =>
            WHEA_XPF_PROCESSOR_ERROR_SECTION.CheckInfoTypes.TryGetValue(_CheckInfoId, out var CheckInfoTypeValue)
                ? CheckInfoTypeValue
                : _CheckInfoId.ToString();

        private WHEA_XPF_PROCINFO_VALIDBITS _ValidBits;

        [JsonProperty(Order = 2)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        [JsonProperty(Order = 3)]
        public WHEA_XPF_CACHE_CHECK CacheCheck;

        [JsonProperty(Order = 3)]
        public WHEA_XPF_TLB_CHECK TlbCheck;

        [JsonProperty(Order = 3)]
        public WHEA_XPF_BUS_CHECK BusCheck;

        [JsonProperty(Order = 3)]
        public WHEA_XPF_MS_CHECK MsCheck;

        [JsonProperty(Order = 4)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong TargetId;

        [JsonProperty(Order = 5)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong RequesterId;

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ResponderId;

        [JsonProperty(Order = 7)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong InstructionPointer;

        public WHEA_XPF_PROCINFO(IntPtr recordAddr, uint xpfProcInfoOffset, uint bytesRemaining) :
            base(typeof(WHEA_XPF_PROCINFO), xpfProcInfoOffset, _StructSize, bytesRemaining) {
            var xpfProcInfoAddr = recordAddr + (int)xpfProcInfoOffset;

            _CheckInfoId = Marshal.PtrToStructure<Guid>(xpfProcInfoAddr);
            var offset = Marshal.SizeOf<Guid>();

            _ValidBits = (WHEA_XPF_PROCINFO_VALIDBITS)Marshal.ReadInt64(xpfProcInfoAddr, offset);
            offset += 8;

            if (ShouldSerializeCacheCheck()) {
                CacheCheck = Marshal.PtrToStructure<WHEA_XPF_CACHE_CHECK>(xpfProcInfoAddr + offset);
            } else if (ShouldSerializeTlbCheck()) {
                TlbCheck = Marshal.PtrToStructure<WHEA_XPF_TLB_CHECK>(xpfProcInfoAddr + offset);
            } else if (ShouldSerializeBusCheck()) {
                BusCheck = Marshal.PtrToStructure<WHEA_XPF_BUS_CHECK>(xpfProcInfoAddr + offset);
            } else if (ShouldSerializeMsCheck()) {
                MsCheck = Marshal.PtrToStructure<WHEA_XPF_MS_CHECK>(xpfProcInfoAddr + offset);
            }

            offset += 8; // All of the above structures are 8 bytes

            TargetId = (ulong)Marshal.ReadInt64(xpfProcInfoAddr, offset);
            RequesterId = (ulong)Marshal.ReadInt64(xpfProcInfoAddr, offset + 8);
            ResponderId = (ulong)Marshal.ReadInt64(xpfProcInfoAddr, offset + 16);
            InstructionPointer = (ulong)Marshal.ReadInt64(xpfProcInfoAddr, offset + 24);

            FinalizeRecord(recordAddr, _StructSize);
        }

        // To gate access to the CheckInfo fields (Cache, TLB, Bus, and MS)
        private bool ShouldSerializeCheckInfo() =>
            (_ValidBits & WHEA_XPF_PROCINFO_VALIDBITS.CheckInfo) ==
            WHEA_XPF_PROCINFO_VALIDBITS.CheckInfo;

        [UsedImplicitly]
        public bool ShouldSerializeCacheCheck() =>
            ShouldSerializeCheckInfo() &&
            _CheckInfoId == WHEA_XPF_PROCESSOR_ERROR_SECTION.WHEA_CACHECHECK_GUID;

        [UsedImplicitly]
        public bool ShouldSerializeTlbCheck() =>
            ShouldSerializeCheckInfo() &&
            _CheckInfoId == WHEA_XPF_PROCESSOR_ERROR_SECTION.WHEA_TLBCHECK_GUID;

        [UsedImplicitly]
        public bool ShouldSerializeBusCheck() =>
            ShouldSerializeCheckInfo() &&
            _CheckInfoId == WHEA_XPF_PROCESSOR_ERROR_SECTION.WHEA_BUSCHECK_GUID;

        [UsedImplicitly]
        public bool ShouldSerializeMsCheck() =>
            ShouldSerializeCheckInfo() &&
            _CheckInfoId == WHEA_XPF_PROCESSOR_ERROR_SECTION.WHEA_MSCHECK_GUID;

        [UsedImplicitly]
        public bool ShouldSerializeTargetId() =>
            (_ValidBits & WHEA_XPF_PROCINFO_VALIDBITS.TargetId) ==
            WHEA_XPF_PROCINFO_VALIDBITS.TargetId;

        [UsedImplicitly]
        public bool ShouldSerializeRequesterId() =>
            (_ValidBits & WHEA_XPF_PROCINFO_VALIDBITS.RequesterId) ==
            WHEA_XPF_PROCINFO_VALIDBITS.RequesterId;

        [UsedImplicitly]
        public bool ShouldSerializeResponderId() =>
            (_ValidBits & WHEA_XPF_PROCINFO_VALIDBITS.ResponderId) ==
            WHEA_XPF_PROCINFO_VALIDBITS.ResponderId;

        [UsedImplicitly]
        public bool ShouldSerializeInstructionPointer() =>
            (_ValidBits & WHEA_XPF_PROCINFO_VALIDBITS.InstructionPointer) ==
            WHEA_XPF_PROCINFO_VALIDBITS.InstructionPointer;
    }

    /*
     * Originally defined as a ULONGLONG bitfield. This structure has the same
     * in memory format but is simpler to interact with.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_XPF_BUS_CHECK {
        private ulong _RawBits;

        private WHEA_XPF_BUS_CHECK_VALIDBITS _ValidBits => (WHEA_XPF_BUS_CHECK_VALIDBITS)(_RawBits & 0xFFFF); // Bits 0-15

        // TODO: Check the bits which map to flags
        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        [JsonProperty(Order = 2)]
        public string TransactionType => Enum.GetName(typeof(WHEA_XPF_BUS_CHECK_TRANSACTION_TYPE), (_RawBits & 0x30000) >> 16); // Bits 16-17

        [JsonProperty(Order = 3)]
        public string Operation => Enum.GetName(typeof(WHEA_XPF_BUS_CHECK_OPERATION), (_RawBits & 0x3C0000) >> 18); // Bits 18-21

        [JsonProperty(Order = 4)]
        public byte Level => (byte)((_RawBits & 0x1C00000) >> 22); // Bits 22-24

        private WHEA_XPF_BUS_CHECK_FLAGS _Flags => (WHEA_XPF_BUS_CHECK_FLAGS)((_RawBits & 0xFE000000) >> 25); // Bits 25-31

        [JsonProperty(Order = 5)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        [JsonProperty(Order = 6)]
        public string Participation => Enum.GetName(typeof(WHEA_XPF_BUS_CHECK_PARTICIPATION), (_RawBits & 0x60000000) >> 29); // Bits 29-30

        [JsonProperty(Order = 7)]
        public string AddressSpace => Enum.GetName(typeof(WHEA_XPF_BUS_CHECK_ADDRESS), (_RawBits & 0x300000000) >> 29); // Bits 32-33

        [UsedImplicitly]
        public bool ShouldSerializeTransactionType() =>
            (_ValidBits & WHEA_XPF_BUS_CHECK_VALIDBITS.TransactionTypeValid) ==
            WHEA_XPF_BUS_CHECK_VALIDBITS.TransactionTypeValid;

        [UsedImplicitly]
        public bool ShouldSerializeOperation() =>
            (_ValidBits & WHEA_XPF_BUS_CHECK_VALIDBITS.OperationValid) ==
            WHEA_XPF_BUS_CHECK_VALIDBITS.OperationValid;

        [UsedImplicitly]
        public bool ShouldSerializeLevel() =>
            (_ValidBits & WHEA_XPF_BUS_CHECK_VALIDBITS.LevelValid) ==
            WHEA_XPF_BUS_CHECK_VALIDBITS.LevelValid;

        [UsedImplicitly]
        public bool ShouldSerializeParticipation() =>
            (_ValidBits & WHEA_XPF_BUS_CHECK_VALIDBITS.ParticipationValid) ==
            WHEA_XPF_BUS_CHECK_VALIDBITS.ParticipationValid;

        [UsedImplicitly]
        public bool ShouldSerializeAddressSpace() =>
            (_ValidBits & WHEA_XPF_BUS_CHECK_VALIDBITS.AddressSpaceValid) ==
            WHEA_XPF_BUS_CHECK_VALIDBITS.AddressSpaceValid;
    }

    /*
     * Originally defined as a ULONGLONG bitfield. This structure has the same
     * in memory format but is simpler to interact with.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_XPF_CACHE_CHECK {
        private ulong _RawBits;

        private WHEA_XPF_CACHE_CHECK_VALIDBITS _ValidBits => (WHEA_XPF_CACHE_CHECK_VALIDBITS)(_RawBits & 0xFFFF); // Bits 0-15

        // TODO: Check the bits which map to flags
        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        [JsonProperty(Order = 2)]
        public string TransactionType => Enum.GetName(typeof(WHEA_XPF_CACHE_CHECK_TRANSACTION_TYPE), (_RawBits & 0x30000) >> 16); // Bits 16-17

        [JsonProperty(Order = 3)]
        public string Operation => Enum.GetName(typeof(WHEA_XPF_CACHE_CHECK_OPERATION), (_RawBits & 0x3C0000) >> 18); // Bits 18-21

        [JsonProperty(Order = 4)]
        public byte Level => (byte)((_RawBits & 0x1C00000) >> 22); // Bits 22-24

        private WHEA_XPF_CACHE_CHECK_FLAGS _Flags => (WHEA_XPF_CACHE_CHECK_FLAGS)((_RawBits & 0x3E000000) >> 25); // Bits 25-29

        [JsonProperty(Order = 5)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        [UsedImplicitly]
        public bool ShouldSerializeTransactionType() =>
            (_ValidBits & WHEA_XPF_CACHE_CHECK_VALIDBITS.TransactionTypeValid) ==
            WHEA_XPF_CACHE_CHECK_VALIDBITS.TransactionTypeValid;

        [UsedImplicitly]
        public bool ShouldSerializeOperation() =>
            (_ValidBits & WHEA_XPF_CACHE_CHECK_VALIDBITS.OperationValid) ==
            WHEA_XPF_CACHE_CHECK_VALIDBITS.OperationValid;

        [UsedImplicitly]
        public bool ShouldSerializeLevel() =>
            (_ValidBits & WHEA_XPF_CACHE_CHECK_VALIDBITS.LevelValid) ==
            WHEA_XPF_CACHE_CHECK_VALIDBITS.LevelValid;
    }

    /*
     * Originally defined as a ULONGLONG bitfield. This structure has the same
     * in memory format but is simpler to interact with.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_XPF_MS_CHECK {
        private ulong _RawBits;

        private WHEA_XPF_MS_CHECK_VALIDBITS _ValidBits => (WHEA_XPF_MS_CHECK_VALIDBITS)(_RawBits & 0xFFFF); // Bits 0-15

        // TODO: Check the bits which map to flags
        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        [JsonProperty(Order = 2)]
        public string ErrorType => Enum.GetName(typeof(WHEA_XPF_MS_CHECK_ERROR_TYPE), (_RawBits & 0x70000) >> 16); // Bits 16-18

        private WHEA_XPF_MS_CHECK_FLAGS _Flags => (WHEA_XPF_MS_CHECK_FLAGS)((_RawBits & 0xF80000) >> 25); // Bits 19-23

        [JsonProperty(Order = 3)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        [UsedImplicitly]
        public bool ShouldSerializeErrorType() =>
            (_ValidBits & WHEA_XPF_MS_CHECK_VALIDBITS.ErrorTypeValid) ==
            WHEA_XPF_MS_CHECK_VALIDBITS.ErrorTypeValid;
    }

    /*
     * Originally defined as a ULONGLONG bitfield. This structure has the same
     * in memory format but is simpler to interact with.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_XPF_TLB_CHECK {
        private ulong _RawBits;

        private WHEA_XPF_TLB_CHECK_VALIDBITS _ValidBits => (WHEA_XPF_TLB_CHECK_VALIDBITS)(_RawBits & 0xFFFF); // Bits 0-15

        // TODO: Check the bits which map to flags
        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        [JsonProperty(Order = 2)]
        public string TransactionType => Enum.GetName(typeof(WHEA_XPF_TLB_CHECK_TRANSACTION_TYPE), (_RawBits & 0x30000) >> 16); // Bits 16-17

        [JsonProperty(Order = 3)]
        public string Operation => Enum.GetName(typeof(WHEA_XPF_TLB_CHECK_OPERATION), (_RawBits & 0x3C0000) >> 18); // Bits 18-21

        [JsonProperty(Order = 4)]
        public byte Level => (byte)((_RawBits & 0x1C00000) >> 22); // Bits 22-24

        private WHEA_XPF_TLB_CHECK_FLAGS _Flags => (WHEA_XPF_TLB_CHECK_FLAGS)((_RawBits & 0x3E000000) >> 25); // Bits 25-29

        [JsonProperty(Order = 5)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        [UsedImplicitly]
        public bool ShouldSerializeTransactionType() =>
            (_ValidBits & WHEA_XPF_TLB_CHECK_VALIDBITS.TransactionTypeValid) ==
            WHEA_XPF_TLB_CHECK_VALIDBITS.TransactionTypeValid;

        [UsedImplicitly]
        public bool ShouldSerializeOperation() =>
            (_ValidBits & WHEA_XPF_TLB_CHECK_VALIDBITS.OperationValid) ==
            WHEA_XPF_TLB_CHECK_VALIDBITS.OperationValid;

        [UsedImplicitly]
        public bool ShouldSerializeLevel() =>
            (_ValidBits & WHEA_XPF_TLB_CHECK_VALIDBITS.LevelValid) ==
            WHEA_XPF_TLB_CHECK_VALIDBITS.LevelValid;
    }

    /*
     * Cannot be directly marshalled as a structure due to the usage of
     * variable length arrays, resulting in a non-static structure size.
     */
    internal sealed class WHEA_XPF_CONTEXT_INFO : WheaErrorRecord {
        // Size up to and including the MmRegisterAddress field
        private const uint BaseStructSize = 16;

        private uint _NativeSize;
        public override uint GetNativeSize() => _NativeSize;

        private WHEA_XPF_CONTEXT_INFO_TYPE _RegisterContextType;

        [JsonProperty(Order = 1)]
        public string RegisterContextType => Enum.GetName(typeof(WHEA_XPF_CONTEXT_INFO_TYPE), _RegisterContextType);

        [JsonProperty(Order = 2)]
        public ushort RegisterDataSize;

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint MSRAddress;

        [JsonProperty(Order = 4)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MmRegisterAddress;

        [JsonProperty(Order = 5)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] RegisterDataRaw;

        [JsonProperty(Order = 5, ItemConverterType = typeof(HexStringJsonConverter))]
        public uint[] RegisterData32;

        [JsonProperty(Order = 5, ItemConverterType = typeof(HexStringJsonConverter))]
        public ulong[] RegisterData64;

        [JsonProperty(Order = 5)]
        public WHEA_X86_REGISTER_STATE RegisterDataContext32;

        [JsonProperty(Order = 5)]
        public WHEA_X64_REGISTER_STATE RegisterDataContext64;

        public WHEA_XPF_CONTEXT_INFO(IntPtr recordAddr, uint xpfContextInfoOffset, uint bytesRemaining) :
            base(typeof(WHEA_XPF_CONTEXT_INFO), xpfContextInfoOffset, BaseStructSize, bytesRemaining) {
            var xpfContextInfoAddr = recordAddr + (int)xpfContextInfoOffset;

            _RegisterContextType = (WHEA_XPF_CONTEXT_INFO_TYPE)Marshal.ReadInt16(xpfContextInfoAddr);
            RegisterDataSize = (ushort)Marshal.ReadInt16(xpfContextInfoAddr, 2);
            MSRAddress = (uint)Marshal.ReadInt32(xpfContextInfoAddr, 4);
            MmRegisterAddress = (ulong)Marshal.ReadInt64(xpfContextInfoAddr, 8);
            var offset = 16;

            int numRegisters;
            switch (_RegisterContextType) {
                case WHEA_XPF_CONTEXT_INFO_TYPE.ContextX32:
                    RegisterDataContext32 = Marshal.PtrToStructure<WHEA_X86_REGISTER_STATE>(xpfContextInfoAddr + offset);
                    break;
                case WHEA_XPF_CONTEXT_INFO_TYPE.ContextX64:
                    RegisterDataContext64 = Marshal.PtrToStructure<WHEA_X64_REGISTER_STATE>(xpfContextInfoAddr + offset);
                    break;
                case WHEA_XPF_CONTEXT_INFO_TYPE.DebugRegistersX32:
                    numRegisters = RegisterDataSize / sizeof(long);
                    var tmpRegisterDataDebug32 = new long[numRegisters];
                    RegisterData32 = new uint[numRegisters];

                    // Values are 32-bit registers zero-extended to 64-bits
                    Marshal.Copy(xpfContextInfoAddr + offset, tmpRegisterDataDebug32, 0, numRegisters);
                    for (var i = 0; i < numRegisters; i++) {
                        RegisterData32[i] = (uint)tmpRegisterDataDebug32[i];
                    }

                    break;
                case WHEA_XPF_CONTEXT_INFO_TYPE.DebugRegistersX64:
                case WHEA_XPF_CONTEXT_INFO_TYPE.MmRegisters:
                case WHEA_XPF_CONTEXT_INFO_TYPE.MsrRegisters:
                    numRegisters = RegisterDataSize / sizeof(long);
                    var tmpRegisterData64 = new long[numRegisters];
                    RegisterData64 = new ulong[numRegisters];

                    Marshal.Copy(xpfContextInfoAddr + offset, tmpRegisterData64, 0, numRegisters);
                    for (var i = 0; i < numRegisters; i++) {
                        RegisterData64[i] = (ulong)tmpRegisterData64[i];
                    }

                    break;
                case WHEA_XPF_CONTEXT_INFO_TYPE.FxSave: // TODO: Implement properly
                case WHEA_XPF_CONTEXT_INFO_TYPE.UnclassifiedData:
                    RegisterDataRaw = new byte[RegisterDataSize];
                    Marshal.Copy(xpfContextInfoAddr + offset, RegisterDataRaw, 0, RegisterDataSize);
                    break;
                default:
                    throw new InvalidDataException($"{nameof(RegisterContextType)} is unknown or invalid: {RegisterContextType}");
            }

            offset += RegisterDataSize;

            // Structure is padded with zero bytes to a multiple of 16
            _NativeSize = (uint)(offset + RegisterDataSize % 16);

            FinalizeRecord(recordAddr, _NativeSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeMSRAddress() =>
            _RegisterContextType == WHEA_XPF_CONTEXT_INFO_TYPE.UnclassifiedData ||
            _RegisterContextType == WHEA_XPF_CONTEXT_INFO_TYPE.MsrRegisters;

        [UsedImplicitly]
        public bool ShouldSerializeMmRegisterAddress() => _RegisterContextType == WHEA_XPF_CONTEXT_INFO_TYPE.MmRegisters;

        [UsedImplicitly]
        public bool ShouldSerializeRegisterDataRaw() => _RegisterContextType == WHEA_XPF_CONTEXT_INFO_TYPE.UnclassifiedData;

        [UsedImplicitly]
        public bool ShouldSerializeRegisterData32() => _RegisterContextType == WHEA_XPF_CONTEXT_INFO_TYPE.DebugRegistersX32;

        [UsedImplicitly]
        public bool ShouldSerializeRegisterData64() =>
            _RegisterContextType == WHEA_XPF_CONTEXT_INFO_TYPE.MsrRegisters ||
            _RegisterContextType == WHEA_XPF_CONTEXT_INFO_TYPE.DebugRegistersX64 ||
            _RegisterContextType == WHEA_XPF_CONTEXT_INFO_TYPE.MmRegisters;

        [UsedImplicitly]
        public bool ShouldSerializeRegisterDataContext32() => _RegisterContextType == WHEA_XPF_CONTEXT_INFO_TYPE.ContextX32;

        [UsedImplicitly]
        public bool ShouldSerializeRegisterDataContext64() => _RegisterContextType == WHEA_XPF_CONTEXT_INFO_TYPE.ContextX64;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_X86_REGISTER_STATE {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Eax;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Ebx;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Ecx;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Edx;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Esi;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Edi;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Ebp;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Esp;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Cs;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Ds;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Ss;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Es;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Fs;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Gs;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Eflags;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Eip;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Cr0;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Cr1;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Cr2;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Cr3;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Cr4;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Gdtr;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Idtr;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Ldtr;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Tr;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_X64_REGISTER_STATE {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Rax;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Rbx;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Rcx;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Rdx;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Rsi;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Rdi;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Rbp;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Rsp;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong R8;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong R9;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong R10;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong R11;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong R12;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong R13;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong R14;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong R15;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Cs;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Ds;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Ss;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Es;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Fs;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Gs;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Reserved;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Rflags;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Eip;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Cr0;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Cr1;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Cr2;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Cr3;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Cr4;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Cr8;

        public WHEA128A Gdtr;
        public WHEA128A Idtr;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Ldtr;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ushort Tr;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();
    }

    // TODO: Original definition has DECLSPEC_ALIGN(16)
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA128A {
        public ulong Low;
        public long High;
    }

    // @formatter:int_align_fields true

    // From preprocessor definitions (XPF_BUS_CHECK_ADDRESS_*)
    internal enum WHEA_XPF_BUS_CHECK_ADDRESS : byte {
        Memory   = 0,
        Reserved = 1,
        IO       = 2,
        Other    = 3
    }

    // Originally defined in the WHEA_XPF_BUS_CHECK bitfield
    [Flags]
    internal enum WHEA_XPF_BUS_CHECK_FLAGS : ushort {
        ProcessorContextCorrupt = 0x1,
        Uncorrected             = 0x2,
        PreciseIP               = 0x4,
        RestartableIP           = 0x8,
        Overflow                = 0x10,
        Timeout                 = 0x80
    }

    // From preprocessor definitions (XPF_BUS_CHECK_OPERATION_*)
    internal enum WHEA_XPF_BUS_CHECK_OPERATION : byte {
        Generic          = 0,
        GenericRead      = 1,
        GenericWrite     = 2,
        DataRead         = 3,
        DataWrite        = 4,
        InstructionFetch = 5,
        Prefetch         = 6
    }

    // From preprocessor definitions (XPF_BUS_CHECK_PARTICIPATION_*)
    internal enum WHEA_XPF_BUS_CHECK_PARTICIPATION : byte {
        ProcessorOriginated = 0,
        ProcessorResponded  = 1,
        ProcessorObserved   = 2,
        Generic             = 3
    }

    // From preprocessor definitions (XPF_BUS_CHECK_TRANSACTIONTYPE_*)
    internal enum WHEA_XPF_BUS_CHECK_TRANSACTION_TYPE : byte {
        Instruction = 0,
        DataAccess  = 1,
        Generic     = 2
    }

    // Originally defined in the WHEA_XPF_BUS_CHECK bitfield
    [Flags]
    internal enum WHEA_XPF_BUS_CHECK_VALIDBITS : ushort {
        TransactionTypeValid         = 0x1,
        OperationValid               = 0x2,
        LevelValid                   = 0x4,
        ProcessorContextCorruptValid = 0x8,
        UncorrectedValid             = 0x10,
        PreciseIPValid               = 0x20,
        RestartableIPValid           = 0x40,
        OverflowValid                = 0x80,
        ParticipationValid           = 0x100,
        TimeoutValid                 = 0x200,
        AddressSpaceValid            = 0x400
    }

    // Originally defined in the WHEA_XPF_CACHE_CHECK bitfield
    [Flags]
    internal enum WHEA_XPF_CACHE_CHECK_FLAGS : byte {
        ProcessorContextCorrupt = 0x1,
        Uncorrected             = 0x2,
        PreciseIP               = 0x4,
        RestartableIP           = 0x8,
        Overflow                = 0x10
    }

    // From preprocessor definitions (XPF_CACHE_CHECK_OPERATION_*)
    internal enum WHEA_XPF_CACHE_CHECK_OPERATION : byte {
        Generic          = 0,
        GenericRead      = 1,
        GenericWrite     = 2,
        DataRead         = 3,
        DataWrite        = 4,
        InstructionFetch = 5,
        Prefetch         = 6,
        Eviction         = 7,
        Snoop            = 8
    }

    // From preprocessor definitions (XPF_CACHE_CHECK_TRANSACTIONTYPE_*)
    internal enum WHEA_XPF_CACHE_CHECK_TRANSACTION_TYPE : byte {
        Instruction = 0,
        DataAccess  = 1,
        Generic     = 2
    }

    // Originally defined in the WHEA_XPF_CACHE_CHECK bitfield
    [Flags]
    internal enum WHEA_XPF_CACHE_CHECK_VALIDBITS : ushort {
        TransactionTypeValid         = 0x1,
        OperationValid               = 0x2,
        LevelValid                   = 0x4,
        ProcessorContextCorruptValid = 0x8,
        UncorrectedValid             = 0x10,
        PreciseIPValid               = 0x20,
        RestartableIPValid           = 0x40,
        OverflowValid                = 0x80
    }

    // From preprocessor definitions (XPF_CONTEXT_INFO_*)
    internal enum WHEA_XPF_CONTEXT_INFO_TYPE : ushort {
        UnclassifiedData  = 0,
        MsrRegisters      = 1,
        ContextX32        = 2,
        ContextX64        = 3,
        FxSave            = 4,
        DebugRegistersX32 = 5,
        DebugRegistersX64 = 6,
        MmRegisters       = 7
    }

    // From preprocessor definitions (XPF_MS_CHECK_ERRORTYPE_*)
    internal enum WHEA_XPF_MS_CHECK_ERROR_TYPE : byte {
        NoError              = 0,
        Unclassified         = 1,
        McRomParity          = 2,
        External             = 3,
        Frc                  = 4,
        InternalUnclassified = 5
    }

    // Originally defined in the WHEA_XPF_MS_CHECK bitfield
    [Flags]
    internal enum WHEA_XPF_MS_CHECK_FLAGS : byte {
        ProcessorContextCorrupt = 0x1,
        Uncorrected             = 0x2,
        PreciseIP               = 0x4,
        RestartableIP           = 0x8,
        Overflow                = 0x10
    }

    // Originally defined in the WHEA_XPF_MS_CHECK bitfield
    [Flags]
    internal enum WHEA_XPF_MS_CHECK_VALIDBITS : ushort {
        ErrorTypeValid               = 0x1,
        ProcessorContextCorruptValid = 0x2,
        UncorrectedValid             = 0x4,
        PreciseIPValid               = 0x8,
        RestartableIPValid           = 0x10,
        OverflowValid                = 0x20
    }

    /*
     * Originally defined as a ULONGLONG bitfield, but out of the 14 non-
     * reserved bits only two are flags. Those flags are defined here and the
     * the remaining non-reserved bits in WHEA_XPF_PROCESSOR_ERROR_SECTION.
     */
    [Flags]
    internal enum WHEA_XPF_PROCESSOR_ERROR_SECTION_VALIDBITS : byte {
        LocalAPICId = 0x1,
        CpuId       = 0x2
    }

    [Flags]
    internal enum WHEA_XPF_PROCINFO_VALIDBITS : ulong {
        CheckInfo          = 0x1,
        TargetId           = 0x2,
        RequesterId        = 0x4,
        ResponderId        = 0x8,
        InstructionPointer = 0x10
    }

    // Originally defined in the WHEA_XPF_TLB_CHECK bitfield
    [Flags]
    internal enum WHEA_XPF_TLB_CHECK_FLAGS : byte {
        ProcessorContextCorrupt = 0x1,
        Uncorrected             = 0x2,
        PreciseIP               = 0x4,
        RestartableIP           = 0x8,
        Overflow                = 0x10
    }

    // From preprocessor definitions (XPF_TLB_CHECK_OPERATION_*)
    internal enum WHEA_XPF_TLB_CHECK_OPERATION : byte {
        Generic          = 0,
        GenericRead      = 1,
        GenericWrite     = 2,
        DataRead         = 3,
        DataWrite        = 4,
        InstructionFetch = 5,
        Prefetch         = 6
    }

    // From preprocessor definitions (XPF_TLB_CHECK_TRANSACTIONTYPE_*)
    internal enum WHEA_XPF_TLB_CHECK_TRANSACTION_TYPE : byte {
        Instruction = 0,
        DataAccess  = 1,
        Generic     = 2
    }

    // Originally defined in the WHEA_XPF_TLB_CHECK bitfield
    [Flags]
    internal enum WHEA_XPF_TLB_CHECK_VALIDBITS : ushort {
        TransactionTypeValid         = 0x1,
        OperationValid               = 0x2,
        LevelValid                   = 0x4,
        ProcessorContextCorruptValid = 0x8,
        UncorrectedValid             = 0x10,
        PreciseIPValid               = 0x20,
        RestartableIPValid           = 0x40,
        OverflowValid                = 0x80
    }

    // @formatter:int_align_fields false
}
