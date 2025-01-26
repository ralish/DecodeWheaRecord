#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly
#pragma warning disable IDE1006 // Naming rule violation

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Descriptors;
using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

/*
 * Module       Version             Arch(s)         Function(s)
 * ntoskrnl     10.0.26100.2605     AMD64           HalpCreateMcaProcessorErrorRecord
 */
namespace DecodeWheaRecord.Errors.UEFI {
    internal sealed class WHEA_XPF_PROCESSOR_ERROR_SECTION : WheaRecord {
        private uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        // Size up to and including the CpuId field
        private const uint MinStructSize = 64;

        // See WHEA_XPF_PROCESSOR_ERROR_SECTION_VALIDBITS structure comment
        private ulong _RawValidBits;

        private WHEA_XPF_PROCESSOR_ERROR_SECTION_VALIDBITS _ValidBits => (WHEA_XPF_PROCESSOR_ERROR_SECTION_VALIDBITS)(_RawValidBits & 0x3); // Bits 0-1

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnumFlagsAsString(_ValidBits);

        // See WHEA_XPF_PROCESSOR_ERROR_SECTION_VALIDBITS structure comment
        [JsonProperty(Order = 2)]
        public byte ProcInfoCount => (byte)((_RawValidBits >> 2) & 0x3F); // Bits 2-7

        // See WHEA_XPF_PROCESSOR_ERROR_SECTION_VALIDBITS structure comment
        [JsonProperty(Order = 3)]
        public byte ContextInfoCount => (byte)((_RawValidBits >> 8) & 0x3F); // Bits 8-13

        [JsonProperty(Order = 4)]
        public ulong LocalAPICId;

        // Future: Decode the returned CPUID data
        [JsonProperty(Order = 5)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] CpuId = new byte[48];

        [JsonProperty(Order = 6)]
        public WHEA_XPF_PROCINFO[] ProcInfo;

        [JsonProperty(Order = 7)]
        public WHEA_XPF_CONTEXT_INFO[] ContextInfo;

        public WHEA_XPF_PROCESSOR_ERROR_SECTION(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_XPF_PROCESSOR_ERROR_SECTION), structOffset, MinStructSize, bytesRemaining) {
            WheaXpfProcessorErrorSection(recordAddr, structOffset, bytesRemaining);
        }

        public WHEA_XPF_PROCESSOR_ERROR_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(typeof(WHEA_XPF_PROCESSOR_ERROR_SECTION), sectionDsc, MinStructSize, bytesRemaining) {
            WheaXpfProcessorErrorSection(recordAddr, sectionDsc.SectionOffset, sectionDsc.SectionLength);
        }

        private void WheaXpfProcessorErrorSection(IntPtr recordAddr, uint structOffset, uint bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _RawValidBits = (ulong)Marshal.ReadInt64(structAddr);
            LocalAPICId = (ulong)Marshal.ReadInt64(structAddr, 8);
            Marshal.Copy(structAddr + 16, CpuId, 0, CpuId.Length);
            var offset = MinStructSize;

            ProcInfo = new WHEA_XPF_PROCINFO[ProcInfoCount];

            if (ProcInfoCount > 0) {
                for (var i = 0; i < ProcInfoCount; i++) {
                    ProcInfo[i] = new WHEA_XPF_PROCINFO(recordAddr, structOffset + offset, bytesRemaining - offset);
                    offset += ProcInfo[i].GetNativeSize();
                }
            }

            ContextInfo = new WHEA_XPF_CONTEXT_INFO[ContextInfoCount];

            if (ContextInfoCount > 0) {
                for (var i = 0; i < ContextInfoCount; i++) {
                    ContextInfo[i] = new WHEA_XPF_CONTEXT_INFO(recordAddr, structOffset + offset, bytesRemaining - offset);

                    // Pad when the size is not a multiple of 16 bytes
                    var ctxInfoStructSize = ContextInfo[i].GetNativeSize();
                    var ctxInfoStructPad = ctxInfoStructSize % 16;
                    offset += ctxInfoStructSize + ctxInfoStructPad;
                }
            }

            _StructSize = offset;
            FinalizeRecord(recordAddr, _StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeLocalAPICId() => (_ValidBits & WHEA_XPF_PROCESSOR_ERROR_SECTION_VALIDBITS.LocalAPICId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeCpuId() => (_ValidBits & WHEA_XPF_PROCESSOR_ERROR_SECTION_VALIDBITS.CpuId) != 0;
    }

    internal sealed class WHEA_XPF_PROCINFO : WheaRecord {
        private const uint StructSize = 64;
        public override uint GetNativeSize() => StructSize;

        private Guid _CheckInfoId;

        [JsonProperty(Order = 1)]
        public string CheckInfoId => WheaGuids.ProcCheckInfoTypes.TryGetValue(_CheckInfoId, out var checkInfoType) ? checkInfoType : _CheckInfoId.ToString();

        private WHEA_XPF_PROCINFO_VALIDBITS _ValidBits;

        [JsonProperty(Order = 2)]
        public string ValidBits => GetEnumFlagsAsString(_ValidBits);

        /*
         * The next four fields contain the check information for the type of
         * check as determined by the CheckInfoId field. The Windows headers
         * define them in a union in the structure but we directly embed them
         * and marshal only the correct one.
         */

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

        public WHEA_XPF_PROCINFO(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_XPF_PROCINFO), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _CheckInfoId = Marshal.PtrToStructure<Guid>(structAddr);
            _ValidBits = (WHEA_XPF_PROCINFO_VALIDBITS)Marshal.ReadInt64(structAddr, 16);

            if (IsCheckInfoValid()) {
                if (_CheckInfoId == WheaGuids.WHEA_CACHECHECK_GUID) {
                    CacheCheck = PtrToStructure<WHEA_XPF_CACHE_CHECK>(structAddr + 24);
                } else if (_CheckInfoId == WheaGuids.WHEA_TLBCHECK_GUID) {
                    TlbCheck = PtrToStructure<WHEA_XPF_TLB_CHECK>(structAddr + 24);
                } else if (_CheckInfoId == WheaGuids.WHEA_BUSCHECK_GUID) {
                    BusCheck = PtrToStructure<WHEA_XPF_BUS_CHECK>(structAddr + 24);
                } else if (_CheckInfoId == WheaGuids.WHEA_MSCHECK_GUID) {
                    MsCheck = PtrToStructure<WHEA_XPF_MS_CHECK>(structAddr + 24);
                } else {
                    throw new InvalidDataException($"{nameof(CheckInfoId)} is unknown or invalid: {CheckInfoId}");
                }
            }

            TargetId = (ulong)Marshal.ReadInt64(structAddr, 32);
            RequesterId = (ulong)Marshal.ReadInt64(structAddr, 40);
            ResponderId = (ulong)Marshal.ReadInt64(structAddr, 48);
            InstructionPointer = (ulong)Marshal.ReadInt64(structAddr, 56);

            FinalizeRecord(recordAddr, StructSize);
        }

        private bool IsCheckInfoValid() => (_ValidBits & WHEA_XPF_PROCINFO_VALIDBITS.CheckInfo) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeCacheCheck() => IsCheckInfoValid() && _CheckInfoId == WheaGuids.WHEA_CACHECHECK_GUID;

        [UsedImplicitly]
        public bool ShouldSerializeTlbCheck() => IsCheckInfoValid() && _CheckInfoId == WheaGuids.WHEA_TLBCHECK_GUID;

        [UsedImplicitly]
        public bool ShouldSerializeBusCheck() => IsCheckInfoValid() && _CheckInfoId == WheaGuids.WHEA_BUSCHECK_GUID;

        [UsedImplicitly]
        public bool ShouldSerializeMsCheck() => IsCheckInfoValid() && _CheckInfoId == WheaGuids.WHEA_MSCHECK_GUID;

        [UsedImplicitly]
        public bool ShouldSerializeTargetId() => (_ValidBits & WHEA_XPF_PROCINFO_VALIDBITS.TargetId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeRequesterId() => (_ValidBits & WHEA_XPF_PROCINFO_VALIDBITS.RequesterId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeResponderId() => (_ValidBits & WHEA_XPF_PROCINFO_VALIDBITS.ResponderId) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeInstructionPointer() => (_ValidBits & WHEA_XPF_PROCINFO_VALIDBITS.InstructionPointer) != 0;
    }

    // Structure size: 8 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_XPF_CACHE_CHECK {
        private ulong _RawBits;

        private WHEA_XPF_CACHE_CHECK_VALIDBITS _ValidBits => (WHEA_XPF_CACHE_CHECK_VALIDBITS)_RawBits; // Bits 0-15

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnumFlagsAsString(_ValidBits);

        // Switched to an enumeration
        [JsonProperty(Order = 2)]
        public string TransactionType => GetEnumValueAsString<WHEA_XPF_CACHE_CHECK_TRANSACTION_TYPE>((byte)((_RawBits >> 16) & 0x3)); // Bits 16-17

        // Switched to an enumeration
        [JsonProperty(Order = 3)]
        public string Operation => GetEnumValueAsString<WHEA_XPF_CACHE_CHECK_OPERATION>((byte)((_RawBits >> 18) & 0xF)); // Bits 18-21

        [JsonProperty(Order = 4)]
        public byte Level => (byte)((_RawBits >> 22) & 0x7); // Bits 22-24

        [JsonProperty(Order = 5)]
        public bool ProcessorContextCorrupt => ((_RawBits >> 25) & 0x1) == 1; // Bit 25

        [JsonProperty(Order = 6)]
        public bool Uncorrected => ((_RawBits >> 26) & 0x1) == 1; // Bit 26

        [JsonProperty(Order = 7)]
        public bool PreciseIP => ((_RawBits >> 27) & 0x1) == 1; // Bit 27

        [JsonProperty(Order = 8)]
        public bool RestartableIP => ((_RawBits >> 28) & 0x1) == 1; // Bit 28

        [JsonProperty(Order = 9)]
        public bool Overflow => ((_RawBits >> 29) & 0x1) == 1; // Bit 29

        [JsonProperty(Order = 10)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Reserved => _RawBits >> 30; // Bits 30-63

        [UsedImplicitly]
        public bool ShouldSerializeTransactionType() => (_ValidBits & WHEA_XPF_CACHE_CHECK_VALIDBITS.TransactionTypeValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeOperation() => (_ValidBits & WHEA_XPF_CACHE_CHECK_VALIDBITS.OperationValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeLevel() => (_ValidBits & WHEA_XPF_CACHE_CHECK_VALIDBITS.LevelValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeProcessorContextCorrupt() => (_ValidBits & WHEA_XPF_CACHE_CHECK_VALIDBITS.ProcessorContextCorruptValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeUncorrected() => (_ValidBits & WHEA_XPF_CACHE_CHECK_VALIDBITS.UncorrectedValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializePreciseIP() => (_ValidBits & WHEA_XPF_CACHE_CHECK_VALIDBITS.PreciseIPValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeRestartableIP() => (_ValidBits & WHEA_XPF_CACHE_CHECK_VALIDBITS.RestartableIPValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeOverflow() => (_ValidBits & WHEA_XPF_CACHE_CHECK_VALIDBITS.OverflowValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 8 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_XPF_TLB_CHECK {
        private ulong _RawBits;

        private WHEA_XPF_TLB_CHECK_VALIDBITS _ValidBits => (WHEA_XPF_TLB_CHECK_VALIDBITS)_RawBits; // Bits 0-15

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnumFlagsAsString(_ValidBits);

        // Switched to an enumeration
        [JsonProperty(Order = 2)]
        public string TransactionType => GetEnumValueAsString<WHEA_XPF_TLB_CHECK_TRANSACTION_TYPE>((byte)((_RawBits >> 16) & 0x3)); // Bits 16-17

        // Switched to an enumeration
        [JsonProperty(Order = 3)]
        public string Operation => GetEnumValueAsString<WHEA_XPF_TLB_CHECK_OPERATION>((byte)((_RawBits >> 18) & 0xF)); // Bits 18-21

        [JsonProperty(Order = 4)]
        public byte Level => (byte)((_RawBits >> 22) & 0x7); // Bits 22-24

        [JsonProperty(Order = 5)]
        public bool ProcessorContextCorrupt => ((_RawBits >> 25) & 0x1) == 1; // Bit 25

        [JsonProperty(Order = 6)]
        public bool Uncorrected => ((_RawBits >> 26) & 0x1) == 1; // Bit 26

        [JsonProperty(Order = 7)]
        public bool PreciseIP => ((_RawBits >> 27) & 0x1) == 1; // Bit 27

        [JsonProperty(Order = 8)]
        public bool RestartableIP => ((_RawBits >> 28) & 0x1) == 1; // Bit 28

        [JsonProperty(Order = 9)]
        public bool Overflow => ((_RawBits >> 29) & 0x1) == 1; // Bit 29

        [JsonProperty(Order = 10)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Reserved => _RawBits >> 30; // Bits 30-63

        [UsedImplicitly]
        public bool ShouldSerializeTransactionType() => (_ValidBits & WHEA_XPF_TLB_CHECK_VALIDBITS.TransactionTypeValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeOperation() => (_ValidBits & WHEA_XPF_TLB_CHECK_VALIDBITS.OperationValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeLevel() => (_ValidBits & WHEA_XPF_TLB_CHECK_VALIDBITS.LevelValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeProcessorContextCorrupt() => (_ValidBits & WHEA_XPF_TLB_CHECK_VALIDBITS.ProcessorContextCorruptValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeUncorrected() => (_ValidBits & WHEA_XPF_TLB_CHECK_VALIDBITS.UncorrectedValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializePreciseIP() => (_ValidBits & WHEA_XPF_TLB_CHECK_VALIDBITS.PreciseIPValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeRestartableIP() => (_ValidBits & WHEA_XPF_TLB_CHECK_VALIDBITS.RestartableIPValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeOverflow() => (_ValidBits & WHEA_XPF_TLB_CHECK_VALIDBITS.OverflowValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 8 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_XPF_BUS_CHECK {
        private ulong _RawBits;

        private WHEA_XPF_BUS_CHECK_VALIDBITS _ValidBits => (WHEA_XPF_BUS_CHECK_VALIDBITS)_RawBits; // Bits 0-15

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnumFlagsAsString(_ValidBits);

        // Switched to an enumeration
        [JsonProperty(Order = 2)]
        public string TransactionType => GetEnumValueAsString<WHEA_XPF_BUS_CHECK_TRANSACTION_TYPE>((byte)((_RawBits >> 16) & 0x3)); // Bits 16-17

        // Switched to an enumeration
        [JsonProperty(Order = 3)]
        public string Operation => GetEnumValueAsString<WHEA_XPF_BUS_CHECK_OPERATION>((byte)((_RawBits >> 18) & 0xF)); // Bits 18-21

        [JsonProperty(Order = 4)]
        public byte Level => (byte)((_RawBits >> 22) & 0x7); // Bits 22-24

        [JsonProperty(Order = 5)]
        public bool ProcessorContextCorrupt => ((_RawBits >> 25) & 0x1) == 1; // Bit 25

        [JsonProperty(Order = 6)]
        public bool Uncorrected => ((_RawBits >> 26) & 0x1) == 1; // Bit 26

        [JsonProperty(Order = 7)]
        public bool PreciseIP => ((_RawBits >> 27) & 0x1) == 1; // Bit 27

        [JsonProperty(Order = 8)]
        public bool RestartableIP => ((_RawBits >> 28) & 0x1) == 1; // Bit 28

        [JsonProperty(Order = 9)]
        public bool Overflow => ((_RawBits >> 29) & 0x1) == 1; // Bit 29

        // Switched to an enumeration
        [JsonProperty(Order = 10)]
        public string Participation => GetEnumValueAsString<WHEA_XPF_BUS_CHECK_PARTICIPATION>((byte)((_RawBits >> 30) & 0x3)); // Bits 30-31

        [JsonProperty(Order = 11)]
        public bool Timeout => ((_RawBits >> 32) & 0x1) == 1; // Bit 32

        // Switched to an enumeration
        [JsonProperty(Order = 12)]
        public string AddressSpace => GetEnumValueAsString<WHEA_XPF_BUS_CHECK_ADDRESS>((byte)((_RawBits >> 33) & 0x3)); // Bits 33-34

        [JsonProperty(Order = 13)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Reserved => _RawBits >> 35; // Bits 35-63

        [UsedImplicitly]
        public bool ShouldSerializeTransactionType() => (_ValidBits & WHEA_XPF_BUS_CHECK_VALIDBITS.TransactionTypeValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeOperation() => (_ValidBits & WHEA_XPF_BUS_CHECK_VALIDBITS.OperationValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeLevel() => (_ValidBits & WHEA_XPF_BUS_CHECK_VALIDBITS.LevelValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeProcessorContextCorrupt() => (_ValidBits & WHEA_XPF_BUS_CHECK_VALIDBITS.ProcessorContextCorruptValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeUncorrected() => (_ValidBits & WHEA_XPF_BUS_CHECK_VALIDBITS.UncorrectedValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializePreciseIP() => (_ValidBits & WHEA_XPF_BUS_CHECK_VALIDBITS.PreciseIPValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeRestartableIP() => (_ValidBits & WHEA_XPF_BUS_CHECK_VALIDBITS.RestartableIPValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeOverflow() => (_ValidBits & WHEA_XPF_BUS_CHECK_VALIDBITS.OverflowValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeParticipation() => (_ValidBits & WHEA_XPF_BUS_CHECK_VALIDBITS.ParticipationValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeTimeout() => (_ValidBits & WHEA_XPF_BUS_CHECK_VALIDBITS.TimeoutValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeAddressSpace() => (_ValidBits & WHEA_XPF_BUS_CHECK_VALIDBITS.AddressSpaceValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 8 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_XPF_MS_CHECK {
        private ulong _RawBits;

        private WHEA_XPF_MS_CHECK_VALIDBITS _ValidBits => (WHEA_XPF_MS_CHECK_VALIDBITS)_RawBits; // Bits 0-15

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnumFlagsAsString(_ValidBits);

        // Switched to an enumeration
        [JsonProperty(Order = 2)]
        public string ErrorType => GetEnumValueAsString<WHEA_XPF_MS_CHECK_ERROR_TYPE>((byte)((_RawBits >> 16) & 0x7)); // Bits 16-18

        [JsonProperty(Order = 3)]
        public bool ProcessorContextCorrupt => ((_RawBits >> 19) & 0x1) == 1; // Bit 19

        [JsonProperty(Order = 4)]
        public bool Uncorrected => ((_RawBits >> 20) & 0x1) == 1; // Bit 20

        [JsonProperty(Order = 5)]
        public bool PreciseIP => ((_RawBits >> 21) & 0x1) == 1; // Bit 21

        [JsonProperty(Order = 6)]
        public bool RestartableIP => ((_RawBits >> 22) & 0x1) == 1; // Bit 22

        [JsonProperty(Order = 7)]
        public bool Overflow => ((_RawBits >> 23) & 0x1) == 1; // Bit 23

        [JsonProperty(Order = 8)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Reserved => _RawBits >> 24; // Bits 24-63

        [UsedImplicitly]
        public bool ShouldSerializeErrorType() => (_ValidBits & WHEA_XPF_MS_CHECK_VALIDBITS.ErrorTypeValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeProcessorContextCorrupt() => (_ValidBits & WHEA_XPF_MS_CHECK_VALIDBITS.ProcessorContextCorruptValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeUncorrected() => (_ValidBits & WHEA_XPF_MS_CHECK_VALIDBITS.UncorrectedValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializePreciseIP() => (_ValidBits & WHEA_XPF_MS_CHECK_VALIDBITS.PreciseIPValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeRestartableIP() => (_ValidBits & WHEA_XPF_MS_CHECK_VALIDBITS.RestartableIPValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeOverflow() => (_ValidBits & WHEA_XPF_MS_CHECK_VALIDBITS.OverflowValid) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    internal sealed class WHEA_XPF_CONTEXT_INFO : WheaRecord {
        private readonly uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        // Size up to and including the MmRegisterAddress field
        private const uint MinStructSize = 16;

        // Switched to an enumeration
        private WHEA_XPF_CONTEXT_INFO_TYPE _RegisterContextType;

        [JsonProperty(Order = 1)]
        public string RegisterContextType => GetEnumValueAsString<WHEA_XPF_CONTEXT_INFO_TYPE>(_RegisterContextType);

        [JsonProperty(Order = 2)]
        public ushort RegisterDataSize;

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint MSRAddress;

        [JsonProperty(Order = 4)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MmRegisterAddress;

        /*
         * The original structure has one additional field typed as a variable
         * length byte array. We've expanded it into separate fields typed to
         * the matching structures from the RegisterContextType enumeration.
         */

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

        public WHEA_XPF_CONTEXT_INFO(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_XPF_CONTEXT_INFO), structOffset, MinStructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _RegisterContextType = (WHEA_XPF_CONTEXT_INFO_TYPE)Marshal.ReadInt16(structAddr);
            RegisterDataSize = (ushort)Marshal.ReadInt16(structAddr, 2);

            if (MinStructSize + RegisterDataSize > bytesRemaining) {
                var checkCalc = $"{MinStructSize} + {RegisterDataSize} > {bytesRemaining}";
                throw new InvalidDataException($"{nameof(RegisterDataSize)} results in size greater than bytes remaining: {checkCalc}");
            }

            MSRAddress = (uint)Marshal.ReadInt32(structAddr, 4);
            MmRegisterAddress = (ulong)Marshal.ReadInt64(structAddr, 8);

            int numRegisters;
            var ctxInfoStructAddr = structAddr + 16;
            int ctxInfoStructSize = RegisterDataSize;

            switch (_RegisterContextType) {
                case WHEA_XPF_CONTEXT_INFO_TYPE.ContextX32:
                    ctxInfoStructSize = Marshal.SizeOf<WHEA_X86_REGISTER_STATE>();
                    CheckSufficientBytes((uint)ctxInfoStructSize, bytesRemaining);
                    RegisterDataContext32 = PtrToStructure<WHEA_X86_REGISTER_STATE>(ctxInfoStructAddr);
                    break;
                case WHEA_XPF_CONTEXT_INFO_TYPE.ContextX64:
                    ctxInfoStructSize = Marshal.SizeOf<WHEA_X64_REGISTER_STATE>();
                    CheckSufficientBytes((uint)ctxInfoStructSize, bytesRemaining);
                    RegisterDataContext64 = PtrToStructure<WHEA_X64_REGISTER_STATE>(ctxInfoStructAddr);
                    break;
                case WHEA_XPF_CONTEXT_INFO_TYPE.DebugRegistersX32:
                    numRegisters = RegisterDataSize / sizeof(long);

                    // Values are 32-bit registers zero-extended to 64-bits
                    var registerDataDebug32Signed = new long[numRegisters];
                    Marshal.Copy(ctxInfoStructAddr, registerDataDebug32Signed, 0, numRegisters);
                    RegisterData32 = new uint[numRegisters];
                    for (var i = 0; i < numRegisters; i++) {
                        RegisterData32[i] = (uint)registerDataDebug32Signed[i];
                    }

                    break;
                case WHEA_XPF_CONTEXT_INFO_TYPE.DebugRegistersX64:
                case WHEA_XPF_CONTEXT_INFO_TYPE.MmRegisters:
                case WHEA_XPF_CONTEXT_INFO_TYPE.MsrRegisters:
                    numRegisters = RegisterDataSize / sizeof(long);

                    var registerData64Signed = new long[numRegisters];
                    Marshal.Copy(ctxInfoStructAddr, registerData64Signed, 0, numRegisters);
                    RegisterData64 = new ulong[numRegisters];
                    for (var i = 0; i < numRegisters; i++) {
                        RegisterData64[i] = (ulong)registerData64Signed[i];
                    }

                    break;
                case WHEA_XPF_CONTEXT_INFO_TYPE.FxSave: // Future: Decode registers returned by FXSAVE instruction
                case WHEA_XPF_CONTEXT_INFO_TYPE.UnclassifiedData:
                    RegisterDataRaw = new byte[RegisterDataSize];
                    Marshal.Copy(ctxInfoStructAddr, RegisterDataRaw, 0, RegisterDataSize);
                    break;
                default:
                    throw new InvalidDataException($"{nameof(RegisterContextType)} is unknown or invalid: {RegisterContextType}");
            }

            if (RegisterDataSize != ctxInfoStructSize) {
                var checkCalc = $"{RegisterDataSize} != {ctxInfoStructSize}";
                throw new InvalidDataException($"{nameof(RegisterDataSize)} differs from marshalled structure size: {checkCalc}");
            }

            _StructSize = MinStructSize + RegisterDataSize;
            FinalizeRecord(recordAddr, _StructSize);
        }

        private static void CheckSufficientBytes(uint bytesRequired, uint bytesRemaining) {
            if (MinStructSize + bytesRequired <= bytesRemaining) return;

            var checkCalc = $"{MinStructSize} + {bytesRequired} > {bytesRemaining}";
            throw new InvalidDataException($"Context info structure is larger than bytes remaining: {checkCalc}");
        }

        [UsedImplicitly]
        public bool ShouldSerializeMSRAddress() =>
            _RegisterContextType == WHEA_XPF_CONTEXT_INFO_TYPE.UnclassifiedData ||
            _RegisterContextType == WHEA_XPF_CONTEXT_INFO_TYPE.MsrRegisters;

        [UsedImplicitly]
        public bool ShouldSerializeMmRegisterAddress() => _RegisterContextType == WHEA_XPF_CONTEXT_INFO_TYPE.MmRegisters;
    }

    // Structure size: 92 bytes
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

    // Structure size: 244 bytes
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
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // Structure size: 16 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA128A {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Low;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong High; // LONG
    }

    // @formatter:int_align_fields true

    /*
     * Despite being a 64-bit bitfield only the first two bits are flags. The
     * next 12 bits consist of two 6-bit integers, while the remaining bits are
     * all reserved. The two 6-bit integers are handled in the parent structure
     * which means a bitwise AND between the ulong variable storing these bits
     * and an appropriate mask must be performed before passing the variable to
     * GetEnumFlagsAsString() or any other method that will check for bits
     * which are set but don't exist in the enumeration.
     */
    [Flags]
    internal enum WHEA_XPF_PROCESSOR_ERROR_SECTION_VALIDBITS : ulong {
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

    // From XPF_CACHE_CHECK_TRANSACTIONTYPE preprocessor definitions
    internal enum WHEA_XPF_CACHE_CHECK_TRANSACTION_TYPE : byte {
        Instruction = 0,
        DataAccess  = 1,
        Generic     = 2
    }

    // From XPF_CACHE_CHECK_OPERATION preprocessor definitions
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

    // From XPF_TLB_CHECK_TRANSACTIONTYPE preprocessor definitions
    internal enum WHEA_XPF_TLB_CHECK_TRANSACTION_TYPE : byte {
        Instruction = 0,
        DataAccess  = 1,
        Generic     = 2
    }

    // From XPF_TLB_CHECK_OPERATION preprocessor definitions
    internal enum WHEA_XPF_TLB_CHECK_OPERATION : byte {
        Generic          = 0,
        GenericRead      = 1,
        GenericWrite     = 2,
        DataRead         = 3,
        DataWrite        = 4,
        InstructionFetch = 5,
        Prefetch         = 6
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

    // From XPF_BUS_CHECK_TRANSACTIONTYPE preprocessor definitions
    internal enum WHEA_XPF_BUS_CHECK_TRANSACTION_TYPE : byte {
        Instruction = 0,
        DataAccess  = 1,
        Generic     = 2
    }

    // From XPF_BUS_CHECK_OPERATION preprocessor definitions
    internal enum WHEA_XPF_BUS_CHECK_OPERATION : byte {
        Generic          = 0,
        GenericRead      = 1,
        GenericWrite     = 2,
        DataRead         = 3,
        DataWrite        = 4,
        InstructionFetch = 5,
        Prefetch         = 6
    }

    // From XPF_BUS_CHECK_PARTICIPATION preprocessor definitions
    internal enum WHEA_XPF_BUS_CHECK_PARTICIPATION : byte {
        ProcessorOriginated = 0,
        ProcessorResponded  = 1,
        ProcessorObserved   = 2,
        Generic             = 3
    }

    // From XPF_BUS_CHECK_ADDRESS preprocessor definitions
    internal enum WHEA_XPF_BUS_CHECK_ADDRESS : byte {
        Memory   = 0,
        Reserved = 1,
        IO       = 2,
        Other    = 3
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

    // From XPF_MS_CHECK_ERRORTYPE preprocessor definitions
    internal enum WHEA_XPF_MS_CHECK_ERROR_TYPE : byte {
        NoError              = 0,
        Unclassified         = 1,
        McRomParity          = 2,
        External             = 3,
        Frc                  = 4,
        InternalUnclassified = 5
    }

    // From XPF_CONTEXT_INFO preprocessor definitions
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

    // @formatter:int_align_fields false
}
