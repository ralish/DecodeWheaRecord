#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable ClassNeverInstantiated.Global
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

namespace DecodeWheaRecord.Errors.UEFI {
    internal sealed class WHEA_PCIXDEVICE_ERROR_SECTION : WheaRecord {
        private uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        // Size up to and including the IoNumber field
        private const uint MinStructSize = 40;

        private WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS _ValidBits;

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnumFlagsAsString(_ValidBits);

        [JsonProperty(Order = 2)]
        public WHEA_ERROR_STATUS ErrorStatus;

        [JsonProperty(Order = 3)]
        public WHEA_PCIXDEVICE_ID IdInfo;

        [JsonProperty(Order = 4)]
        public uint MemoryNumber;

        [JsonProperty(Order = 5)]
        public uint IoNumber;

        [JsonProperty(Order = 6)]
        public WHEA_PCIXDEVICE_REGISTER_PAIR[] RegisterDataPairs;

        public WHEA_PCIXDEVICE_ERROR_SECTION(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_PCIXDEVICE_ERROR_SECTION), structOffset, MinStructSize, bytesRemaining) {
            WheaPciXDeviceErrorSection(recordAddr, structOffset, bytesRemaining);
        }

        public WHEA_PCIXDEVICE_ERROR_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(typeof(WHEA_PCIXDEVICE_ERROR_SECTION), sectionDsc, MinStructSize, bytesRemaining) {
            WheaPciXDeviceErrorSection(recordAddr, sectionDsc.SectionOffset, sectionDsc.SectionLength);
        }

        private void WheaPciXDeviceErrorSection(IntPtr recordAddr, uint structOffset, uint bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _ValidBits = (WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS)Marshal.ReadInt64(structAddr);
            ErrorStatus = PtrToStructure<WHEA_ERROR_STATUS>(structAddr + 8);
            IdInfo = PtrToStructure<WHEA_PCIXDEVICE_ID>(structAddr + 16);
            MemoryNumber = (uint)Marshal.ReadInt32(structAddr, 32);
            IoNumber = (uint)Marshal.ReadInt32(structAddr, 36);
            var offset = MinStructSize;

            uint NumRegisterDataPairs = 0;
            if (ShouldSerializeMemoryNumber()) {
                NumRegisterDataPairs += MemoryNumber;
            }

            if (ShouldSerializeIoNumber()) {
                if (NumRegisterDataPairs != 0) {
                    var msg = $@"
The {nameof(ValidBits)} field indicates both the {nameof(MemoryNumber)} and {nameof(IoNumber)} fields contain
valid data and both fields are set to a non-zero value. It's unclear if this is
a valid state for the structure as the Memory Mapped and Programmed IO register
address/data pair values are represented using the same structure and share the
same array. Distinguishing between the two types of data may not be possible.";
                    WarnOutput(msg, StructType.Name);
                }

                NumRegisterDataPairs += MemoryNumber;
            }

            if (ShouldSerializeRegisterDataPairs()) {
                RegisterDataPairs = new WHEA_PCIXDEVICE_REGISTER_PAIR[NumRegisterDataPairs];

                if (ShouldSerializeMemoryNumber() || ShouldSerializeIoNumber()) {
                    var elementSize = (uint)Marshal.SizeOf<WHEA_PCIXDEVICE_REGISTER_PAIR>();

                    if (MinStructSize + NumRegisterDataPairs * elementSize > bytesRemaining) {
                        var checkCalc = $"{MinStructSize} + {NumRegisterDataPairs} * {elementSize} > {bytesRemaining}";
                        throw new InvalidDataException($"{nameof(RegisterDataPairs)} results in size greater than bytes remaining: {checkCalc}");
                    }

                    for (var i = 0; i < RegisterDataPairs.Length; i++) {
                        RegisterDataPairs[i] = PtrToStructure<WHEA_PCIXDEVICE_REGISTER_PAIR>(structAddr + (int)offset);
                        offset += elementSize;
                    }
                } else {
                    var msg = $@"
The {nameof(ValidBits)} field indicates the {nameof(RegisterDataPairs)} field contains valid data
but neither the {nameof(MemoryNumber)} or {nameof(IoNumber)} fields are marked as valid. One of
these fields is required to determine the size of the {nameof(RegisterDataPairs)} array.
Deserialisation of the array will be skipped.";
                    ErrorOutput(msg, StructType.Name);
                }
            } else {
                var msg = $@"
The {nameof(ValidBits)} field indicates the {nameof(MemoryNumber)} and/or {nameof(IoNumber)} fields contain
valid data but the {nameof(RegisterDataPairs)} field is not marked valid. Deserialisation
of the array containing the register address/data pair values will be skipped.";
                ErrorOutput(msg, StructType.Name);
            }

            _StructSize = offset;
            FinalizeRecord(recordAddr, _StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeErrorStatus() => (_ValidBits & WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.ErrorStatus) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeIdInfo() => (_ValidBits & WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.IdInfo) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeMemoryNumber() => (_ValidBits & WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.MemoryNumber) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeIoNumber() => (_ValidBits & WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.IoNumber) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeRegisterDataPairs() => (_ValidBits & WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.RegisterDataPairs) != 0;
    }

    // Structure size: 16 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCIXDEVICE_ID {
        [JsonProperty(Order = 1)]
        public ushort VendorId;

        [JsonProperty(Order = 2)]
        public ushort DeviceId;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        private byte[] _ClassCode;

        [JsonProperty(Order = 3)]
        public uint ClassCode => (uint)(_ClassCode[0] + (_ClassCode[1] << 8) + (_ClassCode[2] << 16));

        [JsonProperty(Order = 4)]
        public byte FunctionNumber;

        [JsonProperty(Order = 5)]
        public byte DeviceNumber;

        [JsonProperty(Order = 6)]
        public byte BusNumber;

        [JsonProperty(Order = 7)]
        public byte SegmentNumber;

        [JsonProperty(Order = 8)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved1;

        [JsonProperty(Order = 9)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Reserved2;

        [UsedImplicitly]
        public bool ShouldSerializeReserved1() => Reserved1 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved2() => Reserved2 != 0;
    }

    // Structure size: 16 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCIXDEVICE_REGISTER_PAIR {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Register;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Data;
    }

    // @formatter:int_align_fields true

    [Flags]
    internal enum WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS : ulong {
        ErrorStatus       = 0x1,
        IdInfo            = 0x2,
        MemoryNumber      = 0x4,
        IoNumber          = 0x8,
        RegisterDataPairs = 0x10
    }

    // @formatter:int_align_fields false
}
