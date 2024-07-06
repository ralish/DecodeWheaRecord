#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.NativeMethods;
using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors {
    internal sealed class WHEA_PCIXDEVICE_ERROR_SECTION : WheaRecord {
        private int _NativeSize;
        internal override int GetNativeSize() => _NativeSize;

        private WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS _ValidBits;

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

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

        public WHEA_PCIXDEVICE_ERROR_SECTION(IntPtr recordAddr, WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc) {
            DebugOutputPre(typeof(WHEA_PCIXDEVICE_ERROR_SECTION), sectionDsc);
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            _ValidBits = (WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS)Marshal.ReadInt64(sectionAddr);
            var offset = 8;

            ErrorStatus = Marshal.PtrToStructure<WHEA_ERROR_STATUS>(sectionAddr + offset);
            offset += Marshal.SizeOf<WHEA_ERROR_STATUS>();

            IdInfo = Marshal.PtrToStructure<WHEA_PCIXDEVICE_ID>(sectionAddr + offset);
            offset += Marshal.SizeOf<WHEA_PCIXDEVICE_ID>();

            MemoryNumber = (uint)Marshal.ReadInt32(sectionAddr, offset);
            IoNumber = (uint)Marshal.ReadInt32(sectionAddr, offset + 4);
            offset += 8;

            if (ShouldSerializeMemoryNumber() && ShouldSerializeIoNumber()) {
                var msg = $@"[{nameof(WHEA_PCIXDEVICE_ERROR_SECTION)}] 
The {nameof(ValidBits)} member indicates both the {nameof(MemoryNumber)} and {nameof(IoNumber)} members contain valid
data. This is assumed to be an invalid state as it is not possible to distinguish between the two types of register
address/data pairs as they share the same array. This indicates the record is likely malformed and deserialisation of
the {nameof(RegisterDataPairs)} member will be skipped.";
                Console.Error.WriteLine(msg);
                return;
            }

            if (ShouldSerializeMemoryNumber()) {
                RegisterDataPairs = new WHEA_PCIXDEVICE_REGISTER_PAIR[MemoryNumber];
            } else if (ShouldSerializeIoNumber()) {
                RegisterDataPairs = new WHEA_PCIXDEVICE_REGISTER_PAIR[IoNumber];
            } else {
                var msg = $@"[{nameof(WHEA_PCIXDEVICE_ERROR_SECTION)}] 
The {nameof(ValidBits)} member indicates the {nameof(RegisterDataPairs)} member contains valid data but neither the
{nameof(MemoryNumber)} or {nameof(IoNumber)} members are marked as valid. One of these members is required to determine
the size of the {nameof(RegisterDataPairs)} array. This indicates the record is likely malformed and deserialisation of
the {nameof(RegisterDataPairs)} member will be skipped.";
                Console.Error.WriteLine(msg);
                return;
            }

            var elementSize = Marshal.SizeOf<WHEA_PCIXDEVICE_REGISTER_PAIR>();
            for (var i = 0; i < RegisterDataPairs.Length; i++) {
                RegisterDataPairs[i] = Marshal.PtrToStructure<WHEA_PCIXDEVICE_REGISTER_PAIR>(sectionAddr + offset + (i * elementSize));
            }

            offset += RegisterDataPairs.Length * elementSize;

            _NativeSize = offset;
            DebugOutputPost(typeof(WHEA_PCIXDEVICE_ERROR_SECTION), sectionDsc, _NativeSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeErrorStatus() => (_ValidBits & WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.ErrorStatus) ==
                                                    WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.ErrorStatus;

        [UsedImplicitly]
        public bool ShouldSerializeIdInfo() => (_ValidBits & WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.IdInfo) ==
                                               WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.IdInfo;

        [UsedImplicitly]
        public bool ShouldSerializeMemoryNumber() => (_ValidBits & WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.MemoryNumber) ==
                                                     WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.MemoryNumber;

        [UsedImplicitly]
        public bool ShouldSerializeIoNumber() => (_ValidBits & WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.IoNumber) ==
                                                 WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.IoNumber;

        [UsedImplicitly]
        public bool ShouldSerializeRegisterDataPairs() => (_ValidBits & WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.RegisterDataPairs) ==
                                                          WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.RegisterDataPairs;
    }

    /*
     * Originally defined as a structure of which two members are ULONGs as
     * bitfields. This structure has the same in memory format but is simpler
     * to interact with.
     */
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
        public byte Reserved1;

        [JsonProperty(Order = 9)]
        public uint Reserved2;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved1() => IsDebugBuild();

        [UsedImplicitly]
        public static bool ShouldSerializeReserved2() => IsDebugBuild();
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCIXDEVICE_REGISTER_PAIR {
        public ulong Register;
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
