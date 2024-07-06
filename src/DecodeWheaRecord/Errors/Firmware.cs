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
    internal sealed class WHEA_FIRMWARE_ERROR_RECORD_REFERENCE : WheaRecord {
        private int _NativeSize;
        internal override int GetNativeSize() => _NativeSize;

        private WHEA_FIRMWARE_RECORD_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_FIRMWARE_RECORD_TYPE), _Type);

        // Added (subtracted from Reserved member)
        [JsonProperty(Order = 2)]
        public byte Revision;

        [JsonProperty(Order = 3)]
        public byte[] Reserved;

        [JsonProperty(Order = 4)]
        public ulong FirmwareRecordId;

        // Expansion of out-of-date original structure
        [JsonProperty(Order = 5)]
        public Guid FirmwareRecordExt;

        public WHEA_FIRMWARE_ERROR_RECORD_REFERENCE(IntPtr recordAddr, WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc) {
            DebugOutputPre(typeof(WHEA_FIRMWARE_ERROR_RECORD_REFERENCE), sectionDsc);
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            _Type = (WHEA_FIRMWARE_RECORD_TYPE)Marshal.ReadByte(sectionAddr);
            Revision = Marshal.ReadByte(sectionAddr, 1);
            var offset = 2;

            Reserved = new byte[6];
            Marshal.Copy(sectionAddr + offset, Reserved, 0, 6);
            offset += 6;

            FirmwareRecordId = (ulong)Marshal.ReadInt64(sectionAddr, offset);
            offset += 8;

            if (_Type == WHEA_FIRMWARE_RECORD_TYPE.SocFwType2) {
                FirmwareRecordExt = Marshal.PtrToStructure<Guid>(sectionAddr + offset);
                offset += 16;
            }

            // FirmwareRecordId should be NULL for Revision >= 1
            if (Revision >= 1 && FirmwareRecordId != 0) {
                var msg = $"[{nameof(WHEA_FIRMWARE_ERROR_RECORD_REFERENCE)}] {nameof(Revision)} is >= 1 but {nameof(FirmwareRecordId)} is not NULL.";
                Console.Error.WriteLine(msg);
            }

            _NativeSize = offset;
            DebugOutputPost(typeof(WHEA_FIRMWARE_ERROR_RECORD_REFERENCE), sectionDsc, _NativeSize);
        }

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();

        [UsedImplicitly]
        public bool ShouldSerializeFirmwareRecordExt() => _Type == WHEA_FIRMWARE_RECORD_TYPE.SocFwType2;
    }

    // @formatter:int_align_fields true

    // From preprocessor definitions (WHEA_FIRMWARE_RECORD_TYPE_*)
    internal enum WHEA_FIRMWARE_RECORD_TYPE : byte {
        IpfSal     = 0,
        SocFwType1 = 1, // Added
        SocFwType2 = 2  // Added
    }

    // @formatter:int_align_fields false
}
