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

namespace DecodeWheaRecord.Errors.Standard {
    internal sealed class WHEA_FIRMWARE_ERROR_RECORD_REFERENCE : WheaRecord {
        private uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        // Size up to and including the FirmwareRecordId field
        private const uint MinStructSize = 16;

        // Size up to and including the FirmwareRecordExt field
        private const uint StructSizeRev2 = 32;

        // Switched to an enumeration
        private WHEA_FIRMWARE_RECORD_TYPE _Type;

        [JsonProperty(Order = 1)]
        public string Type => Enum.GetName(typeof(WHEA_FIRMWARE_RECORD_TYPE), _Type);

        /*
         * Introduced in UEFI Specification 2.7 and not in Windows headers
         *
         * Prior to this revision the corresponding byte was part of the
         * Reserved field which the specification states must be all zeroes.
         */
        [JsonProperty(Order = 2)]
        public byte Revision;

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] Reserved = new byte[6];

        [JsonProperty(Order = 4)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong FirmwareRecordId;

        /*
         * Revision 2 fields (UEFI Specification 2.7)
         */

        // Not in the Windows headers
        [JsonProperty(Order = 5)]
        public Guid FirmwareRecordExt;

        public WHEA_FIRMWARE_ERROR_RECORD_REFERENCE(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(WHEA_FIRMWARE_ERROR_RECORD_REFERENCE), MinStructSize, bytesRemaining) {
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            _Type = (WHEA_FIRMWARE_RECORD_TYPE)Marshal.ReadByte(sectionAddr);
            Revision = Marshal.ReadByte(sectionAddr, 1);

            uint expectedStructSize;
            switch (Revision) {
                case 0:
                    expectedStructSize = MinStructSize;
                    break;
                case 2:
                    expectedStructSize = StructSizeRev2;
                    break;
                default:
                    throw new InvalidDataException($"Unsupported {nameof(Revision)}: {Revision}");
            }

            if (expectedStructSize > sectionDsc.SectionLength) {
                throw new InvalidDataException($"Expected length is greater than in section descriptor: {expectedStructSize} > {sectionDsc.SectionLength}");
            }

            Marshal.Copy(sectionAddr, Reserved, 2, 6);
            FirmwareRecordId = (ulong)Marshal.ReadInt64(sectionAddr, 8);

            _StructSize = MinStructSize;

            if (Revision >= 2) {
                FirmwareRecordExt = Marshal.PtrToStructure<Guid>(sectionAddr + 16);

                _StructSize = StructSizeRev2;
            }

            if (Revision >= 1 && FirmwareRecordId != 0) {
                WarnOutput($"{nameof(FirmwareRecordId)} is not NULL but {nameof(Revision)} is >= 1.", SectionType.Name);
            }

            if (Revision >= 2 && _Type != WHEA_FIRMWARE_RECORD_TYPE.SocFirmwareType2 && FirmwareRecordExt != Guid.Empty) {
                WarnOutput($"{nameof(FirmwareRecordExt)} is not NULL but {nameof(Type)} indicates it should be.", SectionType.Name);
            }

            FinalizeRecord(recordAddr, _StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeRevision() => Revision != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved.Any(element => element != 0);

        [UsedImplicitly]
        public bool ShouldSerializeFirmwareRecordExt() => _Type == WHEA_FIRMWARE_RECORD_TYPE.SocFirmwareType2;
    }

    // @formatter:int_align_fields true

    // From WHEA_FIRMWARE_RECORD_TYPE preprocessor definitions
    internal enum WHEA_FIRMWARE_RECORD_TYPE : byte {
        IpfSal           = 0,
        SocFirmwareType1 = 1, // Added
        SocFirmwareType2 = 2  // Added
    }

    // @formatter:int_align_fields false
}
