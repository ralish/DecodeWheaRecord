#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

/*
 * Vanilla Windows doesn't appear to have any functionality to report this
 * error. The only implementation I've found is in the Azure PSHED plugin.
 */
namespace DecodeWheaRecord.Errors.Microsoft {
    internal sealed class WHEA_PCIE_CORRECTABLE_ERROR_SECTION : WheaRecord {
        private uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        // At least the header
        private const uint MinStructSize = WHEA_PCIE_CORRECTABLE_ERROR_SECTION_HEADER.StructSize;

        [JsonProperty(Order = 1)]
        public WHEA_PCIE_CORRECTABLE_ERROR_SECTION_HEADER Header;

        [JsonProperty(Order = 2)]
        public WHEA_PCIE_CORRECTABLE_ERROR_DEVICES[] Devices;

        public WHEA_PCIE_CORRECTABLE_ERROR_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(WHEA_PCIE_CORRECTABLE_ERROR_SECTION), MinStructSize, bytesRemaining) {
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            Header = new WHEA_PCIE_CORRECTABLE_ERROR_SECTION_HEADER(recordAddr, sectionDsc.SectionOffset, bytesRemaining);
            var offset = MinStructSize;

            if (Header.Count != 0) {
                var elementSize = (uint)Marshal.SizeOf<WHEA_PCIE_CORRECTABLE_ERROR_DEVICES>();

                if (MinStructSize + Header.Count * elementSize > sectionDsc.SectionLength) {
                    var msg = "Calculated size is greater than in section descriptor: " +
                              $"{MinStructSize} + {Header.Count} * {elementSize} > {sectionDsc.SectionLength}";
                    throw new InvalidDataException(msg);
                }

                Devices = new WHEA_PCIE_CORRECTABLE_ERROR_DEVICES[Header.Count];
                for (var i = 0; i < Header.Count; i++) {
                    Devices[i] = Marshal.PtrToStructure<WHEA_PCIE_CORRECTABLE_ERROR_DEVICES>(sectionAddr + (int)offset);
                    offset += elementSize;
                }
            }

            _StructSize = offset;
            FinalizeRecord(recordAddr, _StructSize);
        }
    }

    internal sealed class WHEA_PCIE_CORRECTABLE_ERROR_SECTION_HEADER : WheaRecord {
        internal const uint StructSize = 4;
        public override uint GetNativeSize() => StructSize;

        /*
         * Verified from the Azure PSHED plugin implementation
         * Function: PshedPiReportPcieCorrectableErrorSummary
         */
        private const ushort ExpectedVersion = 1;

        [JsonProperty(Order = 1)]
        public ushort Version;

        [JsonProperty(Order = 2)]
        public ushort Count;

        public WHEA_PCIE_CORRECTABLE_ERROR_SECTION_HEADER(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_PCIE_CORRECTABLE_ERROR_SECTION_HEADER), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            Version = (ushort)Marshal.ReadInt16(structAddr);

            if (Version != ExpectedVersion) {
                var msg = $"Expected {nameof(Version)} to be {ExpectedVersion} but found: {Version}";
                throw new InvalidDataException(msg);
            }

            Count = (ushort)Marshal.ReadInt16(structAddr, 2);

            if (Count == 0) {
                var msg = $"{nameof(Count)} Expected at least one correctable PCIe error entry.";
                WarnOutput(msg, SectionType.Name);
            }

            FinalizeRecord(recordAddr, StructSize);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCIE_CORRECTABLE_ERROR_DEVICES : WheaRecord {
        private const uint StructSize = 156;
        public override uint GetNativeSize() => StructSize;

        // Count of elements in the CorrectableErrorCount array
        private const ushort WHEA_PCIE_CORRECTABLE_ERROR_SECTION_COUNT_SIZE = 32;

        private WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS _ValidBits;

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        [JsonProperty(Order = 2)]
        public WHEA_PCIE_ADDRESS Address;

        [JsonProperty(Order = 3)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Mask;

        [JsonProperty(Order = 4)]
        public uint[] CorrectableErrorCount = new uint[WHEA_PCIE_CORRECTABLE_ERROR_SECTION_COUNT_SIZE]; // TODO: Deserialize

        public WHEA_PCIE_CORRECTABLE_ERROR_DEVICES(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_PCIE_CORRECTABLE_ERROR_DEVICES), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            _ValidBits = (WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS)Marshal.ReadInt64(structAddr);
            Address = new WHEA_PCIE_ADDRESS(recordAddr, structOffset + 8, bytesRemaining - 8, _ValidBits);
            Mask = (uint)Marshal.ReadInt32(structAddr, 20);

            var CorrectableErrorCountSigned = new int[WHEA_PCIE_CORRECTABLE_ERROR_SECTION_COUNT_SIZE];
            Marshal.Copy(structAddr + 24, CorrectableErrorCountSigned, 0, WHEA_PCIE_CORRECTABLE_ERROR_SECTION_COUNT_SIZE);

            // Convert the signed array to its unsigned equivalent
            for (var i = 0; i < CorrectableErrorCountSigned.Length; i++) {
                CorrectableErrorCount[i] = (uint)CorrectableErrorCountSigned[i];
            }

            FinalizeRecord(recordAddr, StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeMask() => (_ValidBits & WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS.Mask) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeCorrectableErrorCount() => (_ValidBits & WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS.CorrectableErrorCount) != 0;
    }

    // @formatter:int_align_fields true

    [Flags]
    internal enum WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS : ulong {
        Segment               = 0x1,
        Bus                   = 0x2,
        Device                = 0x4,
        Function              = 0x8,
        Mask                  = 0x10,
        CorrectableErrorCount = 0x20
    }

    // @formatter:int_align_fields false
}
