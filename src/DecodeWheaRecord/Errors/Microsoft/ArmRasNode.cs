// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Descriptors;
using DecodeWheaRecord.Internal;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

/*
 * Module       Version             Arch(s)         Function(s)
 * RADARM       10.0.26100.1        Arm64           RadArmSeaCreateErrorRecord
 */
namespace DecodeWheaRecord.Errors.Microsoft {
    internal sealed class WHEA_ARM_RAS_NODE_SECTION : WheaRecord {
        private const uint StructSize = 80;
        public override uint GetNativeSize() => StructSize;

        // Expected number of node fields
        private const uint WHEA_ARM_RAS_NODE_FIELD_COUNT = 8;

        [JsonProperty(Order = 1)]
        public uint NodeFieldCount;

        [JsonProperty(Order = 2)]
        public uint NodeIndex;

        private WHEA_ARM_RAS_NODE_INTERFACES _InterfaceType;

        [JsonProperty(Order = 3)]
        public string InterfaceType => GetEnumValueAsString<WHEA_ARM_RAS_NODE_INTERFACES>(_InterfaceType);

        // Switched to an enumeration
        private WHEA_ARM_RAS_NODE_AEST_NODES _AestNodeType;

        [JsonProperty(Order = 4)]
        public string AestNodeType => GetEnumValueAsString<WHEA_ARM_RAS_NODE_AEST_NODES>(_AestNodeType);

        [JsonProperty(Order = 5)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] Reserved = new byte[6];

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ErrFr;

        [JsonProperty(Order = 7)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ErrCtlr;

        [JsonProperty(Order = 8)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ErrStatus;

        [JsonProperty(Order = 9)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ErrAddr;

        [JsonProperty(Order = 10)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ErrMisc0;

        [JsonProperty(Order = 11)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ErrMisc1;

        [JsonProperty(Order = 12)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ErrMisc2;

        [JsonProperty(Order = 13)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ErrMisc3;

        public WHEA_ARM_RAS_NODE_SECTION(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_ARM_RAS_NODE_SECTION), structOffset, StructSize, bytesRemaining) {
            WheaArmRasNodeSection(recordAddr, structOffset);
        }

        public WHEA_ARM_RAS_NODE_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(typeof(WHEA_ARM_RAS_NODE_SECTION), sectionDsc, StructSize, bytesRemaining) {
            WheaArmRasNodeSection(recordAddr, sectionDsc.SectionOffset);
        }

        private void WheaArmRasNodeSection(IntPtr recordAddr, uint structOffset) {
            var structAddr = recordAddr + (int)structOffset;

            NodeFieldCount = (uint)Marshal.ReadInt32(structAddr);

            if (NodeFieldCount != WHEA_ARM_RAS_NODE_FIELD_COUNT) {
                var isLess = NodeFieldCount < WHEA_ARM_RAS_NODE_FIELD_COUNT;
                var checkCalc = $"{NodeFieldCount} {(isLess ? "<" : ">")} {WHEA_ARM_RAS_NODE_FIELD_COUNT}";
                var msg = $"{nameof(NodeFieldCount)} is {(isLess ? "less" : "more")} than expected: {checkCalc}";

                if (isLess) {
                    throw new InvalidDataException(msg);
                }

                WarnOutput(msg, StructType.Name);
                WarnOutput($"The additional {NodeFieldCount - WHEA_ARM_RAS_NODE_FIELD_COUNT} node field(s) will not be output.", StructType.Name);
            }

            NodeIndex = (uint)Marshal.ReadInt32(structAddr, 4);
            _InterfaceType = (WHEA_ARM_RAS_NODE_INTERFACES)Marshal.ReadByte(structAddr, 8);
            _AestNodeType = (WHEA_ARM_RAS_NODE_AEST_NODES)Marshal.ReadByte(structAddr, 9);
            Marshal.Copy(structAddr + 10, Reserved, 0, 6);
            ErrFr = (ulong)Marshal.ReadInt64(structAddr, 16);
            ErrCtlr = (ulong)Marshal.ReadInt64(structAddr, 24);
            ErrStatus = (ulong)Marshal.ReadInt64(structAddr, 32);
            ErrAddr = (ulong)Marshal.ReadInt64(structAddr, 40);
            ErrMisc0 = (ulong)Marshal.ReadInt64(structAddr, 48);
            ErrMisc1 = (ulong)Marshal.ReadInt64(structAddr, 56);
            ErrMisc2 = (ulong)Marshal.ReadInt64(structAddr, 64);
            ErrMisc3 = (ulong)Marshal.ReadInt64(structAddr, 72);

            FinalizeRecord(recordAddr, StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved.Any(element => element != 0);
    }

    // @formatter:int_align_fields true

    /*
     * ACPI for the Armv8-A RAS Extension and RAS System Architecture 2.0 BET1
     * Document number: DEN0085
     */
    internal enum WHEA_ARM_RAS_NODE_INTERFACES : byte {
        SystemRegister   = 0,
        Mmio             = 1,
        SingleRecordMmio = 2 // Added
    }

    /*
     * ACPI for the Armv8-A RAS Extension and RAS System Architecture 2.0 BET1
     * Document number: DEN0085
     *
     * Not in the Windows headers.
     */
    internal enum WHEA_ARM_RAS_NODE_AEST_NODES : byte {
        Processor     = 0,
        Memory        = 1,
        Smmu          = 2,
        VendorDefined = 3,
        Gic           = 4,
        Pcie          = 5
    }

    // @formatter:int_align_fields false
}
