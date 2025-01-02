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

namespace DecodeWheaRecord.Errors.Microsoft {
    internal sealed class WHEA_ARM_RAS_NODE_SECTION : WheaRecord {
        private const uint StructSize = 80;
        public override uint GetNativeSize() => StructSize;

        // Number of node fields in the structure
        private const uint WHEA_ARM_RAS_NODE_FIELD_COUNT = 8;

        [JsonProperty(Order = 1)]
        public uint NodeFieldCount;

        [JsonProperty(Order = 2)]
        public uint NodeIndex;

        private WHEA_ARM_RAS_NODE_INTERFACES _InterfaceType;

        [JsonProperty(Order = 3)]
        public string InterfaceType => Enum.GetName(typeof(WHEA_ARM_RAS_NODE_INTERFACES), _InterfaceType);

        // Switched to an enumeration
        private WHEA_ARM_RAS_NODE_AEST_NODES _AestNodeType;

        [JsonProperty(Order = 4)]
        public string AestNodeType => Enum.GetName(typeof(WHEA_ARM_RAS_NODE_AEST_NODES), _AestNodeType);

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

        public WHEA_ARM_RAS_NODE_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(WHEA_ARM_RAS_NODE_SECTION), StructSize, bytesRemaining) {
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            NodeFieldCount = (uint)Marshal.ReadInt32(sectionAddr);

            if (NodeFieldCount != WHEA_ARM_RAS_NODE_FIELD_COUNT) {
                var isLess = NodeFieldCount < WHEA_ARM_RAS_NODE_FIELD_COUNT;
                var msg = $"{nameof(NodeFieldCount)} is {(isLess ? "less" : "more")} than expected: " +
                          $"{NodeFieldCount} {(isLess ? "<" : ">")} {WHEA_ARM_RAS_NODE_FIELD_COUNT}";

                if (isLess) {
                    throw new InvalidDataException(msg);
                }

                WarnOutput(msg, SectionType.Name);
                WarnOutput($"The additional {NodeFieldCount - WHEA_ARM_RAS_NODE_FIELD_COUNT} node field(s) will not be output.", SectionType.Name);
            }

            NodeIndex = (uint)Marshal.ReadInt32(sectionAddr, 4);
            _InterfaceType = (WHEA_ARM_RAS_NODE_INTERFACES)Marshal.ReadByte(sectionAddr, 8);
            _AestNodeType = (WHEA_ARM_RAS_NODE_AEST_NODES)Marshal.ReadByte(sectionAddr, 9);
            Marshal.Copy(sectionAddr, Reserved, 10, 6);
            ErrFr = (ulong)Marshal.ReadInt64(sectionAddr, 16);
            ErrCtlr = (ulong)Marshal.ReadInt64(sectionAddr, 24);
            ErrStatus = (ulong)Marshal.ReadInt64(sectionAddr, 32);
            ErrAddr = (ulong)Marshal.ReadInt64(sectionAddr, 40);
            ErrMisc0 = (ulong)Marshal.ReadInt64(sectionAddr, 48);
            ErrMisc1 = (ulong)Marshal.ReadInt64(sectionAddr, 56);
            ErrMisc2 = (ulong)Marshal.ReadInt64(sectionAddr, 64);
            ErrMisc3 = (ulong)Marshal.ReadInt64(sectionAddr, 72);

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
     * Not in the Windows headers.
     *
     * ACPI for the Armv8-A RAS Extension and RAS System Architecture 2.0 BET1
     * Document number: DEN0085
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
