#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Events.Hardware {
    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     WheapLogSRASTableBadDataEvent
     * Notes:           No payload, class name derived from event name
     */
    // TODO
    internal sealed class WHEA_SRAS_TABLE_BAD_DATA : IWheaRecord {
        public uint GetNativeSize() => 0;
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     WheapLogSRASTable
     */
    // TODO
    internal sealed class WHEA_SRAS_TABLE_ENTRIES_EVENT : WheaRecord {
        private uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        // Size up to and including the NumberSignals field
        private const uint MinStructSize = 8;

        [JsonProperty(Order = 1)]
        public uint LogNumber;

        [JsonProperty(Order = 2)]
        public uint NumberSignals;

        // A variable length byte array in the Windows headers
        [JsonProperty(Order = 3)]
        public EFI_ACPI_RAS_SIGNAL_TABLE[] Data;

        public WHEA_SRAS_TABLE_ENTRIES_EVENT(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_SRAS_TABLE_ENTRIES_EVENT), structOffset, MinStructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            LogNumber = (uint)Marshal.ReadInt32(structAddr);
            NumberSignals = (uint)Marshal.ReadInt32(structAddr, 4);
            var offset = (uint)8;

            if (NumberSignals > 0) {
                Data = new EFI_ACPI_RAS_SIGNAL_TABLE[NumberSignals];
                for (var i = 0; i < NumberSignals; i++) {
                    Data[i] = new EFI_ACPI_RAS_SIGNAL_TABLE(recordAddr, structOffset + offset, bytesRemaining - offset);
                    offset += Data[i].GetNativeSize();
                }
            } else {
                WarnOutput($"{nameof(NumberSignals)} Expected at least one RAS signal table.", SectionType.Name);
            }

            _StructSize = offset;
            FinalizeRecord(recordAddr, _StructSize);
        }
    }

    internal sealed class EFI_ACPI_RAS_SIGNAL_TABLE : WheaRecord {
        private uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        // Size up to and including the NumberRecord field
        private const uint MinStructSize = 40;

        [JsonProperty(Order = 1)]
        public WHEA_ACPI_HEADER Header;

        [JsonProperty(Order = 2)]
        public uint NumberRecord;

        [JsonProperty(Order = 3)]
        public SIGNAL_REG_VALUE[] Entries;

        public EFI_ACPI_RAS_SIGNAL_TABLE(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(EFI_ACPI_RAS_SIGNAL_TABLE), structOffset, MinStructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            Header = Marshal.PtrToStructure<WHEA_ACPI_HEADER>(structAddr);
            NumberRecord = (uint)Marshal.ReadInt32(structAddr, 28);
            var offset = (uint)32;

            if (NumberRecord > 0) {
                var elementSize = (uint)Marshal.SizeOf<SIGNAL_REG_VALUE>();

                Entries = new SIGNAL_REG_VALUE[NumberRecord];
                for (var i = 0; i < NumberRecord; i++) {
                    Entries[i] = Marshal.PtrToStructure<SIGNAL_REG_VALUE>(structAddr + (int)offset);
                    offset += elementSize;
                }
            } else {
                WarnOutput($"{nameof(NumberRecord)} Expected at least one RAS signal register.", SectionType.Name);
            }

            _StructSize = offset;
            FinalizeRecord(recordAddr, _StructSize);
        }
    }

    // Structure size: 36 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ACPI_HEADER {
        public uint Signature; // TODO: Possibly an ASCII string?
        public uint Length;
        public byte Revision;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Checksum;

        [JsonConverter(typeof(HexStringJsonConverter))]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] OemId; // TODO: Possibly an ASCII string?

        public ulong OemTableId;
        public uint OemRevision;
        public uint CreatorId;
        public uint CreatorRevision;
    }

    // Structure size: 44 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class SIGNAL_REG_VALUE {
        // Size of the RegName array
        private const int WCS_RAS_REGISTER_NAME_MAX_LENGTH = 32;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = WCS_RAS_REGISTER_NAME_MAX_LENGTH)]
        public byte[] RegName; // TODO: Probably an ASCII string?

        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint MsrAddr;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Value;
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     WheapLogSRASTableErrorEvent
     * Notes:           No payload
     */
    // TODO
    internal sealed class WHEA_SRAS_TABLE_ERROR : IWheaRecord {
        public uint GetNativeSize() => 0;
    }

    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     WheapLogSRASTableNotFound
     * Notes:           No payload
     */
    // TODO
    internal sealed class WHEA_SRAS_TABLE_NOT_FOUND : IWheaRecord {
        public uint GetNativeSize() => 0;
    }
}
