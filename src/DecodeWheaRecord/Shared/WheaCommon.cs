#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System;
using System.Globalization;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Errors.Microsoft;
using DecodeWheaRecord.Internal;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Shared {
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ERROR_STATUS {
        private ulong _RawBits;

        [JsonProperty(Order = 1)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved1 => (byte)_RawBits; // Bits 0-7

        [JsonProperty(Order = 2)]
        public string ErrorType => GetEnumValueAsString<WHEA_ERROR_STATUS_TYPE>((WHEA_ERROR_STATUS_TYPE)(_RawBits >> 8)); // Bits 8-15

        [JsonProperty(Order = 3)]
        public bool Address => ((_RawBits >> 16) & 0x1) == 1; // Bit 16

        [JsonProperty(Order = 4)]
        public bool Control => ((_RawBits >> 17) & 0x1) == 1; // Bit 17

        [JsonProperty(Order = 5)]
        public bool Data => ((_RawBits >> 18) & 0x1) == 1; // Bit 18

        [JsonProperty(Order = 6)]
        public bool Responder => ((_RawBits >> 19) & 0x1) == 1; // Bit 19

        [JsonProperty(Order = 7)]
        public bool Requester => ((_RawBits >> 20) & 0x1) == 1; // Bit 20

        [JsonProperty(Order = 8)]
        public bool FirstError => ((_RawBits >> 21) & 0x1) == 1; // Bit 21

        [JsonProperty(Order = 9)]
        public bool Overflow => ((_RawBits >> 22) & 0x1) == 1; // Bit 22

        [JsonProperty(Order = 10)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Reserved2 => _RawBits >> 23; // Bits 23-63

        [UsedImplicitly]
        public bool ShouldSerializeReserved1() => Reserved1 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved2() => Reserved2 != 0;
    }

    internal sealed class WHEA_PCIE_ADDRESS : WheaRecord {
        private const uint StructSize = 16;
        public override uint GetNativeSize() => StructSize;

        /*
         * The WHEA_PCIE_CORRECTABLE_ERROR_DEVICES structure has a ValidBits
         * field which informs which of the fields in this structure are valid.
         * The following two fields have been added to handle this scenario.
         */
        private readonly WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS _ValidBits;
        private readonly bool _HasValidBits;

        [JsonProperty(Order = 1)]
        public uint Segment;

        [JsonProperty(Order = 2)]
        public uint Bus;

        [JsonProperty(Order = 3)]
        public uint Device;

        [JsonProperty(Order = 4)]
        public uint Function;

        public WHEA_PCIE_ADDRESS(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_PCIE_ADDRESS), structOffset, StructSize, bytesRemaining) {
            WheaPcieAddress(recordAddr, structOffset);
        }

        public WHEA_PCIE_ADDRESS(IntPtr recordAddr, uint structOffset, uint bytesRemaining, WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS validBits) :
            base(typeof(WHEA_PCIE_ADDRESS), structOffset, StructSize, bytesRemaining) {
            WheaPcieAddress(recordAddr, structOffset);

            _ValidBits = validBits;
            _HasValidBits = true;
        }

        private void WheaPcieAddress(IntPtr recordAddr, uint structOffset) {
            var structAddr = recordAddr + (int)structOffset;

            Segment = (uint)Marshal.ReadInt32(structAddr);
            Bus = (uint)Marshal.ReadInt32(structAddr, 4);
            Device = (uint)Marshal.ReadInt32(structAddr, 8);
            Function = (uint)Marshal.ReadInt32(structAddr, 16);

            FinalizeRecord(recordAddr, StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeSegment => _HasValidBits && (_ValidBits & WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS.Segment) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeBus => _HasValidBits && (_ValidBits & WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS.Bus) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeDevice => _HasValidBits && (_ValidBits & WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS.Device) != 0;

        [UsedImplicitly]
        public bool ShouldSerializeFunction => _HasValidBits && (_ValidBits & WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS.Function) != 0;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_REVISION {
        public byte MinorRevision;
        public byte MajorRevision;

        public override string ToString() => $"{MajorRevision}.{MinorRevision}";
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_TIMESTAMP {
        private ulong _RawBits;

        [JsonProperty(Order = 1)]
        public byte Seconds => (byte)_RawBits; // Bits 0-7

        [JsonProperty(Order = 2)]
        public byte Minutes => (byte)(_RawBits >> 8); // Bits 8-15

        [JsonProperty(Order = 3)]
        public byte Hours => (byte)(_RawBits >> 16); // Bits 16-23

        [JsonProperty(Order = 4)]
        public bool Precise => ((_RawBits >> 24) & 0x1) == 1; // Bit 24

        [JsonProperty(Order = 5)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved => (byte)((_RawBits >> 25) & 0x7F); // Bits 25-31

        [JsonProperty(Order = 6)]
        public byte Day => (byte)(_RawBits >> 32); // Bits 32-39

        [JsonProperty(Order = 7)]
        public byte Month => (byte)(_RawBits >> 40); // Bits 40-47

        [JsonProperty(Order = 8)]
        public byte Year => (byte)(_RawBits >> 48); // Bits 48-55

        [JsonProperty(Order = 9)]
        public byte Century => (byte)(_RawBits >> 56); // Bits 56-63

        public override string ToString() {
            var dt = new DateTime(Century * 100 + Year, Month, Day, Hours, Minutes, Seconds);
            return $"{dt.ToString(CultureInfo.CurrentCulture)} ({(Precise ? "Precise" : "Imprecise")})";
        }

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }

    // @formatter:int_align_fields true

    internal enum WHEA_ERROR_SEVERITY : uint {
        Recoverable   = 0,
        Fatal         = 1,
        Corrected     = 2,
        Informational = 3
    }

    internal enum WHEA_ERROR_SOURCE_TYPE : uint {
        MCE          = 0,  // Machine Check Exception
        CMC          = 1,  // Corrected Machine Check
        CPE          = 2,  // Corrected Platform Error
        NMI          = 3,  // Non-Maskable Interrupt
        PCIe         = 4,  // PCI Express error source
        Generic      = 5,  // Other types of error sources
        INIT         = 6,  // IA64 INIT error source
        BOOT         = 7,  // BOOT error source
        SCIGeneric   = 8,  // Generic Hardware Error Source (via Service Control Interrupt)
        IPFMCA       = 9,  // Itanium Machine Check Abort
        IPFCMC       = 10, // Itanium Corrected Machine Check
        IPFCPE       = 11, // Itanium Corrected Platform Error
        GenericV2    = 12, // Other types of error sources v2
        SCIGenericV2 = 13, // Generic Hardware Error Source v2 (via Service Control Interrupt)
        BMC          = 14, // Baseboard Management Controller error source
        PMEM         = 15, // Persistent Memory error source (via Address Range Scrub)
        DeviceDriver = 16, // Device Driver error source
        SEA          = 17, // ARMv8 Synchronous External Abort
        SEI          = 18  // ARMv8 SError Interrupt
    }

    // From ERRTYP preprocessor definitions
    internal enum WHEA_ERROR_STATUS_TYPE : byte {
        Internal = 1,  // Internal error
        Bus      = 16, // Bus error

        // Detailed internal errors
        Memory   = 4, // Memory error
        TLB      = 5, // Translation Lookaside Buffer error
        Cache    = 6, // Cache error
        Function = 7, // Error in one or more functional units
        SelfTest = 8, // Self-test error
        Flow     = 9, // Overflow or underflow of an internal queue

        // Detailed bus errors
        Map            = 17, // Virtual address not found on IO-TLB or IO-PDIR
        Improper       = 18, // Improper access error
        Unimplemented  = 19, // Access to an unmapped memory address
        LossOfLockstep = 20, // Loss of lockstep
        Response       = 21, // Response not associated with a request
        Parity         = 22, // Bus parity error
        Protocol       = 23, // Bus protocol error
        PathError      = 24, // Bus path error
        Timeout        = 25, // Bus timeout error
        Poisoned       = 26  // Read of corrupted data
    }

    // @formatter:int_align_fields false
}
