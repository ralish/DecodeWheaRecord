#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Shared {
    /*
     * Originally defined as a ULONGLONG bitfield. This structure has the same
     * in memory format but is simpler to interact with.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_ERROR_STATUS {
        [JsonProperty(Order = 1)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte Reserved1;

        private WHEA_ERROR_STATUS_TYPE _ErrorType;

        [JsonProperty(Order = 2)]
        public string ErrorType => Enum.GetName(typeof(WHEA_ERROR_STATUS_TYPE), _ErrorType);

        private WHEA_ERROR_STATUS_FLAGS _Flags;

        [JsonProperty(Order = 3)]
        public string Flags => GetEnabledFlagsAsString(_Flags);

        // Add five padding bytes to match the original 64-bit structure
        [JsonConverter(typeof(HexStringJsonConverter))]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
        public byte[] Reserved2;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved1() => IsDebugBuild();

        [UsedImplicitly]
        public static bool ShouldSerializeReserved2() => IsDebugBuild();
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_PCIE_ADDRESS {
        public uint Segment;
        public uint Bus;
        public uint Device;
        public uint Function;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_REVISION {
        public byte MinorRevision;
        public byte MajorRevision;

        public override string ToString() {
            return $"{MajorRevision}.{MinorRevision}";
        }
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

    // Originally defined directly in the WHEA_ERROR_STATUS structure
    [Flags]
    internal enum WHEA_ERROR_STATUS_FLAGS : byte {
        Address    = 0x1,
        Control    = 0x2,
        Data       = 0x4,
        Responder  = 0x8,
        Requester  = 0x10,
        FirstError = 0x20,
        Overflow   = 0x40
    }

    // From preprocessor definitions (ERRTYP_*)
    internal enum WHEA_ERROR_STATUS_TYPE : byte {
        Internal       = 1,  // Internal error
        Memory         = 4,  // Memory error
        TLB            = 5,  // Translation Lookaside Buffer error
        Cache          = 6,  // Cache error
        Function       = 7,  // Error in one or more functional units
        SelfTest       = 8,  // Self-test error
        Flow           = 9,  // Overflow or underflow of an internal queue
        Bus            = 16, // Bus error
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

    internal enum WHEA_PCIEXPRESS_DEVICE_TYPE : uint {
        Endpoint                      = 0,
        LegacyEndpoint                = 1,
        RootPort                      = 4,
        UpstreamSwitchPort            = 5,
        DownstreamSwitchPort          = 6,
        PciExpressToPciXBridge        = 7,
        PciXToExpressBridge           = 8,
        RootComplexIntegratedEndpoint = 9,
        RootComplexEventCollector     = 10
    }

    // @formatter:int_align_fields false
}
