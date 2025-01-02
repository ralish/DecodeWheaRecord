// ReSharper disable InconsistentNaming

namespace DecodeWheaRecord.Hardware {
    // @formatter:int_align_fields true

    // From PCI_CAPABILITY_ID preprocessor definitions
    internal enum PCI_CAPABILITY_ID : byte {
        PowerManagement                  = 1,
        AcceleratedGraphicsPort          = 2,
        VitalProductData                 = 3,
        SlotIdentification               = 4,
        MessageSignaledInterrupts        = 5,
        CompactPciHotSwap                = 6,
        PciX                             = 7,
        HyperTransport                   = 8,
        VendorSpecific                   = 9,
        DebugPort                        = 10,
        CompactPciCentralResourceControl = 11,
        PciHotPlug                       = 12,
        PciBridgeSubsystemVendorId       = 13,
        Agp8x                            = 14,
        SecureDevice                     = 15,
        PciExpress                       = 16,
        MsiX                             = 17,
        SataDataIndexConfig              = 18,
        AdvancedFeatures                 = 19,
        EnhancedAllocation               = 20, // Added
        FlatteningPortalBridge           = 21
    }

    // @formatter:int_align_fields false
}
