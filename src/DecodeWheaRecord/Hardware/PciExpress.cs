// ReSharper disable InconsistentNaming

namespace DecodeWheaRecord.Hardware {
    // @formatter:int_align_fields true

    /*
     * The WHEA_PCIEXPRESS_DEVICE_TYPE enumeration only differs in the value
     * names, which all have an added "Whea" prefix. Where structures used the
     * WHEA_PCIEXPRESS_DEVICE_TYPE enumeration they've been updated to use this
     * enumeration with a comment noting the original.
     */
    internal enum PCI_EXPRESS_DEVICE_TYPE : uint {
        Endpoint                      = 0,
        LegacyEndpoint                = 1,
        RootPort                      = 4,
        UpstreamSwitchPort            = 5,
        DownstreamSwitchPort          = 6,
        PciExpressToPciXBridge        = 7,
        PciXToPciExpressBridge        = 8,
        RootComplexIntegratedEndpoint = 9,
        RootComplexEventCollector     = 10
    }

    // @formatter:int_align_fields false
}
