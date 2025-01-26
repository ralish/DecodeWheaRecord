#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable InconsistentNaming

using System.Runtime.InteropServices;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Hardware {
    // Structure size: 4 bytes
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class PCI_EXPRESS_ENHANCED_CAPABILITY_HEADER {
        // Switched to an enumeration
        private PCI_EXPRESS_CAPABILITY_ID _CapabilityID;

        [JsonProperty(Order = 1)]
        public string CapabilityID => GetEnumValueAsString<PCI_EXPRESS_CAPABILITY_ID>(_CapabilityID);

        private ushort _VersionAndNext;

        [JsonProperty(Order = 2)]
        public byte Version => (byte)(_VersionAndNext & 0xF); // Bits 0-3

        [JsonProperty(Order = 3)]
        public ushort Next => (ushort)(_VersionAndNext >> 4); // Bits 4-15
    }

    // @formatter:int_align_fields true

    // From PCI_EXPRESS_*_CAP_ID preprocessor definitions
    internal enum PCI_EXPRESS_CAPABILITY_ID : ushort {
        AdvancedErrorReporting                       = 1, // AER
        VirtualChannel                               = 2, // VC
        DeviceSerialNumber                           = 3,
        PowerBudgeting                               = 4,
        RootComplexLinkDeclaration                   = 5,
        RootComplexInternalLinkControl               = 6,
        RootComplexEventCollectorEndpointAssociation = 7,
        MultiFunctionVirtualChannel                  = 8,  // MFVC
        VcWithMfvc                                   = 9,  // VC with MFVC
        RootComplexRegisterBlockHeader               = 10, // RCRB Header
        VendorSpecificExtendedCapability             = 11, // VSEC
        ConfigurationAccessCorrelation               = 12, // CAC
        AccessControlServices                        = 13, // ACS
        AlternativeRoutingIdInterpretation           = 14, // ARI
        AddressTranslationServices                   = 15, // ATS
        SingleRootIoVirtualization                   = 16, // SR-IOV
        MultiRootIoVirtualization                    = 17, // MR-IOV
        Multicast                                    = 18,
        PageRequestInterface                         = 19, // PRI
        ReservedForAmd                               = 20,
        ResizableBaseAddressRegister                 = 21, // Resizable BAR
        DynamicPowerAllocation                       = 22, // DPA
        TransactionProcessingHintsRequester          = 23, // TPH Requester
        LatencyToleranceReporting                    = 24, // LTR
        SecondaryPciExpress                          = 25,
        ProtocolMultiplexing                         = 26, // PMUX
        ProcessAddressSpaceId                        = 27, // PASID
        LightweightNotificationRequester             = 28, // LNR
        DownstreamPortContainment                    = 29, // DPC
        L1PowerManagementSubstates                   = 30, // L1 PM Substates
        PrecisionTimeMeasurement                     = 31, // PTM
        PciExpressOverMPHY                           = 32, // M-PCIe
        FunctionReadinessStatusQueueing              = 33, // FRS Queueing
        ReadinessTimeReporting                       = 34,
        DesignatedVsec                               = 35,
        VirtualFunctionResizableBAR                  = 36, // Added, VF Resizable BAR
        DataLinkFeature                              = 37, // Added
        PhysicalLayer16GTs                           = 38, // Added
        LaneMarginingAtTheReceiver                   = 39, // Added
        HierarchyId                                  = 40, // Added
        NativePcieEnclosureManagement                = 41, // Added, NPEM
        PhysicalLayer32GTs                           = 42, // Added
        AlternateProtocol                            = 43, // Added
        SystemFirmwareIntermediary                   = 44, // Added, SFI
        ShadowFunctions                              = 45, // Added
        DataObjectExchange                           = 46, // Added
        Device3                                      = 47, // Added
        IntegrityAndDataEncryption                   = 48, // Added, IDE
        PhysicalLayer64GTs                           = 49, // Added
        FlitLogging                                  = 50, // Added
        FlitPerformanceMeasurement                   = 51, // Added
        FlitErrorInjection                           = 52  // Added
    }

    // @formatter:int_align_fields false
}
