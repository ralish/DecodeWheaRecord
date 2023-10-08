// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable FieldCanBeMadeReadOnly.Global
// ReSharper disable InconsistentNaming
// ReSharper disable MemberCanBePrivate.Global

#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Text;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord {
    internal static class NativeMethods {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal abstract class WheaRecord {
            public virtual void Validate() { }
        }

        #region GUIDs

        public static readonly Dictionary<Guid, string> CreatorIds = new Dictionary<Guid, string> {
            // Microsoft extensions
            { Guid.Parse("cf07c4bd-b789-4e18-b3c4-1f732cb57131"), "Microsoft" },    // WHEA_RECORD_CREATOR_GUID
            { Guid.Parse("57217c8d-5e66-44fb-8033-9b74cacedf5b"), "Device Driver" } // DEFAULT_DEVICE_DRIVER_CREATOR_GUID
        };

        public static readonly Dictionary<Guid, string> NotifyTypes = new Dictionary<Guid, string> {
            // Standard types
            { Guid.Parse("3d61a466-ab40-409a-a698-f362d464b38f"), "Boot Error Record (BOOT)" },         // BOOT_NOTIFY_TYPE_GUID
            { Guid.Parse("2dce8bb1-bdd7-450e-b9ad-9cf4ebd4f890"), "Corrected Machine Check (CMC)" },    // CMC_NOTIFY_TYPE_GUID
            { Guid.Parse("4e292f96-d843-4a55-a8c2-d481f27ebeee"), "Corrected Platform Error (CPE)" },   // CPE_NOTIFY_TYPE_GUID
            { Guid.Parse("667dd791-c6b3-4c27-8a6b-0f8e722deb41"), "DMA Remapping Error (DMAr)" },       // Not in headers
            { Guid.Parse("cc5263e8-9308-454a-89d0-340bd39bc98e"), "INIT Error Record (INIT)" },         // INIT_NOTIFY_TYPE_GUID
            { Guid.Parse("e8f56ffe-919c-4cc5-ba88-65abe14913bb"), "Machine Check Exception (MCE)" },    // MCE_NOTIFY_TYPE_GUID
            { Guid.Parse("5bad89ff-b7e6-42c9-814a-cf2485d6e98a"), "Non-Maskable Interrupt (NMI)" },     // NMI_NOTIFY_TYPE_GUID
            { Guid.Parse("cf93c01f-1a16-4dfc-b8bc-9c4daf67c104"), "PCI Express (PCIe) Error" },         // PCIe_NOTIFY_TYPE_GUID
            { Guid.Parse("09a9d5ac-5204-4214-96e5-94992e752bcd"), "Platform Error Interrupt (PEI)" },   // PEI_NOTIFY_TYPE_GUID
            { Guid.Parse("9a78788a-bbe8-11e4-809e-67611e5d46b0"), "Synchronous External Abort (SEA)" }, // SEA_NOTIFY_TYPE_GUID
            { Guid.Parse("5c284c81-b0ae-4e87-a322-b04c85624323"), "SError Interrupt (SEI)" },           // SEI_NOTIFY_TYPE_GUID
            { Guid.Parse("487565ba-6494-4367-95ca-4eff893522f6"), "BMC_NOTIFY_TYPE_GUID" },             // BMC_NOTIFY_TYPE_GUID
            { Guid.Parse("919448b2-3739-4b7f-a8f1-e0062805c2a3"), "CMCI_NOTIFY_TYPE_GUID" },            // CMCI_NOTIFY_TYPE_GUID
            { Guid.Parse("0033f803-2e70-4e88-992c-6f26daf3db7a"), "DEVICE_DRIVER_NOTIFY_TYPE_GUID" },   // DEVICE_DRIVER_NOTIFY_TYPE_GUID
            { Guid.Parse("fe84086e-b557-43cf-ac1b-17982e078470"), "EXTINT_NOTIFY_TYPE_GUID" },          // EXTINT_NOTIFY_TYPE_GUID
            { Guid.Parse("e9d59197-94ee-4a4f-8ad8-9b7d8bd93d2e"), "SCI_NOTIFY_TYPE_GUID" },             // SCI_NOTIFY_TYPE_GUID

            // Microsoft extensions
            { Guid.Parse("3e62a467-ab40-409a-a698-f362d464b38f"), "Generic Error Record" } // GENERIC_NOTIFY_TYPE_GUID
        };

        public static readonly Dictionary<Guid, string> SectionTypes = new Dictionary<Guid, string> {
            // Standard types not present in headers
            { Guid.Parse("5b51fef7-c79d-4434-8f1b-aa62de3e2c64"), "DMAr Generic" },
            { Guid.Parse("71761d37-32b2-45cd-a7d0-b0fedd93e8cf"), "Intel VT for Directed I/O specific DMAr section" },
            { Guid.Parse("036f84e1-7f37-428c-a79e-575fdfaa84ec"), "IOMMU specific DMAr section" },

            /*
             * Section type:        Microsoft
             * Symbolic name:       MU_TELEMETRY_SECTION_GUID
             * Structure:           MU_TELEMETRY_SECTION
             * Notes:               Name is a guess as the structure is undocumented.
             *                      Incorrectly listed as a standard error section?
             */
            { Guid.Parse("85183a8b-9c41-429c-939c-5c3c087ca280"), "Microsoft Update Telemetry" },

            /*
             * Section type:        Standard
             * Symbolic name:       ARM_PROCESSOR_ERROR_SECTION_GUID
             * Structure:           WHEA_ARM_PROCESSOR_ERROR_SECTION
             */
            { Guid.Parse("e19e3d16-bc11-11e4-9caa-c2051d5d46b0"), "ARM Processor Error" },

            /*
             * Section type:        Microsoft
             * Symbolic name:       WHEA_ERROR_PACKET_SECTION_GUID
             * Structure:           WHEA_ERROR_PACKET_V1 / WHEA_ERROR_PACKET_V2
             */
            { Guid.Parse("e71254e9-c1b9-4940-ab76-909703a4320f"), "Hardware Error Packet" },

            /*
             * Section type:        Microsoft
             * Symbolic name:       RECOVERY_INFO_SECTION_GUID
             * Structure:           WHEA_ERROR_RECOVERY_INFO_SECTION
             * Notes:               Name is a guess as the structure is undocumented.
             *                      Incorrectly listed as a standard error section?
             */
            { Guid.Parse("c34832a1-02c3-4c52-a9f1-9f1d5d7723fc"), "Error Recovery Information" },

            /*
             * Section type:        Standard
             * Symbolic name:       FIRMWARE_ERROR_RECORD_REFERENCE_GUID
             * Structure:           WHEA_FIRMWARE_ERROR_RECORD_REFERENCE
             */
            { Guid.Parse("81212a96-09ed-4996-9471-8d729c8e69ed"), "Firmware Error Record Reference" },

            /*
             * Section type:        Microsoft
             * Symbolic name:       MEMORY_CORRECTABLE_ERROR_SUMMARY_SECTION_GUID
             * Structure:           WHEA_MEMORY_CORRECTABLE_ERROR_SECTION
             */
            { Guid.Parse("0e36c93e-ca15-4a83-ba8a-cbe80f7f0017"), "Correctable Memory Error" },

            /*
             * Section type:        Standard
             * Symbolic name:       MEMORY_ERROR_SECTION_GUID
             * Structure:           WHEA_MEMORY_ERROR_SECTION
             */
            { Guid.Parse("a5bc1114-6f64-4ede-b863-3e83ed7c83b1"), "Memory Error" },

            /*
             * Section type:        Microsoft
             * Symbolic name:       IPMI_MSR_DUMP_SECTION_GUID
             * Structure:           WHEA_MSR_DUMP_SECTION
             */
            { Guid.Parse("1c15b445-9b06-4667-ac25-33c056b88803"), "IPMI MSR Dump" },

            /*
             * Section type:        Microsoft
             * Symbolic name:       NMI_SECTION_GUID
             * Structure:           WHEA_NMI_ERROR_SECTION
             */
            { Guid.Parse("e71254e7-c1b9-4940-ab76-909703a4320f"), "NMI Error" },

            /*
             * Section type:        Microsoft
             * Symbolic name:       PCIE_CORRECTABLE_ERROR_SUMMARY_SECTION_GUID
             * Structure:           WHEA_PCIE_CORRECTABLE_ERROR_SECTION
             */
            { Guid.Parse("e96eca99-53e2-4f52-9be7-d2dbe9508ed0"), "Correctable PCIe Error" },

            /*
             * Section type:        Standard
             * Symbolic name:       PCIEXPRESS_ERROR_SECTION_GUID
             * Structure:           WHEA_PCIEXPRESS_ERROR_SECTION
             */
            { Guid.Parse("d995e954-bbc1-430f-ad91-b44dcb3c6f35"), "PCI Express Error" },

            /*
             * Section type:        Standard
             * Symbolic name:       PCIXBUS_ERROR_SECTION_GUID
             * Structure:           WHEA_PCIXBUS_ERROR_SECTION
             */
            { Guid.Parse("c5753963-3b84-4095-bf78-eddad3f9c9dd"), "PCI/PCI-X Bus Error" },

            /*
             * Section type:        Standard
             * Symbolic name:       PCIXDEVICE_ERROR_SECTION_GUID
             * Structure:           WHEA_PCIXDEVICE_ERROR_SECTION
             */
            { Guid.Parse("eb5e4685-ca66-4769-b6a2-26068b001326"), "PCI Component/Device Error" },

            /*
             * Section type:        Microsoft
             * Symbolic name:       PMEM_ERROR_SECTION_GUID
             * Structure:           WHEA_PMEM_ERROR_SECTION
             */
            { Guid.Parse("81687003-dbfd-4728-9ffd-f0904f97597d"), "Persistent Mememory Error" },

            /*
             * Section type:        Standard
             * Symbolic name:       PROCESSOR_GENERIC_ERROR_SECTION_GUID
             * Structure:           WHEA_PROCESSOR_GENERIC_ERROR_SECTION
             */
            { Guid.Parse("9876ccad-47b4-4bdb-b65e-16f193c4f3db"), "Generic Processor Error" },

            /*
             * Section type:        Standard
             * Symbolic name:       XPF_PROCESSOR_ERROR_SECTION_GUID
             * Structure:           WHEA_XPF_PROCESSOR_ERROR_SECTION
             */
            { Guid.Parse("dc3ea0b0-a144-4797-b95b-53fa242b6e1d"), "IA32/AMD64 Processor Error" },

            /*
             * TODO
             * Section type:        Microsoft
             * Symbolic name:       GENERIC_SECTION_GUID
             * Structure:           TODO
             */
            { Guid.Parse("e71254e8-c1b9-4940-ab76-909703a4320f"), "GENERIC_SECTION_GUID" },

            /*
             * TODO
             * Section type:        Standard
             * Symbolic name:       IPF_PROCESSOR_ERROR_SECTION_GUID
             * Structure:           TODO
             */
            { Guid.Parse("e429faf1-3cb7-11d4-bca7-0080c73c8881"), "IPF_PROCESSOR_ERROR_SECTION_GUID" },

            /*
             * TODO
             * Section type:        Microsoft
             * Symbolic name:       IPF_SAL_RECORD_SECTION_GUID
             * Structure:           TODO
             */
            { Guid.Parse("6f3380d1-6eb0-497f-a578-4d4c65a71617"), "IPF_SAL_RECORD_SECTION_GUID" },

            /*
             * TODO
             * Section type:        Microsoft
             * Symbolic name:       WHEA_DPC_CAPABILITY_SECTION_GUID
             * Structure:           WHEA_PCI_DPC_SECTION (PCI_EXPRESS_DPC_CAPABILITY)
             */
            { Guid.Parse("ec49534b-30e7-4358-972f-eca6958fae3b"), "WHEA_DPC_CAPABILITY_SECTION_GUID" },

            /*
             * TODO
             * Section type:        Microsoft
             * Symbolic name:       XPF_MCA_SECTION_GUID
             * Structure:           WHEA_XPF_MCA_SECTION
             */
            { Guid.Parse("8a1e1d01-42f9-4557-9c33-565e5cc3f7e8"), "XPF_MCA_SECTION_GUID" }
        };

        #endregion

        #region Shared enumerations

        // @formatter:int_align_fields true

        public enum WHEA_ERROR_SEVERITY : uint {
            Recoverable   = 0,
            Fatal         = 1,
            Corrected     = 2,
            Informational = 3
        }

        public enum WHEA_ERROR_SOURCE_TYPE : uint {
            MCE          = 0,  // Machine Check Exception
            CMC          = 1,  // Corrected Machine Check
            CPE          = 2,  // Corrected Platform Error
            NMI          = 3,  // Non-Maskable Interrupt
            PCIe         = 4,  // PCI Express
            Generic      = 5,  // Other types of error sources
            INIT         = 6,  // Itanium INIT
            BOOT         = 7,  // Boot error source
            SCIGeneric   = 8,  // Generic Hardware Error Source (via Service Control Interrupt)
            IPFMCA       = 9,  // Itanium Machine Check Abort
            IPFCMC       = 10, // Itanium Corrected Machine Check
            IPFCPE       = 11, // Itanium Corrected Platform Error
            GenericV2    = 12, // Other types of error sources v2
            SCIGenericV2 = 13, // Generic Hardware Error Source v2 (via Service Control Interrupt)
            BMC          = 14, // Baseboard Management Controller
            PMEM         = 15, // Persistent Memory (via Address Range Scrub)
            DeviceDriver = 16, // Device Driver
            SEA          = 17, // ARMv8 Synchronous External Abort
            SEI          = 18  // ARMv8 SError Interrupt
        }

        // From preprocessor definitions (ERRTYP_*)
        public enum WHEA_ERROR_STATUS_TYPE : byte {
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

        public enum WHEA_PCIEXPRESS_DEVICE_TYPE : uint {
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

        #endregion

        #region Shared flags

        // @formatter:int_align_fields true

        // Originally defined directly in the WHEA_ERROR_STATUS structure
        [Flags]
        public enum WHEA_ERROR_STATUS_FLAGS : uint {
            Address    = 0x1,
            Control    = 0x2,
            Data       = 0x4,
            Responder  = 0x8,
            Requester  = 0x10,
            FirstError = 0x20,
            Overflow   = 0x40
        }

        // @formatter:int_align_fields false

        #endregion

        #region Shared structures

        /*
         * Originally defined as a ULONGLONG bitfield. This structure has the
         * same in memory format, but is simpler to interact with.
         */
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_ERROR_STATUS {
            [JsonProperty(Order = 1)]
            public byte Reserved1;

            private WHEA_ERROR_STATUS_TYPE _ErrorType;

            [JsonProperty(Order = 2)]
            public string ErrorType => Enum.GetName(typeof(WHEA_ERROR_STATUS_TYPE), _ErrorType);

            private WHEA_ERROR_STATUS_FLAGS _Flags;

            [JsonProperty(Order = 3)]
            public string Flags => GetEnabledFlagsAsString(_Flags);

            // Add two padding bytes to match the original 64-bit structure
#pragma warning disable CS0169 // Field is never used
            private ushort Reserved2;
#pragma warning restore CS0169 // Field is never used
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PCIE_ADDRESS {
            public uint Segment;
            public uint Bus;
            public uint Device;
            public uint Function;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_REVISION {
            public byte MinorRevision;
            public byte MajorRevision;
        }

        #endregion

        #region WHEA Error Record Header: Constants

        /*
         * Reversed from what is defined in the header as we perform validation
         * against the member as an ASCII string instead of a ULONG.
         */
        public const string WHEA_ERROR_RECORD_SIGNATURE = "CPER";

        /*
         * The header defines the revision as a single value but the structure
         * has two single byte members, corresponding to the major and minor
         * version, requiring some trivial bit shifting during validation.
         */
        private const ushort WHEA_ERROR_RECORD_REVISION = 0x210; // v2.16

        private const uint WHEA_ERROR_RECORD_SIGNATURE_END = uint.MaxValue; // 0xFFFFFFFF

        /*
         * The value of the signature does not appear to be defined in the
         * header but Microsoft's documentation for the structure states it is
         * "RE". It is reversed as we perform validation against the member as
         * an ASCII string instead of a USHORT.
         */
        public const string WHEA_PERSISTENCE_INFO_SIGNATURE = "ER";

        #endregion

        #region WHEA Error Record Header: Flags

        // @formatter:int_align_fields true

        [Flags]
        public enum WHEA_ERROR_RECORD_HEADER_FLAGS : uint {
            Recovered          = 0x1, // Also a preprocessor definition
            PreviousError      = 0x2, // Also a preprocessor definition
            Simulated          = 0x4, // Also a preprocessor definition
            DeviceDriver       = 0x8, // Also a preprocessor definition
            CriticalEvent      = 0x10,
            PersistPfn         = 0x20,
            SectionsTruncated  = 0x40,
            RecoveryInProgress = 0x80,
            Throttle           = 0x100
        }

        // Also specified as preprocessor definitions
        [Flags]
        public enum WHEA_ERROR_RECORD_HEADER_VALIDBITS : uint {
            PlatformId  = 0x1,
            Timestamp   = 0x2,
            PartitionId = 0x4
        }

        // Originally defined directly in the WHEA_PERSISTENCE_INFO structure
        [Flags]
        public enum WHEA_PERSISTENCE_INFO_FLAGS : byte {
            Attribute1 = 0x1, // Originally a 2-bit member with Attribute2
            Attribute2 = 0x2, // Originally a 2-bit member with Attribute1
            DoNotLog   = 0x4
        }

        // Originally defined directly in the WHEA_TIMESTAMP structure
        [Flags]
        public enum WHEA_TIMESTAMP_FLAGS : byte {
            Precise = 0x1
        }

        // @formatter:int_align_fields false

        #endregion

        #region WHEA Error Record Header: Structures

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_ERROR_RECORD_HEADER : WheaRecord {
            private uint _Signature;

            [JsonProperty(Order = 1)]
            public string Signature {
                get {
                    var bytes = BitConverter.GetBytes(_Signature);
                    return Encoding.ASCII.GetString(bytes);
                }
            }

            [JsonProperty(Order = 2)]
            public WHEA_REVISION Revision;

            [JsonProperty(Order = 3)]
            public uint SignatureEnd;

            [JsonProperty(Order = 4)]
            public ushort SectionCount;

            private WHEA_ERROR_SEVERITY _Severity;

            [JsonProperty(Order = 5)]
            public string Severity => Enum.GetName(typeof(WHEA_ERROR_SEVERITY), _Severity);

            private WHEA_ERROR_RECORD_HEADER_VALIDBITS _ValidBits;

            [JsonProperty(Order = 6)]
            public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

            /*
             * Length of the error record in its entirety. This includes the
             * error record header (this structure), error record section
             * descriptors, and error record sections.
             */
            [JsonProperty(Order = 7)]
            public uint Length; // TODO: Validate in decoder

            [JsonProperty(Order = 8)]
            public WHEA_TIMESTAMP Timestamp;

            [JsonProperty(Order = 9)]
            public Guid PlatformId;

            [JsonProperty(Order = 10)]
            public Guid PartitionId;

            private Guid _CreatorId;

            [JsonProperty(Order = 11)]
            public string CreatorId => CreatorIds.TryGetValue(_CreatorId, out var CreatorIdValue) ? CreatorIdValue : _CreatorId.ToString();

            private Guid _NotifyType;

            [JsonProperty(Order = 12)]
            public string NotifyType => NotifyTypes.TryGetValue(_NotifyType, out var NotifyTypeValue) ? NotifyTypeValue : _NotifyType.ToString();

            [JsonProperty(Order = 13)]
            public ulong RecordId;

            private WHEA_ERROR_RECORD_HEADER_FLAGS _Flags;

            [JsonProperty(Order = 14)]
            public string Flags => GetEnabledFlagsAsString(_Flags);

            [JsonProperty(Order = 15)]
            public WHEA_PERSISTENCE_INFO PersistenceInfo;

            [JsonProperty(Order = 16)]
            public uint OsBuildNumber;

            [JsonProperty(Order = 17)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Reserved;

            // Only populated in Azure by a PSHED plugin (AzPshedPi)
            [UsedImplicitly]
            public bool ShouldSerializeOsBuildNumber() {
                return OsBuildNumber != 0;
            }

            [UsedImplicitly]
            public bool ShouldSerializePartitionId() {
                return (_ValidBits & WHEA_ERROR_RECORD_HEADER_VALIDBITS.PartitionId) == WHEA_ERROR_RECORD_HEADER_VALIDBITS.PartitionId;
            }

            // Absence of the signature means this structure is empty
            [UsedImplicitly]
            public bool ShouldSerializePersistenceInfo() {
                return !string.IsNullOrEmpty(PersistenceInfo.Signature);
            }

            [UsedImplicitly]
            public bool ShouldSerializePlatformId() {
                return (_ValidBits & WHEA_ERROR_RECORD_HEADER_VALIDBITS.PlatformId) == WHEA_ERROR_RECORD_HEADER_VALIDBITS.PlatformId;
            }

            [UsedImplicitly]
            public bool ShouldSerializeTimestamp() {
                return (_ValidBits & WHEA_ERROR_RECORD_HEADER_VALIDBITS.Timestamp) == WHEA_ERROR_RECORD_HEADER_VALIDBITS.Timestamp;
            }

            public override void Validate() {
                if (Signature != WHEA_ERROR_RECORD_SIGNATURE) {
                    var msg = $"[{nameof(WHEA_ERROR_RECORD_HEADER)}] Expected signature \"{WHEA_ERROR_RECORD_SIGNATURE}\" but Signature member is: {Signature}";
                    ExitWithMessage(msg, 2);
                }

                const byte majorRevision = WHEA_ERROR_RECORD_REVISION >> 8;
                if (Revision.MajorRevision != majorRevision) {
                    var msg =
                        $"[{nameof(WHEA_ERROR_RECORD_HEADER)}] Expected major revision {majorRevision} but MajorRevision member is: {Revision.MajorRevision}";
                    ExitWithMessage(msg, 2);
                }

                const byte minorRevision = WHEA_ERROR_RECORD_REVISION & 0xFF;
                if (Revision.MinorRevision != minorRevision) {
                    var msg =
                        $"[{nameof(WHEA_ERROR_RECORD_HEADER)}] Expected minor revision {minorRevision} but MinorRevision member is: {Revision.MinorRevision}";
                    ExitWithMessage(msg, 2);
                }

                if (SignatureEnd != WHEA_ERROR_RECORD_SIGNATURE_END) {
                    var sigEndActual = Convert.ToString(SignatureEnd, 16);
                    var sigEndExpected = Convert.ToString(WHEA_ERROR_RECORD_SIGNATURE_END, 16);
                    var msg = $"[{nameof(WHEA_ERROR_RECORD_HEADER)}] Expected end signature \"{sigEndExpected}\" but SignatureEnd member is: {sigEndActual}";
                    ExitWithMessage(msg, 2);
                }

                if (SectionCount == 0) {
                    var msg = $"[{nameof(WHEA_ERROR_RECORD_HEADER)}] Expected at least one error section but SectionCount is 0.";
                    ExitWithMessage(msg, 2);
                }

                PersistenceInfo.Validate();
            }
        }

        /*
         * Originally defined as a ULONGLONG bitfield. This structure has the
         * same in memory format, but is simpler to interact with.
         */
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PERSISTENCE_INFO {
            private ushort _Signature;

            [JsonProperty(Order = 1)]
            public string Signature {
                get {
                    var bytes = BitConverter.GetBytes(_Signature);
                    return Encoding.ASCII.GetString(bytes).Trim('\0');
                }
            }

            // Length of the error record when stored in persistent storage
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            private byte[] _Length; // TODO: Validate

            [JsonProperty(Order = 2)]
            public uint Length => (uint)(_Length[0] + (_Length[1] << 8) + (_Length[2] << 16));

            [JsonProperty(Order = 3)]
            public ushort Identifier;

            private WHEA_PERSISTENCE_INFO_FLAGS _Flags;

            [JsonProperty(Order = 4)]
            public string Flags => GetEnabledFlagsAsString(_Flags);

            public void Validate() {
                /*
                 * Although not documented, it appears the signature is only
                 * set when the error record is persisted, even though this
                 * structure is always present in the error record header.
                 */
                if (string.IsNullOrEmpty(Signature)) {
                    if (Length != 0 || Identifier != 0 || _Flags != 0) {
                        var msg = $"[{nameof(WHEA_PERSISTENCE_INFO)}] Signature is not present but one or more members have a non-zero value.";
                        ExitWithMessage(msg, 2);
                    }

                    return;
                }

                if (Signature != WHEA_PERSISTENCE_INFO_SIGNATURE) {
                    var msg =
                        $"[{nameof(WHEA_PERSISTENCE_INFO)}] Expected signature \"{WHEA_PERSISTENCE_INFO_SIGNATURE}\" but Signature member is: {Signature}";
                    ExitWithMessage(msg, 2);
                }
            }
        }

        /*
         * Originally defined as a ULONGLONG bitfield. This structure has the
         * same in memory format, but is simpler to interact with.
         */
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_TIMESTAMP {
            [JsonProperty(Order = 1)]
            public byte Seconds;

            [JsonProperty(Order = 2)]
            public byte Minutes;

            [JsonProperty(Order = 3)]
            public byte Hours;

            private WHEA_TIMESTAMP_FLAGS _Flags;

            [JsonProperty(Order = 4)]
            public string Flags => GetEnabledFlagsAsString(_Flags);

            [JsonProperty(Order = 5)]
            public byte Day;

            [JsonProperty(Order = 6)]
            public byte Month;

            [JsonProperty(Order = 7)]
            public byte Year;

            [JsonProperty(Order = 8)]
            public byte Century;
        }

        #endregion

        #region WHEA Error Record Section Descriptor: Constants

        /*
         * The header defines the revision as a single value but the structure
         * has two single byte members, corresponding to the major and minor
         * version, requiring some trivial bit shifting during validation.
         */
        private const ushort WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_REVISION = 0x300; // v3.0

        private const ushort WHEA_PCIE_CORRECTABLE_ERROR_SECTION_COUNT_SIZE = 32;

        #endregion

        #region WHEA Error Record Section Descriptor: Flags

        // @formatter:int_align_fields true

        // Also specified as preprocessor definitions
        [Flags]
        public enum WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS : uint {
            Primary              = 0x1,
            ContainmentWarning   = 0x2,
            Reset                = 0x4,
            ThresholdExceeded    = 0x8,
            ResourceNotAvailable = 0x10,
            LatentError          = 0x20,
            Propagated           = 0x40,
            FruTextByPlugin      = 0x80
        }

        [Flags]
        public enum WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS : byte {
            FRUId   = 0x1,
            FRUText = 0x2
        }

        // @formatter:int_align_fields false

        #endregion

        #region WHEA Error Record Section Descriptor: Structures

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public sealed class WHEA_ERROR_RECORD_SECTION_DESCRIPTOR : WheaRecord {
            /*
             * Offset of the error record section from the start of the error
             * record (i.e. beginning with the error record header).
             */
            [JsonProperty(Order = 1)]
            public uint SectionOffset; // TODO: Validate

            /*
             * Length of the error record section (i.e. the error record
             * section which is described by this descriptor).
             */
            [JsonProperty(Order = 2)]
            public uint SectionLength; // TODO: Validate

            [JsonProperty(Order = 3)]
            public WHEA_REVISION Revision;

            private WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS _ValidBits;

            [JsonProperty(Order = 4)]
            public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

            [JsonProperty(Order = 5)]
            public byte Reserved;

            private WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS _Flags;

            [JsonProperty(Order = 6)]
            public string Flags => GetEnabledFlagsAsString(_Flags);

            private Guid _SectionType;

            [JsonProperty(Order = 7)]
            public string SectionType => SectionTypes.TryGetValue(_SectionType, out var SectionTypeValue) ? SectionTypeValue : _SectionType.ToString();

            // Used by the Decoder class
            internal Guid SectionTypeGuid => _SectionType;

            [JsonProperty(Order = 8)]
            public Guid FRUId;

            private WHEA_ERROR_SEVERITY _SectionSeverity;

            [JsonProperty(Order = 9)]
            public string SectionSeverity => Enum.GetName(typeof(WHEA_ERROR_SEVERITY), _SectionSeverity);

            [JsonProperty(Order = 10)]
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 20)]
            public string FRUText;

            [UsedImplicitly]
            public bool ShouldSerializeFRUId() {
                return (_ValidBits & WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS.FRUId) == WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS.FRUId;
            }

            [UsedImplicitly]
            public bool ShouldSerializeFRUText() {
                return (_ValidBits & WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS.FRUText) == WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS.FRUText;
            }

            public override void Validate() {
                const byte majorRevision = WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_REVISION >> 8;
                if (Revision.MajorRevision != majorRevision) {
                    var msg =
                        $"[{nameof(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR)}] Expected major revision {majorRevision} but MajorRevision member is: {Revision.MajorRevision}";
                    ExitWithMessage(msg, 2);
                }

                const byte minorRevision = WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_REVISION & 0xFF;
                if (Revision.MinorRevision != minorRevision) {
                    var msg =
                        $"[{nameof(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR)}] Expected minor revision {minorRevision} but MinorRevision member is: {Revision.MinorRevision}";
                    ExitWithMessage(msg, 2);
                }
            }
        }

        #endregion

        #region WHEA Error Record Section: MU_TELEMETRY_SECTION

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class MU_TELEMETRY_SECTION : WheaRecord {
            public Guid ComponentID;
            public Guid SubComponentID;
            public uint Reserved;
            public uint ErrorStatusValue;
            public ulong AdditionalInfo1;
            public ulong AdditionalInfo2;

            public override void Validate() { }
        }

        #endregion

        #region WHEA Error Record Section: WHEA_ARM_PROCESSOR_ERROR_SECTION

        // @formatter:int_align_fields true

        [Flags]
        public enum WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS : uint {
            MPIDR              = 0x1,
            AffinityLevel      = 0x2,
            RunningState       = 0x4,
            VendorSpecificInfo = 0x8
        }

        // @formatter:int_align_fields false

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_ARM_PROCESSOR_ERROR_SECTION : WheaRecord {
            private WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS _ValidBits;

            [JsonProperty(Order = 1)]
            public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

            [JsonProperty(Order = 2)]
            public ushort ErrorInformationStructures;

            [JsonProperty(Order = 3)]
            public ushort ContextInformationStructures;

            // TODO: Description
            [JsonProperty(Order = 4)]
            public uint SectionLength; // TODO: Validate

            [JsonProperty(Order = 5)]
            public byte ErrorAffinityLevel;

            [JsonProperty(Order = 6)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public byte[] Reserved;

            [JsonProperty(Order = 7)]
            public ulong MPIDR_EL1;

            [JsonProperty(Order = 8)]
            public ulong MIDR_EL1;

            [JsonProperty(Order = 9)]
            public uint RunningState;

            [JsonProperty(Order = 10)]
            public uint PSCIState;

            /*
             * TODO
             * Variable length arrays need a custom marshaller.
             */
            //[JsonProperty(Order = 11)]
            //public byte Data[];

            [UsedImplicitly]
            public bool ShouldSerializeErrorAffinityLevel() {
                return (_ValidBits & WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.AffinityLevel) == WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.AffinityLevel;
            }

            [UsedImplicitly]
            public bool ShouldSerializeErrorMIDR_EL1() {
                return (_ValidBits & WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.VendorSpecificInfo) ==
                       WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.VendorSpecificInfo;
            }

            [UsedImplicitly]
            public bool ShouldSerializeErrorMPIDR_EL1() {
                return (_ValidBits & WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.MPIDR) == WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.MPIDR;
            }

            [UsedImplicitly]
            public bool ShouldSerializeRunningState() {
                return (_ValidBits & WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.RunningState) == WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.RunningState;
            }

            public override void Validate() { }
        }

        #endregion

        #region WHEA Error Record Section: WHEA_ERROR_PACKET

        // @formatter:int_align_fields true

        public enum WHEA_ERROR_PACKET_DATA_FORMAT : uint {
            IPFSalRecord = 0,
            XPFMCA       = 1,
            Memory       = 2,
            PCIExpress   = 3,
            NMIPort      = 4,
            PCIXBus      = 5,
            PCIXDevice   = 6,
            Generic      = 7
        }

        [Flags]
        public enum WHEA_ERROR_PACKET_FLAGS : uint {
            PreviousError               = 0x1,
            CriticalEvent               = 0x2,
            HypervisorError             = 0x4,
            Simulated                   = 0x8,
            PlatformPfaControl          = 0x10,
            PlatformDirectedOffline     = 0x20,
            AddressTranslationRequired  = 0x40,
            AddressTranslationCompleted = 0x80,
            RecoveryOptional            = 0x100
        }

        public enum WHEA_ERROR_TYPE : uint {
            Processor  = 0,
            Memory     = 1,
            PCIExpress = 2,
            NMI        = 3,
            PCIXBus    = 4,
            PCIXDevice = 5,
            Generic    = 6,
            Pmem       = 7
        }

        public enum WHEA_RAW_DATA_FORMAT : uint {
            IPFSalRecord = 0,
            IA32MCA      = 1,
            Intel64MCA   = 2,
            AMD64MCA     = 3,
            Memory       = 4,
            PCIExpress   = 5,
            NMIPort      = 6,
            PCIXBus      = 7,
            PCIXDevice   = 8,
            Generic      = 9
        }

        // @formatter:int_align_fields false

        /*
         * Reversed from what is defined in the header as we perform validation
         * against the member as an ASCII string instead of a ULONG.
         */
        public const string WHEA_ERROR_PACKET_V1_SIGNATURE = "ErPt";

        private const int WHEA_ERROR_PACKET_V1_VERSION = 2; // Not a typo

        /*
         * Windows Server 2008 & Windows Vista SP1+
         */
        [StructLayout(LayoutKind.Explicit, Pack = 1)]
        public sealed class WHEA_ERROR_PACKET_V1 : WheaRecord {
            [FieldOffset(0)]
            private uint _Signature;

            [JsonProperty(Order = 1)]
            public string Signature {
                get {
                    var bytes = BitConverter.GetBytes(_Signature);
                    return Encoding.ASCII.GetString(bytes);
                }
            }

            [FieldOffset(4)]
            private WHEA_ERROR_PACKET_FLAGS _Flags;

            [JsonProperty(Order = 2)]
            public string Flags => GetEnabledFlagsAsString(_Flags);

            /*
             * Size of the hardware error packet (this structure), including
             * the raw data (see the RawDataLength member).
             */
            [FieldOffset(8)]
            [JsonProperty(Order = 3)]
            public uint Size; // TODO: Validate

            /*
             * Length of the raw hardware error information contained in the
             * RawData member.
             */
            [FieldOffset(12)]
            [JsonProperty(Order = 4)]
            public uint RawDataLength; // TODO: Validate

            [FieldOffset(16)]
            [JsonProperty(Order = 5)]
            public ulong Reserved1;

            [FieldOffset(24)]
            [JsonProperty(Order = 6)]
            public ulong Context;

            [FieldOffset(32)]
            private WHEA_ERROR_TYPE _ErrorType;

            [JsonProperty(Order = 7)]
            public string ErrorType => Enum.GetName(typeof(WHEA_ERROR_TYPE), _ErrorType);

            [FieldOffset(36)]
            private WHEA_ERROR_SEVERITY _ErrorSeverity;

            [JsonProperty(Order = 8)]
            public string ErrorSeverity => Enum.GetName(typeof(WHEA_ERROR_SEVERITY), _ErrorSeverity);

            [FieldOffset(40)]
            [JsonProperty(Order = 9)]
            public uint ErrorSourceId;

            [FieldOffset(44)]
            private WHEA_ERROR_SOURCE_TYPE _ErrorSourceType;

            [JsonProperty(Order = 10)]
            public string ErrorSourceType => Enum.GetName(typeof(WHEA_ERROR_SOURCE_TYPE), _ErrorSourceType);

            [FieldOffset(48)]
            [JsonProperty(Order = 11)]
            public uint Reserved2;

            [FieldOffset(52)]
            [JsonProperty(Order = 12)]
            public uint Version;

            [FieldOffset(56)]
            [JsonProperty(Order = 13)]
            public ulong Cpu;

            [FieldOffset(64)]
            [JsonProperty(Order = 14)]
            public WHEA_PROCESSOR_GENERIC_ERROR_SECTION ProcessorError;

            [FieldOffset(64)]
            [JsonProperty(Order = 15)]
            public WHEA_MEMORY_ERROR_SECTION MemoryError;

            [FieldOffset(64)]
            [JsonProperty(Order = 16)]
            public WHEA_NMI_ERROR_SECTION NmiError;

            [FieldOffset(64)]
            [JsonProperty(Order = 17)]
            public WHEA_PCIEXPRESS_ERROR_SECTION PciExpressError;

            [FieldOffset(64)]
            [JsonProperty(Order = 18)]
            public WHEA_PCIXBUS_ERROR_SECTION PciXBusError;

            [FieldOffset(64)]
            [JsonProperty(Order = 19)]
            public WHEA_PCIXDEVICE_ERROR_SECTION PciXDeviceError;

            [FieldOffset(64)]
            [JsonProperty(Order = 20)]
            public WHEA_PMEM_ERROR_SECTION PmemError;

            [FieldOffset(272)]
            private WHEA_RAW_DATA_FORMAT _RawDataFormat;

            [JsonProperty(Order = 21)]
            public string RawDataFormat => Enum.GetName(typeof(WHEA_RAW_DATA_FORMAT), _RawDataFormat);

            /*
             * Offset from the beginning of the RawData data buffer where a
             * PSHED plug-in can add supplementary platform-specific data. The
             * amount of data that can be added is limited by the Size member.
             */
            [FieldOffset(276)]
            [JsonProperty(Order = 22)]
            public uint RawDataOffset; // TODO: Validate

            /*
             * TODO
             * Variable length arrays need a custom marshaller.
             */
            //[FieldOffset(280)]
            //[JsonProperty(Order = 23)]
            //public byte[] RawData;

            [UsedImplicitly]
            public bool ShouldSerializeMemoryError() {
                return _ErrorType == WHEA_ERROR_TYPE.Memory;
            }

            [UsedImplicitly]
            public bool ShouldSerializeNmiError() {
                return _ErrorType == WHEA_ERROR_TYPE.NMI;
            }

            [UsedImplicitly]
            public bool ShouldSerializePciExpressError() {
                return _ErrorType == WHEA_ERROR_TYPE.PCIExpress;
            }

            [UsedImplicitly]
            public bool ShouldSerializePciXBusError() {
                return _ErrorType == WHEA_ERROR_TYPE.PCIXBus;
            }

            [UsedImplicitly]
            public bool ShouldSerializePciXDeviceError() {
                return _ErrorType == WHEA_ERROR_TYPE.PCIXDevice;
            }

            [UsedImplicitly]
            public bool ShouldSerializePmemError() {
                return _ErrorType == WHEA_ERROR_TYPE.Pmem;
            }

            [UsedImplicitly]
            public bool ShouldSerializeProcessorError() {
                return _ErrorType == WHEA_ERROR_TYPE.Processor;
            }

            public override void Validate() {
                if (Signature != WHEA_ERROR_PACKET_V1_SIGNATURE) {
                    var msg = $"[{nameof(WHEA_ERROR_PACKET_V1)}] Expected signature \"{WHEA_ERROR_PACKET_V1_SIGNATURE}\" but Signature member is: {Signature}";
                    ExitWithMessage(msg, 2);
                }

                if (Version != WHEA_ERROR_PACKET_V1_VERSION) {
                    var msg = $"[{nameof(WHEA_ERROR_PACKET_V1)}] Expected version {WHEA_ERROR_PACKET_V1_VERSION} but Version member is: {Version}";
                    ExitWithMessage(msg, 2);
                }
            }
        }

        /*
         * Reversed from what is defined in the header as we perform validation
         * against the member as an ASCII string instead of a ULONG.
         */
        public const string WHEA_ERROR_PACKET_V2_SIGNATURE = "WHEA";

        private const int WHEA_ERROR_PACKET_V2_VERSION = 3; // Not a typo

        /*
         * Windows Server 2008 R2, Windows Vista 7, and later
         */
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_ERROR_PACKET_V2 : WheaRecord {
            private uint _Signature;

            [JsonProperty(Order = 1)]
            public string Signature {
                get {
                    var bytes = BitConverter.GetBytes(_Signature);
                    return Encoding.ASCII.GetString(bytes);
                }
            }

            [JsonProperty(Order = 2)]
            public uint Version;

            // TODO: Description
            [JsonProperty(Order = 3)]
            public uint Length; // TODO: Validate

            private WHEA_ERROR_PACKET_FLAGS _Flags;

            [JsonProperty(Order = 4)]
            public string Flags => GetEnabledFlagsAsString(_Flags);

            private WHEA_ERROR_TYPE _ErrorType;

            [JsonProperty(Order = 5)]
            public string ErrorType => Enum.GetName(typeof(WHEA_ERROR_TYPE), _ErrorType);

            private WHEA_ERROR_SEVERITY _ErrorSeverity;

            [JsonProperty(Order = 6)]
            public string ErrorSeverity => Enum.GetName(typeof(WHEA_ERROR_SEVERITY), _ErrorSeverity);

            [JsonProperty(Order = 7)]
            public uint ErrorSourceId;

            private WHEA_ERROR_SOURCE_TYPE _ErrorSourceType;

            [JsonProperty(Order = 8)]
            public string ErrorSourceType => Enum.GetName(typeof(WHEA_ERROR_SOURCE_TYPE), _ErrorSourceType);

            private Guid _NotifyType;

            [JsonProperty(Order = 9)]
            public string NotifyType => SectionTypes.TryGetValue(_NotifyType, out var NotifyTypeValue) ? NotifyTypeValue : _NotifyType.ToString();

            [JsonProperty(Order = 10)]
            public ulong Context;

            private WHEA_ERROR_PACKET_DATA_FORMAT _DataFormat;

            [JsonProperty(Order = 11)]
            public string DataFormat => Enum.GetName(typeof(WHEA_ERROR_PACKET_DATA_FORMAT), _DataFormat);

            [JsonProperty(Order = 12)]
            public uint Reserved1;

            // TODO: Description
            [JsonProperty(Order = 13)]
            public uint DataOffset; // TODO: Validate

            // TODO: Description
            [JsonProperty(Order = 14)]
            public uint DataLength; // TODO: Validate

            // TODO: Description
            [JsonProperty(Order = 15)]
            public uint PshedDataOffset; // TODO: Validate

            // TODO: Description
            [JsonProperty(Order = 16)]
            public uint PshedDataLength; // TODO: Validate

            /*
             * TODO
             * Variable length arrays need a custom marshaller.
             */
            //[JsonProperty(Order = 17)]
            //public byte[] Data;

            /*
             * TODO
             * Variable length arrays need a custom marshaller.
             */
            //[JsonProperty(Order = 18)]
            //public byte[] PshedData;

            public override void Validate() {
                if (Signature != WHEA_ERROR_PACKET_V2_SIGNATURE) {
                    var msg = $"[{nameof(WHEA_ERROR_PACKET_V2)}] Expected signature \"{WHEA_ERROR_PACKET_V2_SIGNATURE}\" but Signature member is: {Signature}";
                    ExitWithMessage(msg, 2);
                }

                if (Version != WHEA_ERROR_PACKET_V2_VERSION) {
                    var msg = $"[{nameof(WHEA_ERROR_PACKET_V2)}] Expected version {WHEA_ERROR_PACKET_V2_VERSION} but Version member is: {Version}";
                    ExitWithMessage(msg, 2);
                }
            }
        }

        #endregion

        #region WHEA Error Record Section: WHEA_ERROR_RECOVERY_INFO_SECTION

        // @formatter:int_align_fields true

        [Flags]
        public enum WHEA_RECOVERY_ACTION : uint {
            NoneAttempted    = 0x1,
            TerminateProcess = 0x2,
            ForwardedToVm    = 0x4,
            MarkPageBad      = 0x8,
            PoisonNotPresent = 0x10
        }

        public enum WHEA_RECOVERY_FAILURE_REASON : uint {
            KernelCouldNotMarkMemoryBad        = 1,
            KernelMarkMemoryBadTimedOut        = 2,
            NoRecoveryContext                  = 3,
            NotContinuable                     = 4,
            Pcc                                = 5,
            Overflow                           = 6,
            NotSupported                       = 7,
            MiscOrAddrNotValid                 = 8,
            InvalidAddressMode                 = 9,
            HighIrql                           = 10,
            InsufficientAltContextWrappers     = 11,
            InterruptsDisabled                 = 12,
            SwapBusy                           = 13,
            StackOverflow                      = 14,
            UnexpectedFailure                  = 15,
            KernelWillPageFaultBCAtCurrentIrql = 16,
            FarNotValid                        = 17
        }

        public enum WHEA_RECOVERY_TYPE : uint {
            ActionRequired = 1,
            ActionOptional = 2
        }

        // @formatter:int_align_fields false

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public sealed class WHEA_ERROR_RECOVERY_INFO_SECTION : WheaRecord {
            [JsonProperty(Order = 1)]
            [MarshalAs(UnmanagedType.U1)]
            public bool RecoveryKernel;

            private WHEA_RECOVERY_ACTION _RecoveryAction;

            [JsonProperty(Order = 2)]
            public string RecoveryAction => Enum.GetName(typeof(WHEA_RECOVERY_ACTION), _RecoveryAction);

            private WHEA_RECOVERY_TYPE _RecoveryType;

            [JsonProperty(Order = 3)]
            public string RecoveryType => Enum.GetName(typeof(WHEA_RECOVERY_TYPE), _RecoveryType);

            [JsonProperty(Order = 4)]
            public byte Irql;

            [JsonProperty(Order = 5)]
            [MarshalAs(UnmanagedType.U1)]
            public bool RecoverySucceeded;

            private WHEA_RECOVERY_FAILURE_REASON _FailureReason;

            [JsonProperty(Order = 6)]
            public string FailureReason => Enum.GetName(typeof(WHEA_RECOVERY_FAILURE_REASON), _FailureReason);

            [JsonProperty(Order = 7)]
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 20)]
            public string ProcessName;

            public override void Validate() { }
        }

        #endregion

        #region WHEA Error Record Section: WHEA_FIRMWARE_ERROR_RECORD_REFERENCE

        // @formatter:int_align_fields true

        // From preprocessor definitions (WHEA_FIRMWARE_RECORD_TYPE_*)
        public enum WHEA_FIRMWARE_RECORD_TYPE : byte {
            IpfSal     = 0,
            SocFwType1 = 1, // Added
            SocFwType2 = 2  // Added
        }

        // @formatter:int_align_fields false

        /*
         * Expanded from out-of-date struct in official header.
         */
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_FIRMWARE_ERROR_RECORD_REFERENCE : WheaRecord {
            private WHEA_FIRMWARE_RECORD_TYPE _Type;

            [JsonProperty(Order = 1)]
            public string Type => Enum.GetName(typeof(WHEA_FIRMWARE_RECORD_TYPE), _Type);

            [JsonProperty(Order = 2)]
            public char Revision; // Added

            [JsonProperty(Order = 3)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public byte[] Reserved;

            [JsonProperty(Order = 4)]
            public ulong FirmwareRecordId;

            [JsonProperty(Order = 5)]
            public Guid FirmwareRecordExt; // Added

            public override void Validate() { }
        }

        #endregion

        #region WHEA Error Record Section: WHEA_MEMORY_CORRECTABLE_ERROR_SECTION

        // @formatter:int_align_fields true

        [Flags]
        public enum WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS : ulong {
            SocketId              = 0x1,
            ChannelId             = 0x2,
            DimmSlot              = 0x4,
            CorrectableErrorCount = 0x8
        }

        // @formatter:int_align_fields false

        // TODO
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_MEMORY_CORRECTABLE_ERROR_SECTION : WheaRecord {
            public override void Validate() { }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_MEMORY_CORRECTABLE_ERROR_HEADER {
            public ushort Version; // TODO: Validate
            public ushort Count;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_MEMORY_CORRECTABLE_ERROR_DATA {
            private WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS _ValidBits;

            [JsonProperty(Order = 1)]
            public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

            [JsonProperty(Order = 2)]
            public uint SocketId;

            [JsonProperty(Order = 3)]
            public uint ChannelId;

            [JsonProperty(Order = 4)]
            public uint DimmSlot;

            [JsonProperty(Order = 5)]
            public uint CorrectableErrorCount;

            [UsedImplicitly]
            public bool ShouldSerializeChannelId() {
                return (_ValidBits & WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.ChannelId) == WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.ChannelId;
            }

            [UsedImplicitly]
            public bool ShouldSerializeCorrectableErrorCount() {
                return (_ValidBits & WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.CorrectableErrorCount) ==
                       WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.CorrectableErrorCount;
            }

            [UsedImplicitly]
            public bool ShouldSerializeDimmSlot() {
                return (_ValidBits & WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.DimmSlot) == WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.DimmSlot;
            }

            [UsedImplicitly]
            public bool ShouldSerializeSocketId() {
                return (_ValidBits & WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.SocketId) == WHEA_MEMORY_CORRECTABLE_ERROR_SECTION_VALIDBITS.SocketId;
            }
        }

        #endregion

        #region WHEA Error Record Section: WHEA_MEMORY_ERROR_SECTION

        // @formatter:int_align_fields true

        [Flags]
        public enum WHEA_MEMORY_ERROR_SECTION_VALIDBITS : ulong {
            ErrorStatus         = 0x1,
            PhysicalAddress     = 0x2,
            PhysicalAddressMask = 0x4,
            Node                = 0x8,
            Card                = 0x10,
            Module              = 0x20,
            Bank                = 0x40,
            Device              = 0x80,
            Row                 = 0x100,
            Column              = 0x200,
            BitPosition         = 0x400,
            RequesterId         = 0x800,
            ResponderId         = 0x1000,
            TargetId            = 0x2000,
            ErrorType           = 0x4000,
            RankNumber          = 0x8000,
            CardHandle          = 0x10000,
            ModuleHandle        = 0x20000,
            ExtendedRow         = 0x40000,
            BankGroup           = 0x80000,
            BankAddress         = 0x100000,
            ChipIdentification  = 0x200000
        }

        // From preprocessor definitions (WHEA_MEMERRTYPE_*)
        public enum WHEA_MEMORY_ERROR_TYPE : byte {
            Unknown           = 0,
            NoError           = 1,
            SingleBitECC      = 2,
            MultiBitECC       = 3,
            SingleSymChipKill = 4,
            MultiSymChipKill  = 5,
            MasterAbort       = 6,
            TargetAbort       = 7,
            ParityError       = 8,
            WatchdogTimeout   = 9,
            InvalidAddress    = 10,
            MirrorBroken      = 11,
            MemorySparing     = 12
        }

        // @formatter:int_align_fields false

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_MEMORY_ERROR_SECTION : WheaRecord {
            private WHEA_MEMORY_ERROR_SECTION_VALIDBITS _ValidBits;

            [JsonProperty(Order = 1)]
            public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

            [JsonProperty(Order = 2)]
            public WHEA_ERROR_STATUS ErrorStatus;

            [JsonProperty(Order = 3)]
            public ulong PhysicalAddress;

            [JsonProperty(Order = 4)]
            public ulong PhysicalAddressMask;

            [JsonProperty(Order = 5)]
            public ushort Node;

            [JsonProperty(Order = 6)]
            public ushort Card;

            [JsonProperty(Order = 7)]
            public ushort Module;

            [JsonProperty(Order = 8)]
            public ushort Bank;

            [JsonProperty(Order = 9)]
            public ushort Device;

            [JsonProperty(Order = 10)]
            public ushort Row;

            [JsonProperty(Order = 11)]
            public ushort Column;

            [JsonProperty(Order = 12)]
            public ushort BitPosition;

            [JsonProperty(Order = 13)]
            public ulong RequesterId;

            [JsonProperty(Order = 14)]
            public ulong ResponderId;

            [JsonProperty(Order = 15)]
            public ulong TargetId;

            private WHEA_MEMORY_ERROR_TYPE _ErrorType;

            [JsonProperty(Order = 16)]
            public string ErrorType => GetEnabledFlagsAsString(_ErrorType);

            // From Windows 10, version 1803
            [JsonProperty(Order = 17)]
            public byte Extended;

            // From Windows 10, version 1803
            [JsonProperty(Order = 18)]
            public ushort RankNumber;

            // From Windows 10, version 1803
            [JsonProperty(Order = 19)]
            public ushort CardHandle;

            // From Windows 10, version 1803
            [JsonProperty(Order = 20)]
            public ushort ModuleHandle;

            // TODO: Handle BankAddress, BankGroup, & ChipIdentification in ValidBits

            [UsedImplicitly]
            public bool ShouldSerializeBank() {
                return (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Bank) == WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Bank;
            }

            [UsedImplicitly]
            public bool ShouldSerializeBitPosition() {
                return (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.BitPosition) == WHEA_MEMORY_ERROR_SECTION_VALIDBITS.BitPosition;
            }

            [UsedImplicitly]
            public bool ShouldSerializeCard() {
                return (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Card) == WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Card;
            }

            [UsedImplicitly]
            public bool ShouldSerializeCardHandle() {
                return (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.CardHandle) == WHEA_MEMORY_ERROR_SECTION_VALIDBITS.CardHandle;
            }

            [UsedImplicitly]
            public bool ShouldSerializeColumn() {
                return (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Column) == WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Column;
            }

            [UsedImplicitly]
            public bool ShouldSerializeDevice() {
                return (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Device) == WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Device;
            }

            [UsedImplicitly]
            public bool ShouldSerializeErrorStatus() {
                return (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ErrorStatus) == WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ErrorStatus;
            }

            [UsedImplicitly]
            public bool ShouldSerializeErrorType() {
                return (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ErrorType) == WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ErrorType;
            }

            [UsedImplicitly]
            public bool ShouldSerializeExtended() {
                return (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ExtendedRow) == WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ExtendedRow;
            }

            [UsedImplicitly]
            public bool ShouldSerializeModule() {
                return (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Module) == WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Module;
            }

            [UsedImplicitly]
            public bool ShouldSerializeModuleHandle() {
                return (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ModuleHandle) == WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ModuleHandle;
            }

            [UsedImplicitly]
            public bool ShouldSerializeNode() {
                return (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Node) == WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Node;
            }

            [UsedImplicitly]
            public bool ShouldSerializePhysicalAddress() {
                return (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.PhysicalAddress) == WHEA_MEMORY_ERROR_SECTION_VALIDBITS.PhysicalAddress;
            }

            [UsedImplicitly]
            public bool ShouldSerializePhysicalAddressMask() {
                return (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.PhysicalAddressMask) == WHEA_MEMORY_ERROR_SECTION_VALIDBITS.PhysicalAddressMask;
            }

            [UsedImplicitly]
            public bool ShouldSerializeRankNumber() {
                return (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.RankNumber) == WHEA_MEMORY_ERROR_SECTION_VALIDBITS.RankNumber;
            }

            [UsedImplicitly]
            public bool ShouldSerializeRequesterId() {
                return (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.RequesterId) == WHEA_MEMORY_ERROR_SECTION_VALIDBITS.RequesterId;
            }

            [UsedImplicitly]
            public bool ShouldSerializeResponderId() {
                return (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ResponderId) == WHEA_MEMORY_ERROR_SECTION_VALIDBITS.ResponderId;
            }

            [UsedImplicitly]
            public bool ShouldSerializeRow() {
                return (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Row) == WHEA_MEMORY_ERROR_SECTION_VALIDBITS.Row;
            }

            [UsedImplicitly]
            public bool ShouldSerializeTargetId() {
                return (_ValidBits & WHEA_MEMORY_ERROR_SECTION_VALIDBITS.TargetId) == WHEA_MEMORY_ERROR_SECTION_VALIDBITS.TargetId;
            }

            public override void Validate() { }
        }

        #endregion

        #region WHEA Error Record Section: WHEA_MSR_DUMP_SECTION

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_MSR_DUMP_SECTION : WheaRecord {
            public byte MsrDumpBuffer;

            // TODO: Description
            public uint MsrDumpLength; // TODO: Validate

            /*
             * TODO
             * Variable length arrays need a custom marshaller.
             */
            //public byte[] MsrDumpData;

            public override void Validate() { }
        }

        #endregion

        #region WHEA Error Record Section: WHEA_NMI_ERROR_SECTION

        // @formatter:int_align_fields true

        [Flags]
        public enum WHEA_NMI_ERROR_SECTION_FLAGS : uint {
            HypervisorError = 0x1
        }

        // @formatter:int_align_fields false

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_NMI_ERROR_SECTION : WheaRecord {
            [JsonProperty(Order = 1)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Data; // TODO

            private WHEA_NMI_ERROR_SECTION_FLAGS _Flags;

            [JsonProperty(Order = 2)]
            public string Flags => GetEnabledFlagsAsString(_Flags);

            public override void Validate() { }
        }

        #endregion

        #region WHEA Error Record Section: WHEA_PCIE_CORRECTABLE_ERROR_SECTION

        // @formatter:int_align_fields true

        [Flags]
        public enum WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS : ulong {
            Segment               = 0x1,
            Bus                   = 0x2,
            Device                = 0x4,
            Function              = 0x8,
            Mask                  = 0x10,
            CorrectableErrorCount = 0x20
        }

        // @formatter:int_align_fields false

        // TODO
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PCIE_CORRECTABLE_ERROR_SECTION : WheaRecord {
            public override void Validate() { }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PCIE_CORRECTABLE_ERROR_SECTION_HEADER {
            public ushort Version; // TODO: Validate
            public ushort Count;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PCIE_CORRECTABLE_ERROR_DEVICES {
            private WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS _ValidBits;

            [JsonProperty(Order = 1)]
            public string ValidBits => GetEnabledFlagsAsString(_ValidBits); // TODO: Add remaining ShouldSerialize methods

            [JsonProperty(Order = 2)]
            public WHEA_PCIE_ADDRESS Address;

            [JsonProperty(Order = 3)]
            public uint Mask;

            [JsonProperty(Order = 4)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = WHEA_PCIE_CORRECTABLE_ERROR_SECTION_COUNT_SIZE)]
            public uint[] CorrectableErrorCount;

            [UsedImplicitly]
            public bool ShouldSerializeCorrectableErrorCount() {
                return (_ValidBits & WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS.CorrectableErrorCount) ==
                       WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS.CorrectableErrorCount;
            }

            [UsedImplicitly]
            public bool ShouldSerializeMask() {
                return (_ValidBits & WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS.Mask) == WHEA_PCIE_CORRECTABLE_ERROR_DEVICES_VALIDBITS.Mask;
            }
        }

        #endregion

        #region WHEA Error Record Section: WHEA_PCIEXPRESS_ERROR_SECTION

        // @formatter:int_align_fields true

        [Flags]
        public enum WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS : ulong {
            PortType            = 0x1,
            Version             = 0x2,
            CommandStatus       = 0x4,
            DeviceId            = 0x8,
            DeviceSerialNumber  = 0x10,
            BridgeControlStatus = 0x20,
            ExpressCapability   = 0x40,
            AerInfo             = 0x80
        }

        // @formatter:int_align_fields false

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PCIEXPRESS_ERROR_SECTION : WheaRecord {
            private WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS _ValidBits;

            [JsonProperty(Order = 1)]
            public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

            private WHEA_PCIEXPRESS_DEVICE_TYPE _PortType;

            [JsonProperty(Order = 2)]
            public string PortType => Enum.GetName(typeof(WHEA_PCIEXPRESS_DEVICE_TYPE), _PortType);

            [JsonProperty(Order = 3)]
            public WHEA_PCIEXPRESS_VERSION Version;

            [JsonProperty(Order = 4)]
            public WHEA_PCIEXPRESS_COMMAND_STATUS CommandStatus;

            [JsonProperty(Order = 5)]
            public uint Reserved;

            [JsonProperty(Order = 6)]
            public WHEA_PCIEXPRESS_DEVICE_ID DeviceId;

            [JsonProperty(Order = 7)]
            public ulong DeviceSerialNumber;

            [JsonProperty(Order = 8)]
            public WHEA_PCIEXPRESS_BRIDGE_CONTROL_STATUS BridgeControlStatus;

            [JsonProperty(Order = 9)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 60)]
            public byte[] ExpressCapability; // TODO

            [JsonProperty(Order = 10)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] AerInfo; // TODO

            [UsedImplicitly]
            public bool ShouldSerializeAerInfo() {
                return (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.AerInfo) == WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.AerInfo;
            }

            [UsedImplicitly]
            public bool ShouldSerializeBridgeControlStatus() {
                return (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.BridgeControlStatus) ==
                       WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.BridgeControlStatus;
            }

            [UsedImplicitly]
            public bool ShouldSerializeCommandStatus() {
                return (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.CommandStatus) == WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.CommandStatus;
            }

            [UsedImplicitly]
            public bool ShouldSerializeDeviceId() {
                return (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.DeviceId) == WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.DeviceId;
            }

            [UsedImplicitly]
            public bool ShouldSerializeDeviceSerialNumber() {
                return (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.DeviceSerialNumber) == WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.DeviceSerialNumber;
            }

            [UsedImplicitly]
            public bool ShouldSerializeExpressCapability() {
                return (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.ExpressCapability) == WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.ExpressCapability;
            }

            [UsedImplicitly]
            public bool ShouldSerializePortType() {
                return (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.PortType) == WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.PortType;
            }

            [UsedImplicitly]
            public bool ShouldSerializeVersion() {
                return (_ValidBits & WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.Version) == WHEA_PCIEXPRESS_ERROR_SECTION_VALIDBITS.Version;
            }

            public override void Validate() { }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PCIEXPRESS_BRIDGE_CONTROL_STATUS {
            public ushort BridgeSecondaryStatus;
            public ushort BridgeControl;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PCIEXPRESS_COMMAND_STATUS {
            public ushort Command;
            public ushort Status;
        }

        /*
         * Originally defined as a struct of which three members are ULONGs as
         * bitfields. This structure has the same in memory format, but is
         * simpler to interact with.
         */
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PCIEXPRESS_DEVICE_ID {
            [JsonProperty(Order = 1)]
            public ushort VendorId;

            [JsonProperty(Order = 2)]
            public ushort DeviceId;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            private byte[] _ClassCode;

            [JsonProperty(Order = 3)]
            public uint ClassCode => (uint)(_ClassCode[0] + (_ClassCode[1] << 8) + (_ClassCode[2] << 16));

            [JsonProperty(Order = 4)]
            public byte FunctionNumber;

            [JsonProperty(Order = 5)]
            public byte DeviceNumber;

            [JsonProperty(Order = 6)]
            public ushort Segment;

            [JsonProperty(Order = 7)]
            public byte PrimaryBusNumber;

            [JsonProperty(Order = 8)]
            public byte SecondaryBusNumber;

            private ushort _SlotNumber; // Includes Reserved1 member (Bits 0-2)

            [JsonProperty(Order = 9)]
            public byte Reserved1 => (byte)(_SlotNumber & 0xFFF8); // Bits 0-2

            [JsonProperty(Order = 10)]
            public ushort SlotNumber => (ushort)(_SlotNumber >> 3); // Bits 3-15

            [JsonProperty(Order = 11)]
            public byte Reserved2;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PCIEXPRESS_VERSION {
            public byte MinorVersion;
            public byte MajorVersion;
            public ushort Reserved;
        }

        #endregion

        #region WHEA Error Record Section: WHEA_PCIXBUS_ERROR_SECTION

        // @formatter:int_align_fields true

        // Originally defined directly in the WHEA_PCIXBUS_COMMAND structure
        [Flags]
        public enum WHEA_PCIXBUS_COMMAND_FLAGS : byte {
            PCIXCommand = 0x1
        }

        [Flags]
        public enum WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS : ulong {
            ErrorStatus = 0x1,
            ErrorType   = 0x2,
            BusId       = 0x4,
            BusAddress  = 0x8,
            BusData     = 0x10,
            BusCommand  = 0x20,
            RequesterId = 0x40,
            CompleterId = 0x80,
            TargetId    = 0x100
        }

        // From preprocessor definitions (PCIXBUS_ERRTYPE_*)
        public enum WHEA_PCIXBUS_ERROR_TYPE : ushort {
            Unknown          = 0,
            DataParity       = 1,
            System           = 2,
            MasterAbort      = 3,
            BusTimeout       = 4,
            MasterDataParity = 5,
            AddressParity    = 6,
            CommandParity    = 7
        }

        // @formatter:int_align_fields false

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PCIXBUS_ERROR_SECTION : WheaRecord {
            private WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS _ValidBits;

            [JsonProperty(Order = 1)]
            public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

            [JsonProperty(Order = 2)]
            public WHEA_ERROR_STATUS ErrorStatus;

            private WHEA_PCIXBUS_ERROR_TYPE _ErrorType;

            [JsonProperty(Order = 3)]
            public string ErrorType => Enum.GetName(typeof(WHEA_PCIXBUS_ERROR_TYPE), _ErrorType);

            [JsonProperty(Order = 4)]
            public WHEA_PCIXBUS_ID BusId;

            [JsonProperty(Order = 5)]
            public uint Reserved;

            [JsonProperty(Order = 6)]
            public ulong BusAddress;

            [JsonProperty(Order = 7)]
            public ulong BusData;

            [JsonProperty(Order = 8)]
            public WHEA_PCIXBUS_COMMAND BusCommand;

            [JsonProperty(Order = 9)]
            public ulong RequesterId;

            [JsonProperty(Order = 10)]
            public ulong CompleterId;

            [JsonProperty(Order = 11)]
            public ulong TargetId;

            [UsedImplicitly]
            public bool ShouldSerializeBusAddress() {
                return (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.BusAddress) == WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.BusAddress;
            }

            [UsedImplicitly]
            public bool ShouldSerializeBusData() {
                return (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.BusData) == WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.BusData;
            }

            [UsedImplicitly]
            public bool ShouldSerializeBusId() {
                return (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.BusId) == WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.BusId;
            }

            [UsedImplicitly]
            public bool ShouldSerializeBusCommand() {
                return (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.BusCommand) == WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.BusCommand;
            }

            [UsedImplicitly]
            public bool ShouldSerializeCompleterId() {
                return (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.CompleterId) == WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.CompleterId;
            }

            [UsedImplicitly]
            public bool ShouldSerializeErrorStatus() {
                return (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.ErrorStatus) == WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.ErrorStatus;
            }

            [UsedImplicitly]
            public bool ShouldSerializeErrorType() {
                return (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.ErrorType) == WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.ErrorType;
            }

            [UsedImplicitly]
            public bool ShouldSerializeRequesterId() {
                return (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.RequesterId) == WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.RequesterId;
            }

            [UsedImplicitly]
            public bool ShouldSerializeTargetId() {
                return (_ValidBits & WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.TargetId) == WHEA_PCIXBUS_ERROR_SECTION_VALIDBITS.TargetId;
            }

            public override void Validate() { }
        }

        [StructLayout(LayoutKind.Explicit, Pack = 1)]
        public sealed class WHEA_PCIXBUS_COMMAND {
            [FieldOffset(0)]
            private ulong _Command;

            [JsonProperty(Order = 1)]
            public ulong Command => _Command & 0xFF00000000000000; // Bits 0 - 55

            [FieldOffset(56)]
            private WHEA_PCIXBUS_COMMAND_FLAGS _Flags;

            [JsonProperty(Order = 2)]
            public string Flags => GetEnabledFlagsAsString(_Flags);
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PCIXBUS_ID {
            public byte BusNumber;
            public byte BusSegment;
        }

        #endregion

        #region WHEA Error Record Section: WHEA_PCIXDEVICE_ERROR_SECTION

        // @formatter:int_align_fields true

        [Flags]
        public enum WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS : ulong {
            ErrorStatus       = 0x1,
            IdInfo            = 0x2,
            MemoryNumber      = 0x4,
            IoNumber          = 0x8,
            RegisterDataPairs = 0x10
        }

        // @formatter:int_align_fields false

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PCIXDEVICE_ERROR_SECTION : WheaRecord {
            private WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS _ValidBits;

            [JsonProperty(Order = 1)]
            public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

            [JsonProperty(Order = 2)]
            public WHEA_ERROR_STATUS ErrorStatus;

            [JsonProperty(Order = 3)]
            public WHEA_PCIXDEVICE_ID IdInfo;

            [JsonProperty(Order = 4)]
            public uint MemoryNumber;

            [JsonProperty(Order = 5)]
            public uint IoNumber;

            /*
             * TODO
             * Variable length arrays need a custom marshaller.
             */
            //[JsonProperty(Order = 6)]
            //public WHEA_PCIXDEVICE_REGISTER_PAIR[] RegisterDataPairs;

            [UsedImplicitly]
            public bool ShouldSerializeErrorStatus() {
                return (_ValidBits & WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.ErrorStatus) == WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.ErrorStatus;
            }

            [UsedImplicitly]
            public bool ShouldSerializeIdInfo() {
                return (_ValidBits & WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.IdInfo) == WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.IdInfo;
            }

            [UsedImplicitly]
            public bool ShouldSerializeIoNumber() {
                return (_ValidBits & WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.IoNumber) == WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.IoNumber;
            }

            [UsedImplicitly]
            public bool ShouldSerializeMemoryNumber() {
                return (_ValidBits & WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.MemoryNumber) == WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.MemoryNumber;
            }

            [UsedImplicitly]
            public bool ShouldSerializeRegisterDataPairs() {
                return (_ValidBits & WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.RegisterDataPairs) == WHEA_PCIXDEVICE_ERROR_SECTION_VALIDBITS.RegisterDataPairs;
            }

            public override void Validate() { }
        }

        /*
         * Originally defined as a struct of which two members are ULONGs as
         * bitfields. This structure has the same in memory format, but is
         * simpler to interact with.
         */
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PCIXDEVICE_ID {
            [JsonProperty(Order = 1)]
            public ushort VendorId;

            [JsonProperty(Order = 2)]
            public ushort DeviceId;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            private byte[] _ClassCode;

            [JsonProperty(Order = 3)]
            public uint ClassCode => (uint)(_ClassCode[0] + (_ClassCode[1] << 8) + (_ClassCode[2] << 16));

            [JsonProperty(Order = 4)]
            public byte FunctionNumber;

            [JsonProperty(Order = 5)]
            public byte DeviceNumber;

            [JsonProperty(Order = 6)]
            public byte BusNumber;

            [JsonProperty(Order = 7)]
            public byte SegmentNumber;

            [JsonProperty(Order = 8)]
            public byte Reserved1;

            [JsonProperty(Order = 9)]
            public uint Reserved2;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PCIXDEVICE_REGISTER_PAIR {
            public ulong Register;
            public ulong Data;
        }

        #endregion

        #region WHEA Error Record Section: WHEA_PMEM_ERROR_SECTION

        // @formatter:int_align_fields true

        [Flags]
        public enum WHEA_PMEM_ERROR_SECTION_VALIDBITS : ulong {
            ErrorStatus  = 0x1,
            NFITHandle   = 0x2,
            LocationInfo = 0x4
        }

        // @formatter:int_align_fields false

        private const int WHEA_PMEM_ERROR_SECTION_LOCATION_INFO_SIZE = 64;
        private const int WHEA_PMEM_ERROR_SECTION_MAX_PAGES = 50; // TODO

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PMEM_ERROR_SECTION : WheaRecord {
            private WHEA_PMEM_ERROR_SECTION_VALIDBITS _ValidBits;

            [JsonProperty(Order = 1)]
            public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

            [JsonProperty(Order = 2)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = WHEA_PMEM_ERROR_SECTION_LOCATION_INFO_SIZE)]
            public byte[] LocationInfo; // TODO

            [JsonProperty(Order = 3)]
            public WHEA_ERROR_STATUS ErrorStatus;

            [JsonProperty(Order = 4)]
            public uint NFITHandle;

            [JsonProperty(Order = 5)]
            public uint PageRangeCount;

            /*
             * TODO
             * Variable length arrays need a custom marshaller.
             */
            //[JsonProperty(Order = 6)]
            //public WHEA_PMEM_PAGE_RANGE[] PageRange;

            [UsedImplicitly]
            public bool ShouldSerializeErrorStatus() {
                return (_ValidBits & WHEA_PMEM_ERROR_SECTION_VALIDBITS.ErrorStatus) == WHEA_PMEM_ERROR_SECTION_VALIDBITS.ErrorStatus;
            }

            [UsedImplicitly]
            public bool ShouldSerializeLocationInfo() {
                return (_ValidBits & WHEA_PMEM_ERROR_SECTION_VALIDBITS.LocationInfo) == WHEA_PMEM_ERROR_SECTION_VALIDBITS.LocationInfo;
            }

            [UsedImplicitly]
            public bool ShouldSerializeNFITHandle() {
                return (_ValidBits & WHEA_PMEM_ERROR_SECTION_VALIDBITS.NFITHandle) == WHEA_PMEM_ERROR_SECTION_VALIDBITS.NFITHandle;
            }

            public override void Validate() { }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PMEM_PAGE_RANGE {
            public ulong StartingPfn;
            public ulong PageCount;
            public ulong MarkedBadBitmap;
        }

        #endregion

        #region WHEA Error Record Section: WHEA_PROCESSOR_GENERIC_ERROR_SECTION

        // @formatter:int_align_fields true

        // From preprocessor definitions (GENPROC_FLAGS_*)
        [Flags]
        public enum WHEA_PROCESSOR_GENERIC_ERROR_SECTION_FLAGS : byte {
            Restartable = 0x1,
            PreciseIP   = 0x2,
            Overflow    = 0x4,
            Corrected   = 0x8
        }

        [Flags]
        public enum WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS : ulong {
            ProcessorType      = 0x1,
            InstructionSet     = 0x2,
            ErrorType          = 0x4,
            Operation          = 0x8,
            Flags              = 0x10,
            Level              = 0x20,
            CPUVersion         = 0x40,
            CPUBrandString     = 0x80,
            ProcessorId        = 0x100,
            TargetAddress      = 0x200,
            RequesterId        = 0x400,
            ResponderId        = 0x800,
            InstructionPointer = 0x1000,
            NativeModelId      = 0x2000
        }

        // From preprocessor definitions (GENPROC_PROCERRTYPE_*)
        public enum WHEA_PROCESSOR_GENERIC_ERROR_TYPE : byte {
            Unknown = 0,
            Cache   = 1,
            TLB     = 2,
            Bus     = 4,
            MAE     = 8
        }

        // From preprocessor definitions (GENPROC_PROCISA_*)
        public enum WHEA_PROCESSOR_GENERIC_ISA_TYPE : byte {
            x86   = 0,
            Ipf   = 1,
            x64   = 2,
            Arm32 = 4,
            Arm64 = 8
        }

        // From preprocessor definitions (GENPROC_OP_*)
        public enum WHEA_PROCESSOR_GENERIC_OP_TYPE : byte {
            Generic        = 0,
            DataRead       = 1,
            DataWrite      = 2,
            InstructionExe = 3
        }

        // From preprocessor definitions (GENPROC_PROCTYPE_*)
        public enum WHEA_PROCESSOR_GENERIC_TYPE : byte {
            Xpf = 0,
            Ipf = 1,
            Arm = 2
        }

        // @formatter:int_align_fields false

        [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Ansi, Pack = 1)]
        public sealed class WHEA_PROCESSOR_GENERIC_ERROR_SECTION : WheaRecord {
            [FieldOffset(0)]
            private WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS _ValidBits;

            [JsonProperty(Order = 1)]
            public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

            [FieldOffset(8)]
            private WHEA_PROCESSOR_GENERIC_TYPE _ProcessorType;

            [JsonProperty(Order = 2)]
            public string ProcessorType => Enum.GetName(typeof(WHEA_PROCESSOR_GENERIC_TYPE), _ProcessorType);

            [FieldOffset(9)]
            private WHEA_PROCESSOR_GENERIC_ISA_TYPE _InstructionSet;

            [JsonProperty(Order = 3)]
            public string InstructionSet => Enum.GetName(typeof(WHEA_PROCESSOR_GENERIC_ISA_TYPE), _InstructionSet);

            [FieldOffset(10)]
            private WHEA_PROCESSOR_GENERIC_ERROR_TYPE _ErrorType;

            [JsonProperty(Order = 4)]
            public string ErrorType => Enum.GetName(typeof(WHEA_PROCESSOR_GENERIC_ERROR_TYPE), _ErrorType);

            [FieldOffset(11)]
            private WHEA_PROCESSOR_GENERIC_OP_TYPE _Operation;

            [JsonProperty(Order = 5)]
            public string Operation => Enum.GetName(typeof(WHEA_PROCESSOR_GENERIC_OP_TYPE), _Operation);

            [FieldOffset(12)]
            private WHEA_PROCESSOR_GENERIC_ERROR_SECTION_FLAGS _Flags;

            [JsonProperty(Order = 6)]
            public string Flags => GetEnabledFlagsAsString(_Flags);

            [FieldOffset(13)]
            [JsonProperty(Order = 7)]
            public byte Level;

            [FieldOffset(14)]
            [JsonProperty(Order = 8)]
            public ushort Reserved;

            // TODO
            //[FieldOffset(16)]
            //[JsonProperty(Order = 9)]
            //public ulong CPUVersion;

            [FieldOffset(16)]
            [JsonProperty(Order = 10)]
            public WHEA_PROCESSOR_FAMILY_INFO CPUVersionX86; // Original name: CPUVersion

            [FieldOffset(24)]
            [JsonProperty(Order = 11)]
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string CPUBrandString;

            [FieldOffset(152)]
            [JsonProperty(Order = 12)]
            public ulong ProcessorId;

            [FieldOffset(160)]
            [JsonProperty(Order = 13)]
            public ulong TargetAddress;

            [FieldOffset(168)]
            [JsonProperty(Order = 14)]
            public ulong RequesterId;

            [FieldOffset(176)]
            [JsonProperty(Order = 15)]
            public ulong ResponderId;

            [FieldOffset(184)]
            [JsonProperty(Order = 16)]
            public ulong InstructionPointer;

            // TODO: Handle NativeModelId in ValidBits

            [UsedImplicitly]
            public bool ShouldSerializeCPUBrandString() {
                return (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.CPUBrandString) ==
                       WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.CPUBrandString;
            }

            [UsedImplicitly]
            public bool ShouldSerializeCPUVersion() {
                if ((_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.CPUVersion) == WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.CPUVersion)
                    if (ShouldSerializeProcessorType() && _ProcessorType != WHEA_PROCESSOR_GENERIC_TYPE.Xpf)
                        return true;

                return false;
            }

            [UsedImplicitly]
            public bool ShouldSerializeCPUVersionX86() {
                if ((_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.CPUVersion) == WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.CPUVersion)
                    if (ShouldSerializeProcessorType() && _ProcessorType == WHEA_PROCESSOR_GENERIC_TYPE.Xpf)
                        return true;

                return false;
            }

            [UsedImplicitly]
            public bool ShouldSerializeErrorType() {
                return (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.ErrorType) == WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.ErrorType;
            }

            [UsedImplicitly]
            public bool ShouldSerializeFlags() {
                return (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.Flags) == WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.Flags;
            }

            [UsedImplicitly]
            public bool ShouldSerializeInstructionPointer() {
                return (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.InstructionPointer) ==
                       WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.InstructionPointer;
            }

            [UsedImplicitly]
            public bool ShouldSerializeInstructionSet() {
                return (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.InstructionSet) ==
                       WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.InstructionSet;
            }

            [UsedImplicitly]
            public bool ShouldSerializeLevel() {
                return (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.Level) == WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.Level;
            }

            [UsedImplicitly]
            public bool ShouldSerializeOperation() {
                return (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.Operation) == WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.Operation;
            }

            [UsedImplicitly]
            public bool ShouldSerializeProcessorId() {
                return (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.ProcessorId) == WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.ProcessorId;
            }

            [UsedImplicitly]
            public bool ShouldSerializeProcessorType() {
                return (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.ProcessorType) ==
                       WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.ProcessorType;
            }

            [UsedImplicitly]
            public bool ShouldSerializeRequesterId() {
                return (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.RequesterId) == WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.RequesterId;
            }

            [UsedImplicitly]
            public bool ShouldSerializeResponderId() {
                return (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.ResponderId) == WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.ResponderId;
            }

            [UsedImplicitly]
            public bool ShouldSerializeTargetAddress() {
                return (_ValidBits & WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.TargetAddress) ==
                       WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS.TargetAddress;
            }
        }

        /*
         * Originally defined as a struct with the first of two ULONG members
         * being a bitfield. This structure has the same in memory format, but
         * is simpler to interact with.
         */
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PROCESSOR_FAMILY_INFO {
            private uint _ProcInfo;

            [JsonProperty(Order = 1)]
            public byte Stepping => (byte)(_ProcInfo & 0xF); // Bits 0-3

            [JsonProperty(Order = 2)]
            public byte Model => (byte)((_ProcInfo & 0xF0) >> 4); // Bits 4-7

            [JsonProperty(Order = 3)]
            public byte Family => (byte)((_ProcInfo & 0xF00) >> 8); // Bits 8-11

            [JsonProperty(Order = 4)]
            public byte ProcessorType => (byte)((_ProcInfo & 0x3000) >> 12); // Bits 12-13

            [JsonProperty(Order = 5)]
            public byte Reserved1 => (byte)((_ProcInfo & 0xC000) >> 14); // Bits 14-15

            [JsonProperty(Order = 6)]
            public byte ExtendedModel => (byte)((_ProcInfo & 0xF0000) >> 16); // Bits 16-19

            [JsonProperty(Order = 7)]
            public byte ExtendedFamily => (byte)((_ProcInfo & 0xFF00000) >> 20); // Bits 20-27

            [JsonProperty(Order = 8)]
            public byte Reserved2 => (byte)(_ProcInfo >> 28); // Bits 28-31

            [JsonProperty(Order = 9)]
            public uint NativeModelId;
        }

        #endregion

        #region WHEA Error Record Section: WHEA_XPF_PROCESSOR_ERROR_SECTION

        // @formatter:int_align_fields true

        // From preprocessor definitions (XPF_BUS_CHECK_ADDRESS_*)
        public enum WHEA_XPF_BUS_CHECK_ADDRESS : byte {
            Memory   = 0,
            Reserved = 1,
            IO       = 2,
            Other    = 3
        }

        // From preprocessor definitions (XPF_BUS_CHECK_OPERATION_*)
        public enum WHEA_XPF_BUS_CHECK_OPERATION : byte {
            Generic          = 0,
            GenericRead      = 1,
            GenericWrite     = 2,
            DataRead         = 3,
            DataWrite        = 4,
            InstructionFetch = 5,
            Prefetch         = 6
        }

        // From preprocessor definitions (XPF_BUS_CHECK_PARTICIPATION_*)
        public enum WHEA_XPF_BUS_CHECK_PARTICIPATION : byte {
            ProcessorOriginated = 0,
            ProcessorResponded  = 1,
            ProcessorObserved   = 2,
            Generic             = 3
        }

        // From preprocessor definitions (XPF_BUS_CHECK_TRANSACTIONTYPE_*)
        public enum WHEA_XPF_BUS_CHECK_TRANSACTION_TYPE : byte {
            Instruction = 0,
            DataAccess  = 1,
            Generic     = 2
        }

        // From preprocessor definitions (XPF_CACHE_CHECK_OPERATION_*)
        public enum WHEA_XPF_CACHE_CHECK_OPERATION : byte {
            Generic          = 0,
            GenericRead      = 1,
            GenericWrite     = 2,
            DataRead         = 3,
            DataWrite        = 4,
            InstructionFetch = 5,
            Prefetch         = 6,
            Eviction         = 7,
            Snoop            = 8
        }

        // From preprocessor definitions (XPF_CACHE_CHECK_TRANSACTIONTYPE_*)
        public enum WHEA_XPF_CACHE_CHECK_TRANSACTION_TYPE : byte {
            Instruction = 0,
            DataAccess  = 1,
            Generic     = 2
        }

        // From preprocessor definitions (XPF_CONTEXT_INFO_*)
        public enum WHEA_XPF_CONTEXT_INFO_TYPE : byte {
            UnclassifiedData = 0,
            MSRRegisters     = 1,
            Context32        = 2,
            Context64        = 3,
            FxSave           = 4,
            DebugRegisters32 = 5,
            DebugRegisters64 = 6,
            MmRegisters      = 7
        }

        // From preprocessor definitions (XPF_MS_CHECK_ERRORTYPE_*)
        public enum WHEA_XPF_MS_CHECK_ERROR_TYPE : byte {
            NoError              = 0,
            Unclassified         = 1,
            McRomParity          = 2,
            External             = 3,
            Frc                  = 4,
            InternalUnclassified = 5
        }

        // TODO
        [Flags]
        public enum WHEA_XPF_PROCESSOR_ERROR_SECTION_VALIDBITS : ulong { }

        [Flags]
        public enum WHEA_XPF_PROCINFO_VALIDBITS : ulong {
            CheckInfo          = 0x1,
            TargetId           = 0x2,
            RequesterId        = 0x4,
            ResponderId        = 0x8,
            InstructionPointer = 0x10
        }

        // From preprocessor definitions (XPF_TLB_CHECK_OPERATION_*)
        public enum WHEA_XPF_TLB_CHECK_OPERATION : byte {
            Generic          = 0,
            GenericRead      = 1,
            GenericWrite     = 2,
            DataRead         = 3,
            DataWrite        = 4,
            InstructionFetch = 5,
            Prefetch         = 6
        }

        // From preprocessor definitions (XPF_TLB_CHECK_TRANSACTIONTYPE_*)
        public enum WHEA_XPF_TLB_CHECK_TRANSACTION_TYPE : byte {
            Instruction = 0,
            DataAccess  = 1,
            Generic     = 2
        }

        // @formatter:int_align_fields false

        // TODO
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_XPF_PROCESSOR_ERROR_SECTION : WheaRecord { }

        [StructLayout(LayoutKind.Explicit, Pack = 1)]
        public sealed class WHEA_XPF_PROCINFO {
            [FieldOffset(0)]
            [JsonProperty(Order = 1)]
            public Guid CheckInfoId;

            [FieldOffset(16)]
            private WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS _ValidBits; // TODO: Add ShouldSerialize methods

            [JsonProperty(Order = 2)]
            public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

            [FieldOffset(24)]
            [JsonProperty(Order = 3)]
            public WHEA_XPF_CACHE_CHECK CacheCheck;

            [FieldOffset(24)]
            [JsonProperty(Order = 4)]
            public WHEA_XPF_TLB_CHECK TlbCheck;

            [FieldOffset(24)]
            [JsonProperty(Order = 5)]
            public WHEA_XPF_BUS_CHECK BusCheck;

            [FieldOffset(24)]
            [JsonProperty(Order = 6)]
            public WHEA_XPF_MS_CHECK MsCheck;

            [FieldOffset(32)]
            [JsonProperty(Order = 7)]
            public ulong TargetId;

            [FieldOffset(32)]
            [JsonProperty(Order = 8)]
            public ulong RequesterId;

            [FieldOffset(32)]
            [JsonProperty(Order = 9)]
            public ulong ResponderId;

            [FieldOffset(32)]
            [JsonProperty(Order = 10)]
            public ulong InstructionPointer;
        }

        // TODO
        [StructLayout(LayoutKind.Explicit, Pack = 1)]
        public sealed class WHEA_XPF_BUS_CHECK { }

        // TODO
        [StructLayout(LayoutKind.Explicit, Pack = 1)]
        public sealed class WHEA_XPF_CACHE_CHECK { }

        // TODO
        [StructLayout(LayoutKind.Explicit, Pack = 1)]
        public sealed class WHEA_XPF_MS_CHECK { }

        // TODO
        [StructLayout(LayoutKind.Explicit, Pack = 1)]
        public sealed class WHEA_XPF_TLB_CHECK { }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_XPF_CONTEXT_INFO {
            private WHEA_XPF_CONTEXT_INFO_TYPE _RegisterContextType;

            [JsonProperty(Order = 1)]
            public string RegisterContextType => Enum.GetName(typeof(WHEA_XPF_CONTEXT_INFO_TYPE), _RegisterContextType);

            [JsonProperty(Order = 2)]
            public ushort RegisterDataSize;

            [JsonProperty(Order = 3)]
            public uint MSRAddress;

            [JsonProperty(Order = 4)]
            public ulong MmRegisterAddress;

            /*
             * TODO
             * Variable length arrays need a custom marshaller.
             */
            //[JsonProperty(Order = 5)]
            //public byte[] RegisterData;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_X86_REGISTER_STATE {
            public uint Eax;
            public uint Ebx;
            public uint Ecx;
            public uint Edx;
            public uint Esi;
            public uint Edi;
            public uint Ebp;
            public uint Esp;
            public ushort Cs;
            public ushort Ds;
            public ushort Ss;
            public ushort Es;
            public ushort Fs;
            public ushort Gs;
            public uint Eflags;
            public uint Eip;
            public uint Cr0;
            public uint Cr1;
            public uint Cr2;
            public uint Cr3;
            public uint Cr4;
            public ulong Gdtr;
            public ulong Idtr;
            public ushort Ldtr;
            public ushort Tr;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_X64_REGISTER_STATE {
            public ulong Rax;
            public ulong Rbx;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rsi;
            public ulong Rdi;
            public ulong Rbp;
            public ulong Rsp;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ushort Cs;
            public ushort Ds;
            public ushort Ss;
            public ushort Es;
            public ushort Fs;
            public ushort Gs;
            public uint Reserved;
            public ulong Rflags;
            public ulong Eip;
            public ulong Cr0;
            public ulong Cr1;
            public ulong Cr2;
            public ulong Cr3;
            public ulong Cr4;
            public ulong Cr8;
            public WHEA128A Gdtr;
            public WHEA128A Idtr;
            public ushort Ldtr;
            public ushort Tr;
        }

        /*
         * TODO
         * Original struct uses DECLSPEC_ALIGN(16).
         */
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA128A {
            public ulong Low;
            public long High;
        }

        #endregion

        #region WHEA Error Source Descriptor: Constants

        private const int WHEA_ERROR_SOURCE_DESCRIPTOR_VERSION = 10;

        /*
         * Unused due to expansion of the associated fixed size arrays to work
         * around limitations of the .NET Framework marshaller. Search for the
         * constant name to find its original usage.
         */
        [SuppressMessage("CodeQuality", "IDE0051:Remove unused private members")]
        [SuppressMessage("Performance", "CA1823:Avoid unused private fields")]
        private const int WHEA_MAX_MC_BANKS = 32;

        #endregion

        #region WHEA Error Source Descriptor: Enumerations

        // @formatter:int_align_fields true

        public enum WHEA_ERROR_SOURCE_STATE : uint {
            Stopped       = 1,
            Started       = 2,
            Removed       = 3,
            RemovePending = 4
        }

        // @formatter:int_align_fields false

        #endregion

        #region WHEA Error Source Descriptor: Flags

        // @formatter:int_align_fields true

        [Flags]
        public enum AER_BRIDGE_DESCRIPTOR_FLAGS : ushort {
            UncorrectableErrorMaskRW          = 0x1,
            UncorrectableErrorSeverityRW      = 0x2,
            CorrectableErrorMaskRW            = 0x4,
            AdvancedCapsAndControlRW          = 0x8,
            SecondaryUncorrectableErrorMaskRW = 0x10,
            SecondaryUncorrectableErrorSevRW  = 0x20,
            SecondaryCapsAndControlRW         = 0x40
        }

        [Flags]
        public enum AER_ENDPOINT_DESCRIPTOR_FLAGS : ushort {
            UncorrectableErrorMaskRW     = 0x1,
            UncorrectableErrorSeverityRW = 0x2,
            CorrectableErrorMaskRW       = 0x4,
            AdvancedCapsAndControlRW     = 0x8
        }

        [Flags]
        public enum AER_ROOTPORT_DESCRIPTOR_FLAGS : ushort {
            UncorrectableErrorMaskRW     = 0x1,
            UncorrectableErrorSeverityRW = 0x2,
            CorrectableErrorMaskRW       = 0x4,
            AdvancedCapsAndControlRW     = 0x8,
            RootErrorCommandRW           = 0x10
        }

        // From preprocessor definitions (WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_*)
        public enum WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE : ushort {
            XpfMce       = 0,
            XpfCmc       = 1,
            XpfNmi       = 2,
            IpfMca       = 3,
            IpfCmc       = 4,
            IpfCpe       = 5,
            AerRootPort  = 6,
            AerEndpoint  = 7,
            AerBridge    = 8,
            Generic      = 9,
            GenericV2    = 10,
            DeviceDriver = 11 // TODO: Just a guess as not in the header
        }

        // From preprocessor definitions (WHEA_ERROR_SOURCE_FLAG_*)
        [Flags]
        public enum WHEA_ERROR_SOURCE_FLAGS : uint {
            FirmwareFirst = 0x1,
            Global        = 0x2,
            GhesAssist    = 0x4,
            DefaultSource = 0x80000000
        }

        // From preprocessor definitions (WHEA_XPF_MC_BANK_STATUSFORMAT_*)
        public enum WHEA_XPF_MC_BANK_STATUSFORMAT : byte {
            IA32MCA    = 0,
            Intel64MCA = 1,
            AMD64MCA   = 2
        }

        [Flags]
        public enum XPF_MC_BANK_FLAGS : byte {
            ClearOnInitializationRW = 0x1,
            ControlDataRW           = 0x2
        }

        [Flags]
        public enum XPF_MCE_FLAGS : uint {
            MCG_CapabilityRW    = 0x1,
            MCG_GlobalControlRW = 0x2
        }

        // @formatter:int_align_fields false

        #endregion

        #region WHEA Error Source Descriptor: Structures

        [StructLayout(LayoutKind.Explicit, Pack = 1)]
        public sealed class WHEA_ERROR_SOURCE_DESCRIPTOR : WheaRecord {
            [FieldOffset(0)]
            [JsonProperty(Order = 1)]
            public uint Length;

            [FieldOffset(4)]
            [JsonProperty(Order = 2)]
            public uint Version;

            [FieldOffset(8)]
            private WHEA_ERROR_SOURCE_TYPE _Type;

            [JsonProperty(Order = 3)]
            public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_TYPE), _Type);

            [FieldOffset(12)]
            private WHEA_ERROR_SOURCE_STATE _State;

            [JsonProperty(Order = 4)]
            public string State => Enum.GetName(typeof(WHEA_ERROR_SOURCE_STATE), _State);

            [FieldOffset(16)]
            [JsonProperty(Order = 5)]
            public uint MaxRawDataLength;

            [FieldOffset(20)]
            [JsonProperty(Order = 6)]
            public uint NumRecordsToPreallocate;

            [FieldOffset(24)]
            [JsonProperty(Order = 7)]
            public uint MaxSectionsPerRecord;

            [FieldOffset(28)]
            [JsonProperty(Order = 8)]
            public uint ErrorSourceId;

            [FieldOffset(32)]
            [JsonProperty(Order = 9)]
            public uint PlatformErrorSourceId;

            [FieldOffset(36)]
            private WHEA_ERROR_SOURCE_FLAGS _Flags;

            [JsonProperty(Order = 10)]
            public string Flags => GetEnabledFlagsAsString(_Flags);

            [FieldOffset(40)]
            [JsonProperty(Order = 11)]
            public WHEA_XPF_MCE_DESCRIPTOR XpfMceDescriptor;

            [FieldOffset(40)]
            [JsonProperty(Order = 12)]
            public WHEA_XPF_CMC_DESCRIPTOR XpfCmcDescriptor;

            [FieldOffset(40)]
            [JsonProperty(Order = 13)]
            public WHEA_XPF_NMI_DESCRIPTOR XpfNmiDescriptor;

            [FieldOffset(40)]
            [JsonProperty(Order = 14)]
            public WHEA_IPF_MCA_DESCRIPTOR IpfMcaDescriptor;

            [FieldOffset(40)]
            [JsonProperty(Order = 15)]
            public WHEA_IPF_CMC_DESCRIPTOR IpfCmcDescriptor;

            [FieldOffset(40)]
            [JsonProperty(Order = 16)]
            public WHEA_IPF_CPE_DESCRIPTOR IpfCpeDescriptor;

            [FieldOffset(40)]
            [JsonProperty(Order = 17)]
            public WHEA_AER_ROOTPORT_DESCRIPTOR AerRootportDescriptor;

            [FieldOffset(40)]
            [JsonProperty(Order = 18)]
            public WHEA_AER_ENDPOINT_DESCRIPTOR AerEndpointDescriptor;

            [FieldOffset(40)]
            [JsonProperty(Order = 19)]
            public WHEA_AER_BRIDGE_DESCRIPTOR AerBridgeDescriptor;

            [FieldOffset(40)]
            [JsonProperty(Order = 20)]
            public WHEA_GENERIC_ERROR_DESCRIPTOR GenErrDescriptor;

            [FieldOffset(40)]
            [JsonProperty(Order = 21)]
            public WHEA_GENERIC_ERROR_DESCRIPTOR_V2 GenErrDescriptorV2;

            [FieldOffset(40)]
            [JsonProperty(Order = 22)]
            public WHEA_DEVICE_DRIVER_DESCRIPTOR DeviceDriverDescriptor;

            public bool ShouldSerializeXpfMceDescriptor() {
                return _Type == WHEA_ERROR_SOURCE_TYPE.MCE;
            }

            public bool ShouldSerializeXpfCmcDescriptor() {
                return _Type == WHEA_ERROR_SOURCE_TYPE.CMC;
            }

            public bool ShouldSerializeXpfNmiDescriptor() {
                return _Type == WHEA_ERROR_SOURCE_TYPE.NMI;
            }

            public bool ShouldSerializeIpfMcaDescriptor() {
                return _Type == WHEA_ERROR_SOURCE_TYPE.IPFMCA;
            }

            public bool ShouldSerializeIpfCmcDescriptor() {
                return _Type == WHEA_ERROR_SOURCE_TYPE.IPFCMC;
            }

            public bool ShouldSerializeIpfCpeDescriptor() {
                return _Type == WHEA_ERROR_SOURCE_TYPE.IPFCPE;
            }

            public bool ShouldSerializeAerRootportDescriptor() {
                return _Type == WHEA_ERROR_SOURCE_TYPE.PCIe && AerRootportDescriptor.Validate();
            }

            public bool ShouldSerializeAerEndpointDescriptor() {
                return _Type == WHEA_ERROR_SOURCE_TYPE.PCIe && AerEndpointDescriptor.Validate();
            }

            public bool ShouldSerializeAerBridgeDescriptor() {
                return _Type == WHEA_ERROR_SOURCE_TYPE.PCIe && AerBridgeDescriptor.Validate();
            }

            public bool ShouldSerializeGenErrDescriptor() {
                return _Type == WHEA_ERROR_SOURCE_TYPE.Generic;
            }

            public bool ShouldSerializeGenErrDescriptorV2() {
                return _Type == WHEA_ERROR_SOURCE_TYPE.GenericV2;
            }

            public bool ShouldSerializeDeviceDriverDescriptor() {
                return _Type == WHEA_ERROR_SOURCE_TYPE.DeviceDriver;
            }

            public override void Validate() {
                string msg;

                var expectedLength = Marshal.SizeOf(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR));
                if (Length != expectedLength) {
                    msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Expected length of {expectedLength} bytes but Length member is: {Length}";
                    ExitWithMessage(msg, 2);
                }

                /*
                 * The WHEA header defines versions 10 and 11 but it's unclear
                 * how they differ. The Microsoft docs state the version should
                 * always be set to 10 so for now we just ignore version 11.
                 */
                if (Version != WHEA_ERROR_SOURCE_DESCRIPTOR_VERSION) {
                    msg =
                        $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Expected version {WHEA_ERROR_SOURCE_DESCRIPTOR_VERSION} but Version member is: {Version}";
                    ExitWithMessage(msg, 2);
                }

                if (ShouldSerializeXpfMceDescriptor()) {
                    if (XpfMceDescriptor.Validate()) return;
                    msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type is \"{Type}\" but Type of XpfMceDescriptor is: {XpfMceDescriptor.Type}";
                    ExitWithMessage(msg, 2);
                }

                if (ShouldSerializeXpfCmcDescriptor()) {
                    if (XpfCmcDescriptor.Validate()) return;
                    msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type is \"{Type}\" but Type of XpfCmcDescriptor is: {XpfCmcDescriptor.Type}";
                    ExitWithMessage(msg, 2);
                }

                if (ShouldSerializeXpfNmiDescriptor()) {
                    if (XpfNmiDescriptor.Validate()) return;
                    msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type is \"{Type}\" but Type of XpfNmiDescriptor is: {XpfNmiDescriptor.Type}";
                    ExitWithMessage(msg, 2);
                }

                if (ShouldSerializeIpfMcaDescriptor()) {
                    if (IpfMcaDescriptor.Validate()) return;
                    msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type is \"{Type}\" but Type of IpfMcaDescriptor is: {IpfMcaDescriptor.Type}";
                    ExitWithMessage(msg, 2);
                }

                if (ShouldSerializeIpfCmcDescriptor()) {
                    if (IpfCmcDescriptor.Validate()) return;
                    msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type is \"{Type}\" but Type of IpfCmcDescriptor is: {IpfCmcDescriptor.Type}";
                    ExitWithMessage(msg, 2);
                }

                if (ShouldSerializeIpfCpeDescriptor()) {
                    if (IpfCpeDescriptor.Validate()) return;
                    msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type is \"{Type}\" but Type of IpfCpeDescriptor is: {IpfCpeDescriptor.Type}";
                    ExitWithMessage(msg, 2);
                }

                if (_Type == WHEA_ERROR_SOURCE_TYPE.PCIe) {
                    if (ShouldSerializeAerRootportDescriptor() || ShouldSerializeAerEndpointDescriptor() || ShouldSerializeAerBridgeDescriptor()) return;
                    /*
                     * Using any PCIe AER structure is safe as the Type member
                     * resides at the same offset for all the structures.
                     */
                    msg =
                        $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type is \"{Type}\" but Type in all AER structures is invalid: {AerRootportDescriptor.Type}";
                    ExitWithMessage(msg, 2);
                }

                if (ShouldSerializeGenErrDescriptor()) {
                    if (GenErrDescriptor.Validate()) return;
                    msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type is \"{Type}\" but Type of GenErrDescriptor is: {GenErrDescriptor.Type}";
                    ExitWithMessage(msg, 2);
                }

                if (ShouldSerializeGenErrDescriptorV2()) {
                    if (GenErrDescriptorV2.Validate()) return;
                    msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type is \"{Type}\" but Type of GenErrDescriptorV2 is: {GenErrDescriptorV2.Type}";
                    ExitWithMessage(msg, 2);
                }

                if (ShouldSerializeDeviceDriverDescriptor()) {
                    if (DeviceDriverDescriptor.Validate()) return;
                    msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type is \"{Type}\" but Type of DeviceDriverDescriptor is: {DeviceDriverDescriptor.Type}";
                    ExitWithMessage(msg, 2);
                }

                msg = $"[{nameof(WHEA_ERROR_SOURCE_DESCRIPTOR)}] Type does not match any known descriptor: {Type}";
                ExitWithMessage(msg, 2);
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_XPF_MC_BANK_DESCRIPTOR {
            [JsonProperty(Order = 1)]
            public byte BankNumber;

            [JsonProperty(Order = 2)]
            [MarshalAs(UnmanagedType.U1)]
            public bool ClearOnInitialization;

            private WHEA_XPF_MC_BANK_STATUSFORMAT _StatusDataFormat;

            [JsonProperty(Order = 3)]
            public string StatusDataFormat => Enum.GetName(typeof(WHEA_XPF_MC_BANK_STATUSFORMAT), _StatusDataFormat);

            private XPF_MC_BANK_FLAGS _Flags;

            [JsonProperty(Order = 4)]
            public string Flags => GetEnabledFlagsAsString(_Flags);

            [JsonProperty(Order = 5)]
            public uint ControlMsr;

            [JsonProperty(Order = 6)]
            public uint StatusMsr;

            [JsonProperty(Order = 7)]
            public uint AddressMsr;

            [JsonProperty(Order = 8)]
            public uint MiscMsr;

            [JsonProperty(Order = 9)]
            public ulong ControlData;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_XPF_MCE_DESCRIPTOR {
            private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

            [JsonProperty(Order = 1)]
            public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

            [JsonProperty(Order = 2)]
            public byte Enabled;

            [JsonProperty(Order = 3)]
            public byte NumberOfBanks;

            private XPF_MCE_FLAGS _Flags;

            [JsonProperty(Order = 4)]
            public string Flags => GetEnabledFlagsAsString(_Flags);

            [JsonProperty(Order = 5)]
            public ulong MCG_Capability;

            [JsonProperty(Order = 6)]
            public ulong MCG_GlobalControl;

            /*
             * TODO
             * The original structure uses a fixed size array defined as:
             * WHEA_XPF_MC_BANK_DESCRIPTOR Banks[WHEA_MAX_MC_BANKS];
             *
             * Unfortunately, we have to expand this as the .NET Framework will
             * not marshal it correctly due to it being a non-blittable type.
             */
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank1;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank2;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank3;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank4;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank5;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank6;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank7;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank8;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank9;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank10;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank11;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank12;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank13;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank14;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank15;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank16;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank17;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank18;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank19;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank20;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank21;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank22;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank23;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank24;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank25;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank26;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank27;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank28;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank29;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank30;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank31;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank32;

            public bool Validate() {
                return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.XpfMce;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_XPF_CMC_DESCRIPTOR {
            private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

            [JsonProperty(Order = 1)]
            public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

            [JsonProperty(Order = 2)]
            [MarshalAs(UnmanagedType.U1)]
            public bool Enabled;

            [JsonProperty(Order = 3)]
            public byte NumberOfBanks;

            [JsonProperty(Order = 4)]
            public uint Reserved;

            [JsonProperty(Order = 5)]
            public WHEA_NOTIFICATION_DESCRIPTOR Notify;

            /*
             * TODO
             * The original structure uses a fixed size array defined as:
             * WHEA_XPF_MC_BANK_DESCRIPTOR Banks[WHEA_MAX_MC_BANKS];
             *
             * Unfortunately, we have to expand this as the .NET Framework will
             * not marshal it correctly due to it being a non-blittable type.
             */
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank1;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank2;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank3;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank4;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank5;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank6;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank7;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank8;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank9;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank10;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank11;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank12;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank13;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank14;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank15;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank16;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank17;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank18;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank19;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank20;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank21;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank22;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank23;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank24;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank25;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank26;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank27;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank28;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank29;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank30;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank31;
            public WHEA_XPF_MC_BANK_DESCRIPTOR Bank32;

            public bool Validate() {
                return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.XpfCmc;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_XPF_NMI_DESCRIPTOR {
            private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

            [JsonProperty(Order = 1)]
            public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

            [JsonProperty(Order = 2)]
            [MarshalAs(UnmanagedType.U1)]
            public bool Enabled;

            public bool Validate() {
                return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.XpfNmi;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_IPF_MCA_DESCRIPTOR {
            private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

            [JsonProperty(Order = 1)]
            public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

            [JsonProperty(Order = 2)]
            public byte Enabled;

            [JsonProperty(Order = 3)]
            public byte Reserved;

            public bool Validate() {
                return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.IpfMca;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_IPF_CMC_DESCRIPTOR {
            private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

            [JsonProperty(Order = 1)]
            public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

            [JsonProperty(Order = 2)]
            public byte Enabled;

            [JsonProperty(Order = 3)]
            public byte Reserved;

            public bool Validate() {
                return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.IpfCmc;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_IPF_CPE_DESCRIPTOR {
            private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

            [JsonProperty(Order = 1)]
            public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

            [JsonProperty(Order = 2)]
            public byte Enabled;

            [JsonProperty(Order = 3)]
            public byte Reserved;

            public bool Validate() {
                return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.IpfCpe;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PCI_SLOT_NUMBER {
            private byte _DevFuncNumber;

            [JsonProperty(Order = 1)]
            public byte DeviceNumber => (byte)(_DevFuncNumber & 0x1F); // Bits 0-4

            [JsonProperty(Order = 2)]
            public byte FunctionNumber => (byte)(_DevFuncNumber >> 5); // Bits 5-7

            [JsonProperty(Order = 3)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public byte[] Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_AER_ROOTPORT_DESCRIPTOR {
            private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

            [JsonProperty(Order = 1)]
            public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

            [JsonProperty(Order = 2)]
            [MarshalAs(UnmanagedType.U1)]
            public bool Enabled;

            [JsonProperty(Order = 3)]
            public byte Reserved;

            [JsonProperty(Order = 4)]
            public uint BusNumber;

            [JsonProperty(Order = 5)]
            public WHEA_PCI_SLOT_NUMBER Slot;

            [JsonProperty(Order = 6)]
            public ushort DeviceControl;

            private AER_ROOTPORT_DESCRIPTOR_FLAGS _Flags;

            [JsonProperty(Order = 7)]
            public string Flags => GetEnabledFlagsAsString(_Flags);

            [JsonProperty(Order = 8)]
            public uint UncorrectableErrorMask;

            [JsonProperty(Order = 9)]
            public uint UncorrectableErrorSeverity;

            [JsonProperty(Order = 10)]
            public uint CorrectableErrorMask;

            [JsonProperty(Order = 11)]
            public uint AdvancedCapsAndControl;

            [JsonProperty(Order = 12)]
            public uint RootErrorCommand;

            public bool Validate() {
                return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerRootPort;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_AER_ENDPOINT_DESCRIPTOR {
            private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

            [JsonProperty(Order = 1)]
            public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

            [JsonProperty(Order = 2)]
            [MarshalAs(UnmanagedType.U1)]
            public bool Enabled;

            [JsonProperty(Order = 3)]
            public byte Reserved;

            [JsonProperty(Order = 4)]
            public uint BusNumber;

            [JsonProperty(Order = 5)]
            public WHEA_PCI_SLOT_NUMBER Slot;

            [JsonProperty(Order = 6)]
            public ushort DeviceControl;

            private AER_ENDPOINT_DESCRIPTOR_FLAGS _Flags;

            [JsonProperty(Order = 7)]
            public string Flags => GetEnabledFlagsAsString(_Flags);

            [JsonProperty(Order = 8)]
            public uint UncorrectableErrorMask;

            [JsonProperty(Order = 9)]
            public uint UncorrectableErrorSeverity;

            [JsonProperty(Order = 10)]
            public uint CorrectableErrorMask;

            [JsonProperty(Order = 11)]
            public uint AdvancedCapsAndControl;

            public bool Validate() {
                return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerEndpoint;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_AER_BRIDGE_DESCRIPTOR {
            private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

            [JsonProperty(Order = 1)]
            public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

            [JsonProperty(Order = 2)]
            [MarshalAs(UnmanagedType.U1)]
            public bool Enabled;

            [JsonProperty(Order = 3)]
            public byte Reserved;

            [JsonProperty(Order = 4)]
            public uint BusNumber;

            [JsonProperty(Order = 5)]
            public WHEA_PCI_SLOT_NUMBER Slot;

            [JsonProperty(Order = 6)]
            public ushort DeviceControl;

            private AER_BRIDGE_DESCRIPTOR_FLAGS _Flags;

            [JsonProperty(Order = 7)]
            public string Flags => GetEnabledFlagsAsString(_Flags);

            [JsonProperty(Order = 8)]
            public uint UncorrectableErrorMask;

            [JsonProperty(Order = 9)]
            public uint UncorrectableErrorSeverity;

            [JsonProperty(Order = 10)]
            public uint CorrectableErrorMask;

            [JsonProperty(Order = 11)]
            public uint AdvancedCapsAndControl;

            [JsonProperty(Order = 12)]
            public uint SecondaryUncorrectableErrorMask;

            [JsonProperty(Order = 13)]
            public uint SecondaryUncorrectableErrorSev;

            [JsonProperty(Order = 14)]
            public uint SecondaryCapsAndControl;

            public bool Validate() {
                return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.AerBridge;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_GENERIC_ERROR_DESCRIPTOR {
            private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

            [JsonProperty(Order = 1)]
            public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

            [JsonProperty(Order = 2)]
            public byte Reserved;

            [JsonProperty(Order = 3)]
            public byte Enabled;

            [JsonProperty(Order = 4)]
            public uint ErrStatusBlockLength;

            [JsonProperty(Order = 5)]
            public uint RelatedErrorSourceId;

            // Next five members are equivalent to GEN_ADDR struct
            [JsonProperty(Order = 6)]
            public byte ErrStatusAddressSpaceID;

            [JsonProperty(Order = 7)]
            public byte ErrStatusAddressBitWidth;

            [JsonProperty(Order = 8)]
            public byte ErrStatusAddressBitOffset;

            [JsonProperty(Order = 9)]
            public byte ErrStatusAddressAccessSize;

            [JsonProperty(Order = 10)]
            public long ErrStatusAddress; // TODO: WHEA_PHYSICAL_ADDRESS

            [JsonProperty(Order = 11)]
            public WHEA_NOTIFICATION_DESCRIPTOR Notify;

            public bool Validate() {
                return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.Generic;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_GENERIC_ERROR_DESCRIPTOR_V2 {
            private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

            [JsonProperty(Order = 1)]
            public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

            [JsonProperty(Order = 2)]
            public byte Reserved;

            [JsonProperty(Order = 3)]
            public byte Enabled;

            [JsonProperty(Order = 4)]
            public uint ErrStatusBlockLength;

            [JsonProperty(Order = 5)]
            public uint RelatedErrorSourceId;

            // Next five members are equivalent to GEN_ADDR struct
            [JsonProperty(Order = 6)]
            public byte ErrStatusAddressSpaceID;

            [JsonProperty(Order = 7)]
            public byte ErrStatusAddressBitWidth;

            [JsonProperty(Order = 8)]
            public byte ErrStatusAddressBitOffset;

            [JsonProperty(Order = 9)]
            public byte ErrStatusAddressAccessSize;

            [JsonProperty(Order = 10)]
            public long ErrStatusAddress; // TODO: WHEA_PHYSICAL_ADDRESS

            [JsonProperty(Order = 11)]
            public WHEA_NOTIFICATION_DESCRIPTOR Notify;

            // Next five members are equivalent to GEN_ADDR struct
            [JsonProperty(Order = 12)]
            public byte ReadAckAddressSpaceID;

            [JsonProperty(Order = 13)]
            public byte ReadAckAddressBitWidth;

            [JsonProperty(Order = 14)]
            public byte ReadAckAddressBitOffset;

            [JsonProperty(Order = 15)]
            public byte ReadAckAddressAccessSize;

            [JsonProperty(Order = 16)]
            public long ReadAckAddress; // TODO: WHEA_PHYSICAL_ADDRESS

            [JsonProperty(Order = 17)]
            public ulong ReadAckPreserveMask;

            [JsonProperty(Order = 18)]
            public ulong ReadAckWriteMask;

            public bool Validate() {
                return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.GenericV2;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_DEVICE_DRIVER_DESCRIPTOR {
            private WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE _Type;

            [JsonProperty(Order = 1)]
            public string Type => Enum.GetName(typeof(WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE), _Type);

            [JsonProperty(Order = 2)]
            [MarshalAs(UnmanagedType.U1)]
            public bool Enabled;

            [JsonProperty(Order = 3)]
            public byte Reserved;

            [JsonProperty(Order = 4)]
            public Guid SourceGuid;

            [JsonProperty(Order = 5)]
            public ushort LogTag;

            [JsonProperty(Order = 6)]
            public ushort Reserved2;

            [JsonProperty(Order = 7)]
            public uint PacketLength;

            [JsonProperty(Order = 8)]
            public uint PacketCount;

            [JsonProperty(Order = 9)]
            public IntPtr PacketBuffer; // TODO: PUCHAR

            [JsonProperty(Order = 10)]
            public WHEA_ERROR_SOURCE_CONFIGURATION_DD Config;

            [JsonProperty(Order = 11)]
            public Guid CreatorId;

            [JsonProperty(Order = 12)]
            public Guid PartitionId;

            [JsonProperty(Order = 13)]
            public uint MaxSectionDataLength;

            [JsonProperty(Order = 14)]
            public uint MaxSectionsPerRecord;

            [JsonProperty(Order = 15)]
            public IntPtr PacketStateBuffer; // TODO: PUCHAR

            [JsonProperty(Order = 16)]
            public int OpenHandles;

            public bool Validate() {
                return _Type == WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE.DeviceDriver;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_ERROR_SOURCE_CONFIGURATION_DD {
            // Callback
            // WHEA_ERROR_SOURCE_INITIALIZE_DEVICE_DRIVER(PVOID Context, ULONG ErrorSourceId)
            public IntPtr Initialize;

            // Callback
            // WHEA_ERROR_SOURCE_UNINITIALIZE_DEVICE_DRIVER(PVOID Context)
            public IntPtr Uninitialize;

            // Callback
            // WHEA_ERROR_SOURCE_CORRECT_DEVICE_DRIVER(PVOID ErrorSourceDesc, PULONG MaximumSectionLength)
            public IntPtr Correct;
        }

        #endregion

        #region WHEA Event Log Entry: Constants

        /*
         * Reversed from what is defined in the header as we perform validation
         * against the member as an ASCII string instead of a ULONG.
         */
        public const string WHEA_ERROR_LOG_ENTRY_SIGNATURE = "WhLg";

        private const int WHEA_ERROR_LOG_ENTRY_VERSION = 1;
        private const int WHEA_ERROR_TEXT_LEN = 32;

        #endregion

        #region WHEA Event Log Entry: Enumerations

        // @formatter:int_align_fields true

        public enum PSHED_PI_ERR_READING_PCIE_OVERRIDES : uint {
            NoErr        = 0,
            NoMemory     = 1,
            QueryErr     = 2,
            BadSize      = 3,
            BadSignature = 4,
            NoCapOffset  = 5,
            NotBinary    = 6
        }

        /*
         * TODO
         * Unassociated structures:
         * - WHEA_SEL_BUGCHECK_RECOVERY_STATUS_MULTIPLE_BUGCHECK_EVENT
         * - WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE1_EVENT
         * - WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE2_EVENT
         * - WHEA_SEL_BUGCHECK_RECOVERY_STATUS_START_EVENT
         * - WHEAP_DEFERRED_EVENT
         * - WHEAP_PLUGIN_PFA_EVENT
         */
        public enum WHEA_EVENT_LOG_ENTRY_ID : uint {
            CmcPollingTimeout       = 0x80000001, // TODO
            WheaInit                = 0x80000002, // TODO
            CmcSwitchToPolling      = 0x80000003, // TODO
            DroppedCorrectedError   = 0x80000004, // WHEAP_DROPPED_CORRECTED_ERROR_EVENT
            StartedReportHwError    = 0x80000005, // WHEAP_STARTED_REPORT_HW_ERROR (SEL only)
            PFAMemoryOfflined       = 0x80000006, // WHEAP_PFA_MEMORY_OFFLINED
            PFAMemoryRemoveMonitor  = 0x80000007, // WHEAP_PFA_MEMORY_REMOVE_MONITOR
            PFAMemoryPolicy         = 0x80000008, // WHEAP_PFA_MEMORY_POLICY
            PshedInjectError        = 0x80000009, // WHEAP_PSHED_INJECT_ERROR
            OscCapabilities         = 0x8000000a, // WHEAP_OSC_IMPLEMENTED
            PshedPluginRegister     = 0x8000000b, // WHEAP_PSHED_PLUGIN_REGISTER
            AddRemoveErrorSource    = 0x8000000c, // WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT
            WorkQueueItem           = 0x8000000d, // TODO
            AttemptErrorRecovery    = 0x8000000e, // WHEAP_ATTEMPT_RECOVERY_EVENT
            McaFoundErrorInBank     = 0x8000000f, // WHEAP_FOUND_ERROR_IN_BANK_EVENT
            McaStuckErrorCheck      = 0x80000010, // WHEAP_STUCK_ERROR_EVENT
            McaErrorCleared         = 0x80000011, // WHEAP_ERROR_CLEARED_EVENT
            ClearedPoison           = 0x80000012, // WHEAP_CLEARED_POISON_EVENT
            ProcessEINJ             = 0x80000013, // WHEAP_PROCESS_EINJ_EVENT
            ProcessHEST             = 0x80000014, // WHEAP_PROCESS_HEST_EVENT
            CreateGenericRecord     = 0x80000015, // WHEAP_CREATE_GENERIC_RECORD_EVENT
            ErrorRecord             = 0x80000016, // WHEAP_ERROR_RECORD_EVENT
            ErrorRecordLimit        = 0x80000017, // TODO
            AerNotGrantedToOs       = 0x80000018, // No payload
            ErrSrcArrayInvalid      = 0x80000019, // WHEAP_ERR_SRC_ARRAY_INVALID_EVENT
            AcpiTimeOut             = 0x8000001a, // WHEAP_ACPI_TIMEOUT_EVENT
            CmciRestart             = 0x8000001b, // WHEAP_CMCI_RESTART_EVENT
            CmciFinalRestart        = 0x8000001c, // TODO
            EntryEtwOverFlow        = 0x8000001d, // WHEA_ETW_OVERFLOW_EVENT
            AzccRootBusSearchErr    = 0x8000001e, // WHEA_AZCC_ROOT_BUS_ERR_EVENT
            AzccRootBusList         = 0x8000001f, // WHEA_AZCC_ROOT_BUS_LIST_EVENT
            ErrSrcInvalid           = 0x80000020, // WHEAP_ERR_SRC_INVALID_EVENT
            GenericErrMemMap        = 0x80000021, // WHEAP_GENERIC_ERR_MEM_MAP_EVENT
            PshedCallbackCollision  = 0x80000022, // TODO
            SELBugCheckProgress     = 0x80000023, // WHEA_SEL_BUGCHECK_PROGRESS
            PshedPluginLoad         = 0x80000024, // WHEA_PSHED_PLUGIN_LOAD_EVENT
            PshedPluginUnload       = 0x80000025, // WHEA_PSHED_PLUGIN_UNLOAD_EVENT
            PshedPluginSupported    = 0x80000026, // WHEA_PSHED_PLUGIN_PLATFORM_SUPPORT_EVENT
            DeviceDriver            = 0x80000027, // WHEAP_DEVICE_DRV_EVENT
            CmciImplPresent         = 0x80000028, // WHEAP_CMCI_IMPLEMENTED_EVENT
            CmciInitError           = 0x80000029, // WHEAP_CMCI_INITERR_EVENT
            SELBugCheckRecovery     = 0x8000002a, // TODO
            DrvErrSrcInvalid        = 0x8000002b, // TODO
            DrvHandleBusy           = 0x8000002c, // TODO
            WheaHeartbeat           = 0x8000002d, // WHEA_PSHED_PLUGIN_HEARTBEAT (no payload)
            AzccRootBusPoisonSet    = 0x8000002e, // WHEA_AZCC_SET_POISON_EVENT
            SELBugCheckInfo         = 0x8000002f, // TODO
            ErrDimmInfoMismatch     = 0x80000030, // WHEA_PSHED_PLUGIN_DIMM_MISMATCH
            eDpcEnabled             = 0x80000031, // WHEAP_EDPC_ENABLED_EVENT
            PageOfflineDone         = 0x80000032, // WHEA_OFFLINE_DONE_EVENT
            PageOfflinePendMax      = 0x80000033, // TODO
            BadPageLimitReached     = 0x80000034, // TODO
            SrarDetail              = 0x80000035, // WHEA_SRAR_DETAIL_EVENT
            EarlyError              = 0x80000036, // TODO
            PcieOverrideInfo        = 0x80000037, // WHEAP_PCIE_OVERRIDE_INFO
            ReadPcieOverridesErr    = 0x80000038, // WHEAP_PCIE_READ_OVERRIDES_ERR
            PcieConfigInfo          = 0x80000039, // WHEAP_PCIE_CONFIG_INFO
            PcieSummaryFailed       = 0x80000040, // TODO
            ThrottleRegCorrupt      = 0x80000041, // WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT
            ThrottleAddErrSrcFailed = 0x80000042, // WHEA_THROTTLE_ADD_ERR_SRC_FAILED_EVENT (no payload)
            ThrottleRegDataIgnored  = 0x80000043, // WHEA_THROTTLE_REG_DATA_IGNORED_EVENT
            EnableKeyNotifFailed    = 0x80000044, // WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_FAILED_EVENT
            KeyNotificationFailed   = 0x80000045, // WHEA_REGISTER_KEY_NOTIFICATION_FAILED_EVENT (no payload)
            PcieRemoveDevice        = 0x80000046, // WHEA_THROTTLE_PCIE_REMOVE_EVENT
            PcieAddDevice           = 0x80000047, // WHEA_THROTTLE_PCIE_ADD_EVENT
            PcieSpuriousErrSource   = 0x80000048, // WHEAP_SPURIOUS_AER_EVENT
            MemoryAddDevice         = 0x80000049, // WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT
            MemoryRemoveDevice      = 0x8000004a, // WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT
            MemorySummaryFailed     = 0x8000004b, // WHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT
            PcieDpcError            = 0x8000004c, // WHEAP_DPC_ERROR_EVENT
            CpuBusesInitFailed      = 0x8000004d, // WHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT
            PshedPluginInitFailed   = 0x8000004e, // WHEA_PSHED_PLUGIN_INIT_FAILED_EVENT
            FailedAddToDefectList   = 0x8000004f, // WHEA_FAILED_ADD_DEFECT_LIST_EVENT (no payload)
            DefectListFull          = 0x80000050, // WHEAP_PLUGIN_DEFECT_LIST_FULL_EVENT (no payload)
            DefectListUEFIVarFailed = 0x80000051, // WHEAP_PLUGIN_DEFECT_LIST_UEFI_VAR_FAILED (no payload)
            DefectListCorrupt       = 0x80000052, // WHEAP_PLUGIN_DEFECT_LIST_CORRUPT (no payload)
            BadHestNotifyData       = 0x80000053, // WHEAP_BAD_HEST_NOTIFY_DATA_EVENT
            SrasTableNotFound       = 0x80000054, // WHEA_SRAS_TABLE_NOT_FOUND (no payload)
            SrasTableError          = 0x80000055, // WHEA_SRAS_TABLE_ERROR (no payload)
            SrasTableEntries        = 0x80000056, // WHEA_SRAS_TABLE_ENTRIES_EVENT
            RowFailure              = 0x80000057, // WHEAP_ROW_FAILURE_EVENT
            CpusFrozen              = 0x80000060, // No payload
            CpusFrozenNoCrashDump   = 0x80000061, // TODO
            PshedPiTraceLog         = 0x80040010  // WHEA_PSHED_PI_TRACE_EVENT
        }

        public enum WHEA_EVENT_LOG_ENTRY_TYPE : uint {
            Informational = 0,
            Warning       = 1,
            Error         = 2
        }

        public enum WHEA_PFA_REMOVE_TRIGGER : uint {
            ErrorThreshold = 1,
            Timeout        = 2,
            Capacity       = 3
        }

        public enum WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_ERRORS : uint {
            CreateNotifyEvent  = 1,
            CreateSystemThread = 2
        }

        public enum WHEA_THROTTLE_TYPE : uint {
            Pcie   = 0,
            Memory = 1
        }

        public enum WHEAP_DPC_ERROR_EVENT_TYPE : uint {
            NoErr        = 0,
            BusNotFound  = 1,
            DpcedSubtree = 2,
            DeviceIdBad  = 3,
            ResetFailed  = 4,
            NoChildren   = 5
        }

        public enum WHEAP_PFA_OFFLINE_DECISION_TYPE : uint {
            PredictiveFailure = 1,
            UncorrectedError  = 2
        }

        // @formatter:int_align_fields false

        #endregion

        #region WHEA Event Log Entry: Flags

        // @formatter:int_align_fields true

        [Flags]
        public enum WHEA_EVENT_LOG_ENTRY_FLAGS : uint {
            Reserved       = 0x1,
            LogInternalEtw = 0x2,
            LogBlackbox    = 0x4,
            LogSel         = 0x8,
            RawSel         = 0x10,
            NoFormat       = 0x20,
            Driver         = 0x40
        }

        // @formatter:int_align_fields false

        #endregion

        #region WHEA Event Log Entry: Structures

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_EVENT_LOG_ENTRY_HEADER : WheaRecord {
            private uint _Signature;

            [JsonProperty(Order = 1)]
            public string Signature {
                get {
                    var bytes = BitConverter.GetBytes(_Signature);
                    return Encoding.ASCII.GetString(bytes);
                }
            }

            [JsonProperty(Order = 2)]
            public uint Version;

            // TODO: Description
            [JsonProperty(Order = 3)]
            public uint Length; // TODO: Validate against Type and PayloadLength

            private WHEA_EVENT_LOG_ENTRY_TYPE _Type;

            [JsonProperty(Order = 4)]
            public string Type => Enum.GetName(typeof(WHEA_EVENT_LOG_ENTRY_TYPE), _Type);

            [JsonProperty(Order = 5)]
            public uint OwnerTag;

            private WHEA_EVENT_LOG_ENTRY_ID _Id;

            [JsonProperty(Order = 6)]
            public string Id => Enum.GetName(typeof(WHEA_EVENT_LOG_ENTRY_ID), _Id);

            private WHEA_EVENT_LOG_ENTRY_FLAGS _Flags;

            [JsonProperty(Order = 7)]
            public string Flags => GetEnabledFlagsAsString(_Flags);

            // TODO: Description
            [JsonProperty(Order = 8)]
            public uint PayloadLength; // TODO: Validate against Type and PayloadLength

            public override void Validate() {
                if (Signature != WHEA_ERROR_LOG_ENTRY_SIGNATURE) {
                    var msg =
                        $"[{nameof(WHEA_EVENT_LOG_ENTRY_HEADER)}] Expected signature \"{WHEA_ERROR_LOG_ENTRY_SIGNATURE}\" but Signature member is: {Signature}";
                    ExitWithMessage(msg, 2);
                }

                if (Version != WHEA_ERROR_LOG_ENTRY_VERSION) {
                    var msg = $"[{nameof(WHEA_EVENT_LOG_ENTRY_HEADER)}] Expected version {WHEA_ERROR_LOG_ENTRY_VERSION} but Version member is: {Version}";
                    ExitWithMessage(msg, 2);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_AZCC_ROOT_BUS_ERR_EVENT : WheaRecord {
            [MarshalAs(UnmanagedType.U1)]
            public bool MaxBusCountPassed;

            [MarshalAs(UnmanagedType.U1)]
            public bool InvalidBusMSR;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_AZCC_ROOT_BUS_LIST_EVENT : WheaRecord {
            public uint RootBusCount;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public uint[] RootBuses;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_AZCC_SET_POISON_EVENT : WheaRecord {
            public uint Bus;

            [MarshalAs(UnmanagedType.U1)]
            public bool ReadSuccess;

            [MarshalAs(UnmanagedType.U1)]
            public bool WriteSuccess;

            [MarshalAs(UnmanagedType.U1)]
            public bool IsEnable;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_ETW_OVERFLOW_EVENT : WheaRecord {
            public ulong RecordId;
        }

        // Deliberately empty (no payload)
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_FAILED_ADD_DEFECT_LIST_EVENT : WheaRecord { }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_MEMORY_THROTTLE_SUMMARY_FAILED_EVENT : WheaRecord {
            public uint Status; // TODO: NTSTATUS
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_OFFLINE_DONE_EVENT : WheaRecord {
            public ulong Address;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PSHED_PI_CPU_BUSES_INIT_FAILED_EVENT : WheaRecord {
            public uint Status; // TODO: NTSTATUS
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public sealed class WHEA_PSHED_PI_TRACE_EVENT : WheaRecord {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string Buffer;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PSHED_PLUGIN_DIMM_MISMATCH : WheaRecord {
            public ushort FirmwareBank;
            public ushort FirmwareCol;
            public ushort FirmwareRow;
            public ushort RetryRdBank;
            public ushort RetryRdCol;
            public ushort RetryRdRow;
            public ushort TaBank;
            public ushort TaCol;
            public ushort TaRow;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_FAILED_EVENT : WheaRecord {
            private WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_ERRORS _EnableError;

            [JsonProperty(Order = 1)]
            public string EnableError => Enum.GetName(typeof(WHEA_PSHED_PLUGIN_ENABLE_NOTIFY_ERRORS), _EnableError);
        }

        // Deliberately empty (no payload)
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PSHED_PLUGIN_HEARTBEAT : WheaRecord { }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_PSHED_PLUGIN_INIT_FAILED_EVENT : WheaRecord {
            public uint Status; // TODO: NTSTATUS
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
        public sealed class WHEA_PSHED_PLUGIN_LOAD_EVENT : WheaRecord {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WHEA_ERROR_TEXT_LEN)]
            public string PluginName;

            public uint MajorVersion;
            public uint MinorVersion;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
        public sealed class WHEA_PSHED_PLUGIN_PLATFORM_SUPPORT_EVENT : WheaRecord {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WHEA_ERROR_TEXT_LEN)]
            public string PluginName;

            [MarshalAs(UnmanagedType.U1)]
            public bool Supported;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
        public sealed class WHEA_PSHED_PLUGIN_UNLOAD_EVENT : WheaRecord {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WHEA_ERROR_TEXT_LEN)]
            public string PluginName;
        }

        // Deliberately empty (no payload)
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_REGISTER_KEY_NOTIFICATION_FAILED_EVENT : WheaRecord { }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_SEL_BUGCHECK_PROGRESS : WheaRecord {
            public uint BugCheckCode;
            public uint BugCheckProgressSummary;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_SRAR_DETAIL_EVENT : WheaRecord {
            public uint RecoveryContextFlags;
            public ulong RecoveryContextPa;
            public uint PageOfflineStatus; // TODO: NTSTATUS

            [MarshalAs(UnmanagedType.U1)]
            public bool KernelConsumerError;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_SRAS_TABLE_ENTRIES_EVENT : WheaRecord {
            public uint LogNumber;
            public uint NumberSignals;

            /*
             * TODO
             * Variable length arrays need a custom marshaller.
             */
            //public byte[] Data;
        }

        // Deliberately empty (no payload)
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_SRAS_TABLE_ERROR : WheaRecord { }

        // Deliberately empty (no payload)
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_SRAS_TABLE_NOT_FOUND : WheaRecord { }

        // Deliberately empty (no payload)
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_THROTTLE_ADD_ERR_SRC_FAILED_EVENT : WheaRecord { }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_THROTTLE_MEMORY_ADD_OR_REMOVE_EVENT : WheaRecord {
            public uint SocketId;
            public uint ChannelId;
            public uint DimmSlot;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_THROTTLE_PCIE_ADD_EVENT : WheaRecord {
            public WHEA_PCIE_ADDRESS Address;
            public uint Mask;

            [MarshalAs(UnmanagedType.U1)]
            public bool Updated;

            public uint Status; // TODO: NTSTATUS
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_THROTTLE_PCIE_REMOVE_EVENT : WheaRecord {
            public WHEA_PCIE_ADDRESS Address;
            public uint Mask;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_THROTTLE_REG_DATA_IGNORED_EVENT : WheaRecord {
            private WHEA_THROTTLE_TYPE _ThrottleType;

            [JsonProperty(Order = 1)]
            public string ThrottleType => Enum.GetName(typeof(WHEA_THROTTLE_TYPE), _ThrottleType);
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_THROTTLE_REGISTRY_CORRUPT_EVENT : WheaRecord {
            private WHEA_THROTTLE_TYPE _ThrottleType;

            [JsonProperty(Order = 1)]
            public string ThrottleType => Enum.GetName(typeof(WHEA_THROTTLE_TYPE), _ThrottleType);
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public sealed class WHEAP_ACPI_TIMEOUT_EVENT : WheaRecord {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WHEA_ERROR_TEXT_LEN)]
            public string TableType;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WHEA_ERROR_TEXT_LEN)]
            public string TableRequest;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT : WheaRecord {
            public WHEA_ERROR_SOURCE_DESCRIPTOR Descriptor;
            public uint Status; // TODO: NTSTATUS

            [MarshalAs(UnmanagedType.U1)]
            public bool IsRemove;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_ATTEMPT_RECOVERY_EVENT : WheaRecord {
            public WHEA_ERROR_RECORD_HEADER ErrorHeader;

            [MarshalAs(UnmanagedType.U1)]
            public bool ArchitecturalRecovery;

            [MarshalAs(UnmanagedType.U1)]
            public bool PshedRecovery;

            public uint Status; // TODO: NTSTATUS
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_BAD_HEST_NOTIFY_DATA_EVENT : WheaRecord {
            public ushort SourceId;
            public ushort Reserved;
            public WHEA_NOTIFICATION_DESCRIPTOR NotifyDesc;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_CLEARED_POISON_EVENT : WheaRecord {
            public ulong PhysicalAddress;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_CMCI_IMPLEMENTED_EVENT : WheaRecord {
            [MarshalAs(UnmanagedType.U1)]
            public bool CmciAvailable;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_CMCI_INITERR_EVENT : WheaRecord {
            public ulong Msr;
            public uint Type;
            public uint Bank;
            public uint EpIndex;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_CMCI_RESTART_EVENT : WheaRecord {
            public uint CmciRestoreAttempts;
            public uint MaxCmciRestoreLimit;
            public uint MaxCorrectedErrorsFound;
            public uint MaxCorrectedErrorLimit;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public sealed class WHEAP_CREATE_GENERIC_RECORD_EVENT : WheaRecord {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WHEA_ERROR_TEXT_LEN)]
            public string Error;

            public uint EntryCount;
            public uint Status; // TODO: NTSTATUS
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public sealed class WHEAP_DEVICE_DRV_EVENT : WheaRecord {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WHEA_ERROR_TEXT_LEN)]
            public string Function;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_DPC_ERROR_EVENT : WheaRecord {
            private WHEAP_DPC_ERROR_EVENT_TYPE _ErrType;

            [JsonProperty(Order = 1)]
            public string ErrType => Enum.GetName(typeof(WHEAP_DPC_ERROR_EVENT_TYPE), _ErrType);

            [JsonProperty(Order = 2)]
            public uint Bus;

            [JsonProperty(Order = 3)]
            public uint Device;

            [JsonProperty(Order = 4)]
            public uint Function;

            [JsonProperty(Order = 5)]
            public ushort DeviceId;

            [JsonProperty(Order = 6)]
            public ushort VendorId;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_DROPPED_CORRECTED_ERROR_EVENT : WheaRecord {
            private WHEA_ERROR_SOURCE_TYPE _ErrorSourceType;

            [JsonProperty(Order = 1)]
            public string ErrorSourceType => Enum.GetName(typeof(WHEA_ERROR_SOURCE_TYPE), _ErrorSourceType);

            [JsonProperty(Order = 2)]
            public uint ErrorSourceId;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_EDPC_ENABLED_EVENT : WheaRecord {
            [MarshalAs(UnmanagedType.U1)]
            public bool eDPCEnabled;

            [MarshalAs(UnmanagedType.U1)]
            public bool eDPCRecovEnabled;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_ERR_SRC_ARRAY_INVALID_EVENT : WheaRecord {
            public uint ErrorSourceCount;
            public uint ReportedLength;
            public uint ExpectedLength;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public sealed class WHEAP_ERR_SRC_INVALID_EVENT : WheaRecord {
            public WHEA_ERROR_SOURCE_DESCRIPTOR ErrDescriptor;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WHEA_ERROR_TEXT_LEN)]
            public string Error;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_ERROR_CLEARED_EVENT : WheaRecord {
            public uint EpIndex;
            public uint Bank;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_ERROR_RECORD_EVENT : WheaRecord {
            /*
             * TODO
             * How is this a pointer to an error record in the context of a
             * hex-encoded serialized record? Need a sample record to inspect.
             */
            //PWHEA_ERROR_RECORD Record;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_FOUND_ERROR_IN_BANK_EVENT : WheaRecord {
            public uint EpIndex;
            public uint Bank;
            public ulong MciStatus;
            public uint ErrorType;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public sealed class WHEAP_GENERIC_ERR_MEM_MAP_EVENT : WheaRecord {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WHEA_ERROR_TEXT_LEN)]
            public string MapReason;

            public ulong PhysicalAddress;
            public ulong Length;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_OSC_IMPLEMENTED : WheaRecord {
            [MarshalAs(UnmanagedType.U1)]
            public bool OscImplemented;

            [MarshalAs(UnmanagedType.U1)]
            public bool DebugChecked;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_PCIE_CONFIG_INFO : WheaRecord {
            public uint Segment;
            public uint Bus;
            public uint Device;
            public uint Function;
            public uint Offset;
            public uint Length;
            public ulong Value;
            public byte Succeeded;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public byte[] Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_PCIE_OVERRIDE_INFO : WheaRecord {
            public uint Segment;
            public uint Bus;
            public uint Device;
            public uint Function;
            public byte ValidBits; // TODO

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public byte[] Reserved;

            public uint UncorrectableErrorMask;
            public uint UncorrectableErrorSeverity;
            public uint CorrectableErrorMask;
            public uint CapAndControl;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_PCIE_READ_OVERRIDES_ERR : WheaRecord {
            private PSHED_PI_ERR_READING_PCIE_OVERRIDES _FailureReason;

            [JsonProperty(Order = 1)]
            public string FailureReason => Enum.GetName(typeof(PSHED_PI_ERR_READING_PCIE_OVERRIDES), _FailureReason);

            [JsonProperty(Order = 2)]
            public uint FailureStatus; // TODO: NTSTATUS
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_PFA_MEMORY_OFFLINED : WheaRecord {
            private WHEAP_PFA_OFFLINE_DECISION_TYPE _DecisionType;

            [JsonProperty(Order = 1)]
            public string DecisionType => Enum.GetName(typeof(WHEAP_PFA_OFFLINE_DECISION_TYPE), _DecisionType);

            [JsonProperty(Order = 2)]
            [MarshalAs(UnmanagedType.U1)]
            public bool ImmediateSuccess;

            [JsonProperty(Order = 3)]
            public uint Page;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_PFA_MEMORY_POLICY : WheaRecord {
            public uint RegistryKeysPresent;

            [MarshalAs(UnmanagedType.U1)]
            public bool DisableOffline;

            [MarshalAs(UnmanagedType.U1)]
            public bool PersistOffline;

            [MarshalAs(UnmanagedType.U1)]
            public bool PfaDisabled;

            public uint PageCount;
            public uint ErrorThreshold;
            public uint TimeOut;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_PFA_MEMORY_REMOVE_MONITOR : WheaRecord {
            private WHEA_PFA_REMOVE_TRIGGER _RemoveTrigger;

            [JsonProperty(Order = 1)]
            public string RemoveTrigger => Enum.GetName(typeof(WHEA_PFA_REMOVE_TRIGGER), _RemoveTrigger);

            [JsonProperty(Order = 2)]
            public uint TimeInList;

            [JsonProperty(Order = 3)]
            public uint ErrorCount;

            [JsonProperty(Order = 4)]
            public uint Page;
        }

        // Deliberately empty (no payload)
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_PLUGIN_DEFECT_LIST_CORRUPT : WheaRecord { }

        // Deliberately empty (no payload)
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_PLUGIN_DEFECT_LIST_FULL_EVENT : WheaRecord { }

        // Deliberately empty (no payload)
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_PLUGIN_DEFECT_LIST_UEFI_VAR_FAILED : WheaRecord { }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public sealed class WHEAP_PROCESS_EINJ_EVENT : WheaRecord {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WHEA_ERROR_TEXT_LEN)]
            public string Error;

            [MarshalAs(UnmanagedType.U1)]
            public bool InjectionActionTableValid;

            public uint BeginInjectionInstructionCount;
            public uint GetTriggerErrorActionTableInstructionCount;
            public uint SetErrorTypeInstructionCount;
            public uint GetErrorTypeInstructionCount;
            public uint EndOperationInstructionCount;
            public uint ExecuteOperationInstructionCount;
            public uint CheckBusyStatusInstructionCount;
            public uint GetCommandStatusInstructionCount;
            public uint SetErrorTypeWithAddressInstructionCount;
            public uint GetExecuteOperationTimingsInstructionCount;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        public sealed class WHEAP_PROCESS_HEST_EVENT : WheaRecord {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WHEA_ERROR_TEXT_LEN)]
            public string Error;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WHEA_ERROR_TEXT_LEN)]
            public string EntryType;

            public uint EntryIndex;

            [MarshalAs(UnmanagedType.U1)]
            public bool HestValid;

            public uint CmcCount;
            public uint MceCount;
            public uint NmiCount;
            public uint AerRootCount;
            public uint AerBridgeCount;
            public uint AerEndPointCount;
            public uint GenericV1Count;
            public uint GenericV2Count;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_PSHED_INJECT_ERROR : WheaRecord {
            public uint ErrorType;
            public ulong Parameter1;
            public ulong Parameter2;
            public ulong Parameter3;
            public ulong Parameter4;
            public uint InjectionStatus; // TODO: NTSTATUS

            [MarshalAs(UnmanagedType.U1)]
            public bool InjectionAttempted;

            [MarshalAs(UnmanagedType.U1)]
            public bool InjectionByPlugin;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_PSHED_PLUGIN_REGISTER : WheaRecord {
            public uint Version; // TODO: Validate

            // TODO: Description
            public uint Length; // TODO: Validate

            public uint FunctionalAreaMask;
            public uint Status; // TODO: NTSTATUS
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_ROW_FAILURE_EVENT : WheaRecord {
            public uint LowOrderPage;  // TODO: PFN_NUMBER
            public uint HighOrderPage; // TODO: PFN_NUMBER
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_SPURIOUS_AER_EVENT : WheaRecord {
            private WHEA_ERROR_SEVERITY _ErrorSeverity;

            [JsonProperty(Order = 1)]
            public string ErrorSeverity => Enum.GetName(typeof(WHEA_ERROR_SEVERITY), _ErrorSeverity);

            private WHEA_PCIEXPRESS_DEVICE_TYPE _ErrorHandlerType;

            [JsonProperty(Order = 2)]
            public string ErrorHandlerType => Enum.GetName(typeof(WHEA_PCIEXPRESS_DEVICE_TYPE), _ErrorHandlerType);

            [JsonProperty(Order = 3)]
            public uint SpuriousErrorSourceId;

            [JsonProperty(Order = 4)]
            public uint RootErrorCommand;

            [JsonProperty(Order = 5)]
            public uint RootErrorStatus;

            [JsonProperty(Order = 6)]
            public uint DeviceAssociationBitmap;

            public override void Validate() {
                if (_ErrorHandlerType != WHEA_PCIEXPRESS_DEVICE_TYPE.RootPort
                    && _ErrorHandlerType != WHEA_PCIEXPRESS_DEVICE_TYPE.DownstreamSwitchPort
                    && _ErrorHandlerType != WHEA_PCIEXPRESS_DEVICE_TYPE.RootComplexEventCollector) {
                    var msg = $"[{nameof(WHEAP_SPURIOUS_AER_EVENT)}] ErrorHandlerType is invalid: {ErrorHandlerType}";
                    ExitWithMessage(msg, 2);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_STARTED_REPORT_HW_ERROR : WheaRecord {
            /*
             * TODO
             * How is this a pointer to an error packet in the context of a
             * hex-encoded serialized record? Need a sample record to inspect.
             */
            //PWHEA_ERROR_PACKET ErrorPacket;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEAP_STUCK_ERROR_EVENT : WheaRecord {
            public uint EpIndex;
            public uint Bank;
            public ulong MciStatus;
        }

        #endregion

        #region WHEA Notification Descriptor: Enumerations

        // @formatter:int_align_fields true

        // From preprocessor definitions (WHEA_NOTIFICATION_TYPE_*)
        public enum WHEA_NOTIFICATION_TYPE : byte {
            Polled                = 0,
            ExternalInterrupt     = 1,
            LocalInterrupt        = 2,
            Sci                   = 3,
            Nmi                   = 4,
            Cmci                  = 5,
            Mce                   = 6,
            GpioSignal            = 7,
            Armv8Sea              = 8,
            Armv8Sei              = 9,
            ExternalInterruptGsiv = 10,
            Sdei                  = 11
        }

        // @formatter:int_align_fields false

        #endregion

        #region WHEA Notification Descriptor: Flags

        // @formatter:int_align_fields true

        [Flags]
        public enum WHEA_NOTIFICATION_FLAGS : ushort {
            PollIntervalRW             = 0x1,
            SwitchToPollingThresholdRW = 0x2,
            SwitchToPollingWindowRW    = 0x4,
            ErrorThresholdRW           = 0x8,
            ErrorThresholdWindowRW     = 0x10
        }

        // @formatter:int_align_fields false

        #endregion

        #region WHEA Notification Descriptor: Structures

        /*
         * This structure has been simplified from the original, which contains
         * multiple in-line structs which are members of a union, with all but
         * one of those structs having the same members.
         */
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public sealed class WHEA_NOTIFICATION_DESCRIPTOR : WheaRecord {
            private WHEA_NOTIFICATION_TYPE _Type;

            [JsonProperty(Order = 1)]
            public string Type => Enum.GetName(typeof(WHEA_NOTIFICATION_TYPE), _Type);

            [JsonProperty(Order = 2)]
            public byte Length;

            private WHEA_NOTIFICATION_FLAGS _Flags;

            [JsonProperty(Order = 3)]
            public string Flags => GetEnabledFlagsAsString(_Flags);

            [JsonProperty(Order = 4)]
            public uint PollInterval;

            [JsonProperty(Order = 5)]
            public uint Vector;

            [JsonProperty(Order = 6)]
            public uint SwitchToPollingThreshold;

            [JsonProperty(Order = 7)]
            public uint SwitchToPollingWindow;

            [JsonProperty(Order = 8)]
            public uint ErrorThreshold;

            [JsonProperty(Order = 9)]
            public uint ErrorThresholdWindow;

            private bool IsPolled() {
                return _Type == WHEA_NOTIFICATION_TYPE.Polled;
            }

            public bool ShouldSerializeVector() {
                return !IsPolled();
            }

            public bool ShouldSerializeSwitchToPollingThreshold() {
                return !IsPolled();
            }

            public bool ShouldSerializeSwitchToPollingWindow() {
                return !IsPolled();
            }

            public bool ShouldSerializeErrorThreshold() {
                return !IsPolled();
            }

            public bool ShouldSerializeErrorThresholdWindow() {
                return !IsPolled();
            }

            public override void Validate() {
                var expectedLength = Marshal.SizeOf(typeof(WHEA_NOTIFICATION_DESCRIPTOR));
                if (Length != expectedLength) {
                    var msg = $"[{nameof(WHEA_NOTIFICATION_DESCRIPTOR)}] Expected length of {expectedLength} bytes but Length member is: {Length}";
                    ExitWithMessage(msg, 2);
                }

                /*
                 * TODO
                 * These notification types are not mapped to any structure as
                 * of the Windows 11 22H2 SDK. For now we'll assume they map to
                 * an Interrupt structure.
                 */
                if (_Type == WHEA_NOTIFICATION_TYPE.Cmci
                    || _Type == WHEA_NOTIFICATION_TYPE.Mce
                    || _Type == WHEA_NOTIFICATION_TYPE.GpioSignal
                    || _Type == WHEA_NOTIFICATION_TYPE.Sdei)
                    Console.Error.WriteLine(
                        $"[{nameof(WHEA_NOTIFICATION_DESCRIPTOR)}] Type \"{Type}\" is not explicitly mapped to a structure; defaulting to Interrupt.");
            }
        }

        #endregion
    }
}
