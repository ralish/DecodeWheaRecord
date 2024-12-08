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
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

using DecodeWheaRecord.Errors;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord {
    internal static class NativeMethods {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal abstract class WheaRecord {
            internal virtual int GetNativeSize() {
                throw new NotImplementedException();
            }

            public virtual void Validate() { }
        }

        #region GUIDs

        /*
         * Creator IDs
         */

        // Microsoft extensions
        public static readonly Guid WHEA_RECORD_CREATOR_GUID = Guid.Parse("cf07c4bd-b789-4e18-b3c4-1f732cb57131");
        public static readonly Guid DEFAULT_DEVICE_DRIVER_CREATOR_GUID = Guid.Parse("57217c8d-5e66-44fb-8033-9b74cacedf5b");

        public static readonly Dictionary<Guid, string> CreatorIds = new Dictionary<Guid, string> {
            // Microsoft extensions
            { WHEA_RECORD_CREATOR_GUID, "Microsoft" },
            { DEFAULT_DEVICE_DRIVER_CREATOR_GUID, "Device Driver (default)" }
        };


        /*
         * Notification types
         */

        // Standard notifications
        public static readonly Guid BOOT_NOTIFY_TYPE_GUID = Guid.Parse("3d61a466-ab40-409a-a698-f362d464b38f");
        public static readonly Guid CMC_NOTIFY_TYPE_GUID = Guid.Parse("2dce8bb1-bdd7-450e-b9ad-9cf4ebd4f890");
        public static readonly Guid CPE_NOTIFY_TYPE_GUID = Guid.Parse("4e292f96-d843-4a55-a8c2-d481f27ebeee");
        public static readonly Guid INIT_NOTIFY_TYPE_GUID = Guid.Parse("cc5263e8-9308-454a-89d0-340bd39bc98e");
        public static readonly Guid MCE_NOTIFY_TYPE_GUID = Guid.Parse("e8f56ffe-919c-4cc5-ba88-65abe14913bb");
        public static readonly Guid NMI_NOTIFY_TYPE_GUID = Guid.Parse("5bad89ff-b7e6-42c9-814a-cf2485d6e98a");
        public static readonly Guid PCIe_NOTIFY_TYPE_GUID = Guid.Parse("cf93c01f-1a16-4dfc-b8bc-9c4daf67c104");
        public static readonly Guid PEI_NOTIFY_TYPE_GUID = Guid.Parse("09a9d5ac-5204-4214-96e5-94992e752bcd");
        public static readonly Guid SEA_NOTIFY_TYPE_GUID = Guid.Parse("9a78788a-bbe8-11e4-809e-67611e5d46b0");
        public static readonly Guid SEI_NOTIFY_TYPE_GUID = Guid.Parse("5c284c81-b0ae-4e87-a322-b04c85624323");

        // Microsoft notifications
        public static readonly Guid BMC_NOTIFY_TYPE_GUID = Guid.Parse("487565ba-6494-4367-95ca-4eff893522f6");
        public static readonly Guid CMCI_NOTIFY_TYPE_GUID = Guid.Parse("919448b2-3739-4b7f-a8f1-e0062805c2a3");
        public static readonly Guid DEVICE_DRIVER_NOTIFY_TYPE_GUID = Guid.Parse("0033f803-2e70-4e88-992c-6f26daf3db7a");
        public static readonly Guid EXTINT_NOTIFY_TYPE_GUID = Guid.Parse("fe84086e-b557-43cf-ac1b-17982e078470");
        public static readonly Guid GENERIC_NOTIFY_TYPE_GUID = Guid.Parse("3e62a467-ab40-409a-a698-f362d464b38f");
        public static readonly Guid SCI_NOTIFY_TYPE_GUID = Guid.Parse("e9d59197-94ee-4a4f-8ad8-9b7d8bd93d2e");

        public static readonly Dictionary<Guid, string> NotifyTypes = new Dictionary<Guid, string> {
            // Standard notifications
            { BOOT_NOTIFY_TYPE_GUID, "Boot Error Record (BOOT)" },
            { CMC_NOTIFY_TYPE_GUID, "Corrected Machine Check (CMC)" },
            { CPE_NOTIFY_TYPE_GUID, "Corrected Platform Error (CPE)" },
            { INIT_NOTIFY_TYPE_GUID, "Init Error Record (INIT)" },
            { MCE_NOTIFY_TYPE_GUID, "Machine Check Exception (MCE)" },
            { NMI_NOTIFY_TYPE_GUID, "Non-Maskable Interrupt (NMI)" },
            { PCIe_NOTIFY_TYPE_GUID, "PCI Express Error (PCIe)" },
            { PEI_NOTIFY_TYPE_GUID, "Platform Error Interrupt (PEI)" },
            { SEA_NOTIFY_TYPE_GUID, "Synchronous External Abort (SEA)" },
            { SEI_NOTIFY_TYPE_GUID, "SError Interrupt (SEI)" },

            // Standard notifications not in headers
            { Guid.Parse("69293bc9-41df-49a3-b4bd-4fb0db3041f6"), "Compute Express Link (CXL)" },
            { Guid.Parse("667dd791-c6b3-4c27-8a6b-0f8e722deb41"), "DMA Remapping Error (DMAr)" },

            // Microsoft notifications
            { BMC_NOTIFY_TYPE_GUID, "Baseboard Management Controller (BMC)" },
            { CMCI_NOTIFY_TYPE_GUID, "Corrected Machine Check Interrupt (CMCI)" },
            { DEVICE_DRIVER_NOTIFY_TYPE_GUID, "Device Driver" },
            { EXTINT_NOTIFY_TYPE_GUID, "External Interrupt" },
            { GENERIC_NOTIFY_TYPE_GUID, "Generic Error Record" },
            { SCI_NOTIFY_TYPE_GUID, "Service Control Interrupt (SCI)" }
        };


        /*
         * Section types
         */

        // Standard sections
        public static readonly Guid ARM_PROCESSOR_ERROR_SECTION_GUID = Guid.Parse("e19e3d16-bc11-11e4-9caa-c2051d5d46b0");
        public static readonly Guid FIRMWARE_ERROR_RECORD_REFERENCE_GUID = Guid.Parse("81212a96-09ed-4996-9471-8d729c8e69ed");
        public static readonly Guid IPF_PROCESSOR_ERROR_SECTION_GUID = Guid.Parse("e429faf1-3cb7-11d4-bca7-0080c73c8881");
        public static readonly Guid MEMORY_ERROR_SECTION_GUID = Guid.Parse("a5bc1114-6f64-4ede-b863-3e83ed7c83b1");
        public static readonly Guid PCIEXPRESS_ERROR_SECTION_GUID = Guid.Parse("d995e954-bbc1-430f-ad91-b44dcb3c6f35");
        public static readonly Guid PCIXBUS_ERROR_SECTION_GUID = Guid.Parse("c5753963-3b84-4095-bf78-eddad3f9c9dd");
        public static readonly Guid PCIXDEVICE_ERROR_SECTION_GUID = Guid.Parse("eb5e4685-ca66-4769-b6a2-26068b001326");
        public static readonly Guid PROCESSOR_GENERIC_ERROR_SECTION_GUID = Guid.Parse("9876ccad-47b4-4bdb-b65e-16f193c4f3db");
        public static readonly Guid XPF_PROCESSOR_ERROR_SECTION_GUID = Guid.Parse("dc3ea0b0-a144-4797-b95b-53fa242b6e1d");

        // Microsoft sections
        public static readonly Guid GENERIC_SECTION_GUID = Guid.Parse("e71254e8-c1b9-4940-ab76-909703a4320f");
        public static readonly Guid IPF_SAL_RECORD_SECTION_GUID = Guid.Parse("6f3380d1-6eb0-497f-a578-4d4c65a71617");
        public static readonly Guid IPMI_MSR_DUMP_SECTION_GUID = Guid.Parse("1c15b445-9b06-4667-ac25-33c056b88803");
        public static readonly Guid MEMORY_CORRECTABLE_ERROR_SUMMARY_SECTION_GUID = Guid.Parse("0e36c93e-ca15-4a83-ba8a-cbe80f7f0017");
        public static readonly Guid MU_TELEMETRY_SECTION_GUID = Guid.Parse("85183a8b-9c41-429c-939c-5c3c087ca280");
        public static readonly Guid NMI_SECTION_GUID = Guid.Parse("e71254e7-c1b9-4940-ab76-909703a4320f");
        public static readonly Guid PCIE_CORRECTABLE_ERROR_SUMMARY_SECTION_GUID = Guid.Parse("e96eca99-53e2-4f52-9be7-d2dbe9508ed0");
        public static readonly Guid PMEM_ERROR_SECTION_GUID = Guid.Parse("81687003-dbfd-4728-9ffd-f0904f97597d");
        public static readonly Guid RECOVERY_INFO_SECTION_GUID = Guid.Parse("c34832a1-02c3-4c52-a9f1-9f1d5d7723fc");
        public static readonly Guid WHEA_DPC_CAPABILITY_SECTION_GUID = Guid.Parse("ec49534b-30e7-4358-972f-eca6958fae3b");
        public static readonly Guid WHEA_ERROR_PACKET_SECTION_GUID = Guid.Parse("e71254e9-c1b9-4940-ab76-909703a4320f");
        public static readonly Guid XPF_MCA_SECTION_GUID = Guid.Parse("8a1e1d01-42f9-4557-9c33-565e5cc3f7e8");

        public static readonly Dictionary<Guid, string> SectionTypes = new Dictionary<Guid, string> {
            // Standard sections not in headers
            { Guid.Parse("91335ef6-ebfb-4478-a6a6-88b728cf75d7"), "CCIX PER Log Error" },
            { Guid.Parse("80b9efb4-52b5-4de3-a777-68784b771048"), "CXL Protocol Error" },
            { Guid.Parse("5b51fef7-c79d-4434-8f1b-aa62de3e2c64"), "DMAr Generic Error" },
            { Guid.Parse("5e4706c1-5356-48c6-930b-52f2120a4458"), "FRU Memory Poison" },
            { Guid.Parse("71761d37-32b2-45cd-a7d0-b0fedd93e8cf"), "Intel VT for Directed I/O Specific DMAr Error" },
            { Guid.Parse("036f84e1-7f37-428c-a79e-575fdfaa84ec"), "IOMMU Specific DMAr Error" },

            // Standard sections
            { ARM_PROCESSOR_ERROR_SECTION_GUID, "ARM Processor Error" },
            { FIRMWARE_ERROR_RECORD_REFERENCE_GUID, "Firmware Error Record Reference" },
            { PROCESSOR_GENERIC_ERROR_SECTION_GUID, "Generic Processor Error" },
            { XPF_PROCESSOR_ERROR_SECTION_GUID, "IA32/AMD64 Processor Error" },
            { IPF_PROCESSOR_ERROR_SECTION_GUID, "IA64 Processor Error" },
            { MEMORY_ERROR_SECTION_GUID, "Memory Error" },
            { PCIXDEVICE_ERROR_SECTION_GUID, "PCI Component/Device Error" },
            { PCIEXPRESS_ERROR_SECTION_GUID, "PCI Express Error" },
            { PCIXBUS_ERROR_SECTION_GUID, "PCI/PCI-X Bus Error" },

            // Microsoft sections
            { MEMORY_CORRECTABLE_ERROR_SUMMARY_SECTION_GUID, "Correctable Memory Error" },
            { PCIE_CORRECTABLE_ERROR_SUMMARY_SECTION_GUID, "Correctable PCIe Error" },
            { RECOVERY_INFO_SECTION_GUID, "Error Recovery Information" },
            { WHEA_ERROR_PACKET_SECTION_GUID, "Hardware Error Packet" },
            { XPF_MCA_SECTION_GUID, "IA32/AMD64 Machine Check Error" },
            { IPMI_MSR_DUMP_SECTION_GUID, "MSR Dump" },
            { NMI_SECTION_GUID, "NMI Error" },
            { PMEM_ERROR_SECTION_GUID, "Persistent Mememory Error" },
            { MU_TELEMETRY_SECTION_GUID, "Project Mu Telemetry" },

            // Microsoft sections (unknown)
            { GENERIC_SECTION_GUID, "GENERIC_SECTION_GUID" },
            { IPF_SAL_RECORD_SECTION_GUID, "IPF_SAL_RECORD_SECTION_GUID" },
            { WHEA_DPC_CAPABILITY_SECTION_GUID, "WHEA_DPC_CAPABILITY_SECTION_GUID" }
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
        public enum WHEA_ERROR_STATUS_FLAGS : byte {
            Address    = 0x1,
            Control    = 0x2,
            Data       = 0x4,
            Responder  = 0x8,
            Requester  = 0x10,
            FirstError = 0x20,
            Overflow   = 0x40
        }

        // Originally defined directly in the WHEA_TIMESTAMP structure
        [Flags]
        public enum WHEA_TIMESTAMP_FLAGS : byte {
            Precise = 0x1
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

            // Add five padding bytes to match the original 64-bit structure
#pragma warning disable CS0169 // Field is never used
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
            public byte[] Reserved2;
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

            public override string ToString() {
                return $"{MajorRevision}.{MinorRevision}";
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

            // TODO: Surface flags
            public override string ToString() {
                var dt = new DateTime(Century * 100 + Year, Month, Day, Hours, Minutes, Seconds);
                return dt.ToString(CultureInfo.CurrentCulture);
            }
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

            [UsedImplicitly]
            public bool ShouldSerializeVector() {
                return !IsPolled();
            }

            [UsedImplicitly]
            public bool ShouldSerializeSwitchToPollingThreshold() {
                return !IsPolled();
            }

            [UsedImplicitly]
            public bool ShouldSerializeSwitchToPollingWindow() {
                return !IsPolled();
            }

            [UsedImplicitly]
            public bool ShouldSerializeErrorThreshold() {
                return !IsPolled();
            }

            [UsedImplicitly]
            public bool ShouldSerializeErrorThresholdWindow() {
                return !IsPolled();
            }

            public override void Validate() {
                var expectedLength = Marshal.SizeOf<WHEA_NOTIFICATION_DESCRIPTOR>();
                if (Length != expectedLength) {
                    var msg = $"[{nameof(WHEA_NOTIFICATION_DESCRIPTOR)}] Expected length of {expectedLength} bytes but Length member is: {Length}";
                    ExitWithMessage(msg, code: 2);
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
                    || _Type == WHEA_NOTIFICATION_TYPE.Sdei) {
                    Console.Error.WriteLine(
                        $"[{nameof(WHEA_NOTIFICATION_DESCRIPTOR)}] Type \"{Type}\" is not explicitly mapped to a structure; defaulting to Interrupt.");
                }
            }
        }

        #endregion
    }
}
