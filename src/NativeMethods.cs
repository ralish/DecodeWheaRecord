// @formatter:off
// ReSharper disable InconsistentNaming

#pragma warning disable CS0649  // Field is never assigned to

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;


namespace DecodeWheaRecord {
    internal static class NativeMethods {
        #region Enumerations

        [Flags]
        private enum WHEA_ERROR_RECORD_HEADER_FLAGS : uint {
            Recovered           = 0x1,
            PreviousError       = 0x2,
            Simulated           = 0x4,
            DeviceDriver        = 0x8,
            CriticalEvent       = 0x10,
            PersistPfn          = 0x20,
            SectionsTruncated   = 0x40,
            RecoveryInProgress  = 0x80,
            Throttle            = 0x100
        }

        [Flags]
        private enum WHEA_ERROR_RECORD_HEADER_VALIDBITS : uint {
            PlatformId  = 0x1,
            Timestamp   = 0x2,
            PartitionId = 0x4
        }

        [Flags]
        private enum WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS : uint {
            Primary                 = 0x1,
            ContainmentWarning      = 0x2,
            Reset                   = 0x4,
            ThresholdExceeded       = 0x8,
            ResourceNotAvailable    = 0x10,
            LatentError             = 0x20,
            Propagated              = 0x40,
            Overflow                = 0x80
        }

        [Flags]
        private enum WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS : byte {
            FRUId       = 0x1,
            FRUText     = 0x2,
            Reserved1   = 0x4,
            Reserved2   = 0x8,
            Reserved3   = 0x10,
            Reserved4   = 0x20,
            Reserved5   = 0x40,
            Reserved6   = 0x80
        }

        private enum WHEA_ERROR_SEVERITY {
            WheaErrSevRecoverable   = 0,
            WheaErrSevFatal         = 1,
            WheaErrSevCorrected     = 2,
            WheaErrSevInformational = 3
        }

        // Unofficial
        private enum WHEA_FIRMWARE_ERROR_RECORD_REFERENCE_TYPE : byte {
            IpfSal      = 0,
            SocFwType1  = 1,
            SocFwType2  = 2
        }

        [Flags]
        private enum WHEA_PERSISTENCE_INFO_FLAGS : byte {
            Attribute1  = 0x1,
            Attribute2  = 0x2,
            DoNotLog    = 0x4,
            Unused1     = 0x8,
            Unused2     = 0x10,
            Unused3     = 0x20,
            Unused4     = 0x40,
            Unused5     = 0x80
        }

        [Flags]
        private enum WHEA_TIMESTAMP_FLAGS : byte {
            Precise = 0x1
        }

        #endregion

        #region GUIDs

        internal static readonly Dictionary<Guid, string> CreatorIds = new Dictionary<Guid, string>{
            // Microsoft extensions
            { Guid.Parse("cf07c4bd-b789-4e18-b3c4-1f732cb57131"), "Microsoft" },
            { Guid.Parse("57217c8d-5e66-44fb-8033-9b74cacedf5b"), "Device Driver" }
        };

        internal static readonly Dictionary<Guid, string> NotifyTypes = new Dictionary<Guid, string>{
            // Standard types
            { Guid.Parse("3d61a466-ab40-409a-a698-f362d464b38f"), "Boot Error Record (BOOT)" },
            { Guid.Parse("2dce8bb1-bdd7-450e-b9ad-9cf4ebd4f890"), "Corrected Machine Check (CMC)" }, // DevSkim: ignore DS187371
            { Guid.Parse("4e292f96-d843-4a55-a8c2-d481f27ebeee"), "Corrected Platform Error (CPE)" },
            { Guid.Parse("667dd791-c6b3-4c27-8a6b-0f8e722deb41"), "DMA Remapping Error (DMAr)" },
            { Guid.Parse("cc5263e8-9308-454a-89d0-340bd39bc98e"), "INIT Record (INIT)" },
            { Guid.Parse("e8f56ffe-919c-4cc5-ba88-65abe14913bb"), "Machine Check Exception (MCE)" },
            { Guid.Parse("5bad89ff-b7e6-42c9-814a-cf2485d6e98a"), "Non-Maskable Interrupt (NMI)" },
            { Guid.Parse("cf93c01f-1a16-4dfc-b8bc-9c4daf67c104"), "PCI Express Error (PCIe)" },
            { Guid.Parse("09a9d5ac-5204-4214-96e5-94992e752bcd"), "Platform Error Interrupt (PEI)" },
            { Guid.Parse("9a78788a-bbe8-11e4-809e-67611e5d46b0"), "Synchronous External Abort (SEA)" },
            { Guid.Parse("5c284c81-b0ae-4e87-a322-b04c85624323"), "SError Interrupt (SEI)" },
            { Guid.Parse("487565ba-6494-4367-95ca-4eff893522f6"), "BMC_NOTIFY_TYPE_GUID" }, // VERIFY
            { Guid.Parse("919448b2-3739-4b7f-a8f1-e0062805c2a3"), "CMCI_NOTIFY_TYPE_GUID" }, // VERIFY
            { Guid.Parse("0033f803-2e70-4e88-992c-6f26daf3db7a"), "DEVICE_DRIVER_NOTIFY_TYPE_GUID" }, // VERIFY
            { Guid.Parse("fe84086e-b557-43cf-ac1b-17982e078470"), "EXTINT_NOTIFY_TYPE_GUID" }, // VERIFY
            { Guid.Parse("e9d59197-94ee-4a4f-8ad8-9b7d8bd93d2e"), "SCI_NOTIFY_TYPE_GUID" }, // VERIFY

            // Microsoft extensions
            { Guid.Parse("3e62a467-ab40-409a-a698-f362d464b38f"), "GENERIC_NOTIFY_TYPE_GUID" }
        };

        internal static readonly Dictionary<Guid, string> SectionTypes = new Dictionary<Guid, string>{
            // Standard types
            { Guid.Parse("5b51fef7-c79d-4434-8f1b-aa62de3e2c64"), "DMAr Generic" },
            { Guid.Parse("81212a96-09ed-4996-9471-8d729c8e69ed"), "Firmware Error Record Reference" },
            { Guid.Parse("71761d37-32b2-45cd-a7d0-b0fedd93e8cf"), "Intel VT for Directed I/O specific DMAr section" },
            { Guid.Parse("036f84e1-7f37-428c-a79e-575fdfaa84ec"), "IOMMU specific DMAr section" },
            { Guid.Parse("c5753963-3b84-4095-bf78-eddad3f9c9dd"), "PCI/PCI-X Bus" },
            { Guid.Parse("eb5e4685-ca66-4769-b6a2-26068b001326"), "PCI Component/Device" },
            { Guid.Parse("d995e954-bbc1-430f-ad91-b44dcb3c6f35"), "PCI Express" },
            { Guid.Parse("a5bc1114-6f64-4ede-b863-3e83ed7c83b1"), "Platform Memory" },
            { Guid.Parse("9876ccad-47b4-4bdb-b65e-16f193c4f3db"), "Processor Generic" },
            { Guid.Parse("e19e3d16-bc11-11e4-9caa-c2051d5d46b0"), "Processor Specific: ARM" },
            { Guid.Parse("dc3ea0b0-a144-4797-b95b-53fa242b6e1d"), "Processor Specific: IA32/X64" },
            { Guid.Parse("e429faf1-3cb7-11d4-bca7-0080c73c8881"), "Processor Specific: IPF" },
            { Guid.Parse("85183a8b-9c41-429c-939c-5c3c087ca280"), "MU_TELEMETRY_SECTION_GUID" }, // VERIFY
            { Guid.Parse("81687003-dbfd-4728-9ffd-f0904f97597d"), "PMEM_ERROR_SECTION_GUID" }, // VERIFY

            // Microsoft extensions
            { Guid.Parse("e71254e8-c1b9-4940-ab76-909703a4320f"), "GENERIC_SECTION_GUID" },
            { Guid.Parse("6f3380d1-6eb0-497f-a578-4d4c65a71617"), "IPF_SAL_RECORD_SECTION_GUID" },
            { Guid.Parse("1c15b445-9b06-4667-ac25-33c056b88803"), "IPMI_MSR_DUMP_SECTION_GUID" },
            { Guid.Parse("e71254e7-c1b9-4940-ab76-909703a4320f"), "NMI_SECTION_GUID" },
            { Guid.Parse("ec49534b-30e7-4358-972f-eca6958fae3b"), "WHEA_DPC_CAPABILITY_SECTION_GUID" },
            { Guid.Parse("e71254e9-c1b9-4940-ab76-909703a4320f"), "WHEA_ERROR_PACKET_SECTION_GUID" },
            { Guid.Parse("8a1e1d01-42f9-4557-9c33-565e5cc3f7e8"), "XPF_MCA_SECTION_GUID" }
        };

        #endregion

        #region Structures

        [StructLayout(LayoutKind.Sequential)]
        internal abstract class WheaRecord {
            public virtual void Validate() { }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal class WHEA_ERROR_RECORD : WheaRecord {
            public WHEA_ERROR_RECORD_HEADER                 Header;

            // FIXME: Hard-coded for our sample
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public WHEA_ERROR_RECORD_SECTION_DESCRIPTOR[]   SectionDescriptor;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
        internal class WHEA_ERROR_RECORD_HEADER : WheaRecord {
            // Should always be "CPER"
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            private char[]                              Signature;

            [JsonProperty(Order = 2)]
            public WHEA_REVISION                        Revision;

            // Should always be 0xFFFFFFFF
            [JsonProperty(Order = 3)]
            public uint                                 SignatureEnd;

            [JsonProperty(Order = 4)]
            public ushort                               SectionCount;

            private WHEA_ERROR_SEVERITY                 Severity;
            private WHEA_ERROR_RECORD_HEADER_VALIDBITS  ValidBits;

            [JsonProperty(Order = 7)]
            public uint                                 Length;

            [JsonProperty(Order = 8)]
            public WHEA_TIMESTAMP                       Timestamp;

            [JsonProperty(Order = 9)]
            public Guid                                 PlatformId;

            [JsonProperty(Order = 10)]
            public Guid                                 PartitionId;

            internal Guid                               CreatorId;
            internal Guid                               NotifyType;

            [JsonProperty(Order = 13)]
            public ulong                                RecordId;

            private WHEA_ERROR_RECORD_HEADER_FLAGS      Flags;

            [JsonProperty(Order = 15)]
            public WHEA_PERSISTENCE_INFO                PersistenceInfo;

            [JsonProperty(Order = 16)]
            public uint                                 OsBuildNumber;

            [JsonProperty(Order = 17)]
            public ulong                                Reserved;

            [JsonProperty("Signature", Order = 1)]
            public string SignatureString => new string(Signature);

            [JsonProperty("Severity", Order = 5)]
            public string SeverityName => Enum.GetName(typeof(WHEA_ERROR_SEVERITY), Severity);

            [JsonProperty("ValidBits", Order = 6)]
            public string ValidBitsEnabled => GetEnabledFlagsAsString(ValidBits);

            [JsonProperty("CreatorId", Order = 11)]
            public string CreatorIdString => CreatorIds.ContainsKey(CreatorId) ? CreatorIds[CreatorId] : CreatorId.ToString();

            [JsonProperty("NotifyType", Order = 12)]
            public string NotifyTypeString => NotifyTypes.ContainsKey(NotifyType) ? NotifyTypes[NotifyType] : NotifyType.ToString();

            [JsonProperty("Flags", Order = 14)]
            public string FlagsEnabled => GetEnabledFlagsAsString(Flags);

            public override void Validate() {
                if (SignatureString != "CPER") {
                    ExitWithMessage($"[{nameof(WHEA_ERROR_RECORD_HEADER)}] Signature should be \"CPER\" but found: {SignatureString}");
                }

                if (SignatureEnd != uint.MaxValue) {
                    ExitWithMessage($"[{nameof(WHEA_ERROR_RECORD_HEADER)}] SignatureEnd should be {uint.MaxValue} but found: {SignatureEnd}");
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal class WHEA_ERROR_RECORD_SECTION_DESCRIPTOR : WheaRecord {
            [JsonProperty(Order = 1)]
            public uint                                             SectionOffset;

            [JsonProperty(Order = 2)]
            public uint                                             SectionLength;

            [JsonProperty(Order = 3)]
            public WHEA_REVISION                                    Revision;

            private WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS  ValidBits;

            [JsonProperty(Order = 5)]
            public char                                             Reserved;

            private WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS      Flags;
            internal Guid                                           SectionType;

            [JsonProperty(Order = 8)]
            public Guid                                             FRUId;

            private WHEA_ERROR_SEVERITY                             SectionSeverity;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
            private char[]                                          FRUText;

            [JsonProperty("ValidBits", Order = 4)]
            public string ValidBitsEnabled => GetEnabledFlagsAsString(ValidBits);

            [JsonProperty("Flags", Order = 6)]
            public string FlagsEnabled => GetEnabledFlagsAsString(Flags);

            [JsonProperty("SectionType", Order = 7)]
            public string SectionTypeString => SectionTypes.ContainsKey(SectionType) ? SectionTypes[SectionType] : SectionType.ToString();

            [JsonProperty("SectionSeverity", Order = 9)]
            public string SectionSeverityName => Enum.GetName(typeof(WHEA_ERROR_SEVERITY), SectionSeverity);

            [JsonProperty("FRUText", Order = 10)]
            public string FRUTextString => new string(FRUText).Trim('\0');
        }

        // Expanded from out-of-date struct in official headers
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal class WHEA_FIRMWARE_ERROR_RECORD_REFERENCE : WheaRecord {
            private WHEA_FIRMWARE_ERROR_RECORD_REFERENCE_TYPE   Type;

            [JsonProperty(Order = 2)]
            public char                                         Revision;

            private byte                                        Reserved1;
            private byte                                        Reserved2;
            private byte                                        Reserved3;
            private byte                                        Reserved4;
            private byte                                        Reserved5;
            private byte                                        Reserved6;

            [JsonProperty(Order = 3)]
            public ulong                                        RecordId;

            [JsonProperty(Order = 4)]
            public Guid                                         RecordExt;

            [JsonProperty("Type", Order = 1)]
            public string TypeName => Enum.GetName(typeof(WHEA_FIRMWARE_ERROR_RECORD_REFERENCE_TYPE), Type);
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal class WHEA_PERSISTENCE_INFO : WheaRecord {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 2)]
            private char[]                      Signature;

            [JsonProperty(Order = 2)]
            public byte                         Length1;

            [JsonProperty(Order = 3)]
            public byte                         Length2;

            [JsonProperty(Order = 4)]
            public byte                         Length3;

            [JsonProperty(Order = 5)]
            public ushort                       Identifier;

            private WHEA_PERSISTENCE_INFO_FLAGS Flags;

            [JsonProperty("Signature", Order = 1)]
            public string SignatureString => new string(Signature);

            [JsonProperty("Flags", Order = 6)]
            public string FlagsEnabled => GetEnabledFlagsAsString(Flags);
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal class WHEA_REVISION : WheaRecord {
            public char MajorRevision;
            public char MinorRevision;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal class WHEA_TIMESTAMP : WheaRecord {
            [JsonProperty(Order = 1)]
            public byte                     Seconds;

            [JsonProperty(Order = 2)]
            public byte                     Minutes;

            [JsonProperty(Order = 3)]
            public byte                     Hours;

            private WHEA_TIMESTAMP_FLAGS    Flags;

            [JsonProperty(Order = 5)]
            public byte                     Day;

            [JsonProperty(Order = 6)]
            public byte                     Month;

            [JsonProperty(Order = 7)]
            public byte                     Year;

            [JsonProperty(Order = 8)]
            public byte                     Century;

            [JsonProperty("Flags", Order = 4)]
            public string FlagsEnabled => GetEnabledFlagsAsString(Flags);
        }

        #endregion
    }
}
