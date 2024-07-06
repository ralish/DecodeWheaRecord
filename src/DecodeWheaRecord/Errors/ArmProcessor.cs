#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.NativeMethods;
using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors {
    internal sealed class WHEA_ARM_PROCESSOR_ERROR_SECTION : WheaRecord {
        internal override int GetNativeSize() => (int)SectionLength;

        private WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS _ValidBits;

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        [JsonProperty(Order = 2)]
        public ushort ErrorInformationStructures;

        [JsonProperty(Order = 3)]
        public ushort ContextInformationStructures;

        // TODO: Description & validation
        [JsonProperty(Order = 4)]
        public uint SectionLength;

        [JsonProperty(Order = 5)]
        public byte ErrorAffinityLevel;

        [JsonProperty(Order = 6)]
        public byte[] Reserved = new byte[3];

        [JsonProperty(Order = 7)]
        public ulong MPIDR_EL1; // Multiprocessor Affinity Register

        [JsonProperty(Order = 8)]
        public ulong MIDR_EL1; // Main ID Register

        [JsonProperty(Order = 9)]
        public uint RunningState;

        [JsonProperty(Order = 10)]
        public uint PSCIState; // Power State Coordination Interface

        [JsonProperty(Order = 11)]
        public byte[] Data;

        public WHEA_ARM_PROCESSOR_ERROR_SECTION(IntPtr recordAddr, WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc) {
            DebugOutputPre(typeof(WHEA_ARM_PROCESSOR_ERROR_SECTION), sectionDsc);
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            _ValidBits = (WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS)Marshal.ReadInt32(sectionAddr);
            ErrorInformationStructures = (ushort)Marshal.ReadInt16(sectionAddr, 4);
            ContextInformationStructures = (ushort)Marshal.ReadInt16(sectionAddr, 6);
            SectionLength = (uint)Marshal.ReadInt32(sectionAddr, 8);
            ErrorAffinityLevel = Marshal.ReadByte(sectionAddr, 12);
            Marshal.Copy(sectionAddr + 13, Reserved, 0, 3);
            MPIDR_EL1 = (ulong)Marshal.ReadInt64(sectionAddr, 16);
            MIDR_EL1 = (ulong)Marshal.ReadInt64(sectionAddr, 24);
            RunningState = (uint)Marshal.ReadInt32(sectionAddr, 32);
            PSCIState = (uint)Marshal.ReadInt32(sectionAddr, 36);
            const int offset = 40;

            var dataLen = SectionLength - offset;
            if (dataLen > 0) {
                Data = new byte[dataLen];
                Marshal.Copy(sectionAddr + offset, Data, 0, (int)dataLen);
            }

            // At least one error information structure should be present
            if (ErrorInformationStructures == 0) {
                var msg = $"[{nameof(WHEA_ARM_PROCESSOR_ERROR_SECTION)}] {nameof(ErrorInformationStructures)} is not >= 1.";
                Console.Error.WriteLine(msg);
            }

            // PSCIState should be zero when bit 0 of RunningState is set
            if (ShouldSerializeRunningState() && (RunningState & 0x1) == 1 && PSCIState != 0) {
                var msg = $"[{nameof(WHEA_ARM_PROCESSOR_ERROR_SECTION)}] {nameof(RunningState)} indicates {nameof(PSCIState)} should be zero.";
                Console.Error.WriteLine(msg);
            }

            DebugOutputPost(typeof(WHEA_ARM_PROCESSOR_ERROR_SECTION), sectionDsc, (int)SectionLength);
        }

        [UsedImplicitly]
        public bool ShouldSerializeErrorAffinityLevel() => (_ValidBits & WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.AffinityLevel) ==
                                                           WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.AffinityLevel;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();

        [UsedImplicitly]
        public bool ShouldSerializeErrorMPIDR_EL1() => (_ValidBits & WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.MPIDR) ==
                                                       WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.MPIDR;

        [UsedImplicitly]
        public bool ShouldSerializeErrorMIDR_EL1() => (_ValidBits & WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.VendorSpecificInfo) ==
                                                      WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.VendorSpecificInfo;

        [UsedImplicitly]
        public bool ShouldSerializeRunningState() => (_ValidBits & WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.RunningState) ==
                                                     WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.RunningState;

        [UsedImplicitly]
        public bool ShouldSerializePSCIState() {
            // Field is valid when bit 32 of RunningState is unset
            return ShouldSerializeRunningState() && (RunningState & 0xF0000000) == 0;
        }
    }

    // @formatter:int_align_fields true

    [Flags]
    internal enum WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS : uint {
        MPIDR              = 0x1, // Multiprocessor Affinity Register
        AffinityLevel      = 0x2,
        RunningState       = 0x4,
        VendorSpecificInfo = 0x8
    }

    // @formatter:int_align_fields false
}
