#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Errors {
    /*
     * Cannot be directly marshalled as a structure due to the usage of a
     * variable length array, resulting in a non-static structure size.
     */
    internal sealed class WHEA_ARM_PROCESSOR_ERROR_SECTION : WheaErrorRecord {
        // Size up to and including the PSCIState field
        private const uint BaseStructSize = 40;

        // As per the UEFI specification
        private const byte MaxErrorAffinityLevel = 3;

        public override uint GetNativeSize() => SectionLength;

        private WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS _ValidBits;

        [JsonProperty(Order = 1)]
        public string ValidBits => GetEnabledFlagsAsString(_ValidBits);

        [JsonProperty(Order = 2)]
        public ushort ErrorInformationStructures;

        [JsonProperty(Order = 3)]
        public ushort ContextInformationStructures;

        // Total size of the error section
        [JsonProperty(Order = 4)]
        public uint SectionLength;

        [JsonProperty(Order = 5)]
        public byte ErrorAffinityLevel;

        [JsonProperty(Order = 6)]
        public byte[] Reserved = new byte[3];

        [JsonProperty(Order = 7)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MPIDR_EL1; // Multiprocessor Affinity Register

        [JsonProperty(Order = 8)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong MIDR_EL1; // Main ID Register

        [JsonProperty(Order = 9)]
        public uint RunningState;

        [JsonProperty(Order = 10)]
        public uint PSCIState; // Power State Coordination Interface

        [JsonProperty(Order = 11)]
        public byte[] Data; // TODO: Deserialize

        public WHEA_ARM_PROCESSOR_ERROR_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(sectionDsc, typeof(WHEA_ARM_PROCESSOR_ERROR_SECTION), BaseStructSize, bytesRemaining) {
            var logCat = SectionType.Name;
            var sectionAddr = recordAddr + (int)sectionDsc.SectionOffset;

            _ValidBits = (WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS)Marshal.ReadInt32(sectionAddr);
            ErrorInformationStructures = (ushort)Marshal.ReadInt16(sectionAddr, 4);
            ContextInformationStructures = (ushort)Marshal.ReadInt16(sectionAddr, 6);

            SectionLength = (uint)Marshal.ReadInt32(sectionAddr, 8);
            if (SectionLength > sectionDsc.SectionLength) {
                var errMsg = $"{nameof(SectionLength)} is greater than in section descriptor: {SectionLength} > {sectionDsc.SectionLength}";
                throw new InvalidDataException(errMsg);
            }

            ErrorAffinityLevel = Marshal.ReadByte(sectionAddr, 12);
            Marshal.Copy(sectionAddr + 13, Reserved, 0, 3);
            MPIDR_EL1 = (ulong)Marshal.ReadInt64(sectionAddr, 16);
            MIDR_EL1 = (ulong)Marshal.ReadInt64(sectionAddr, 24);
            RunningState = (uint)Marshal.ReadInt32(sectionAddr, 32);
            PSCIState = (uint)Marshal.ReadInt32(sectionAddr, 36);

            var dataLen = SectionLength - BaseStructSize;
            if (dataLen > 0) {
                Data = new byte[dataLen];
                Marshal.Copy(sectionAddr + (int)BaseStructSize, Data, 0, (int)dataLen);
            }

            if (ErrorInformationStructures == 0) {
                WarnOutput($"{nameof(ErrorInformationStructures)} is zero (expected at least one structure).", logCat);
            }

            if (ErrorAffinityLevel > MaxErrorAffinityLevel) {
                WarnOutput($"{nameof(ErrorAffinityLevel)} above maximum of {MaxErrorAffinityLevel}.", logCat);
            }

            // PSCIState should be zero when bit 0 of RunningState is set
            if (ShouldSerializeRunningState() && (RunningState & 0x1) == 1 && PSCIState != 0) {
                WarnOutput($"{nameof(PSCIState)} is non-zero but {nameof(RunningState)} indicates it shouldn't be.", logCat);
            }

            Debug.Assert(BaseStructSize + dataLen == SectionLength);
            FinalizeRecord(recordAddr, SectionLength);
        }

        [UsedImplicitly]
        public bool ShouldSerializeErrorAffinityLevel() =>
            (_ValidBits & WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.AffinityLevel) ==
            WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.AffinityLevel;

        [UsedImplicitly]
        public static bool ShouldSerializeReserved() => IsDebugBuild();

        [UsedImplicitly]
        public bool ShouldSerializeErrorMPIDR_EL1() =>
            (_ValidBits & WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.MPIDR) ==
            WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.MPIDR;

        [UsedImplicitly]
        public bool ShouldSerializeErrorMIDR_EL1() =>
            (_ValidBits & WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.VendorSpecificInfo) ==
            WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.VendorSpecificInfo;

        [UsedImplicitly]
        public bool ShouldSerializeRunningState() =>
            (_ValidBits & WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.RunningState) ==
            WHEA_ARM_PROCESSOR_ERROR_SECTION_VALID_BITS.RunningState;

        [UsedImplicitly]
        public bool ShouldSerializePSCIState() =>
            // Valid when bit 31 of RunningState is zero
            ShouldSerializeRunningState() && (RunningState & 0x80000000) == 0;
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
