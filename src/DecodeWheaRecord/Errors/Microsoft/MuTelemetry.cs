// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Descriptors;
using DecodeWheaRecord.Internal;

using JetBrains.Annotations;

using Newtonsoft.Json;

/*
 * MS WHEA Package
 * https://microsoft.github.io/mu/dyn/mu_plus/MsWheaPkg/readme/
 *
 * Vanilla Windows doesn't appear to have built-in reporting.
 */
namespace DecodeWheaRecord.Errors.Microsoft {
    internal sealed class MU_TELEMETRY_SECTION : WheaRecord {
        private const uint StructSize = 56;
        public override uint GetNativeSize() => StructSize;

        public Guid ComponentID;
        public Guid SubComponentID;

        [JsonConverter(typeof(HexStringJsonConverter))]
        // ReSharper disable once MemberCanBePrivate.Global
        public uint Reserved;

        /*
         * Appendix D - Status Codes
         * https://uefi.org/specs/UEFI/2.11/Apx_D_Status_Codes.html
         *
         * Future: Convert codes to their symbolic value
         */
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint ErrorStatusValue;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong AdditionalInfo1;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong AdditionalInfo2;

        public MU_TELEMETRY_SECTION(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(MU_TELEMETRY_SECTION), structOffset, StructSize, bytesRemaining) {
            MuTelemetrySection(recordAddr, structOffset);
        }

        public MU_TELEMETRY_SECTION(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(typeof(MU_TELEMETRY_SECTION), sectionDsc, StructSize, bytesRemaining) {
            MuTelemetrySection(recordAddr, sectionDsc.SectionOffset);
        }

        private void MuTelemetrySection(IntPtr recordAddr, uint structOffset) {
            var structAddr = recordAddr + (int)structOffset;

            ComponentID = Marshal.PtrToStructure<Guid>(structAddr);
            SubComponentID = Marshal.PtrToStructure<Guid>(structAddr + 16);
            Reserved = (uint)Marshal.ReadInt32(structAddr, 32);
            ErrorStatusValue = (uint)Marshal.ReadInt32(structAddr, 36);
            AdditionalInfo1 = (ulong)Marshal.ReadInt64(structAddr, 40);
            AdditionalInfo2 = (ulong)Marshal.ReadInt64(structAddr, 48);

            FinalizeRecord(recordAddr, StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved != 0;
    }
}
