#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Errors;
using DecodeWheaRecord.Shared;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Events.Software {
    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogAddErrorSourceFailedEvent
     * Notes:           No payload
     */
    // TODO
    internal sealed class WHEA_THROTTLE_ADD_ERR_SRC_FAILED_EVENT : IWheaRecord {
        public uint GetNativeSize() => 0;
    }

    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheaAddErrorSource
     *                  WheaRemoveErrorSource
     */
    // TODO
    internal sealed class WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT : WheaRecord {
        private const uint StructSize = 977;
        public override uint GetNativeSize() => StructSize;

        [JsonProperty(Order = 1)]
        public WHEA_ERROR_SOURCE_DESCRIPTOR Descriptor;

        private readonly NtStatus _Status;

        [JsonProperty(Order = 2)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);

        [JsonProperty(Order = 3)]
        public bool IsRemove;

        public WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            Descriptor = new WHEA_ERROR_SOURCE_DESCRIPTOR(recordAddr, structOffset, bytesRemaining);
            _Status = (NtStatus)Marshal.ReadInt32(structAddr, 972);
            IsRemove = Marshal.ReadByte(structAddr, 976) != 0;

            FinalizeRecord(recordAddr, StructSize);
        }
    }

    // TODO
    internal sealed class WHEAP_ATTEMPT_RECOVERY_EVENT : WheaRecord {
        private const uint StructSize = 134;
        public override uint GetNativeSize() => StructSize;

        [JsonProperty(Order = 1)]
        public WHEA_ERROR_RECORD_HEADER ErrorHeader;

        [JsonProperty(Order = 2)]
        public bool ArchitecturalRecovery;

        [JsonProperty(Order = 3)]
        public bool PshedRecovery;

        private NtStatus _Status;

        [JsonProperty(Order = 4)]
        public string Status => Enum.GetName(typeof(NtStatus), _Status);

        public WHEAP_ATTEMPT_RECOVERY_EVENT(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEAP_ATTEMPT_RECOVERY_EVENT), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            ErrorHeader = new WHEA_ERROR_RECORD_HEADER(recordAddr, structOffset, bytesRemaining);
            ArchitecturalRecovery = Marshal.ReadByte(structAddr, 128) != 0;
            PshedRecovery = Marshal.ReadByte(structAddr, 129) != 0;
            _Status = (NtStatus)Marshal.ReadInt32(structAddr, 130);

            FinalizeRecord(recordAddr, StructSize);
        }
    }
}
