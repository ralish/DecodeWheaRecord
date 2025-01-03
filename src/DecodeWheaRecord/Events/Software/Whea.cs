// ReSharper disable InconsistentNaming

namespace DecodeWheaRecord.Events.Software {
    /*
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogAddErrorSourceFailedEvent
     * Notes:           No payload
     */
    internal sealed class WHEA_THROTTLE_ADD_ERR_SRC_FAILED_EVENT : IWheaRecord {
        public uint GetNativeSize() => 0;
    }
}
