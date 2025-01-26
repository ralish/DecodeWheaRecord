#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Events {
    internal sealed class WHEA_EVENT_LOG_ENTRY_HEADER : WheaRecord {
        internal const uint StructSize = 32;
        public override uint GetNativeSize() => StructSize;

        /*
         * Value is reversed from header definition as validation is performed
         * against the field as a string instead of an integer.
         */
        internal const string WHEA_ERROR_LOG_ENTRY_SIGNATURE = "WhLg";

        private const int WHEA_ERROR_LOG_ENTRY_VERSION = 1;

        private uint _Signature;

        [JsonProperty(Order = 1)]
        public string Signature => _Signature.ToAsciiOrHexString();

        [JsonProperty(Order = 2)]
        public uint Version;

        /*
         * Length of the event log entry in its entirety; i.e. the header (this
         * structure) and the entry itself (the payload).
         */
        [JsonProperty(Order = 3)]
        public uint Length;

        private WHEA_EVENT_LOG_ENTRY_TYPE _Type;

        [JsonProperty(Order = 4)]
        public string Type => GetEnumValueAsString<WHEA_EVENT_LOG_ENTRY_TYPE>(_Type);

        private uint _OwnerTag;

        [JsonProperty(Order = 5)]
        public string OwnerTag => _OwnerTag.ToAsciiOrHexString();

        private WHEA_EVENT_LOG_ENTRY_ID _Id;

        [JsonProperty(Order = 6)]
        public string Id => GetEnumValueAsString<WHEA_EVENT_LOG_ENTRY_ID>(_Id);

        private WHEA_EVENT_LOG_ENTRY_FLAGS _Flags;

        [JsonProperty(Order = 7)]
        public string Flags => GetEnumFlagsAsString(_Flags);

        // Length of the event (excluding this header)
        [JsonProperty(Order = 8)]
        public uint PayloadLength;

        public WHEA_EVENT_LOG_ENTRY_HEADER(IntPtr recordAddr, uint recordSize) :
            base(typeof(WHEA_EVENT_LOG_ENTRY_HEADER), 0, StructSize, recordSize) {
            _Signature = (uint)Marshal.ReadInt32(recordAddr);

            if (Signature != WHEA_ERROR_LOG_ENTRY_SIGNATURE) {
                throw new InvalidDataException($"Expected {nameof(Signature)} to be \"{WHEA_ERROR_LOG_ENTRY_SIGNATURE}\" but found: {Signature}");
            }

            Version = (uint)Marshal.ReadInt32(recordAddr, 4);

            if (Version != WHEA_ERROR_LOG_ENTRY_VERSION) {
                throw new InvalidDataException($"Expected {nameof(Version)} to be {WHEA_ERROR_LOG_ENTRY_VERSION} but found: {Version}");
            }

            Length = (uint)Marshal.ReadInt32(recordAddr, 8);

            if (Length != recordSize) {
                var isGreater = Length > recordSize;
                var checkCalc = $"{Length} {(isGreater ? ">" : "<")} {recordSize}";
                var msg = $"{nameof(Length)} is {(isGreater ? "greater" : "less")} than bytes remaining: {checkCalc}";

                if (isGreater) {
                    throw new InvalidDataException(msg);
                }

                WarnOutput(msg, StructType.Name);
                WarnOutput("Event log entry may be corrupt or incorrectly and/or partially decoded.", StructType.Name);
            }

            _Type = (WHEA_EVENT_LOG_ENTRY_TYPE)Marshal.ReadInt32(recordAddr, 12);
            _OwnerTag = (uint)Marshal.ReadInt32(recordAddr, 16);
            _Id = (WHEA_EVENT_LOG_ENTRY_ID)Marshal.ReadInt32(recordAddr, 20);
            _Flags = (WHEA_EVENT_LOG_ENTRY_FLAGS)Marshal.ReadInt32(recordAddr, 24);
            PayloadLength = (uint)Marshal.ReadInt32(recordAddr, 28);

            if (StructSize + PayloadLength != Length) {
                var isGreater = StructSize + PayloadLength > Length;
                var checkCalc = $"{StructSize} + {PayloadLength} {(isGreater ? ">" : "<")} {Length}";
                var msg = $"{nameof(PayloadLength)} results in size {(isGreater ? "greater" : "less")} than event log entry length: {checkCalc}";

                if (isGreater) {
                    throw new InvalidDataException(msg);
                }

                WarnOutput(msg, StructType.Name);
                WarnOutput("Event log entry may be corrupt or incorrectly and/or partially decoded.", StructType.Name);
            }

            FinalizeRecord(recordAddr, StructSize);
        }
    }

    // @formatter:int_align_fields true

    internal enum WHEA_EVENT_LOG_ENTRY_TYPE : uint {
        Informational = 0,
        Warning       = 1,
        Error         = 2
    }

    internal enum WHEA_EVENT_LOG_ENTRY_ID : uint {
        CmcPollingTimeout             = 0x80000001,
        WheaInit                      = 0x80000002,
        CmcSwitchToPolling            = 0x80000003,
        DroppedCorrectedError         = 0x80000004,
        StartedReportHwError          = 0x80000005, // SEL only
        PFAMemoryOfflined             = 0x80000006,
        PFAMemoryRemoveMonitor        = 0x80000007,
        PFAMemoryPolicy               = 0x80000008,
        PshedInjectError              = 0x80000009,
        OscCapabilities               = 0x8000000a,
        PshedPluginRegister           = 0x8000000b,
        AddRemoveErrorSource          = 0x8000000c,
        WorkQueueItem                 = 0x8000000d,
        AttemptErrorRecovery          = 0x8000000e,
        McaFoundErrorInBank           = 0x8000000f,
        McaStuckErrorCheck            = 0x80000010,
        McaErrorCleared               = 0x80000011,
        ClearedPoison                 = 0x80000012,
        ProcessEINJ                   = 0x80000013,
        ProcessHEST                   = 0x80000014,
        CreateGenericRecord           = 0x80000015,
        ErrorRecord                   = 0x80000016,
        ErrorRecordLimit              = 0x80000017,
        AerNotGrantedToOs             = 0x80000018,
        ErrSrcArrayInvalid            = 0x80000019,
        AcpiTimeOut                   = 0x8000001a,
        CmciRestart                   = 0x8000001b,
        CmciFinalRestart              = 0x8000001c,
        EtwOverFlow                   = 0x8000001d,
        AzccRootBusSearchErr          = 0x8000001e,
        AzccRootBusList               = 0x8000001f,
        ErrSrcInvalid                 = 0x80000020,
        GenericErrMemMap              = 0x80000021,
        PshedCallbackCollision        = 0x80000022,
        SELBugCheckProgress           = 0x80000023,
        PshedPluginLoad               = 0x80000024,
        PshedPluginUnload             = 0x80000025,
        PshedPluginSupported          = 0x80000026,
        DeviceDriver                  = 0x80000027,
        CmciImplPresent               = 0x80000028,
        CmciInitError                 = 0x80000029,
        SELBugCheckRecovery           = 0x8000002a,
        DrvErrSrcInvalid              = 0x8000002b,
        DrvHandleBusy                 = 0x8000002c,
        WheaHeartbeat                 = 0x8000002d,
        AzccRootBusPoisonSet          = 0x8000002e,
        SELBugCheckInfo               = 0x8000002f,
        ErrDimmInfoMismatch           = 0x80000030,
        eDpcEnabled                   = 0x80000031,
        PageOfflineDone               = 0x80000032,
        PageOfflinePendMax            = 0x80000033,
        BadPageLimitReached           = 0x80000034,
        SrarDetail                    = 0x80000035,
        EarlyError                    = 0x80000036,
        PcieOverrideInfo              = 0x80000037,
        ReadPcieOverridesErr          = 0x80000038,
        PcieConfigInfo                = 0x80000039,
        PcieSummaryFailed             = 0x80000040,
        ThrottleRegCorrupt            = 0x80000041,
        ThrottleAddErrSrcFailed       = 0x80000042,
        ThrottleRegDataIgnored        = 0x80000043,
        EnableKeyNotifFailed          = 0x80000044,
        KeyNotificationFailed         = 0x80000045,
        PcieRemoveDevice              = 0x80000046,
        PcieAddDevice                 = 0x80000047,
        PcieSpuriousErrSource         = 0x80000048,
        MemoryAddDevice               = 0x80000049,
        MemoryRemoveDevice            = 0x8000004a,
        MemorySummaryFailed           = 0x8000004b,
        PcieDpcError                  = 0x8000004c,
        CpuBusesInitFailed            = 0x8000004d,
        PshedPluginInitFailed         = 0x8000004e,
        FailedAddToDefectList         = 0x8000004f,
        DefectListFull                = 0x80000050,
        DefectListUEFIVarFailed       = 0x80000051,
        DefectListCorrupt             = 0x80000052,
        BadHestNotifyData             = 0x80000053,
        RowFailure                    = 0x80000054,
        SrasTableNotFound             = 0x80000055,
        SrasTableError                = 0x80000056,
        SrasTableEntries              = 0x80000057,
        PFANotifyCallbackAction       = 0x80000058,
        SELBugCheckCpusQuiesced       = 0x80000059,
        PshedPiCpuid                  = 0x8000005a,
        SrasTableBadData              = 0x8000005b,
        DriFsStatus                   = 0x8000005c,
        CpusFrozen                    = 0x80000060,
        CpusFrozenNoCrashDump         = 0x80000061,
        RegNotifyPolicyChange         = 0x80000062,
        RegError                      = 0x80000063,
        RowOfflineEvent               = 0x80000064,
        BitOfflineEvent               = 0x80000065,
        BadGasFields                  = 0x80000066,
        CrashDumpError                = 0x80000067,
        CrashDumpCheckpoint           = 0x80000068,
        CrashDumpProgressPercent      = 0x80000069,
        PreviousCrashBugCheckProgress = 0x8000006a,
        SELBugCheckStackDump          = 0x8000006b,
        PciePromotedAerErr            = 0x8000006c,
        PshedPiTraceLog               = 0x80040010
    }

    [Flags]
    internal enum WHEA_EVENT_LOG_ENTRY_FLAGS : uint {
        Reserved       = 0x1,
        LogInternalEtw = 0x2,
        LogBlackbox    = 0x4,
        LogSel         = 0x8,
        RawSel         = 0x10,
        NoFormat       = 0x20,
        Driver         = 0x40
    }

    // @formatter:int_align_fields false
}
