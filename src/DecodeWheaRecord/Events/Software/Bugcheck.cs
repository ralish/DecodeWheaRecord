#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable FieldCanBeMadeReadOnly.Global
// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Events.Software {
    /*
     * Entry ID:        CrashDumpProgressPercent
     * Module:          crashdmp.sys
     * Version:         10.0.26100.1882
     * Function(s):     CrashdmpLogSELCheckpoint_ULONG1
     * Header flags:    LogSel, RawSel
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_CRASHDUMP_EVENT_LOG_ENTRY_ULONG1 : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_CRASHDUMP_EVENT_LOG_ENTRY_ULONG1>(); // 4 bytes

        public uint Value;
    }

    /*
     * Entry ID:        CrashDumpError
     * Module:          crashdmp.sys
     * Version:         10.0.26100.1882
     * Function(s):     CrashdmpLogSELError
     * Header flags:    LogSel, RawSel
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_CRASHDUMP_EVENT_LOG_ENTRY_WITH_STATUS : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_CRASHDUMP_EVENT_LOG_ENTRY_WITH_STATUS>(); // 8 bytes

        [JsonProperty(Order = 1)]
        public uint SourceLocationId;

        private NtStatus _Status;

        [JsonProperty(Order = 2)]
        public string Status => GetEnumValueAsString<NtStatus>(_Status);
    }

    /*
     * Entry ID:        SELBugCheckProgress
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     IoSaveBugCheckProgress
     * Header flags:    LogSel, RawSel
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_SEL_BUGCHECK_PROGRESS : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_SEL_BUGCHECK_PROGRESS>(); // 8 bytes

        public uint BugCheckCode;
        public uint BugCheckProgressSummary;
    }

    /*
     * Entry ID:        SELBugCheckRecovery
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     IoSaveBugCheckRecoveryStatus
     * Header flags:    LogSel
     * Notes:           Entry ID is shared with multiple other structures which
     *                  are distinguished by their payload size.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_SEL_BUGCHECK_RECOVERY_STATUS_MULTIPLE_BUGCHECK_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_SEL_BUGCHECK_RECOVERY_STATUS_MULTIPLE_BUGCHECK_EVENT>(); // 3 bytes

        [MarshalAs(UnmanagedType.U1)]
        public bool IsBugcheckOwner;

        public byte RecursionCount;

        [MarshalAs(UnmanagedType.U1)]
        public bool IsBugcheckRecoveryOwner;
    }

    /*
     * Entry ID:        SELBugCheckRecovery
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     IoSaveBugCheckRecoveryStatus
     * Header flags:    LogSel
     * Notes:           Entry ID is shared with multiple other structures which
     *                  are distinguished by their payload size.
     */
    internal sealed class WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE1_EVENT : WheaRecord {
        private const uint StructSize = 8;
        public override uint GetNativeSize() => StructSize;

        private const uint WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE1_VERSION = 1;

        public bool Success;
        public byte Version;
        public ushort EntryCount;

        /*
         * Version 1 information
         */

        public byte DumpPolicy;

        [JsonConverter(typeof(HexStringJsonConverter))]
        // ReSharper disable once MemberCanBePrivate.Global
        public byte[] Reserved = new byte[3];

        public WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE1_EVENT(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE1_EVENT), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            Success = Marshal.ReadByte(structAddr) != 0;
            Version = Marshal.ReadByte(structAddr, 1);

            if (Version != WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE1_VERSION) {
                throw new InvalidDataException($"Expected {nameof(Version)} to be {WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE1_VERSION} but found: {Version}");
            }

            EntryCount = (ushort)Marshal.ReadInt16(structAddr, 2);
            DumpPolicy = Marshal.ReadByte(structAddr, 4);
            Marshal.Copy(structAddr + 5, Reserved, 0, 3);

            FinalizeRecord(recordAddr, StructSize);
        }

        [UsedImplicitly]
        public bool ShouldSerializeReserved() => Reserved.Any(element => element != 0);
    }

    /*
     * Entry ID:        SELBugCheckRecovery
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     IoSaveBugCheckRecoveryStatus
     * Header flags:    LogSel
     * Notes:           Entry ID is shared with multiple other structures which
     *                  are distinguished by their payload size.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE2_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_SEL_BUGCHECK_RECOVERY_STATUS_PHASE2_EVENT>(); // 5 bytes

        public uint BootId;

        [MarshalAs(UnmanagedType.U1)]
        public bool Success;
    }

    /*
     * Entry ID:        SELBugCheckRecovery
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     IoSaveBugCheckRecoveryStatus
     * Header flags:    LogSel
     * Notes:           Entry ID is shared with multiple other structures which
     *                  are distinguished by their payload size.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_SEL_BUGCHECK_RECOVERY_STATUS_START_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_SEL_BUGCHECK_RECOVERY_STATUS_START_EVENT>(); // 1 byte

        public byte StartingIrql; // KIRQL
    }

    /*
     * Entry ID:        SELBugCheckStackDump
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     PspVsmLogBugCheckCallback
     * Header flags:    LogSel, RawSel
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_SEL_RAW_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_SEL_RAW_EVENT>(); // 256 bytes

        private const int MAX_SEL_RAW_EVENT_PAYLOAD_LENGTH = 256;

        [JsonConverter(typeof(HexStringJsonConverter))]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = MAX_SEL_RAW_EVENT_PAYLOAD_LENGTH)]
        public byte[] Payload;
    }

    /*
     * Entry ID:        CpusFrozen
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     KiBugCheckProgressCpusFrozen
     * Header flags:    LogSel, RawSel
     * Notes:           Structure is not public
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_BUGCHECK_CPUS_FROZEN_EVENT : IWheaRecord {
        public uint GetNativeSize() => 0;
    }
}
