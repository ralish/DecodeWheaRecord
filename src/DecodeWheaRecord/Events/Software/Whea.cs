#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Descriptors;
using DecodeWheaRecord.Errors;
using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Events.Software {
    /*
     * Entry ID:        ThrottleAddErrSrcFailed
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPipLogAddErrorSourceFailedEvent
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_THROTTLE_ADD_ERR_SRC_FAILED_EVENT : IWheaRecord {
        public uint GetNativeSize() => 0;
    }

    /*
     * Entry ID:        AddRemoveErrorSource
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheaAddErrorSource
     *                  WheaRemoveErrorSource
     */
    internal sealed class WHEAP_ADD_REMOVE_ERROR_SOURCE_EVENT : WheaRecord {
        private const uint StructSize = 977;
        public override uint GetNativeSize() => StructSize;

        [JsonProperty(Order = 1)]
        public WHEA_ERROR_SOURCE_DESCRIPTOR Descriptor;

        private NtStatus _Status;

        [JsonProperty(Order = 2)]
        public string Status => GetEnumValueAsString<NtStatus>(_Status);

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

    /*
     * Entry ID:        AttemptErrorRecovery
     * Module:          Unknown
     * Version:         Unknown
     * Function(s):     Unknown
     * Notes:           Unable to locate the responsible function in Windows
     *                  Server 2025.
     */
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
        public string Status => GetEnumValueAsString<NtStatus>(_Status);

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

    /*
     * Entry ID:        EarlyError
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheaReportHwError
     * Notes:           Structure is not public
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_EARLY_ERROR : IWheaRecord {
        public uint GetNativeSize() => 0;
    }

    /*
     * Entry ID:        ErrorRecord
     * Module:          Unknown
     * Version:         Unknown
     * Function(s):     Unknown
     * Notes:           Unable to locate the responsible function in Windows
     *                  Server 2025.
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEAP_ERROR_RECORD_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_ERROR_RECORD_EVENT>(); // 4 bytes (x86), 8 bytes (x64)

        [JsonConverter(typeof(HexStringJsonConverter))]
        public IntPtr Record; // PWHEA_ERROR_RECORD
    }

    /*
     * Entry ID:        GenericErrMemMap
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     HalpInitGenericErrorSourceEntry
     *                  HalpInitGenericErrorSourceEntryV2
     */
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal sealed class WHEAP_GENERIC_ERR_MEM_MAP_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEAP_GENERIC_ERR_MEM_MAP_EVENT>(); // 48 bytes

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WHEA_EVENT_LOG_ENTRY.WHEA_ERROR_TEXT_LEN)]
        public string MapReason;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong PhysicalAddress;

        public ulong Length;
    }

    /*
     * Entry ID:        WheaInit
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     WheapLogInitEvent
     * Notes:           Structure is not public
     */
    internal sealed class WHEAP_INIT_EVENT : WheaRecord {
        private readonly uint _StructSize;
        public override uint GetNativeSize() => _StructSize;

        [JsonProperty(Order = 1)]
        public List<WHEAP_INIT_ERROR_SOURCE> ErrorSources;

        public WHEAP_INIT_EVENT(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEAP_INIT_EVENT), structOffset, 0, bytesRemaining) {
            const uint errorSourceStructSize = WHEAP_INIT_ERROR_SOURCE.StructSize;

            if (bytesRemaining % errorSourceStructSize != 0) {
                var checkCalc = $"{bytesRemaining} % {errorSourceStructSize} != 0";
                throw new InvalidDataException($"Division of bytes remaining by error source structure size leaves remainder: {checkCalc}");
            }

            var numErrorSources = bytesRemaining / errorSourceStructSize;
            ErrorSources = new List<WHEAP_INIT_ERROR_SOURCE>((int)numErrorSources);

            for (var i = 0; i < numErrorSources; i++) {
                var errorSource = new WHEAP_INIT_ERROR_SOURCE(recordAddr, structOffset, bytesRemaining);
                ErrorSources.Add(errorSource);
                structOffset += errorSourceStructSize;
                bytesRemaining -= errorSourceStructSize;
            }

            _StructSize = numErrorSources * errorSourceStructSize;
            FinalizeRecord(recordAddr, _StructSize);
        }
    }

    /*
     * In contrast to almost every other native structure we marshal, this
     * structure does not use 1 byte packing, instead using the default field
     * packing for the architecture. This means the "gaps" seen between some
     * fields in the marshalling offsets are deliberate.
     */
    internal sealed class WHEAP_INIT_ERROR_SOURCE : WheaRecord {
        internal const uint StructSize = 1072;
        public override uint GetNativeSize() => StructSize;

        [JsonProperty(Order = 1)]
        public LIST_ENTRY ListEntry;

        [JsonProperty(Order = 2)]
        public uint FailedAllocations;

        [JsonProperty(Order = 3)]
        public uint PlatformErrorSourceId;

        [JsonProperty(Order = 4)]
        public int ErrorCount;

        [JsonProperty(Order = 5)]
        public uint RecordCount;

        [JsonProperty(Order = 6)]
        public uint RecordLength;

        private uint _PoolTag;

        [JsonProperty(Order = 7)]
        public string PoolTag => _PoolTag.ToAsciiOrHexString();

        private WHEA_ERROR_SOURCE_TYPE _Type;

        [JsonProperty(Order = 8)]
        public string Type => GetEnumValueAsString<WHEA_ERROR_SOURCE_TYPE>(_Type);

        [JsonProperty(Order = 9)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public IntPtr Records;

        [JsonProperty(Order = 10)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public IntPtr Context;

        [JsonProperty(Order = 11)]
        public uint SectionCount;

        [JsonProperty(Order = 12)]
        public uint SectionLength;

        [JsonProperty(Order = 13)]
        public long TickCountAtLastError; // LARGE_INTEGER

        [JsonProperty(Order = 14)]
        public uint AccumulatedErrors;

        [JsonProperty(Order = 15)]
        public uint TotalErrors;

        [JsonProperty(Order = 16)]
        public bool Deferred; // UCHAR

        [JsonProperty(Order = 17)]
        public int Busy;

        [JsonProperty(Order = 18)]
        public WHEA_ERROR_SOURCE_DESCRIPTOR Descriptor;

        public WHEAP_INIT_ERROR_SOURCE(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEAP_INIT_ERROR_SOURCE), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;
            var isPtrSize64 = IntPtr.Size == 8;

            ListEntry = Marshal.PtrToStructure<LIST_ENTRY>(structAddr);
            FailedAllocations = (uint)Marshal.ReadInt32(structAddr, isPtrSize64 ? 16 : 8);
            PlatformErrorSourceId = (uint)Marshal.ReadInt32(structAddr, isPtrSize64 ? 20 : 12);
            ErrorCount = Marshal.ReadInt32(structAddr, isPtrSize64 ? 24 : 16);
            RecordCount = (uint)Marshal.ReadInt32(structAddr, isPtrSize64 ? 28 : 20);
            RecordLength = (uint)Marshal.ReadInt32(structAddr, isPtrSize64 ? 32 : 24);
            _PoolTag = (uint)Marshal.ReadInt32(structAddr, isPtrSize64 ? 36 : 28);
            _Type = (WHEA_ERROR_SOURCE_TYPE)Marshal.ReadInt32(structAddr, isPtrSize64 ? 40 : 32);
            Records = Marshal.ReadIntPtr(structAddr, isPtrSize64 ? 48 : 36);
            Context = Marshal.ReadIntPtr(structAddr, isPtrSize64 ? 56 : 40);
            SectionCount = (uint)Marshal.ReadInt32(structAddr, isPtrSize64 ? 64 : 44);
            SectionLength = (uint)Marshal.ReadInt32(structAddr, isPtrSize64 ? 68 : 48);
            TickCountAtLastError = Marshal.ReadInt64(structAddr, isPtrSize64 ? 72 : 52);
            AccumulatedErrors = (uint)Marshal.ReadInt32(structAddr, isPtrSize64 ? 80 : 60);
            TotalErrors = (uint)Marshal.ReadInt32(structAddr, isPtrSize64 ? 84 : 64);
            Deferred = Marshal.ReadByte(structAddr, isPtrSize64 ? 88 : 68) != 0;
            Busy = Marshal.ReadInt32(structAddr, isPtrSize64 ? 92 : 72);

            structOffset += isPtrSize64 ? (uint)96 : 76;
            bytesRemaining += isPtrSize64 ? (uint)96 : 76;

            Descriptor = new WHEA_ERROR_SOURCE_DESCRIPTOR(recordAddr, structOffset, bytesRemaining);

            FinalizeRecord(recordAddr, StructSize);
        }
    }

    // Structure size: 8 bytes (x86), 16 bytes (x64)
    [StructLayout(LayoutKind.Sequential)]
    internal sealed class LIST_ENTRY {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public IntPtr Flink;

        [JsonConverter(typeof(HexStringJsonConverter))]
        public IntPtr Blink;
    }
}
