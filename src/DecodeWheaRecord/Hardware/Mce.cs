#pragma warning disable CS0649  // Field is never assigned to
#pragma warning disable IDE0044 // Make field readonly

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Errors.Microsoft;
using DecodeWheaRecord.Internal;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

namespace DecodeWheaRecord.Hardware {
    // The CMC_EXCEPTION and CPE_EXCEPTION types are aliases of this structure
    internal sealed class MCA_EXCEPTION : WheaRecord {
        private const uint StructSize = 256;
        public override uint GetNativeSize() => StructSize;

        // Latest and only supported structure version
        private const uint ExpectedVersion = 2;

        // Count of extended registers in the ExtReg array
        private const uint MCA_EXTREG_V2_MAX = 24;

        [JsonProperty(Order = 1)]
        public uint VersionNumber;

        private MCA_EXCEPTION_TYPE _ExceptionType;

        [JsonProperty(Order = 2)]
        public string ExceptionType => GetEnumValueAsString<MCA_EXCEPTION_TYPE>(_ExceptionType);

        [JsonProperty(Order = 3)]
        public ulong TimeStamp; // LARGE_INTEGER

        [JsonProperty(Order = 4)]
        public uint ProcessorNumber;

        [JsonProperty(Order = 5)]
        public uint Reserved1;

        [JsonProperty(Order = 6)]
        public MCA_EXCEPTION_MCA Mca;

        [JsonProperty(Order = 6)]
        public MCA_EXCEPTION_MCE Mce;

        /*
         * Version 2 fields
         *
         * Introduced in Windows XP. As WHEA was introduced with Windows Server
         * 2008 and Windows Vista SP1, we don't support the original structure.
         */

        [JsonProperty(Order = 7)]
        public uint ExtCnt;

        [JsonProperty(Order = 8)]
        public uint Reserved2;

        [JsonProperty(Order = 9)]
        public ulong[] ExtReg = new ulong[MCA_EXTREG_V2_MAX];

        public MCA_EXCEPTION(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(MCA_EXCEPTION), structOffset, StructSize, bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            VersionNumber = (uint)Marshal.ReadInt32(structAddr);

            if (VersionNumber != ExpectedVersion) {
                throw new InvalidDataException($"Expected {nameof(VersionNumber)} to be {ExpectedVersion} but found: {VersionNumber}");
            }

            _ExceptionType = (MCA_EXCEPTION_TYPE)Marshal.ReadInt32(structAddr, 4);
            TimeStamp = (ulong)Marshal.ReadInt64(structAddr, 8);
            ProcessorNumber = (uint)Marshal.ReadInt32(structAddr, 16);
            Reserved1 = (uint)Marshal.ReadInt32(structAddr, 20);

            switch (_ExceptionType) {
                case MCA_EXCEPTION_TYPE.MCA:
                    Mca = PtrToStructure<MCA_EXCEPTION_MCA>(structAddr + 24);
                    break;
                case MCA_EXCEPTION_TYPE.MCE:
                    Mce = PtrToStructure<MCA_EXCEPTION_MCE>(structAddr + 24);
                    break;
                default:
                    throw new InvalidDataException($"{nameof(ExceptionType)} is unknown or invalid: {ExceptionType}");
            }

            ExtCnt = (uint)Marshal.ReadInt32(structAddr, 56);
            Reserved2 = (uint)Marshal.ReadInt32(structAddr, 60);

            var extRegSigned = new long[MCA_EXTREG_V2_MAX];
            Marshal.Copy(structAddr + 64, extRegSigned, 0, (int)MCA_EXTREG_V2_MAX);
            for (var i = 0; i < MCA_EXTREG_V2_MAX; i++) {
                ExtReg[i] = (ulong)extRegSigned[i];
            }

            FinalizeRecord(recordAddr, StructSize);
        }
    }

    /*
     * Structure size: 32 bytes
     *
     * Originally the "Mca" union embedded in the MCA_EXCEPTION structure.
     */
    [StructLayout(LayoutKind.Sequential)]
    internal sealed class MCA_EXCEPTION_MCA {
        public byte BankNumber;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)]
        public byte[] Reserved;

        /*
         * The mce.h header defines this as an MCI_STATS structure but it's
         * identical to the MCI_STATUS_BITS_COMMON structure. In addition, it
         * defines different structures for IA32 and AMD64 but they only differ
         * in some field names, and even those changes seem to be immaterial.
         */
        public MCI_STATUS_BITS_COMMON Status;

        public MCI_ADDR Address;
        public ulong Misc;
    }

    // Structure size: 8 bytes
    [StructLayout(LayoutKind.Sequential)]
    internal sealed class MCI_ADDR {
        public uint Address;
        public uint Reserved;
    }

    /*
     * Structure size: 16 bytes
     *
     * Originally the "Mce" union embedded in the MCA_EXCEPTION structure.
     */
    [StructLayout(LayoutKind.Sequential)]
    internal sealed class MCA_EXCEPTION_MCE {
        public ulong Address;
        public ulong Type;
    }

    // @formatter:int_align_fields true

    internal enum MCA_EXCEPTION_TYPE : uint {
        MCE = 0,
        MCA = 1
    }

    // @formatter:int_align_fields false
}
