using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using static DecodeWheaRecord.NativeMethods;
using static DecodeWheaRecord.Utilities;


// Mark assembly as not CLS compliant
[assembly: CLSCompliant(false)]


namespace DecodeWheaRecord {
    public static class Program {
        private static byte[] _recordBytes;
        private static int _recordOffset;

        public static void Main(string[] args) {
            if (args.Length == 0) {
                ExitWithMessage($"Usage: {Assembly.GetExecutingAssembly().GetName().Name} <WheaHexRecord>", 0);
            } else if (args.Length > 1) {
                ExitWithMessage($"Expected a hex encoded WHEA record but received {args.Length} arguments.");
            }

            _recordBytes = ConvertHexToBytes(args[0]);

            var header = MarshalWheaRecord(typeof(WHEA_ERROR_RECORD_HEADER)) as WHEA_ERROR_RECORD_HEADER;
            Debug.Assert(header != null, nameof(header) + " != null");

            var headerJson = JsonConvert.SerializeObject(header, Formatting.Indented);
            Console.Out.WriteLine(headerJson);

            for (var sectionIndex = 0; sectionIndex < header.SectionCount; sectionIndex++) {
                var sectionDsc =
                    MarshalWheaRecord(typeof(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR)) as
                        WHEA_ERROR_RECORD_SECTION_DESCRIPTOR;
                Debug.Assert(sectionDsc != null, nameof(sectionDsc) + " != null");

                var sectionDscJson = JsonConvert.SerializeObject(sectionDsc, Formatting.Indented);
                Console.Out.WriteLine(sectionDscJson);

                if (sectionDsc.SectionType == new Guid("81212a96-09ed-4996-9471-8d729c8e69ed")) {
                    var fwRecordRef =
                        MarshalWheaRecord(typeof(WHEA_FIRMWARE_ERROR_RECORD_REFERENCE)) as
                            WHEA_FIRMWARE_ERROR_RECORD_REFERENCE;
                    var fwRecordRefJson = JsonConvert.SerializeObject(fwRecordRef, Formatting.Indented);
                    Console.Out.WriteLine(fwRecordRefJson);
                }
            }
        }

        private static WheaRecord MarshalWheaRecord(Type recordType) {
            var recordSize = Marshal.SizeOf(recordType);

            var remainingBytes = _recordBytes.Length - _recordOffset;
            if (remainingBytes < recordSize) {
                ExitWithMessage($"[{nameof(recordType)}] Provided record is too small: {remainingBytes} bytes");
            }

            var recordBytes = new byte[recordSize];
            for (var i = 0; i < recordBytes.Length; i++) {
                recordBytes[i] = _recordBytes[_recordOffset + i];
            }

            WheaRecord record;
            var hRecord = GCHandle.Alloc(recordBytes, GCHandleType.Pinned);
            try {
                record = Marshal.PtrToStructure(hRecord.AddrOfPinnedObject(), recordType) as WheaRecord;
                Debug.Assert(record != null, nameof(record) + " != null");
                record.Validate();
            } finally {
                hRecord.Free();
            }

            _recordOffset += recordSize;
            return record;
        }
    }
}
