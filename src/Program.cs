using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;

using Newtonsoft.Json;

using static DecodeWheaRecord.NativeMethods;
using static DecodeWheaRecord.Utilities;


// Mark assembly as not CLS compliant
[assembly: CLSCompliant(false)]


namespace DecodeWheaRecord {
    internal class Program {
        public static void Main(string[] args) {
            if (args.Length == 0) {
                Console.Out.WriteLine($"Usage: {Assembly.GetExecutingAssembly().GetName().Name} <WheaHexRecord>");
                Environment.Exit(0);
            } else if (args.Length > 1) {
                Console.Error.WriteLine($"Expected a hex encoded WHEA record but received {args.Length} arguments.");
                Environment.Exit(1);
            }

            var recordBytes = ConvertHexToBytes(args[0]);
            Console.Error.WriteLine($"WHEA error record converted to byte array: {recordBytes.Length} bytes");

            var recordHeaderSize = Marshal.SizeOf<WHEA_ERROR_RECORD_HEADER>();
            Console.Error.WriteLine($"[{nameof(WHEA_ERROR_RECORD_HEADER)}] Structure size: {recordHeaderSize} bytes");

            var recordHeaderBytes = new byte[recordHeaderSize];
            for (var i = 0; i < recordHeaderBytes.Length; i++) {
                recordHeaderBytes[i] = recordBytes[i];
            }

            WHEA_ERROR_RECORD_HEADER recordHeader;
            var hRecordHeader = GCHandle.Alloc(recordHeaderBytes, GCHandleType.Pinned);
            try {
                recordHeader = Marshal.PtrToStructure<WHEA_ERROR_RECORD_HEADER>(hRecordHeader.AddrOfPinnedObject());
            } finally {
                hRecordHeader.Free();
            }
            Console.Error.WriteLine($"[{nameof(WHEA_ERROR_RECORD_HEADER)}] Section count: {recordHeader.SectionCount}");

            var recordSectionDscSize = Marshal.SizeOf<WHEA_ERROR_RECORD_SECTION_DESCRIPTOR>();
            Console.Error.WriteLine(
                $"[{nameof(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR)}] Structure size: {recordSectionDscSize} bytes");

            var recordSectionDscs = new List<WHEA_ERROR_RECORD_SECTION_DESCRIPTOR>();
            var recordSectionDscOffset = recordHeaderSize;

            for (var recordSectionDscIdx = 0; recordSectionDscIdx < recordHeader.SectionCount; recordSectionDscIdx++) {
                var recordSectionDscBytes = new byte[recordSectionDscSize];
                for (var i = 0; i < recordSectionDscBytes.Length; i++) {
                    recordSectionDscBytes[i] = recordBytes[recordSectionDscOffset + i];
                }
                recordSectionDscOffset += recordSectionDscSize;

                WHEA_ERROR_RECORD_SECTION_DESCRIPTOR recordSectionDsc;
                var hRecordSectionDsc = GCHandle.Alloc(recordSectionDscBytes, GCHandleType.Pinned);
                try {
                    recordSectionDsc =
                        Marshal.PtrToStructure<WHEA_ERROR_RECORD_SECTION_DESCRIPTOR>(
                            hRecordSectionDsc.AddrOfPinnedObject());
                } finally {
                    hRecordSectionDsc.Free();
                }

                recordSectionDscs.Add(recordSectionDsc);
            }

            var recordSize = recordHeaderSize + (recordSectionDscs.Count * recordSectionDscSize);
            Console.Error.WriteLine($"Total size of marshaled structures: {recordSize}\n");

            var recordHeaderJson = JsonConvert.SerializeObject(recordHeader, Formatting.Indented);
            Console.Out.WriteLine(recordHeaderJson);

            foreach (var recordSectionDsc in recordSectionDscs) {
                var recordSectionDscJson = JsonConvert.SerializeObject(recordSectionDsc, Formatting.Indented);
                Console.Out.WriteLine(recordSectionDscJson);
            }
        }
    }
}
