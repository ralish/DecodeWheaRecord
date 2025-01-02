using System;
using System.Diagnostics;
using System.Numerics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

using DecodeWheaRecord.Errors;
using DecodeWheaRecord.Events;
using DecodeWheaRecord.Hardware;
using DecodeWheaRecord.Internal;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

// Mark assembly as not CLS compliant
[assembly: CLSCompliant(false)]

namespace DecodeWheaRecord {
    public static class Program {
        internal static bool TestMode;

        public static void Main(string[] args) {
            Debug.Assert(args != null, nameof(args) + " != null");
            ValidateArgs(args);

            var recordBytes = ConvertHexToBytes(args[0]);
            var recordHandle = GCHandle.Alloc(recordBytes, GCHandleType.Pinned);
            var recordAddr = recordHandle.AddrOfPinnedObject();

            byte[] signatureBytes = { recordBytes[0], recordBytes[1], recordBytes[2], recordBytes[3] };
            var signature = Encoding.ASCII.GetString(signatureBytes);

            switch (signature) {
                case WHEA_EVENT_LOG_ENTRY_HEADER.WHEA_ERROR_LOG_ENTRY_SIGNATURE:
                    DebugOutput($"Found signature: {signature}");
                    var eventLogEntry = new WHEA_EVENT_LOG_ENTRY(recordBytes);
                    Console.Out.WriteLine(JsonConvert.SerializeObject(eventLogEntry, Formatting.Indented));
                    break;
                case WHEA_ERROR_RECORD_HEADER.WHEA_ERROR_RECORD_SIGNATURE:
                    DebugOutput($"Found signature: {signature}");
                    var errorRecord = new WHEA_ERROR_RECORD(recordAddr, (uint)recordBytes.Length);
                    Console.Out.WriteLine(JsonConvert.SerializeObject(errorRecord, Formatting.Indented));
                    break;
                default:
                    ExitWithMessage($"Unknown WHEA record signature: {signature}", code: 2);
                    break;
            }

            //_recordHandle.Free();

            /*
            var remainingBytes = _recordBytes.Length - _recordOffset;
            if (remainingBytes == 0) return;

            var allBytesZero = true;
            for (var i = _recordOffset; i < _recordBytes.Length; i++) {
                if (_recordBytes[i] == 0) continue;

                allBytesZero = false;
                break;
            }

            Console.Error.WriteLine(allBytesZero
                                        ? $"Ignoring remaining {remainingBytes} bytes (all zero)."
                                        : $"{remainingBytes} remaining bytes were not processed.");
            */
        }

        /*
         * When running tests, throw an ArgumentException instead of calling
         * Environment.Exit() when ExitWithMessage() is called.
         */
        public static void MainTest(string[] args) {
            TestMode = true;
            Main(args);
        }

        private static void ValidateArgs(string[] args) {
            if (args.Length == 0) {
                ExitWithMessage($"Usage: {Assembly.GetExecutingAssembly().GetName().Name} <WheaHexRecord>");
            }

            if (args.Length > 1) {
                ExitWithMessage($"Expected a single argument but received {args.Length}.", code: 1);
            }

            // WHEA records begin with a 4 byte signature
            if (args[0].Length <= 8) {
                ExitWithMessage($"Expected at least 8 hexadecimal characters but received {args[0].Length}.", code: 1);
            }
        }
    }
}
