using System;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Text;

using Newtonsoft.Json;

using static DecodeWheaRecord.Decoder;
using static DecodeWheaRecord.NativeMethods;
using static DecodeWheaRecord.Utilities;


// Mark assembly as not CLS compliant
[assembly: CLSCompliant(false)]


namespace DecodeWheaRecord {
    public static class Program {
        private static byte[] _recordBytes;

        internal static bool TestMode;

        [SuppressMessage("Design", "CA1062:Validate arguments of public methods")]
        public static void Main(string[] args) {
            if (args.Length == 0)
                ExitWithMessage($"Usage: {Assembly.GetExecutingAssembly().GetName().Name} <WheaHexRecord>");
            else if (args.Length > 1)
                ExitWithMessage($"Expected a hex encoded WHEA record but received {args.Length} arguments.", 1);
            else if (args[0].Length < 8)
                ExitWithMessage("Expected at least 8 hex characters for the 4 byte WHEA record signature.", 2);

            _recordBytes = ConvertHexToBytes(args[0]);
            byte[] signatureBytes = { _recordBytes[0], _recordBytes[1], _recordBytes[2], _recordBytes[3] };
            var signature = Encoding.ASCII.GetString(signatureBytes);

            switch (signature) {
                case WHEA_ERROR_LOG_ENTRY_SIGNATURE:
                    var recEvent = new WheaEventRecord(_recordBytes);
                    recEvent.Decode();
                    recEvent.Validate();
                    Console.Out.WriteLine(JsonConvert.SerializeObject(recEvent, Formatting.Indented));
                    break;
                case WHEA_ERROR_RECORD_SIGNATURE:
                    var recError = new WheaErrorRecord(_recordBytes);
                    recError.Decode();
                    recError.Validate();
                    Console.Out.WriteLine(JsonConvert.SerializeObject(recError, Formatting.Indented));
                    break;
                default:
                    ExitWithMessage($"Unknown WHEA record signature: {signature}", 2);
                    break;
            }

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

        public static void MainTest(string[] args) {
            /*
             * Throw an ArgumentException instead of calling Environment.Exit()
             * when ExitWithMessage() is called.
             */
            TestMode = true;

            Main(args);
        }
    }
}
