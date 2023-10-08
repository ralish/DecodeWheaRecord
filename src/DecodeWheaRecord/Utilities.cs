using System;
using System.Collections.Generic;
using System.Globalization;

namespace DecodeWheaRecord {
    internal static class Utilities {
        internal static byte[] ConvertHexToBytes(string hexString) {
            if (hexString.Length % 2 != 0)
                ExitWithMessage($"Hex string has an odd number of bytes: {hexString.Length}", 2);

            var byteArray = new byte[hexString.Length / 2];
            for (var i = 0; i < byteArray.Length; i++) {
                var hexByte = hexString.Substring(i * 2, 2);
                byteArray[i] = byte.Parse(hexByte, NumberStyles.HexNumber);
            }

            return byteArray;
        }

        internal static void ExitUnsupportedEvent(string eventName) {
            var msg = $"The \"{eventName}\" event is not yet supported.\n\n" +
                      "Would you consider sending us the event to help us add support?\n" +
                      "https://github.com/ralish/DecodeWheaRecord/issues/new";
            ExitWithMessage(msg, 1);
        }

        internal static void ExitWithMessage(string message, int code = 0) {
            if (code == 0)
                Console.Out.WriteLine(message);
            else
                Console.Error.WriteLine(message);

            if (!Program.TestMode) Environment.Exit(code);

            throw new ArgumentException($"{message} [rc={code}]");
        }

        internal static string GetEnabledFlagsAsString(Enum flags) {
            var enabledFlags = new List<string>();

            foreach (Enum flag in Enum.GetValues(flags.GetType())) {
                if (flags.HasFlag(flag))
                    enabledFlags.Add(flag.ToString());
            }

            return string.Join(", ", enabledFlags);
        }
    }
}
