using System;
using System.Collections.Generic;
using System.Globalization;


namespace DecodeWheaRecord {
    internal static class Utilities {
        internal static byte[] ConvertHexToBytes(string hexString) {
            if (hexString.Length % 2 != 0) {
                throw new ArgumentException("Hex string has an odd number of bytes.");
            }

            var byteArray = new byte[hexString.Length / 2];
            for (var i = 0; i < byteArray.Length; i++) {
                var hexByte = hexString.Substring(i * 2, 2);
                byteArray[i] = byte.Parse(hexByte, NumberStyles.HexNumber);
            }

            return byteArray;
        }

        internal static string GetEnabledFlagsAsString(Enum flags) {
            var enabledFlags = new List<string>();

            foreach (Enum flag in Enum.GetValues(flags.GetType())) {
                var flagName = flag.ToString();

                if (flags.HasFlag(flag)) {
                    enabledFlags.Add(flagName);
                }
            }

            return string.Join(", ", enabledFlags);
        }
    }
}
