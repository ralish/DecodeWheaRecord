using System.Globalization;
using System.Text.RegularExpressions;

namespace DecodeWheaRecord {
    internal static partial class Utilities {
        internal static byte[] ConvertHexToBytes(string hex) {
            if (hex.Length % 2 != 0) {
                ExitWithMessage($"Hexadecimal string has an odd number of characters: {hex.Length}", code: 2);
            }

            if (!Regex.IsMatch(hex, "^[0-9A-F]+$", RegexOptions.IgnoreCase)) {
                ExitWithMessage("Hexadecimal string contains invalid characters.", code: 2);
            }

            var bytes = new byte[hex.Length / 2];
            for (var i = 0; i < bytes.Length; i++) {
                var hexByte = hex.Substring(i * 2, 2);
                bytes[i] = byte.Parse(hexByte, NumberStyles.HexNumber);
            }

            return bytes;
        }
    }
}
