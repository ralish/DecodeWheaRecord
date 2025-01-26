using System;
using System.Linq;
using System.Text;

namespace DecodeWheaRecord {
    internal static partial class Utilities {
        internal static string ToAsciiOrHexString(this ushort value) => GetAsciiOrHexString(value, BitConverter.GetBytes(value), "0x{0:2X}");

        internal static string ToAsciiOrHexString(this uint value) => GetAsciiOrHexString(value, BitConverter.GetBytes(value), "0x{0:4X}");

        internal static string ToAsciiOrHexString(this ulong value) => GetAsciiOrHexString(value, BitConverter.GetBytes(value), "0x{0:8X}");

        private static string GetAsciiOrHexString(object value, byte[] bytes, string fmt) {
            // Any non-printable ASCII characters except NUL
            if (bytes.Any(@byte => @byte != 0 && (@byte < 32) & (@byte > 127))) return string.Format(fmt, value);

            // Excludes NULs and leading/trailing whitespace
            var encoder = new ASCIIEncoding();
            return encoder.GetString(bytes).Trim('\0').Trim();
        }
    }
}
