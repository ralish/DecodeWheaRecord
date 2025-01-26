using System;

namespace DecodeWheaRecord {
    internal static partial class Utilities {
        private static readonly char[] TrimZeroes = { '0' };

        internal static string ToHexString(this IntPtr ptr, bool trimLeadingZeroes = false) {
            string str;

            switch (IntPtr.Size) {
                case 4:
                    str = $"{(ulong)ptr:X8}";
                    break;
                case 8:
                    // Filthy hack to get the unsigned value
                    var uptr = BitConverter.ToUInt64(BitConverter.GetBytes(ptr.ToInt64()), 0);
                    str = $"{uptr:X16}";
                    break;
                default:
                    throw new NotImplementedException();
            }

            if (trimLeadingZeroes) {
                str = str.TrimStart(TrimZeroes);
            }

            return $"0x{str}";
        }
    }
}
