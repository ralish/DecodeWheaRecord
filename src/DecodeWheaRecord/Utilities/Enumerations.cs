using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace DecodeWheaRecord {
    internal static partial class Utilities {
        internal static string GetEnumFlagsAsString(Enum flags) {
            var enumType = flags.GetType();
            var enumSize = Marshal.SizeOf(Enum.GetUnderlyingType(enumType));

            var flagsAsUInt64 = Convert.ToUInt64(flags);
            var flagsEnabled = new List<string>();

            for (var bitNum = 0; bitNum < enumSize * 8; bitNum++) {
                if ((flagsAsUInt64 & 1) != 0) {
                    string flagName;
                    var flagValue = (ulong)Math.Pow(2, bitNum);

                    switch (enumSize) {
                        case 1: // 8 bits
                            flagName = Enum.GetName(enumType, (byte)flagValue);
                            break;
                        case 2: // 16 bits
                            flagName = Enum.GetName(enumType, (ushort)flagValue);
                            break;
                        case 4: // 32 bits
                            flagName = Enum.GetName(enumType, (uint)flagValue);
                            break;
                        case 8: // 64 bits
                            flagName = Enum.GetName(enumType, flagValue);
                            break;
                        default:
                            throw new NotImplementedException();
                    }

                    if (flagName == null) {
                        flagName = $"Bit {bitNum} (Unknown)";
                    }

                    flagsEnabled.Add(flagName);
                }

                flagsAsUInt64 >>= 1;
            }

            return string.Join(", ", flagsEnabled);
        }

        internal static string GetEnumValueAsString<T>(object value) => Enum.GetName(typeof(T), value) ?? $"Unknown value ({value})";
    }
}
