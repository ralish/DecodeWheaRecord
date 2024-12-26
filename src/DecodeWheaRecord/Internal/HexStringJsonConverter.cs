// ReSharper disable InconsistentNaming

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Numerics;

using Newtonsoft.Json;

namespace DecodeWheaRecord.Internal {
    /*
     * Credit to Dmitry Shectman for initial implementation
     * https://stackoverflow.com/a/43494134
     */
#pragma warning disable CA1515
    public class HexStringJsonConverter : JsonConverter {
#pragma warning restore CA1515
        public override bool CanConvert(Type objectType) {
            return typeof(byte) == objectType ||
                   typeof(ushort) == objectType ||
                   typeof(uint) == objectType ||
                   typeof(ulong) == objectType ||
                   typeof(byte[]) == objectType ||
                   typeof(BigInteger) == objectType;
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer) {
            throw new NotImplementedException();
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer) {
            Debug.Assert(writer != null, nameof(writer) + " != null");

            switch (value) {
                case byte _:
                    writer.WriteValue($"0x{value:X2}");
                    break;
                case ushort _:
                    writer.WriteValue($"0x{value:X4}");
                    break;
                case uint _:
                    writer.WriteValue($"0x{value:X8}");
                    break;
                case ulong _:
                    writer.WriteValue($"0x{value:X16}");
                    break;
                case byte[] bytes:
                    writer.WriteValue(BitConverter.ToString(bytes).Replace("-", null));
                    break;
                case BigInteger bigInt:
                    if (bigInt.Sign == -1) {
                        throw new InvalidDataException($"BigInteger type has a negative value: {bigInt}");
                    }

                    var bigIntBytesRaw = bigInt.ToByteArray(); // Little-endian

                    // Check integer is not larger than a UInt128 (16 bytes)
                    if (bigIntBytesRaw.Length > 16) {
                        /*
                         * Check for the edge case where BigInteger outputs an
                         * additional zero byte to disambiguate the sign bit.
                         */
                        if (bigIntBytesRaw.Length != 17 || bigIntBytesRaw[16] != 0) {
                            throw new InvalidDataException($"BigInteger type exceeds 128-bit integer size: {bigIntBytesRaw.Length} bytes");
                        }
                    }

                    // Ensure we have exactly 16 bytes (128-bits)
                    byte[] bigIntBytesLE;
                    switch (bigIntBytesRaw.Length) {
                        case 16: // Already 16 bytes!
                            bigIntBytesLE = bigIntBytesRaw;
                            break;
                        case 17: // Truncate the last byte (see above comment)
                            bigIntBytesLE = new byte[16];
                            Buffer.BlockCopy(bigIntBytesRaw, 0, bigIntBytesLE, 0, 16);
                            break;
                        default: // Zero-extend to 16 bytes
                            bigIntBytesLE = new byte[16];
                            Buffer.BlockCopy(bigIntBytesRaw, 0, bigIntBytesLE, 0, bigIntBytesRaw.Length);
                            for (var i = bigIntBytesRaw.Length; i < bigIntBytesLE.Length; i++) bigIntBytesLE[i] = 0;
                            break;
                    }

                    // Reverse the array so bytes are in big-endian order
                    var bigIntBytesBE = bigIntBytesLE.Reverse().ToArray();

                    // Finally, convert the bytes to hex-encoded format
                    writer.WriteValue(BitConverter.ToString(bigIntBytesBE).Replace("-", null).Insert(0, "0x"));
                    break;
                default:
                    throw new NotImplementedException();
            }
        }
    }
}
