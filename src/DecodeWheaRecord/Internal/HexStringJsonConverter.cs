using System;
using System.Diagnostics;
using System.IO;
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
                   typeof(BigInteger) == objectType ||
                   typeof(IntPtr) == objectType;
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
                    writer.WriteValue(Convert.ToHexString(bytes));
                    break;
                case BigInteger bigInt:
                    if (bigInt.Sign == -1) {
                        throw new InvalidDataException($"BigInteger type has a negative value: {bigInt}");
                    }

                    writer.WriteValue(bigInt.ToString("X32"));
                    break;
                case IntPtr intPtr:
                    writer.WriteValue(intPtr.ToHexString());
                    break;
                default:
                    throw new NotImplementedException();
            }
        }
    }
}
