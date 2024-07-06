// ReSharper disable InconsistentNaming

using System;
using System.Diagnostics;

using Newtonsoft.Json;

namespace DecodeWheaRecord {
    /*
     * All credit to Dmitry Shectman
     * https://stackoverflow.com/a/43494134
     */
    public class HexStringJsonConverter : JsonConverter {
        public override bool CanConvert(Type objectType) {
            return typeof(uint) == objectType;
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer) {
            Debug.Assert(reader != null, nameof(reader) + " != null");
            var str = reader.ReadAsString();
            if (str == null || !str.StartsWith("0x", StringComparison.InvariantCulture)) {
                throw new JsonSerializationException();
            }

            return Convert.ToUInt32(str);
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer) {
            Debug.Assert(writer != null, nameof(writer) + " != null");
            writer.WriteValue($"0x{value:x}");
        }
    }
}
