using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.RegularExpressions;

using DecodeWheaRecord.Errors;

namespace DecodeWheaRecord {
    internal static class Utilities {
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

        internal static void ExitUnsupportedEvent(string eventName) {
            var msg = $"The \"{eventName}\" event is not yet supported.\n\n" +
                      "Would you consider sending us the event to help us add support?\n" +
                      "https://github.com/ralish/DecodeWheaRecord/issues/new";
            ExitWithMessage(msg, code: 1);
        }

        internal static void ExitWithMessage(string msg, string category = null, int code = 0) {
            msg = category != null ? $"[{category}] {msg}" : msg;

            if (code == 0) {
                Console.Out.WriteLine(msg);
            } else {
                Console.Error.WriteLine(msg);
            }

            if (!Program.TestMode) {
                Environment.Exit(code);
            }

            throw new ArgumentException($"{msg} [rc={code}]");
        }

        internal static string GetEnabledFlagsAsString(Enum flags) {
            var enabledFlags = new List<string>();

            foreach (Enum flag in Enum.GetValues(flags.GetType())) {
                if (flags.HasFlag(flag)) {
                    enabledFlags.Add(flag.ToString());
                }
            }

            return string.Join(", ", enabledFlags);
        }

        internal static bool IsDebugBuild() {
#if DEBUG
            return false;
#else
            return false;
#endif
        }

        internal static void DebugOutput(string msg) {
            Console.Error.WriteLine(msg);
        }

        internal static void DebugOutput(string msg, string cat) {
            Console.Error.WriteLine($"[{cat}] {msg}");
        }

        internal static void DebugOutputPre(Type structType, int startOffset) {
            DebugOutput($"Start offset: {startOffset}", structType.Name);
        }

        internal static void DebugOutputPre(Type sectionType, WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc) {
            DebugOutput($"Start offset: {sectionDsc.SectionOffset} | Expected length: {sectionDsc.SectionLength}", sectionType.Name);
        }

        internal static void DebugOutputPost(Type structType, int endOffset, int structSize) {
            DebugOutput($"End offset: {endOffset} | Size: {structSize}", structType.Name);
        }

        internal static void DebugOutputPost(Type sectionType, WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, int bytesMarshalled) {
            var endOffset = sectionDsc.SectionOffset + bytesMarshalled;
            DebugOutput($"End offset: {endOffset} | Length: {bytesMarshalled}", sectionType.Name);

            var sectionLength = sectionDsc.SectionLength;
            if (sectionLength == bytesMarshalled) {
                return;
            }

            var diffStr = sectionLength > bytesMarshalled ? "greater" : "less";
            var diffSym = sectionLength > bytesMarshalled ? ">" : "<";
            var msg = $"Size of section in descriptor is {diffStr} than number of deserialized bytes: {sectionLength} {diffSym} {bytesMarshalled}";

            DebugOutput(msg, sectionType.Name);
            if (sectionLength > bytesMarshalled) {
                Environment.Exit(2);
            }

            DebugOutput("Section is likely to be partially and/or incorrectly decoded.", sectionType.Name);
        }
    }
}
