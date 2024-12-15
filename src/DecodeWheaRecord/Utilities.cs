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

        #region Logging helpers

        private static string FormatMessage(string level, string cat, string msg, uint depth = 0) {
            if (depth != 0 && !string.IsNullOrWhiteSpace(cat)) {
                cat = $"{new string(' ', (int)depth * 2)}{cat}";
            }

            return string.IsNullOrWhiteSpace(cat) ? $"[{level,-5}] {msg}" : $"[{level,-5}] {cat,-50} {msg}";
        }

        internal static string DebugMessage(string msg, string cat = null, uint depth = 0) {
            return FormatMessage("DEBUG", cat, msg, depth);
        }

        internal static void DebugOutput(string msg, string cat = null, uint depth = 0) {
            Console.Error.WriteLine(DebugMessage(msg, cat, depth));
        }

        internal static string ErrorMessage(string msg, string cat = null, uint depth = 0) {
            return FormatMessage("ERROR", cat, msg, depth);
        }

        internal static void ErrorOutput(string msg, string cat = null, uint depth = 0) {
            Console.Error.WriteLine(ErrorMessage(msg, cat, depth));
        }

        internal static string InfoMessage(string msg, string cat = null, uint depth = 0) {
            return FormatMessage("INFO", cat, msg, depth);
        }

        internal static void InfoOutput(string msg, string cat = null, uint depth = 0) {
            Console.Error.WriteLine(InfoMessage(msg, cat, depth));
        }

        internal static string WarnMessage(string msg, string cat = null, uint depth = 0) {
            return FormatMessage("WARN", cat, msg, depth);
        }

        internal static void WarnOutput(string msg, string cat = null, uint depth = 0) {
            Console.Error.WriteLine(WarnMessage(msg, cat, depth));
        }

        #endregion


        internal static void DebugAfterDecode(Type structType, int endOffset, int structSize) {
            DebugOutput($"End offset: {endOffset} | Size: {structSize}", structType.Name);
        }

        internal static void DebugAfterDecode(Type sectionType, WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, int bytesMarshalled) {
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

        internal static void DebugBeforeDecode(Type structType, int startOffset) {
            DebugOutput($"Start offset: {startOffset}", structType.Name);
        }

        internal static void DebugBeforeDecode(Type sectionType, WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc) {
            DebugOutput($"Start offset: {sectionDsc.SectionOffset} | Expected length: {sectionDsc.SectionLength}", sectionType.Name);
        }

        // TODO: Custom exception
        internal static void ValidateSufficientRecordBytes(Type sectionType, uint requiredBytes, uint remainingBytes) {
            if (remainingBytes < requiredBytes) {
                var msg = $"{sectionType.Name} section is {requiredBytes} bytes but only {remainingBytes} bytes remaining in record.";
                throw new ArgumentOutOfRangeException(msg);
            }
        }
    }
}
