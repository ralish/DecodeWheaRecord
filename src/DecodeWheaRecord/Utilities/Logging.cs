using System;

namespace DecodeWheaRecord {
    internal static partial class Utilities {
        internal static void DebugOutput(string msg, string cat = null, uint depth = 0) => Console.Error.WriteLine(FormatMessage("DEBUG", cat, msg, depth));

        internal static void ErrorOutput(string msg, string cat = null, uint depth = 0) => Console.Error.WriteLine(FormatMessage("ERROR", cat, msg, depth));

        internal static void InfoOutput(string msg, string cat = null, uint depth = 0) => Console.Error.WriteLine(FormatMessage("INFO", cat, msg, depth));

        internal static void WarnOutput(string msg, string cat = null, uint depth = 0) => Console.Error.WriteLine(FormatMessage("WARN", cat, msg, depth));

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

        private static string FormatMessage(string level, string cat, string msg, uint depth = 0) {
            if (depth != 0 && !string.IsNullOrWhiteSpace(cat)) {
                cat = $"{new string(' ', (int)depth * 2)}{cat}";
            }

            return string.IsNullOrWhiteSpace(cat) ? $"[{level,-5}] {msg}" : $"[{level,-5}] {cat,-50} {msg}";
        }
    }
}
