#pragma warning disable CS0649 // Field is never assigned to

// ReSharper disable InconsistentNaming

using System.Runtime.InteropServices;

namespace DecodeWheaRecord.Events.Software {
    /*
     * Module:          ntoskrnl.exe
     * Version:         10.0.26100.2314
     * Function(s):     IoSaveBugCheckProgress
     */
    // TODO: Not certain about above function
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_SEL_BUGCHECK_PROGRESS : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_SEL_BUGCHECK_PROGRESS>(); // 8 bytes

        public uint BugCheckCode;
        public uint BugCheckProgressSummary;
    }
}
