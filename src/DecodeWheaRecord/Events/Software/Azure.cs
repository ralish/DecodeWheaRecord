#pragma warning disable CS0649 // Field is never assigned to

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable InconsistentNaming

using System.Runtime.InteropServices;

using DecodeWheaRecord.Internal;

namespace DecodeWheaRecord.Events.Software {
    /*
     * Entry ID:        AzccRootBusSearchErr
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPiHsxFindRootBusNumbers
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_AZCC_ROOT_BUS_ERR_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_AZCC_ROOT_BUS_ERR_EVENT>(); // 2 bytes

        [MarshalAs(UnmanagedType.U1)]
        public bool MaxBusCountPassed;

        [MarshalAs(UnmanagedType.U1)]
        public bool InvalidBusMSR;
    }

    /*
     * Entry ID:        AzccRootBusList
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPiHsxFindRootBusNumbers
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_AZCC_ROOT_BUS_LIST_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_AZCC_ROOT_BUS_LIST_EVENT>(); // 36 bytes

        public uint RootBusCount;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public uint[] RootBuses;
    }

    /*
     * Entry ID:        AzccRootBusPoisonSet
     * Module:          AzPshedPi.sys
     * Version:         11.0.2404.15001
     * Function(s):     PshedPiHsxSetPoisonSev
     *                  PshedPiHsxUnsetPoisonSev
     */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal sealed class WHEA_AZCC_SET_POISON_EVENT : IWheaRecord {
        public uint GetNativeSize() => (uint)Marshal.SizeOf<WHEA_AZCC_SET_POISON_EVENT>(); // 7 bytes

        public uint Bus;

        [MarshalAs(UnmanagedType.U1)]
        public bool ReadSuccess;

        [MarshalAs(UnmanagedType.U1)]
        public bool WriteSuccess;

        [MarshalAs(UnmanagedType.U1)]
        public bool IsEnable;
    }
}
