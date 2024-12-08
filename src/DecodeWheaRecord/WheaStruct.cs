using System.Runtime.InteropServices;

namespace DecodeWheaRecord {
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal abstract class WheaStruct {
        internal abstract int GetNativeSize();

        public virtual void Validate() { }
    }
}
