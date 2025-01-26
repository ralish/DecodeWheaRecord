/*
 * The minimal interface implemented by all WHEA error and event structures
 * which are marshalled without being encapsulated in another WHEA structure.
 *
 * The problem this solves is that many WHEA structures are of a variable size
 * and so their "native" size can't be determined by calling Marshal.SizeOf().
 * This interface ensures a consistent method to get the WHEA structure size.
 *
 * We need to know the "native" size of these structures primarily for:
 * - Basic error checking; e.g. were the correct number of bytes deserialized
 *   and are there "residual" bytes in the WHEA record that may be important.
 * - Calculating the offset at which to deserialize a structure, particularly
 *   in the case of variable length arrays of a given WHEA structure type.
 */

namespace DecodeWheaRecord.Internal {
    internal interface IWheaRecord {
        uint GetNativeSize();
    }
}
