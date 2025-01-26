// ReSharper disable InconsistentNaming

using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

using DecodeWheaRecord.Descriptors;
using DecodeWheaRecord.Errors.UEFI;
using DecodeWheaRecord.Hardware;
using DecodeWheaRecord.Internal;
using DecodeWheaRecord.Shared;

using JetBrains.Annotations;

using Newtonsoft.Json;

using static DecodeWheaRecord.Utilities;

/*
 * Module       Version             Arch(s)         Function(s)
 * AzPshedPi    11.0.2404.15001     AMD64           PshedPiCommonFinalize
 * ntoskrnl     10.0.26100.2605     AMD64           HalpCreateMcaMemoryErrorRecord
 *                                  AMD64           HalpCreateMcaProcessorErrorRecord
 *                                  AMD64 / Arm64   HalpCreateNMIErrorRecord
 *                                  AMD64 / Arm64   WheaGetErrPacketFromErrRecord
 *                                  AMD64 / Arm64   WheapAddRecoveryPacketToErrorRecord
 *                                  AMD64 / Arm64   WheapCompressErrorRecord
 * pci          10.0.26100.2454     AMD64 / Arm64   PciWheaCreateErrorRecord
 *                                  AMD64           WheaGetErrPacketFromErrRecord
 * pshed        10.0.26100.1150     AMD64           PshedpPopulateRecoverySection
 * RADARM       10.0.26100.1        Arm64           RadArmSeaCreateErrorRecord
 */
namespace DecodeWheaRecord.Errors.Microsoft {
    internal static class WHEA_ERROR_PACKET {
        // Signature is the first 4 bytes in both structure versions
        private const uint MinSignatureBytes = 4;

        /*
         * Values are reversed from header definitions as validation is
         * performed against the fields as a string instead of an integer.
         */
        private const string WHEA_ERROR_PACKET_V1_SIGNATURE = "ErPt";
        private const string WHEA_ERROR_PACKET_V2_SIGNATURE = "WHEA";

        public static WheaRecord CreateBySignature(IntPtr recordAddr, uint structOffset, uint bytesRemaining) {
            var signature = GetSignature(recordAddr, structOffset, bytesRemaining);

            switch (signature) {
                case WHEA_ERROR_PACKET_V1_SIGNATURE:
                    return new WHEA_ERROR_PACKET_V1(recordAddr, structOffset, bytesRemaining);
                case WHEA_ERROR_PACKET_V2_SIGNATURE:
                    return new WHEA_ERROR_PACKET_V2(recordAddr, structOffset, bytesRemaining);
                default:
                    throw new InvalidDataException($"Unknown signature: {signature}");
            }
        }

        public static WheaRecord CreateBySignature(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) {
            var signature = GetSignature(recordAddr, sectionDsc.SectionOffset, bytesRemaining);

            switch (signature) {
                case WHEA_ERROR_PACKET_V1_SIGNATURE:
                    return new WHEA_ERROR_PACKET_V1(sectionDsc, recordAddr, bytesRemaining);
                case WHEA_ERROR_PACKET_V2_SIGNATURE:
                    return new WHEA_ERROR_PACKET_V2(sectionDsc, recordAddr, bytesRemaining);
                default:
                    throw new InvalidDataException($"Unknown signature: {signature}");
            }
        }

        private static string GetSignature(IntPtr recordAddr, uint structOffset, uint bytesRemaining) {
            if (bytesRemaining < MinSignatureBytes) {
                var msg = $"Expected at least {MinSignatureBytes} bytes for the structure signature.";
                throw new ArgumentOutOfRangeException(nameof(bytesRemaining), msg);
            }

            var signatureAddr = recordAddr + (int)structOffset;
            var signatureBytes = (uint)Marshal.ReadInt32(signatureAddr);
            return signatureBytes.ToAsciiOrHexString();
        }
    }

    // Windows Server 2008 & Windows Vista SP1+
    internal sealed class WHEA_ERROR_PACKET_V1 : WheaRecord {
        public override uint GetNativeSize() => Size;

        /*
         * Size up to and including the RawDataOffset field. The embedded
         * WHEA_*_ERROR_SECTION structures vary in size but occupy a union.
         */
        private const uint MinStructSize = 280;

        // Offset of the error structure (type subject to the ErrorType field)
        private const uint ErrorTypeStructOffset = 64;

        // Size of the union for error type structures
        private const uint ErrorTypeUnionSize = 208;

        private const int WHEA_ERROR_PACKET_V1_VERSION = 2; // Not a typo

        private uint _Signature;

        [JsonProperty(Order = 1)]
        public string Signature => _Signature.ToAsciiOrHexString();

        private WHEA_ERROR_PACKET_FLAGS _Flags;

        [JsonProperty(Order = 2)]
        public string Flags => GetEnumFlagsAsString(_Flags);

        /*
         * Size of the hardware error packet including the raw data (the
         * RawDataLength field).
         */
        [JsonProperty(Order = 3)]
        public uint Size;

        /*
         * Length of the raw hardware error information contained in the
         * RawData field in the original structure. The RawData field is
         * separated into multiple fields in this implementation. See the
         * comment on the Data field for further details.
         */
        [JsonProperty(Order = 4)]
        public uint RawDataLength;

        [JsonProperty(Order = 5)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Reserved1;

        [JsonProperty(Order = 6)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Context;

        private WHEA_ERROR_TYPE _ErrorType;

        [JsonProperty(Order = 7)]
        public string ErrorType => GetEnumValueAsString<WHEA_ERROR_TYPE>(_ErrorType);

        private WHEA_ERROR_SEVERITY _ErrorSeverity;

        [JsonProperty(Order = 8)]
        public string ErrorSeverity => GetEnumValueAsString<WHEA_ERROR_SEVERITY>(_ErrorSeverity);

        [JsonProperty(Order = 9)]
        public uint ErrorSourceId;

        private WHEA_ERROR_SOURCE_TYPE _ErrorSourceType;

        [JsonProperty(Order = 10)]
        public string ErrorSourceType => GetEnumValueAsString<WHEA_ERROR_SOURCE_TYPE>(_ErrorSourceType);

        [JsonProperty(Order = 11)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Reserved2;

        [JsonProperty(Order = 12)]
        public uint Version;

        [JsonProperty(Order = 13)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Cpu;

        [JsonProperty(Order = 14)]
        public WHEA_PROCESSOR_GENERIC_ERROR_SECTION ProcessorError;

        [JsonProperty(Order = 14)]
        public WHEA_MEMORY_ERROR_SECTION MemoryError;

        [JsonProperty(Order = 14)]
        public WHEA_NMI_ERROR_SECTION NmiError;

        [JsonProperty(Order = 14)]
        public WHEA_PCIEXPRESS_ERROR_SECTION PciExpressError;

        [JsonProperty(Order = 14)]
        public WHEA_PCIXBUS_ERROR_SECTION PciXBusError;

        [JsonProperty(Order = 14)]
        public WHEA_PCIXDEVICE_ERROR_SECTION PciXDeviceError;

        [JsonProperty(Order = 14)]
        public WHEA_PMEM_ERROR_SECTION PmemError;

        /*
         * Not part of the original structure. We define this field to store
         * unused bytes for error types with a structure which does not fill
         * the entire union. It is only output if there are non-zero bytes.
         */
        [JsonProperty(Order = 15)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] ErrorTypeUnusedBytes;

        private WHEA_RAW_DATA_FORMAT _RawDataFormat;

        [JsonProperty(Order = 16)]
        public string RawDataFormat => GetEnumValueAsString<WHEA_RAW_DATA_FORMAT>(_RawDataFormat);

        /*
         * Offset from the beginning of what was originally the RawData buffer
         * where a PSHED plugin can add supplementary platform-specific data.
         * The amount of data that can be added is limited by the Size field.
         *
         * See the comments on the RawDataLength and Data fields for further
         * information on how the data in the referenced buffer is marshalled.
         */
        [JsonProperty(Order = 17)]
        public uint RawDataOffset;

        /*
         * The original structure defines a RawData field as a byte array
         * containing "raw" error data *and* "supplementary platform-specific
         * data" which is optionally added by a PSHED plugin. This approach is
         * one of many reasons why this structure is a design disaster; a fact
         * Microsoft apparently recognised given they completely changed it
         * in the next Windows release, giving the v2 error packet structure.
         *
         * When marshalling the data in what was the RawData field we separate
         * out the raw error data from any PSHED plugin data, emulating the v2
         * error packet approach. If the raw error data is in a format which
         * can be marshalled to a specific structure, as determined by the
         * RawDataFormat field, we'll do so and store it in one of the added
         * fields below. If not, we'll just marshal the data as a byte array.
         *
         * Any PSHED plugin data is stored in the added PshedData byte array.
         */
        [JsonProperty(Order = 18)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] Data = Array.Empty<byte>();

        /*
         * Per the above comment, these fields have been added to allow for the
         * marshalling of raw error data to a supported structure if possible.
         */

        [JsonProperty(Order = 18)]
        public MCA_EXCEPTION DataMcaException;

        [JsonProperty(Order = 18)]
        public PCI_EXPRESS_AER_CAPABILITY DataAerInfo;

        [JsonProperty(Order = 18)]
        public WHEA_GENERIC_ERROR DataGenericError;

        /*
         * Not part of the original structure. We define this field to store
         * unused bytes which exist after the marshalled raw error data but
         * before any PSHED plugin data. This is implicitly only possible if
         * marshalling the data to a supported error data structure instead of
         * as a byte array. It is only output if there are non-zero bytes.
         */
        [JsonProperty(Order = 19)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] DataUnusedBytes;

        /*
         * Stores any PSHED plugin data that resides at the end of the RawData
         * buffer in the original structure definition. See the earlier comment
         * for the Data field for more details.
         */
        [JsonProperty(Order = 20)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] PshedData = Array.Empty<byte>();

        public WHEA_ERROR_PACKET_V1(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_ERROR_PACKET_V1), structOffset, MinStructSize, bytesRemaining) {
            WheaErrorPacketV1(recordAddr, structOffset, bytesRemaining);
        }

        public WHEA_ERROR_PACKET_V1(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(typeof(WHEA_ERROR_PACKET_V1), sectionDsc, MinStructSize, bytesRemaining) {
            WheaErrorPacketV1(recordAddr, sectionDsc.SectionOffset, sectionDsc.SectionLength);
        }

        private void WheaErrorPacketV1(IntPtr recordAddr, uint structOffset, uint bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            // Verified previously in CreateBySignature
            _Signature = (uint)Marshal.ReadInt32(structAddr);

            _Flags = (WHEA_ERROR_PACKET_FLAGS)Marshal.ReadInt32(structAddr, 4);
            Size = (uint)Marshal.ReadInt32(structAddr, 8);

            if (Size < MinStructSize) {
                var checkCalc = $"{Size} < {MinStructSize}";
                throw new InvalidDataException($"{nameof(Size)} is less than minimum structure size: {checkCalc}");
            }

            if (Size > bytesRemaining) {
                var checkCalc = $"{Size} > {bytesRemaining}";
                throw new InvalidDataException($"{nameof(Size)} is greater than bytes remaining: {checkCalc}");
            }

            RawDataLength = (uint)Marshal.ReadInt32(structAddr, 12);

            if (MinStructSize + RawDataLength > Size) {
                var checkCalc = $"{MinStructSize} + {RawDataLength} > {Size}";
                throw new InvalidDataException($"{nameof(RawDataLength)} results in size greater than structure size: {checkCalc}");
            }

            Reserved1 = (ulong)Marshal.ReadInt64(structAddr, 16);
            Context = (ulong)Marshal.ReadInt64(structAddr, 24);
            _ErrorType = (WHEA_ERROR_TYPE)Marshal.ReadInt32(structAddr, 32);
            _ErrorSeverity = (WHEA_ERROR_SEVERITY)Marshal.ReadInt32(structAddr, 36);
            ErrorSourceId = (uint)Marshal.ReadInt32(structAddr, 40);
            _ErrorSourceType = (WHEA_ERROR_SOURCE_TYPE)Marshal.ReadInt32(structAddr, 44);
            Reserved2 = (uint)Marshal.ReadInt32(structAddr, 48);
            Version = (uint)Marshal.ReadInt32(structAddr, 52);

            if (Version != WHEA_ERROR_PACKET_V1_VERSION) {
                throw new InvalidDataException($"Expected {nameof(Version)} to be {WHEA_ERROR_PACKET_V1_VERSION} but found: {Version}");
            }

            Cpu = (ulong)Marshal.ReadInt64(structAddr, 56);

            uint errorTypeStructSize = 0;
            switch (_ErrorType) {
                case WHEA_ERROR_TYPE.Processor:
                    ProcessorError = new WHEA_PROCESSOR_GENERIC_ERROR_SECTION(recordAddr, ErrorTypeStructOffset, ErrorTypeUnionSize);
                    errorTypeStructSize = ProcessorError.GetNativeSize();
                    break;
                case WHEA_ERROR_TYPE.Memory:
                    /*
                     * The WHEA_MEMORY_ERROR_SECTION structure had additional
                     * fields added to the end of the structure in Windows 10,
                     * version 1803. The presence of these fields can only be
                     * determined by the size of the structure, which is a bit
                     * problematic as we're embedded in a union which will have
                     * plenty of unused bytes when this structure is present.
                     *
                     * Because the WHEA_ERROR_PACKET_V1 structure is limited to
                     * only Windows Server 2008 and Windows Vista we know that
                     * if the structure is present it must not have the newer
                     * appended fields, so we "hint" this to the constructor by
                     * capping bytesRemaining to the original structure size.
                     */
                    MemoryError = new WHEA_MEMORY_ERROR_SECTION(recordAddr, ErrorTypeStructOffset, WHEA_MEMORY_ERROR_SECTION.MinStructSize);
                    errorTypeStructSize = MemoryError.GetNativeSize();
                    break;
                case WHEA_ERROR_TYPE.NMI:
                    NmiError = new WHEA_NMI_ERROR_SECTION(recordAddr, ErrorTypeStructOffset, ErrorTypeUnionSize);
                    errorTypeStructSize = NmiError.GetNativeSize();
                    break;
                case WHEA_ERROR_TYPE.PCIExpress:
                    PciExpressError = new WHEA_PCIEXPRESS_ERROR_SECTION(recordAddr, ErrorTypeStructOffset, ErrorTypeUnionSize);
                    errorTypeStructSize = PciExpressError.GetNativeSize();
                    break;
                case WHEA_ERROR_TYPE.PCIXBus:
                    PciXBusError = new WHEA_PCIXBUS_ERROR_SECTION(recordAddr, ErrorTypeStructOffset, ErrorTypeUnionSize);
                    errorTypeStructSize = PciXBusError.GetNativeSize();
                    break;
                case WHEA_ERROR_TYPE.PCIXDevice:
                    PciXDeviceError = new WHEA_PCIXDEVICE_ERROR_SECTION(recordAddr, ErrorTypeStructOffset, ErrorTypeUnionSize);
                    errorTypeStructSize = PciXDeviceError.GetNativeSize();
                    break;
                case WHEA_ERROR_TYPE.Pmem:
                    PmemError = new WHEA_PMEM_ERROR_SECTION(recordAddr, ErrorTypeStructOffset, ErrorTypeUnionSize);
                    errorTypeStructSize = PmemError.GetNativeSize();
                    break;
                case WHEA_ERROR_TYPE.Generic: // TODO: No associated structure?
                    break;
                default:
                    throw new InvalidDataException($"{nameof(ErrorType)} is unknown or invalid: {ErrorType}");
            }

            var errorTypeBytesUnused = ErrorTypeUnionSize - errorTypeStructSize;
            if (errorTypeBytesUnused != 0) {
                ErrorTypeUnusedBytes = new byte[errorTypeBytesUnused];
                Marshal.Copy(structAddr + (int)ErrorTypeStructOffset + (int)errorTypeStructSize, ErrorTypeUnusedBytes, 0, (int)errorTypeBytesUnused);

                if (ErrorTypeUnusedBytes.Any(element => element != 0)) {
                    WarnOutput($"{nameof(ErrorTypeUnusedBytes)} has non-zero bytes.", StructType.Name);
                }
            }

            _RawDataFormat = (WHEA_RAW_DATA_FORMAT)Marshal.ReadInt32(structAddr, 272);
            RawDataOffset = (uint)Marshal.ReadInt32(structAddr, 276);

            if (RawDataOffset > RawDataLength) {
                var checkCalc = $"{RawDataOffset} > {RawDataLength}";
                throw new InvalidDataException($"{nameof(RawDataOffset)} is beyond the RawData buffer: {checkCalc}");
            }

            /*
             * The implementation in this block may at first look wrong but is
             * (hopefully) correct. Note that the RawDataOffset field is very
             * misleadingly named. See the comment on it earlier for details.
             * Also, be sure to at least read the comment for the Data field.
             *
             * Note as well that the Size, RawDataLength, and RawDataOffset
             * fields have all been validated by the time we reach this point.
             *
             * First things first: is there any data in the RawData buffer in
             * the original structure definition?
             */
            if (RawDataLength > 0) {
                /*
                 * The offset from the beginning of the RawData buffer where a
                 * PSHED plugin can add its own data. My interpretation is this
                 * implies a non-zero value if there's any non-PSHED data.
                 */
                if (RawDataOffset > 0) {
                    var dataLength = RawDataOffset;
                    // ReSharper disable once SwitchStatementHandlesSomeKnownEnumValuesWithDefault
                    switch (_RawDataFormat) {
                        case WHEA_RAW_DATA_FORMAT.IA32MCA:
                        case WHEA_RAW_DATA_FORMAT.Intel64MCA:
                        case WHEA_RAW_DATA_FORMAT.AMD64MCA:
                            dataLength = DataMcaException.GetNativeSize();
                            CheckSufficientBytes(dataLength, RawDataOffset);
                            DataMcaException = PtrToStructure<MCA_EXCEPTION>(structAddr + (int)MinStructSize);
                            Data = null;
                            break;
                        case WHEA_RAW_DATA_FORMAT.PCIExpress:
                            dataLength = (uint)Marshal.SizeOf<PCI_EXPRESS_AER_CAPABILITY>();
                            CheckSufficientBytes(dataLength, RawDataOffset);
                            DataAerInfo = PtrToStructure<PCI_EXPRESS_AER_CAPABILITY>(structAddr + (int)MinStructSize);
                            Data = null;
                            break;
                        case WHEA_RAW_DATA_FORMAT.Generic:
                            DataGenericError = new WHEA_GENERIC_ERROR(recordAddr, structOffset + RawDataOffset, RawDataOffset);
                            Data = null;
                            break;
                        default:
                            Data = new byte[RawDataOffset];
                            Marshal.Copy(structAddr + (int)MinStructSize, Data, 0, (int)RawDataOffset);
                            WarnOutput($"{RawDataFormat} is an unsupported type and will be output in hexadecimal.", StructType.Name);
                            break;
                    }

                    if (dataLength < RawDataOffset) {
                        var dataBytesUnused = RawDataOffset - dataLength;
                        DataUnusedBytes = new byte[dataBytesUnused];
                        Marshal.Copy(structAddr + (int)MinStructSize + (int)dataLength, DataUnusedBytes, 0, (int)dataBytesUnused);

                        if (DataUnusedBytes.Any(element => element != 0)) {
                            WarnOutput($"{nameof(DataUnusedBytes)} has non-zero bytes.", StructType.Name);
                        }
                    }
                }

                /*
                 * The existence of PSHED data should(?) imply an offset that
                 * is less than the total size of the RawData buffer. We can't
                 * marshal this data to anything other than a byte aray, so we
                 * don't have to be concerned about any "unused" bytes.
                 */
                if (RawDataOffset < RawDataLength) {
                    var pshedDataLength = RawDataLength - RawDataOffset;
                    PshedData = new byte[pshedDataLength];
                    Marshal.Copy(structAddr + (int)MinStructSize + (int)RawDataOffset, PshedData, 0, (int)pshedDataLength);
                }
            }

            FinalizeRecord(recordAddr, Size);
        }

        private static void CheckSufficientBytes(uint bytesRequired, uint bytesRemaining) {
            if (MinStructSize + bytesRequired <= bytesRemaining) return;

            var checkCalc = $"{MinStructSize} + {bytesRequired} > {bytesRemaining}";
            throw new InvalidDataException($"Raw data structure is larger than bytes remaining: {checkCalc}");
        }

        [UsedImplicitly]
        public bool ShouldSerializeReserved1() => Reserved1 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeReserved2() => Reserved2 != 0;

        [UsedImplicitly]
        public bool ShouldSerializeErrorTypeUnusedBytes() => ErrorTypeUnusedBytes != null && ErrorTypeUnusedBytes.Any(element => element != 0);

        [UsedImplicitly]
        public bool ShouldSerializeDataUnusedBytes() => DataUnusedBytes != null && DataUnusedBytes.Any(element => element != 0);
    }

    // Windows Server 2008 R2, Windows 7, and later
    internal sealed class WHEA_ERROR_PACKET_V2 : WheaRecord {
        public override uint GetNativeSize() => Length;

        // Size up to and including the PshedDataLength field
        private const uint MinStructSize = 80;

        private const int WHEA_ERROR_PACKET_V2_VERSION = 3; // Not a typo

        private uint _Signature;

        [JsonProperty(Order = 1)]
        public string Signature => _Signature.ToAsciiOrHexString();

        [JsonProperty(Order = 2)]
        public uint Version;

        /*
         * Size of the hardware error packet including the data (the DataLength
         * field) and the PSHED data (the PshedDataLength field).
         */
        [JsonProperty(Order = 3)]
        public uint Length;

        private WHEA_ERROR_PACKET_FLAGS _Flags;

        [JsonProperty(Order = 4)]
        public string Flags => GetEnumFlagsAsString(_Flags);

        private WHEA_ERROR_TYPE _ErrorType;

        [JsonProperty(Order = 5)]
        public string ErrorType => GetEnumValueAsString<WHEA_ERROR_TYPE>(_ErrorType);

        private WHEA_ERROR_SEVERITY _ErrorSeverity;

        [JsonProperty(Order = 6)]
        public string ErrorSeverity => GetEnumValueAsString<WHEA_ERROR_SEVERITY>(_ErrorSeverity);

        [JsonProperty(Order = 7)]
        public uint ErrorSourceId;

        private WHEA_ERROR_SOURCE_TYPE _ErrorSourceType;

        [JsonProperty(Order = 8)]
        public string ErrorSourceType => GetEnumValueAsString<WHEA_ERROR_SOURCE_TYPE>(_ErrorSourceType);

        private Guid _NotifyType;

        [JsonProperty(Order = 9)]
        public string NotifyType => WheaGuids.NotifyTypes.TryGetValue(_NotifyType, out var notifyType) ? notifyType : _NotifyType.ToString();

        [JsonProperty(Order = 10)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong Context;

        private WHEA_ERROR_PACKET_DATA_FORMAT _DataFormat;

        [JsonProperty(Order = 11)]
        public string DataFormat => GetEnumValueAsString<WHEA_ERROR_PACKET_DATA_FORMAT>(_DataFormat);

        [JsonProperty(Order = 12)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public uint Reserved1;

        // Offset of the Data buffer from the beginning of the structure
        [JsonProperty(Order = 13)]
        public uint DataOffset;

        // Length of the Data buffer
        [JsonProperty(Order = 14)]
        public uint DataLength;

        // Offset of the PshedData buffer from the beginning of the structure
        [JsonProperty(Order = 15)]
        public uint PshedDataOffset;

        // Length of the PshedData buffer
        [JsonProperty(Order = 16)]
        public uint PshedDataLength;

        [JsonProperty(Order = 17)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] Data; // TODO: Deserialize

        [JsonProperty(Order = 18)]
        [JsonConverter(typeof(HexStringJsonConverter))]
        public byte[] PshedData;

        public WHEA_ERROR_PACKET_V2(IntPtr recordAddr, uint structOffset, uint bytesRemaining) :
            base(typeof(WHEA_ERROR_PACKET_V2), structOffset, MinStructSize, bytesRemaining) {
            WheaErrorPacketV2(recordAddr, structOffset, bytesRemaining);
        }

        public WHEA_ERROR_PACKET_V2(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR sectionDsc, IntPtr recordAddr, uint bytesRemaining) :
            base(typeof(WHEA_ERROR_PACKET_V2), sectionDsc, MinStructSize, bytesRemaining) {
            WheaErrorPacketV2(recordAddr, sectionDsc.SectionOffset, sectionDsc.SectionLength);
        }

        private void WheaErrorPacketV2(IntPtr recordAddr, uint structOffset, uint bytesRemaining) {
            var structAddr = recordAddr + (int)structOffset;

            // Verified previously in CreateBySignature
            _Signature = (uint)Marshal.ReadInt32(structAddr);

            Version = (uint)Marshal.ReadInt32(structAddr, 4);

            if (Version != WHEA_ERROR_PACKET_V2_VERSION) {
                throw new InvalidDataException($"Expected {nameof(Version)} to be {WHEA_ERROR_PACKET_V2_VERSION} but found: {Version}");
            }

            Length = (uint)Marshal.ReadInt32(structAddr, 8);

            if (Length < MinStructSize) {
                var checkCalc = $"{Length} < {MinStructSize}";
                throw new InvalidDataException($"{nameof(Length)} is less than minimum structure size: {checkCalc}");
            }

            if (Length > bytesRemaining) {
                var checkCalc = $"{Length} > {bytesRemaining}";
                throw new InvalidDataException($"{nameof(Length)} is greater than bytes remaining: {checkCalc}");
            }

            _Flags = (WHEA_ERROR_PACKET_FLAGS)Marshal.ReadInt32(structAddr, 12);
            _ErrorType = (WHEA_ERROR_TYPE)Marshal.ReadInt32(structAddr, 16);
            _ErrorSeverity = (WHEA_ERROR_SEVERITY)Marshal.ReadInt32(structAddr, 20);
            ErrorSourceId = (uint)Marshal.ReadInt32(structAddr, 24);
            _ErrorSourceType = (WHEA_ERROR_SOURCE_TYPE)Marshal.ReadInt32(structAddr, 28);
            _NotifyType = Marshal.PtrToStructure<Guid>(structAddr + 32);
            Context = (ulong)Marshal.ReadInt64(structAddr, 48);
            _DataFormat = (WHEA_ERROR_PACKET_DATA_FORMAT)Marshal.ReadInt32(structAddr, 56);
            Reserved1 = (uint)Marshal.ReadInt32(structAddr, 60);
            DataOffset = (uint)Marshal.ReadInt32(structAddr, 64);
            DataLength = (uint)Marshal.ReadInt32(structAddr, 68);
            PshedDataOffset = (uint)Marshal.ReadInt32(structAddr, 72);
            PshedDataLength = (uint)Marshal.ReadInt32(structAddr, 76);

            if (MinStructSize + DataLength + PshedDataLength > Length) {
                var checkInputs = $"{nameof(MinStructSize)}, {nameof(DataLength)}, and {nameof(PshedDataLength)}";
                var checkCalc = $"{MinStructSize} + {DataLength} + {PshedDataLength} > {Length}";
                throw new InvalidDataException($"Sum of {checkInputs} results in size greater than structure size: {checkCalc}");
            }

            /*
             * Assumes there's no padding bytes between the PshedDataLength
             * field and the Data buffer.
             */
            if (DataOffset != MinStructSize) {
                var checkCalc = $"{DataOffset} != {MinStructSize}";
                throw new InvalidDataException($"{nameof(DataOffset)} does not equal the expected offset: {checkCalc}");
            }

            /*
             * Assumes there's no padding bytes between the error data and the
             * PSHED data.
             */
            if (PshedDataOffset != MinStructSize + DataLength) {
                var checkCalc = $"{PshedDataOffset} != {MinStructSize + DataLength}";
                throw new InvalidDataException($"{nameof(PshedDataOffset)} does not equal the expected offset: {checkCalc}");
            }

            if (DataLength > 0) {
                Data = new byte[DataLength];
                Marshal.Copy(structAddr + (int)DataOffset, Data, 0, (int)DataLength);
            }

            if (PshedDataLength > 0) {
                PshedData = new byte[PshedDataLength];
                Marshal.Copy(structAddr + (int)PshedDataOffset, PshedData, 0, (int)PshedDataLength);
            }

            FinalizeRecord(recordAddr, Length);
        }

        [UsedImplicitly]
        public bool ShouldSerializeReserved1() => Reserved1 != 0;
    }

    // @formatter:int_align_fields true

    [Flags]
    internal enum WHEA_ERROR_PACKET_FLAGS : uint {
        PreviousError               = 0x1,
        CriticalEvent               = 0x2,
        HypervisorError             = 0x4,
        Simulated                   = 0x8,
        PlatformPfaControl          = 0x10,
        PlatformDirectedOffline     = 0x20,
        AddressTranslationRequired  = 0x40,
        AddressTranslationCompleted = 0x80,
        RecoveryOptional            = 0x100
    }

    internal enum WHEA_ERROR_TYPE : uint {
        Processor  = 0,
        Memory     = 1,
        PCIExpress = 2,
        NMI        = 3,
        PCIXBus    = 4,
        PCIXDevice = 5,
        Generic    = 6,
        Pmem       = 7
    }

    internal enum WHEA_RAW_DATA_FORMAT : uint {
        IPFSalRecord = 0,
        IA32MCA      = 1,
        Intel64MCA   = 2,
        AMD64MCA     = 3,
        Memory       = 4,
        PCIExpress   = 5,
        NMIPort      = 6,
        PCIXBus      = 7,
        PCIXDevice   = 8,
        Generic      = 9
    }

    internal enum WHEA_ERROR_PACKET_DATA_FORMAT : uint {
        IPFSalRecord = 0,
        XPFMCA       = 1,
        Memory       = 2,
        PCIExpress   = 3,
        NMIPort      = 4,
        PCIXBus      = 5,
        PCIXDevice   = 6,
        Generic      = 7
    }

    // @formatter:int_align_fields false
}
