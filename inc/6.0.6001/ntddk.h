/*++ BUILD Version: 0186    // Increment this if a change has global effects

Copyright (c) Microsoft Corporation. All rights reserved.

Module Name:

 ntddk.h

Abstract:

    This module defines the NT types, constants, and functions that are
    exposed to device drivers.

Revision History:

--*/

#ifndef _NTDDK_
#define _NTDDK_

#if !defined(_NTHAL_) && !defined(_NTIFS_)
#define _NTDDK_INCLUDED_
#define _DDK_DRIVER_
#endif

#ifndef RC_INVOKED
#if _MSC_VER < 1300
#error Compiler version not supported by Windows DDK
#endif
#endif // RC_INVOKED

#define NT_INCLUDED
#define _CTYPE_DISABLE_MACROS

#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning(disable:4115) // named type definition in parentheses
#pragma warning(disable:4201) // nameless struct/union
#pragma warning(disable:4214) // bit field types other than int

#include <wdm.h>
#include <excpt.h>
#include <ntdef.h>
#include <ntstatus.h>
#include <bugcodes.h>
#include <ntiologc.h>

#include <driverspecs.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// Define types that are not exported.
//

typedef struct _BUS_HANDLER *PBUS_HANDLER;
typedef struct _CALLBACK_OBJECT *PCALLBACK_OBJECT;
typedef struct _DEVICE_HANDLER_OBJECT *PDEVICE_HANDLER_OBJECT;
#if defined(_NTHAL_INCLUDED_)
typedef struct _KPROCESS *PEPROCESS;
typedef struct _ETHREAD *PETHREAD;
#elif defined(_NTIFS_INCLUDED_)
typedef struct _KPROCESS *PEPROCESS;
typedef struct _KTHREAD *PETHREAD;
#else
typedef struct _EPROCESS *PEPROCESS;
typedef struct _ETHREAD *PETHREAD;
#endif
typedef struct _IO_TIMER *PIO_TIMER;
typedef struct _KINTERRUPT *PKINTERRUPT;
typedef struct _KTHREAD *PKTHREAD, *PRKTHREAD;
typedef struct _OBJECT_TYPE *POBJECT_TYPE;
typedef struct _PEB *PPEB;
typedef struct _IMAGE_NT_HEADERS *PIMAGE_NT_HEADERS32;
typedef struct _IMAGE_NT_HEADERS64 *PIMAGE_NT_HEADERS64;
#ifdef _WIN64
typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
#else
typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;
#endif

#define PsGetCurrentProcess IoGetCurrentProcess

#if (NTDDI_VERSION >= NTDDI_VISTA)
extern NTSYSAPI volatile CCHAR KeNumberProcessors;
#else
#if (NTDDI_VERSION >= NTDDI_WINXP)
extern NTSYSAPI CCHAR KeNumberProcessors;
#else
extern PCCHAR KeNumberProcessors;
#endif
#endif

#include <mce.h>

#ifndef FAR
#define FAR
#endif

#ifdef _X86_

//
// Disable these two pragmas that evaluate to "sti" "cli" on x86 so that driver
// writers to not leave them inadvertantly in their code.
//

#if !defined(MIDL_PASS)
#if !defined(RC_INVOKED)

#if _MSC_VER >= 1200
#pragma warning(push)
#endif
#pragma warning(disable:4164)   // disable C4164 warning so that apps that
                                // build with /Od don't get weird errors !
#ifdef _M_IX86
#pragma function(_enable)
#pragma function(_disable)
#endif

#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning(default:4164)   // reenable C4164 warning
#endif

#endif
#endif

//
// Size of kernel mode stack.
//

#define KERNEL_STACK_SIZE 12288

//
// Define size of large kernel mode stack for callbacks.
//

#define KERNEL_LARGE_STACK_SIZE 61440

//
// Define number of pages to initialize in a large kernel stack.
//

#define KERNEL_LARGE_STACK_COMMIT 12288

#ifdef _X86_

#if !defined(MIDL_PASS) && defined(_M_IX86)

#if !defined(_M_CEE_PURE)

#pragma warning( push )
#pragma warning( disable : 4793 )
FORCEINLINE
VOID
MemoryBarrier (
    VOID
    )
{
    LONG Barrier;
    __asm {
        xchg Barrier, eax
    }
}
#pragma warning( pop )

#endif /* _M_CEE_PURE */
//
// Prefetch is not supported on all x86 procssors.
//

#define PreFetchCacheLine(l, a)
#define PrefetchForWrite(p)
#define ReadForWriteAccess(p) (*(p))

//
// PreFetchCacheLine level defines.
//

#define PF_TEMPORAL_LEVEL_1
#define PF_NON_TEMPORAL_LEVEL_ALL

//
// Define function to read the value of a performance counter.
//

#if _MSC_FULL_VER >= 140050727

#define ReadPMC __readpmc

ULONG64
__readpmc (
    __in ULONG Counter
    );

#pragma intrinsic(__readpmc)

#else

FORCEINLINE
ULONG64
ReadPMC (
    __in ULONG Counter
    )

{

    __asm {
        mov ecx, Counter
        rdpmc
    };
}

#endif

//
// Define function to read the value of the time stamp counter
//

#if _MSC_FULL_VER >= 140040310

#define ReadTimeStampCounter() __rdtsc()

ULONG64
__rdtsc (
    VOID
    );

#pragma intrinsic(__rdtsc)

#else

FORCEINLINE
ULONG64
ReadTimeStampCounter (
    VOID
    )

{

    __asm rdtsc
}

#endif

#endif // !defined(MIDL_PASS) && defined(_M_IX86)

//
//  Define the size of the 80387 save area, which is in the context frame.
//

#define SIZE_OF_80387_REGISTERS      80

//
// The following flags control the contents of the CONTEXT structure.
//

#if !defined(RC_INVOKED)

#define CONTEXT_i386    0x00010000    // this assumes that i386 and
#define CONTEXT_i486    0x00010000    // i486 have identical context records



#define CONTEXT_CONTROL         (CONTEXT_i386 | 0x00000001L) // SS:SP, CS:IP, FLAGS, BP
#define CONTEXT_INTEGER         (CONTEXT_i386 | 0x00000002L) // AX, BX, CX, DX, SI, DI
#define CONTEXT_SEGMENTS        (CONTEXT_i386 | 0x00000004L) // DS, ES, FS, GS
#define CONTEXT_FLOATING_POINT  (CONTEXT_i386 | 0x00000008L) // 387 state
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_i386 | 0x00000010L) // DB 0-3,6,7
#define CONTEXT_EXTENDED_REGISTERS  (CONTEXT_i386 | 0x00000020L) // cpu specific extensions

#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER |\
                      CONTEXT_SEGMENTS)

#define CONTEXT_ALL             (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | \
                                 CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | \
                                 CONTEXT_EXTENDED_REGISTERS)



#endif // !defined(RC_INVOKED)

#define MAXIMUM_SUPPORTED_EXTENSION     512

typedef struct _FLOATING_SAVE_AREA {
    ULONG   ControlWord;
    ULONG   StatusWord;
    ULONG   TagWord;
    ULONG   ErrorOffset;
    ULONG   ErrorSelector;
    ULONG   DataOffset;
    ULONG   DataSelector;
    UCHAR   RegisterArea[SIZE_OF_80387_REGISTERS];
    ULONG   Cr0NpxState;
} FLOATING_SAVE_AREA;

typedef FLOATING_SAVE_AREA *PFLOATING_SAVE_AREA;

//
// Context Frame
//
//  This frame has a several purposes: 1) it is used as an argument to
//  NtContinue, 2) is is used to constuct a call frame for APC delivery,
//  and 3) it is used in the user level thread creation routines.
//
//  The layout of the record conforms to a standard call frame.
//

typedef struct _CONTEXT {

    //
    // The flags values within this flag control the contents of
    // a CONTEXT record.
    //
    // If the context record is used as an input parameter, then
    // for each portion of the context record controlled by a flag
    // whose value is set, it is assumed that that portion of the
    // context record contains valid context. If the context record
    // is being used to modify a threads context, then only that
    // portion of the threads context will be modified.
    //
    // If the context record is used as an IN OUT parameter to capture
    // the context of a thread, then only those portions of the thread's
    // context corresponding to set flags will be returned.
    //
    // The context record is never used as an OUT only parameter.
    //

    ULONG ContextFlags;

    //
    // This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
    // set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
    // included in CONTEXT_FULL.
    //

    ULONG   Dr0;
    ULONG   Dr1;
    ULONG   Dr2;
    ULONG   Dr3;
    ULONG   Dr6;
    ULONG   Dr7;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_FLOATING_POINT.
    //

    FLOATING_SAVE_AREA FloatSave;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_SEGMENTS.
    //

    ULONG   SegGs;
    ULONG   SegFs;
    ULONG   SegEs;
    ULONG   SegDs;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_INTEGER.
    //

    ULONG   Edi;
    ULONG   Esi;
    ULONG   Ebx;
    ULONG   Edx;
    ULONG   Ecx;
    ULONG   Eax;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_CONTROL.
    //

    ULONG   Ebp;
    ULONG   Eip;
    ULONG   SegCs;              // MUST BE SANITIZED
    ULONG   EFlags;             // MUST BE SANITIZED
    ULONG   Esp;
    ULONG   SegSs;

    //
    // This section is specified/returned if the ContextFlags word
    // contains the flag CONTEXT_EXTENDED_REGISTERS.
    // The format and contexts are processor specific
    //

    UCHAR   ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];

} CONTEXT;



typedef CONTEXT *PCONTEXT;


#endif //_X86_

#endif // _X86_

#ifdef _AMD64_

//
// Size of kernel mode stack.
//

#define KERNEL_STACK_SIZE 0x6000

//
// Define size of large kernel mode stack for callbacks.
//

#define KERNEL_LARGE_STACK_SIZE 0x12000

//
// Define number of pages to initialize in a large kernel stack.
//

#define KERNEL_LARGE_STACK_COMMIT KERNEL_STACK_SIZE

//
// Define the size of the stack used for processing an MCA exception.
//

#define KERNEL_MCA_EXCEPTION_STACK_SIZE 0x2000

//
// The following values specify the type of access in the first parameter
// of the exception record whan the exception code specifies an access
// violation.
//

#define EXCEPTION_READ_FAULT 0          // exception caused by a read
#define EXCEPTION_WRITE_FAULT 1         // exception caused by a write
#define EXCEPTION_EXECUTE_FAULT 8       // exception caused by an instruction fetch


//
// The following flags control the contents of the CONTEXT structure.
//

#if !defined(RC_INVOKED)

#define CONTEXT_AMD64   0x100000



#define CONTEXT_CONTROL (CONTEXT_AMD64 | 0x1L)
#define CONTEXT_INTEGER (CONTEXT_AMD64 | 0x2L)
#define CONTEXT_SEGMENTS (CONTEXT_AMD64 | 0x4L)
#define CONTEXT_FLOATING_POINT  (CONTEXT_AMD64 | 0x8L)
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_AMD64 | 0x10L)

#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)

#define CONTEXT_ALL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS)

#define CONTEXT_EXCEPTION_ACTIVE 0x8000000
#define CONTEXT_SERVICE_ACTIVE 0x10000000
#define CONTEXT_EXCEPTION_REQUEST 0x40000000
#define CONTEXT_EXCEPTION_REPORTING 0x80000000



#endif // !defined(RC_INVOKED)

//
// Define initial MxCsr and FpCsr control.
//

#define INITIAL_MXCSR 0x1f80            // initial MXCSR value
#define INITIAL_FPCSR 0x027f            // initial FPCSR value

//
// Define 128-bit 16-byte aligned xmm register type.
//

typedef struct DECLSPEC_ALIGN(16) _M128A {
    ULONGLONG Low;
    LONGLONG High;
} M128A, *PM128A;

//
// Format of data for 32-bit fxsave/fxrstor instructions.
//

typedef struct _XMM_SAVE_AREA32 {
    USHORT ControlWord;
    USHORT StatusWord;
    UCHAR TagWord;
    UCHAR Reserved1;
    USHORT ErrorOpcode;
    ULONG ErrorOffset;
    USHORT ErrorSelector;
    USHORT Reserved2;
    ULONG DataOffset;
    USHORT DataSelector;
    USHORT Reserved3;
    ULONG MxCsr;
    ULONG MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    UCHAR Reserved4[96];
} XMM_SAVE_AREA32, *PXMM_SAVE_AREA32;

#define LEGACY_SAVE_AREA_LENGTH sizeof(XMM_SAVE_AREA32)

//
// Context Frame
//
//  This frame has a several purposes: 1) it is used as an argument to
//  NtContinue, 2) is is used to constuct a call frame for APC delivery,
//  and 3) it is used in the user level thread creation routines.
//
//
// The flags field within this record controls the contents of a CONTEXT
// record.
//
// If the context record is used as an input parameter, then for each
// portion of the context record controlled by a flag whose value is
// set, it is assumed that that portion of the context record contains
// valid context. If the context record is being used to modify a threads
// context, then only that portion of the threads context is modified.
//
// If the context record is used as an output parameter to capture the
// context of a thread, then only those portions of the thread's context
// corresponding to set flags will be returned.
//
// CONTEXT_CONTROL specifies SegSs, Rsp, SegCs, Rip, and EFlags.
//
// CONTEXT_INTEGER specifies Rax, Rcx, Rdx, Rbx, Rbp, Rsi, Rdi, and R8-R15.
//
// CONTEXT_SEGMENTS specifies SegDs, SegEs, SegFs, and SegGs.
//
// CONTEXT_DEBUG_REGISTERS specifies Dr0-Dr3 and Dr6-Dr7.
//
// CONTEXT_MMX_REGISTERS specifies the floating point and extended registers
//     Mm0/St0-Mm7/St7 and Xmm0-Xmm15).
//

typedef struct DECLSPEC_ALIGN(16) _CONTEXT {

    //
    // Register parameter home addresses.
    //
    // N.B. These fields are for convience - they could be used to extend the
    //      context record in the future.
    //

    ULONG64 P1Home;
    ULONG64 P2Home;
    ULONG64 P3Home;
    ULONG64 P4Home;
    ULONG64 P5Home;
    ULONG64 P6Home;

    //
    // Control flags.
    //

    ULONG ContextFlags;
    ULONG MxCsr;

    //
    // Segment Registers and processor flags.
    //

    USHORT SegCs;
    USHORT SegDs;
    USHORT SegEs;
    USHORT SegFs;
    USHORT SegGs;
    USHORT SegSs;
    ULONG EFlags;

    //
    // Debug registers
    //

    ULONG64 Dr0;
    ULONG64 Dr1;
    ULONG64 Dr2;
    ULONG64 Dr3;
    ULONG64 Dr6;
    ULONG64 Dr7;

    //
    // Integer registers.
    //

    ULONG64 Rax;
    ULONG64 Rcx;
    ULONG64 Rdx;
    ULONG64 Rbx;
    ULONG64 Rsp;
    ULONG64 Rbp;
    ULONG64 Rsi;
    ULONG64 Rdi;
    ULONG64 R8;
    ULONG64 R9;
    ULONG64 R10;
    ULONG64 R11;
    ULONG64 R12;
    ULONG64 R13;
    ULONG64 R14;
    ULONG64 R15;

    //
    // Program counter.
    //

    ULONG64 Rip;

    //
    // Floating point state.
    //

    union {
        XMM_SAVE_AREA32 FltSave;
        struct {
            M128A Header[2];
            M128A Legacy[8];
            M128A Xmm0;
            M128A Xmm1;
            M128A Xmm2;
            M128A Xmm3;
            M128A Xmm4;
            M128A Xmm5;
            M128A Xmm6;
            M128A Xmm7;
            M128A Xmm8;
            M128A Xmm9;
            M128A Xmm10;
            M128A Xmm11;
            M128A Xmm12;
            M128A Xmm13;
            M128A Xmm14;
            M128A Xmm15;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    //
    // Vector registers.
    //

    M128A VectorRegister[26];
    ULONG64 VectorControl;

    //
    // Special debug control registers.
    //

    ULONG64 DebugControl;
    ULONG64 LastBranchToRip;
    ULONG64 LastBranchFromRip;
    ULONG64 LastExceptionToRip;
    ULONG64 LastExceptionFromRip;
} CONTEXT, *PCONTEXT;


#endif // _AMD64_


#ifdef _IA64_

//
// Define size of kernel mode stack.
//

#define KERNEL_STACK_SIZE 0x8000

//
// Define size of large kernel mode stack for callbacks.
//

#define KERNEL_LARGE_STACK_SIZE 0x1A000

//
// Define number of pages to initialize in a large kernel stack.
//

#define KERNEL_LARGE_STACK_COMMIT 0x8000

//
//  Define size of kernel mode backing store stack.
//

#define KERNEL_BSTORE_SIZE 0x8000

//
//  Define size of large kernel mode backing store for callbacks.
//

#define KERNEL_LARGE_BSTORE_SIZE 0x10000

//
//  Define number of pages to initialize in a large kernel backing store.
//

#define KERNEL_LARGE_BSTORE_COMMIT 0x8000

//
// Define base address for kernel and user space.
//

#define UREGION_INDEX 0

#define KREGION_INDEX 7

#define UADDRESS_BASE ((ULONGLONG)UREGION_INDEX << 61)


#define KADDRESS_BASE ((ULONGLONG)KREGION_INDEX << 61)


#if defined(_M_IA64) && !defined(RC_INVOKED) && !defined(MIDL_PASS)

#ifdef __cplusplus
extern "C" {
#endif

//
// Define bit test intrinsics.
//

#define BitTest _bittest
#define BitTestAndComplement _bittestandcomplement
#define BitTestAndSet _bittestandset
#define BitTestAndReset _bittestandreset

#define BitTest64 _bittest64
#define BitTestAndComplement64 _bittestandcomplement64
#define BitTestAndSet64 _bittestandset64
#define BitTestAndReset64 _bittestandreset64

BOOLEAN
_bittest (
    IN LONG const *Base,
    IN LONG Offset
    );

BOOLEAN
_bittestandcomplement (
    IN LONG *Base,
    IN LONG Offset
    );

BOOLEAN
_bittestandset (
    IN LONG *Base,
    IN LONG Offset
    );

BOOLEAN
_bittestandreset (
    IN LONG *Base,
    IN LONG Offset
    );

BOOLEAN
_bittest64 (
    IN LONG64 const *Base,
    IN LONG64 Offset
    );

BOOLEAN
_bittestandcomplement64 (
    IN LONG64 *Base,
    IN LONG64 Offset
    );

BOOLEAN
_bittestandset64 (
    IN LONG64 *Base,
    IN LONG64 Offset
    );

BOOLEAN
_bittestandreset64 (
    IN LONG64 *Base,
    IN LONG64 Offset
    );

#pragma intrinsic(_bittest)
#pragma intrinsic(_bittestandcomplement)
#pragma intrinsic(_bittestandset)
#pragma intrinsic(_bittestandreset)

#pragma intrinsic(_bittest64)
#pragma intrinsic(_bittestandcomplement64)
#pragma intrinsic(_bittestandset64)
#pragma intrinsic(_bittestandreset64)

//
// Define bit scan intrinsics.
//

#define BitScanForward _BitScanForward
#define BitScanReverse _BitScanReverse
#define BitScanForward64 _BitScanForward64
#define BitScanReverse64 _BitScanReverse64

BOOLEAN
_BitScanForward (
    OUT ULONG *Index,
    IN ULONG Mask
    );

BOOLEAN
_BitScanReverse (
    OUT ULONG *Index,
    IN ULONG Mask
    );

BOOLEAN
_BitScanForward64 (
    OUT ULONG *Index,
    IN ULONG64 Mask
    );

BOOLEAN
_BitScanReverse64 (
    OUT ULONG *Index,
    IN ULONG64 Mask
    );

#pragma intrinsic(_BitScanForward)
#pragma intrinsic(_BitScanReverse)
#pragma intrinsic(_BitScanForward64)
#pragma intrinsic(_BitScanReverse64)

#define InterlockedCompareExchange16 _InterlockedCompareExchange16

SHORT
_InterlockedCompareExchange16 (
    __inout SHORT volatile *Destination,
    __in SHORT ExChange,
    __in SHORT Comperand
    );

#pragma intrinsic(_InterlockedCompareExchange16)

#ifdef __cplusplus
}
#endif

#define InterlockedAdd              _InterlockedAdd
#define InterlockedAddAcquire           _InterlockedAdd_acq
#define InterlockedAddRelease           _InterlockedAdd_rel

#define InterlockedIncrement            _InterlockedIncrement
#define InterlockedIncrementAcquire         _InterlockedIncrement_acq
#define InterlockedIncrementRelease         _InterlockedIncrement_rel

#define InterlockedDecrement            _InterlockedDecrement
#define InterlockedDecrementAcquire         _InterlockedDecrement_acq
#define InterlockedDecrementRelease         _InterlockedDecrement_rel

#define InterlockedExchange             _InterlockedExchange
#define InterlockedExchangeAcquire      _InterlockedExchange_acq

#define InterlockedExchangeAdd          _InterlockedExchangeAdd
#define InterlockedExchangeAddAcquire       _InterlockedExchangeAdd_acq
#define InterlockedExchangeAddRelease       _InterlockedExchangeAdd_rel

#define InterlockedAdd64            _InterlockedAdd64
#define InterlockedAddAcquire64         _InterlockedAdd64_acq
#define InterlockedAddRelease64         _InterlockedAdd64_rel

#define InterlockedIncrement64          _InterlockedIncrement64
#define InterlockedIncrementAcquire64       _InterlockedIncrement64_acq
#define InterlockedIncrementRelease64       _InterlockedIncrement64_rel

#define InterlockedDecrement64          _InterlockedDecrement64
#define InterlockedDecrementAcquire64       _InterlockedDecrement64_acq
#define InterlockedDecrementRelease64       _InterlockedDecrement64_rel

#define InterlockedExchange64           _InterlockedExchange64
#define InterlockedExchangeAcquire64        _InterlockedExchange64_acq

#define InterlockedExchangeAdd64        _InterlockedExchangeAdd64
#define InterlockedExchangeAddAcquire64     _InterlockedExchangeAdd64_acq
#define InterlockedExchangeAddRelease64     _InterlockedExchangeAdd64_rel

#define InterlockedCompareExchange64        _InterlockedCompareExchange64
#define InterlockedCompareExchangeAcquire64     _InterlockedCompareExchange64_acq
#define InterlockedCompareExchangeRelease64     _InterlockedCompareExchange64_rel

#define InterlockedCompare64Exchange128     _InterlockedCompare64Exchange128
#define InterlockedCompare64ExchangeAcquire128  _InterlockedCompare64Exchange128_acq
#define InterlockedCompare64ExchangeRelease128  _InterlockedCompare64Exchange128_rel

#define InterlockedCompareExchange      _InterlockedCompareExchange
#define InterlockedCompareExchangeAcquire   _InterlockedCompareExchange_acq
#define InterlockedCompareExchangeRelease   _InterlockedCompareExchange_rel

#define InterlockedExchangePointer      _InterlockedExchangePointer
#define InterlockedExchangePointerAcquire       _InterlockedExchangePointer_acq

#define InterlockedCompareExchangePointer    _InterlockedCompareExchangePointer
#define InterlockedCompareExchangePointerRelease _InterlockedCompareExchangePointer_rel
#define InterlockedCompareExchangePointerAcquire _InterlockedCompareExchangePointer_acq


#define InterlockedExchangeAddSizeT(a, b) InterlockedExchangeAdd64((LONG64 *)a, b)
#define InterlockedIncrementSizeT(a) InterlockedIncrement64((LONG64 *)a)
#define InterlockedDecrementSizeT(a) InterlockedDecrement64((LONG64 *)a)

#define InterlockedOr       _InterlockedOr
#define InterlockedOrAcquire   _InterlockedOr_acq
#define InterlockedOrRelease   _InterlockedOr_rel
#define InterlockedOr8      _InterlockedOr8
#define InterlockedOr8Acquire  _InterlockedOr8_acq
#define InterlockedOr8Release  _InterlockedOr8_rel
#define InterlockedOr16     _InterlockedOr16
#define InterlockedOr16Acquire _InterlockedOr16_acq
#define InterlockedOr16Release _InterlockedOr16_rel
#define InterlockedOr64     _InterlockedOr64
#define InterlockedOr64Acquire _InterlockedOr64_acq
#define InterlockedOr64Release _InterlockedOr64_rel
#define InterlockedXor      _InterlockedXor
#define InterlockedXorAcquire  _InterlockedXor_acq
#define InterlockedXorRelease  _InterlockedXor_rel
#define InterlockedXor8     _InterlockedXor8
#define InterlockedXor8Acquire _InterlockedXor8_acq
#define InterlockedXor8Release _InterlockedXor8_rel
#define InterlockedXor16    _InterlockedXor16
#define InterlockedXor16Acquire _InterlockedXor16_acq
#define InterlockedXor16Release _InterlockedXor16_rel
#define InterlockedXor64     _InterlockedXor64
#define InterlockedXor64Acquire _InterlockedXor64_acq
#define InterlockedXor64Release _InterlockedXor64_rel
#define InterlockedAnd       _InterlockedAnd
#define InterlockedAndAcquire   _InterlockedAnd_acq
#define InterlockedAndRelease   _InterlockedAnd_rel
#define InterlockedAnd8      _InterlockedAnd8
#define InterlockedAnd8Acquire  _InterlockedAnd8_acq
#define InterlockedAnd8Release  _InterlockedAnd8_rel
#define InterlockedAnd16     _InterlockedAnd16
#define InterlockedAnd16Acquire _InterlockedAnd16_acq
#define InterlockedAnd16Release _InterlockedAnd16_rel
#define InterlockedAnd64     _InterlockedAnd64
#define InterlockedAnd64Acquire _InterlockedAnd64_acq
#define InterlockedAnd64Release _InterlockedAnd64_rel

#ifdef __cplusplus
extern "C" {
#endif

LONG
__cdecl
InterlockedAdd (
    LONG volatile *Addend,
    LONG Value
    );

LONG
__cdecl
InterlockedAddAcquire (
    LONG volatile *Addend,
    LONG Value
    );

LONG
__cdecl
InterlockedAddRelease (
    LONG volatile *Addend,
    LONG Value
    );

LONGLONG
__cdecl
InterlockedAdd64 (
    LONGLONG volatile *Addend,
    LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedAddAcquire64 (
    LONGLONG volatile *Addend,
    LONGLONG Value
    );


LONGLONG
__cdecl
InterlockedAddRelease64 (
    LONGLONG volatile *Addend,
    LONGLONG Value
    );

LONG
__cdecl
InterlockedIncrement(
    IN OUT LONG volatile *Addend
    );

LONG
__cdecl
InterlockedDecrement(
    IN OUT LONG volatile *Addend
    );

LONG
__cdecl
InterlockedIncrementAcquire(
    IN OUT LONG volatile *Addend
    );

LONG
__cdecl
InterlockedDecrementAcquire(
    IN OUT LONG volatile *Addend
    );

LONG
__cdecl
InterlockedIncrementRelease(
    IN OUT LONG volatile *Addend
    );

LONG
__cdecl
InterlockedDecrementRelease(
    IN OUT LONG volatile *Addend
    );

LONG
__cdecl
InterlockedExchange(
    IN OUT LONG volatile *Target,
    IN LONG Value
    );

LONG
__cdecl
InterlockedExchangeAcquire(
    IN OUT LONG volatile *Target,
    IN LONG Value
    );

LONG
__cdecl
InterlockedExchangeAdd(
    IN OUT LONG volatile *Addend,
    IN LONG Value
    );

LONG
__cdecl
InterlockedExchangeAddAcquire(
    IN OUT LONG volatile *Addend,
    IN LONG Value
    );

LONG
__cdecl
InterlockedExchangeAddRelease(
    IN OUT LONG volatile *Addend,
    IN LONG Value
    );
LONG
__cdecl
InterlockedCompareExchange (
    IN OUT LONG volatile *Destination,
    IN LONG ExChange,
    IN LONG Comperand
    );


LONG
__cdecl
InterlockedCompareExchangeRelease (
    IN OUT LONG volatile *Destination,
    IN LONG ExChange,
    IN LONG Comperand
    );


LONG
__cdecl
InterlockedCompareExchangeAcquire (
    IN OUT LONG volatile *Destination,
    IN LONG ExChange,
    IN LONG Comperand
    );


LONGLONG
__cdecl
InterlockedIncrement64(
    IN OUT LONGLONG volatile *Addend
    );

LONGLONG
__cdecl
InterlockedIncrementAcquire64(
    IN OUT LONGLONG volatile *Addend
    );

LONGLONG
__cdecl
InterlockedIncrementRelease64(
    IN OUT LONGLONG volatile *Addend
    );

LONGLONG
__cdecl
InterlockedDecrement64(
    IN OUT LONGLONG volatile *Addend
    );

LONGLONG
__cdecl
InterlockedDecrementAcquire64(
    IN OUT LONGLONG volatile *Addend
    );

LONGLONG
__cdecl
InterlockedDecrementRelease64(
    IN OUT LONGLONG volatile *Addend
    );

LONGLONG
__cdecl
InterlockedExchange64(
    IN OUT LONGLONG volatile *Target,
    IN LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedExchangeAcquire64(
    IN OUT LONGLONG volatile *Target,
    IN LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedExchangeAdd64(
    IN OUT LONGLONG volatile *Addend,
    IN LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedExchangeAddAcquire64(
    IN OUT LONGLONG volatile *Addend,
    IN LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedExchangeAddRelease64(
    IN OUT LONGLONG volatile *Addend,
    IN LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedCompareExchange64 (
    IN OUT LONGLONG volatile *Destination,
    IN LONGLONG ExChange,
    IN LONGLONG Comperand
    );

LONGLONG
__cdecl
InterlockedCompareExchangeAcquire64 (
    IN OUT LONGLONG volatile *Destination,
    IN LONGLONG ExChange,
    IN LONGLONG Comperand
    );

LONGLONG
__cdecl
InterlockedCompareExchangeRelease64 (
    IN OUT LONGLONG volatile *Destination,
    IN LONGLONG ExChange,
    IN LONGLONG Comperand
    );

LONG64
__cdecl
InterlockedCompare64Exchange128(
    __inout LONG64 volatile * Destination,
    __in LONG64 ExchangeHigh,
    __in LONG64 ExchangeLow,
    __in LONG64 Comperand
    );

LONG64
__cdecl
InterlockedCompare64ExchangeAcquire128(
    __inout LONG64 volatile * Destination,
    __in LONG64 ExchangeHigh,
    __in LONG64 ExchangeLow,
    __in LONG64 Comperand
    );

LONG64
__cdecl
InterlockedCompare64ExchangeRelease128(
    __inout LONG64 volatile * Destination,
    __in LONG64 ExchangeHigh,
    __in LONG64 ExchangeLow,
    __in LONG64 Comperand
    );

PVOID
__cdecl
InterlockedCompareExchangePointer (
    IN OUT PVOID volatile *Destination,
    IN PVOID Exchange,
    IN PVOID Comperand
    );

PVOID
__cdecl
InterlockedCompareExchangePointerAcquire (
    IN OUT PVOID volatile *Destination,
    IN PVOID Exchange,
    IN PVOID Comperand
    );

PVOID
__cdecl
InterlockedCompareExchangePointerRelease (
    IN OUT PVOID volatile *Destination,
    IN PVOID Exchange,
    IN PVOID Comperand
    );

PVOID
__cdecl
InterlockedExchangePointer(
    IN OUT PVOID volatile *Target,
    IN PVOID Value
    );

PVOID
__cdecl
InterlockedExchangePointerAcquire(
    IN OUT PVOID volatile *Target,
    IN PVOID Value
    );

LONG
__cdecl
InterlockedOr (
    IN OUT LONG volatile *Destination,
    IN LONG Value
    );

LONG
__cdecl
InterlockedOrAcquire (
    IN OUT LONG volatile *Destination,
    IN LONG Value
    );

LONG
__cdecl
InterlockedOrRelease (
    IN OUT LONG volatile *Destination,
    IN LONG Value
    );

CHAR
__cdecl
InterlockedOr8 (
    IN OUT CHAR volatile *Destination,
    IN    CHAR Value
    );

CHAR
__cdecl
InterlockedOr8Acquire (
    IN OUT CHAR volatile *Destination,
    IN    CHAR Value
    );

CHAR
__cdecl
InterlockedOr8Release (
    IN OUT CHAR volatile *Destination,
    IN CHAR Value
    );

SHORT
__cdecl
InterlockedOr16(
    IN OUT SHORT volatile *Destination,
    IN SHORT Value
    );

SHORT
__cdecl
InterlockedOr16Acquire (
    IN OUT SHORT volatile *Destination,
    IN SHORT Value
    );

SHORT
__cdecl
InterlockedOr16Release (
    IN OUT SHORT volatile *Destination,
    IN SHORT Value
    );

LONGLONG
__cdecl
InterlockedOr64 (
    IN OUT LONGLONG volatile *Destination,
    IN LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedOr64Acquire (
    IN OUT LONGLONG volatile *Destination,
    IN LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedOr64Release (
    IN OUT LONGLONG volatile *Destination,
    IN LONGLONG Value
    );

LONG
__cdecl
InterlockedXor (
    IN OUT LONG volatile *Destination,
    IN LONG Value
    );

LONG
__cdecl
InterlockedXorAcquire (
    IN OUT LONG volatile *Destination,
    IN LONG Value
    );

LONG
__cdecl
InterlockedXorRelease (
    IN OUT LONG volatile *Destination,
    IN LONG Value
    );

CHAR
__cdecl
InterlockedXor8 (
    IN OUT CHAR volatile *Destination,
    IN CHAR Value
    );

CHAR
__cdecl
InterlockedXor8Acquire (
    IN OUT CHAR volatile *Destination,
    IN CHAR Value
    );

CHAR
__cdecl
InterlockedXor8Release (
    IN OUT CHAR volatile *Destination,
    IN CHAR Value
    );

SHORT
__cdecl
InterlockedXor16(
    IN OUT SHORT volatile *Destination,
    IN SHORT Value
    );

SHORT
__cdecl
InterlockedXor16Acquire (
    IN OUT SHORT volatile *Destination,
    IN SHORT Value
    );

SHORT
__cdecl
InterlockedXor16Release (
    IN OUT SHORT volatile *Destination,
    IN SHORT Value
    );

LONGLONG
__cdecl
InterlockedXor64 (
    IN OUT LONGLONG volatile *Destination,
    IN LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedXor64Acquire (
    IN OUT LONGLONG volatile *Destination,
    IN LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedXor64Release (
    IN OUT LONGLONG volatile *Destination,
    IN LONGLONG Value
    );

LONG
__cdecl
InterlockedAnd (
    IN OUT LONG volatile *Destination,
    IN LONG Value
    );

LONG
__cdecl
InterlockedAndAcquire (
    IN OUT LONG volatile *Destination,
    IN LONG Value
    );

LONG
__cdecl
InterlockedAndRelease (
    IN OUT LONG volatile *Destination,
    IN LONG Value
    );

CHAR
__cdecl
InterlockedAnd8 (
    IN OUT CHAR volatile *Destination,
    IN CHAR Value
    );

CHAR
__cdecl
InterlockedAnd8Acquire (
    IN OUT CHAR volatile *Destination,
    IN CHAR Value
    );

CHAR
__cdecl
InterlockedAnd8Release (
    IN OUT CHAR volatile *Destination,
    IN CHAR Value
    );

SHORT
__cdecl
InterlockedAnd16(
    IN OUT SHORT volatile *Destination,
    IN SHORT Value
    );

SHORT
__cdecl
InterlockedAnd16Acquire (
    IN OUT SHORT volatile *Destination,
    IN SHORT Value
    );

SHORT
__cdecl
InterlockedAnd16Release (
    IN OUT SHORT volatile *Destination,
    IN SHORT Value
    );

LONGLONG
__cdecl
InterlockedAnd64 (
    IN OUT LONGLONG volatile *Destination,
    IN LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedAnd64Acquire (
    IN OUT LONGLONG volatile *Destination,
    IN LONGLONG Value
    );

LONGLONG
__cdecl
InterlockedAnd64Release (
    IN OUT LONGLONG volatile *Destination,
    IN LONGLONG Value
    );

#pragma intrinsic(_InterlockedAdd)
#pragma intrinsic(_InterlockedIncrement)
#pragma intrinsic(_InterlockedIncrement_acq)
#pragma intrinsic(_InterlockedIncrement_rel)
#pragma intrinsic(_InterlockedDecrement)
#pragma intrinsic(_InterlockedDecrement_acq)
#pragma intrinsic(_InterlockedDecrement_rel)
#pragma intrinsic(_InterlockedExchange)
#pragma intrinsic(_InterlockedCompareExchange)
#pragma intrinsic(_InterlockedCompareExchange_acq)
#pragma intrinsic(_InterlockedCompareExchange_rel)
#pragma intrinsic(_InterlockedExchangeAdd)
#pragma intrinsic(_InterlockedAdd64)
#pragma intrinsic(_InterlockedIncrement64)
#pragma intrinsic(_InterlockedDecrement64)
#pragma intrinsic(_InterlockedExchange64)
#pragma intrinsic(_InterlockedExchange64_acq)
#pragma intrinsic(_InterlockedCompareExchange64)
#pragma intrinsic(_InterlockedCompareExchange64_acq)
#pragma intrinsic(_InterlockedCompareExchange64_rel)
#pragma intrinsic(_InterlockedCompare64Exchange128)
#pragma intrinsic(_InterlockedCompare64Exchange128_acq)
#pragma intrinsic(_InterlockedCompare64Exchange128_rel)
#pragma intrinsic(_InterlockedExchangeAdd64)
#pragma intrinsic(_InterlockedExchangePointer)
#pragma intrinsic(_InterlockedCompareExchangePointer)
#pragma intrinsic(_InterlockedCompareExchangePointer_acq)
#pragma intrinsic(_InterlockedCompareExchangePointer_rel)
#pragma intrinsic(_InterlockedAdd_acq)
#pragma intrinsic(_InterlockedAdd_rel)
#pragma intrinsic(_InterlockedExchange_acq)
#pragma intrinsic(_InterlockedExchangeAdd_acq)
#pragma intrinsic(_InterlockedExchangeAdd_rel)
#pragma intrinsic(_InterlockedAdd64_acq)
#pragma intrinsic(_InterlockedAdd64_rel)
#pragma intrinsic(_InterlockedIncrement64_acq)
#pragma intrinsic(_InterlockedIncrement64_rel)
#pragma intrinsic(_InterlockedDecrement64_acq)
#pragma intrinsic(_InterlockedDecrement64_rel)
#pragma intrinsic(_InterlockedExchangeAdd64_acq)
#pragma intrinsic(_InterlockedExchangeAdd64_rel)
#pragma intrinsic(_InterlockedExchangePointer_acq)
#pragma intrinsic (_InterlockedOr)
#pragma intrinsic (_InterlockedOr_acq)
#pragma intrinsic (_InterlockedOr_rel)
#pragma intrinsic (_InterlockedOr8)
#pragma intrinsic (_InterlockedOr8_acq)
#pragma intrinsic (_InterlockedOr8_rel)
#pragma intrinsic (_InterlockedOr16)
#pragma intrinsic (_InterlockedOr16_acq)
#pragma intrinsic (_InterlockedOr16_rel)
#pragma intrinsic (_InterlockedOr64)
#pragma intrinsic (_InterlockedOr64_acq)
#pragma intrinsic (_InterlockedOr64_rel)
#pragma intrinsic (_InterlockedXor)
#pragma intrinsic (_InterlockedXor_acq)
#pragma intrinsic (_InterlockedXor_rel)
#pragma intrinsic (_InterlockedXor8)
#pragma intrinsic (_InterlockedXor8_acq)
#pragma intrinsic (_InterlockedXor8_rel)
#pragma intrinsic (_InterlockedXor16)
#pragma intrinsic (_InterlockedXor16_acq)
#pragma intrinsic (_InterlockedXor16_rel)
#pragma intrinsic (_InterlockedXor64)
#pragma intrinsic (_InterlockedXor64_acq)
#pragma intrinsic (_InterlockedXor64_rel)
#pragma intrinsic (_InterlockedAnd)
#pragma intrinsic (_InterlockedAnd_acq)
#pragma intrinsic (_InterlockedAnd_rel)
#pragma intrinsic (_InterlockedAnd8)
#pragma intrinsic (_InterlockedAnd8_acq)
#pragma intrinsic (_InterlockedAnd8_rel)
#pragma intrinsic (_InterlockedAnd16)
#pragma intrinsic (_InterlockedAnd16_acq)
#pragma intrinsic (_InterlockedAnd16_rel)
#pragma intrinsic (_InterlockedAnd64)
#pragma intrinsic (_InterlockedAnd64_acq)
#pragma intrinsic (_InterlockedAnd64_rel)

#if !defined (InterlockedAnd64)

#define InterlockedAnd64 InterlockedAnd64_Inline

LONGLONG
FORCEINLINE
InterlockedAnd64_Inline (
    IN OUT LONGLONG volatile *Destination,
    IN LONGLONG Value
    )
{
    LONGLONG Old;

    do {
        Old = *Destination;
    } while (InterlockedCompareExchange64(Destination,
                                          Old & Value,
                                          Old) != Old);

    return Old;
}

#endif

#define InterlockedAndAffinity InterlockedAnd64

#if !defined (InterlockedOr64)

#define InterlockedOr64 InterlockedOr64_Inline

LONGLONG
FORCEINLINE
InterlockedOr64_Inline (
    IN OUT LONGLONG volatile *Destination,
    IN LONGLONG Value
    )
{
    LONGLONG Old;

    do {
        Old = *Destination;
    } while (InterlockedCompareExchange64(Destination,
                                          Old | Value,
                                          Old) != Old);

    return Old;
}

#endif

#define InterlockedOrAffinity InterlockedOr64

#if !defined (InterlockedXor64)

#define InterlockedXor64 InterlockedXor64_Inline

LONGLONG
FORCEINLINE
InterlockedXor64_Inline (
    IN OUT LONGLONG volatile *Destination,
    IN LONGLONG Value
    )
{
    LONGLONG Old;

    do {
        Old = *Destination;
    } while (InterlockedCompareExchange64(Destination,
                                          Old ^ Value,
                                          Old) != Old);

    return Old;
}

#endif

#if !defined (InterlockedBitTestAndSet)

#define InterlockedBitTestAndSet InterlockedBitTestAndSet_Inline

BOOLEAN
FORCEINLINE
InterlockedBitTestAndSet_Inline (
    IN LONG volatile *Base,
    IN LONG Bit
    )
{
    LONG tBit;

    tBit = 1<<(Bit & (sizeof (*Base)*8-1));
    return (BOOLEAN) ((InterlockedOr (&Base[Bit/(sizeof (*Base)*8)], tBit)&tBit) != 0);
}

#endif

#if !defined (InterlockedBitTestAndReset)

#define InterlockedBitTestAndReset InterlockedBitTestAndReset_Inline

BOOLEAN
FORCEINLINE
InterlockedBitTestAndReset_Inline (
    IN LONG volatile *Base,
    IN LONG Bit
    )
{
    LONG tBit;

    tBit = 1<<(Bit & (sizeof (*Base)*8-1));
    return (BOOLEAN) ((InterlockedAnd (&Base[Bit/(sizeof (*Base)*8)], ~tBit)&tBit) != 0);
}

#endif

#if !defined (InterlockedBitTestAndSet64)

#define InterlockedBitTestAndSet64 InterlockedBitTestAndSet64_Inline

BOOLEAN
FORCEINLINE
InterlockedBitTestAndSet64_Inline (
    IN LONG64 volatile *Base,
    IN LONG64 Bit
    )
{
    LONG64 tBit;

    tBit = 1i64<<(Bit & (sizeof (*Base)*8-1));
    return (BOOLEAN) ((InterlockedOr64 (&Base[Bit/(sizeof (*Base)*8)], tBit)&tBit) != 0);
}

#endif

#if !defined (InterlockedBitTestAndReset64)

#define InterlockedBitTestAndReset64 InterlockedBitTestAndReset64_Inline

BOOLEAN
FORCEINLINE
InterlockedBitTestAndReset64_Inline (
    IN LONG64 volatile *Base,
    IN LONG64 Bit
    )
{
    LONG64 tBit;

    tBit = 1i64<<(Bit & (sizeof (*Base)*8-1));
    return (BOOLEAN) ((InterlockedAnd64 (&Base[Bit/(sizeof (*Base)*8)], ~tBit)&tBit) != 0);
}

#endif

#if !defined (InterlockedBitTestAndComplement)

#define InterlockedBitTestAndComplement InterlockedBitTestAndComplement_Inline

BOOLEAN
FORCEINLINE
InterlockedBitTestAndComplement_Inline (
    IN LONG volatile *Base,
    IN LONG Bit
    )
{
    LONG tBit;

    tBit = 1<<(Bit & (sizeof (*Base)*8-1));
    return (BOOLEAN) ((InterlockedXor (&Base[Bit/(sizeof (*Base)*8)], tBit)&tBit) != 0);
}

#endif

#if !defined (InterlockedBitTestAndComplement64)

#define InterlockedBitTestAndComplement64 InterlockedBitTestAndComplement64_Inline

BOOLEAN
FORCEINLINE
InterlockedBitTestAndComplement64_Inline (
    IN LONG64 volatile *Base,
    IN LONG64 Bit
    )
{
    LONG64 tBit;

    tBit = 1i64<<(Bit & (sizeof (*Base)*8-1));
    return (BOOLEAN) ((InterlockedXor64 (&Base[Bit/(sizeof (*Base)*8)], tBit)&tBit) != 0);
}

#endif

#ifdef __cplusplus
}
#endif

#endif /* defined(_M_IA64) && !defined(RC_INVOKED) && !defined(MIDL_PASS) */


#ifdef __cplusplus
extern "C" {
#endif



#if defined(_IA64_) && defined(_M_IA64) && !defined(RC_INVOKED) && !defined(MIDL_PASS)

void
__break(
    int
    );

#pragma intrinsic (__break)

#define BREAK_DEBUG_BASE    0x080000
#define ASSERT_BREAKPOINT         (BREAK_DEBUG_BASE+3)  // Cause a STATUS_ASSERTION_FAILURE exception to be raised.

#define DbgRaiseAssertionFailure() __break(ASSERT_BREAKPOINT)

#endif



void
__yield(
   void
   );

void
__mf(
    void
    );

void
__lfetch(
    int Level,
    __in volatile VOID CONST *Address
    );

void
__lfetchfault(
    __in int Level,
    __in volatile VOID CONST *Address
    );

void
__lfetch_excl(
    __in int Level,
    __in volatile VOID CONST *Address
    );

void
__lfetchfault_excl(
    __in int Level,
    __in volatile VOID CONST *Address
    );

//
// __lfetch control defines.
//

#define MD_LFHINT_NONE    0x00
#define MD_LFHINT_NT1     0x01
#define MD_LFHINT_NT2     0x02
#define MD_LFHINT_NTA     0x03

#pragma intrinsic (__yield)
#pragma intrinsic (__lfetch)
#pragma intrinsic (__lfetchfault)
#pragma intrinsic (__lfetchfault_excl)
#pragma intrinsic (__lfetch_excl)
#pragma intrinsic (__mf)

//
// Define function to read the value of the time stamp counter
//
// N.B. The register number for the time stamp counter is CV_IA64_ApITC which
//      is 3116.
//

#define ReadTimeStampCounter() __getReg(3116)

unsigned __int64
__getReg (
    int Number
    );

#pragma intrinsic(__getReg)

#define YieldProcessor          __yield
#define MemoryBarrier           __mf
#define PreFetchCacheLine       __lfetch
#define PrefetchForWrite(p)
#define ReadForWriteAccess(p)   (__lfetch_excl(MD_LFHINT_NONE, (p)), (*(p)))


//
// PreFetchCacheLine level defines.
//

#define PF_TEMPORAL_LEVEL_1         MD_LFHINT_NONE
#define PF_TEMPORAL_LEVEL_2         MD_LFHINT_NT1
#define PF_TEMPORAL_LEVEL_3         MD_LFHINT_NT2
#define PF_NON_TEMPORAL_LEVEL_ALL   MD_LFHINT_NTA

//
// Define functions to capture the high 64-bits of a 128-bit multiply.
//

#define UnsignedMultiplyHigh __UMULH

ULONGLONG
UnsignedMultiplyHigh (
    IN ULONGLONG Multiplier,
    IN ULONGLONG Multiplicand
    );

#pragma intrinsic(__UMULH)

#if (_MSC_VER >= 1400)

#define UnsignedMultiply128 _umul128

ULONG64
UnsignedMultiply128 (
    __in unsigned __int64 Multiplier,
    __in unsigned __int64 Multiplicand,
    __out __deref_out_range(==,Multiplier * Multiplicand) unsigned __int64 *HighProduct
    );
#pragma intrinsic(_umul128)

#endif

#ifdef __cplusplus
}
#endif


//
// The following values specify the type of failing access when the status is
// STATUS_ACCESS_VIOLATION and the first parameter in the exception record.
//

#define EXCEPTION_READ_FAULT          0 // Access violation was caused by a read
#define EXCEPTION_WRITE_FAULT         1 // Access violation was caused by a write
#define EXCEPTION_EXECUTE_FAULT       2 // Access violation was caused by an instruction fetch

//
// The following flags control the contents of the CONTEXT structure.
//

#if !defined(RC_INVOKED)

#define CONTEXT_IA64                    0x00080000

#define CONTEXT_CONTROL                 (CONTEXT_IA64 | 0x00000001L)
#define CONTEXT_LOWER_FLOATING_POINT    (CONTEXT_IA64 | 0x00000002L)
#define CONTEXT_HIGHER_FLOATING_POINT   (CONTEXT_IA64 | 0x00000004L)
#define CONTEXT_INTEGER                 (CONTEXT_IA64 | 0x00000008L)
#define CONTEXT_DEBUG                   (CONTEXT_IA64 | 0x00000010L)
#define CONTEXT_IA32_CONTROL            (CONTEXT_IA64 | 0x00000020L)  // Includes StIPSR


#define CONTEXT_FLOATING_POINT          (CONTEXT_LOWER_FLOATING_POINT | CONTEXT_HIGHER_FLOATING_POINT)
#define CONTEXT_FULL                    (CONTEXT_CONTROL | CONTEXT_FLOATING_POINT | CONTEXT_INTEGER | CONTEXT_IA32_CONTROL)
#define CONTEXT_ALL                     (CONTEXT_CONTROL | CONTEXT_FLOATING_POINT | CONTEXT_INTEGER | CONTEXT_DEBUG | CONTEXT_IA32_CONTROL)

#define CONTEXT_EXCEPTION_ACTIVE        0x8000000
#define CONTEXT_SERVICE_ACTIVE          0x10000000
#define CONTEXT_EXCEPTION_REQUEST       0x40000000
#define CONTEXT_EXCEPTION_REPORTING     0x80000000

#endif // !defined(RC_INVOKED)

//
// Context Frame
//
//  This frame has a several purposes: 1) it is used as an argument to
//  NtContinue, 2) it is used to construct a call frame for APC delivery,
//  3) it is used to construct a call frame for exception dispatching
//  in user mode, 4) it is used in the user level thread creation
//  routines, and 5) it is used to to pass thread state to debuggers.
//
//  N.B. Because this record is used as a call frame, it must be EXACTLY
//  a multiple of 16 bytes in length and aligned on a 16-byte boundary.
//

typedef struct _CONTEXT {

    //
    // The flags values within this flag control the contents of
    // a CONTEXT record.
    //
    // If the context record is used as an input parameter, then
    // for each portion of the context record controlled by a flag
    // whose value is set, it is assumed that that portion of the
    // context record contains valid context. If the context record
    // is being used to modify a thread's context, then only that
    // portion of the threads context will be modified.
    //
    // If the context record is used as an IN OUT parameter to capture
    // the context of a thread, then only those portions of the thread's
    // context corresponding to set flags will be returned.
    //
    // The context record is never used as an OUT only parameter.
    //

    ULONG ContextFlags;
    ULONG Fill1[3];         // for alignment of following on 16-byte boundary

    //
    // This section is specified/returned if the ContextFlags word contains
    // the flag CONTEXT_DEBUG.
    //
    // N.B. CONTEXT_DEBUG is *not* part of CONTEXT_FULL.
    //

    ULONGLONG DbI0;
    ULONGLONG DbI1;
    ULONGLONG DbI2;
    ULONGLONG DbI3;
    ULONGLONG DbI4;
    ULONGLONG DbI5;
    ULONGLONG DbI6;
    ULONGLONG DbI7;

    ULONGLONG DbD0;
    ULONGLONG DbD1;
    ULONGLONG DbD2;
    ULONGLONG DbD3;
    ULONGLONG DbD4;
    ULONGLONG DbD5;
    ULONGLONG DbD6;
    ULONGLONG DbD7;

    //
    // This section is specified/returned if the ContextFlags word contains
    // the flag CONTEXT_LOWER_FLOATING_POINT.
    //

    FLOAT128 FltS0;
    FLOAT128 FltS1;
    FLOAT128 FltS2;
    FLOAT128 FltS3;
    FLOAT128 FltT0;
    FLOAT128 FltT1;
    FLOAT128 FltT2;
    FLOAT128 FltT3;
    FLOAT128 FltT4;
    FLOAT128 FltT5;
    FLOAT128 FltT6;
    FLOAT128 FltT7;
    FLOAT128 FltT8;
    FLOAT128 FltT9;

    //
    // This section is specified/returned if the ContextFlags word contains
    // the flag CONTEXT_HIGHER_FLOATING_POINT.
    //

    FLOAT128 FltS4;
    FLOAT128 FltS5;
    FLOAT128 FltS6;
    FLOAT128 FltS7;
    FLOAT128 FltS8;
    FLOAT128 FltS9;
    FLOAT128 FltS10;
    FLOAT128 FltS11;
    FLOAT128 FltS12;
    FLOAT128 FltS13;
    FLOAT128 FltS14;
    FLOAT128 FltS15;
    FLOAT128 FltS16;
    FLOAT128 FltS17;
    FLOAT128 FltS18;
    FLOAT128 FltS19;

    FLOAT128 FltF32;
    FLOAT128 FltF33;
    FLOAT128 FltF34;
    FLOAT128 FltF35;
    FLOAT128 FltF36;
    FLOAT128 FltF37;
    FLOAT128 FltF38;
    FLOAT128 FltF39;

    FLOAT128 FltF40;
    FLOAT128 FltF41;
    FLOAT128 FltF42;
    FLOAT128 FltF43;
    FLOAT128 FltF44;
    FLOAT128 FltF45;
    FLOAT128 FltF46;
    FLOAT128 FltF47;
    FLOAT128 FltF48;
    FLOAT128 FltF49;

    FLOAT128 FltF50;
    FLOAT128 FltF51;
    FLOAT128 FltF52;
    FLOAT128 FltF53;
    FLOAT128 FltF54;
    FLOAT128 FltF55;
    FLOAT128 FltF56;
    FLOAT128 FltF57;
    FLOAT128 FltF58;
    FLOAT128 FltF59;

    FLOAT128 FltF60;
    FLOAT128 FltF61;
    FLOAT128 FltF62;
    FLOAT128 FltF63;
    FLOAT128 FltF64;
    FLOAT128 FltF65;
    FLOAT128 FltF66;
    FLOAT128 FltF67;
    FLOAT128 FltF68;
    FLOAT128 FltF69;

    FLOAT128 FltF70;
    FLOAT128 FltF71;
    FLOAT128 FltF72;
    FLOAT128 FltF73;
    FLOAT128 FltF74;
    FLOAT128 FltF75;
    FLOAT128 FltF76;
    FLOAT128 FltF77;
    FLOAT128 FltF78;
    FLOAT128 FltF79;

    FLOAT128 FltF80;
    FLOAT128 FltF81;
    FLOAT128 FltF82;
    FLOAT128 FltF83;
    FLOAT128 FltF84;
    FLOAT128 FltF85;
    FLOAT128 FltF86;
    FLOAT128 FltF87;
    FLOAT128 FltF88;
    FLOAT128 FltF89;

    FLOAT128 FltF90;
    FLOAT128 FltF91;
    FLOAT128 FltF92;
    FLOAT128 FltF93;
    FLOAT128 FltF94;
    FLOAT128 FltF95;
    FLOAT128 FltF96;
    FLOAT128 FltF97;
    FLOAT128 FltF98;
    FLOAT128 FltF99;

    FLOAT128 FltF100;
    FLOAT128 FltF101;
    FLOAT128 FltF102;
    FLOAT128 FltF103;
    FLOAT128 FltF104;
    FLOAT128 FltF105;
    FLOAT128 FltF106;
    FLOAT128 FltF107;
    FLOAT128 FltF108;
    FLOAT128 FltF109;

    FLOAT128 FltF110;
    FLOAT128 FltF111;
    FLOAT128 FltF112;
    FLOAT128 FltF113;
    FLOAT128 FltF114;
    FLOAT128 FltF115;
    FLOAT128 FltF116;
    FLOAT128 FltF117;
    FLOAT128 FltF118;
    FLOAT128 FltF119;

    FLOAT128 FltF120;
    FLOAT128 FltF121;
    FLOAT128 FltF122;
    FLOAT128 FltF123;
    FLOAT128 FltF124;
    FLOAT128 FltF125;
    FLOAT128 FltF126;
    FLOAT128 FltF127;

    //
    // This section is specified/returned if the ContextFlags word contains
    // the flag CONTEXT_LOWER_FLOATING_POINT | CONTEXT_HIGHER_FLOATING_POINT | CONTEXT_CONTROL.
    //

    ULONGLONG StFPSR;       //  FP status

    //
    // This section is specified/returned if the ContextFlags word contains
    // the flag CONTEXT_INTEGER.
    //
    // N.B. The registers gp, sp, rp are part of the control context
    //

    ULONGLONG IntGp;        //  r1, volatile
    ULONGLONG IntT0;        //  r2-r3, volatile
    ULONGLONG IntT1;        //
    ULONGLONG IntS0;        //  r4-r7, preserved
    ULONGLONG IntS1;
    ULONGLONG IntS2;
    ULONGLONG IntS3;
    ULONGLONG IntV0;        //  r8, volatile
    ULONGLONG IntT2;        //  r9-r11, volatile
    ULONGLONG IntT3;
    ULONGLONG IntT4;
    ULONGLONG IntSp;        //  stack pointer (r12), special
    ULONGLONG IntTeb;       //  teb (r13), special
    ULONGLONG IntT5;        //  r14-r31, volatile
    ULONGLONG IntT6;
    ULONGLONG IntT7;
    ULONGLONG IntT8;
    ULONGLONG IntT9;
    ULONGLONG IntT10;
    ULONGLONG IntT11;
    ULONGLONG IntT12;
    ULONGLONG IntT13;
    ULONGLONG IntT14;
    ULONGLONG IntT15;
    ULONGLONG IntT16;
    ULONGLONG IntT17;
    ULONGLONG IntT18;
    ULONGLONG IntT19;
    ULONGLONG IntT20;
    ULONGLONG IntT21;
    ULONGLONG IntT22;

    ULONGLONG IntNats;      //  Nat bits for r1-r31
                            //  r1-r31 in bits 1 thru 31.
    ULONGLONG Preds;        //  predicates, preserved

    ULONGLONG BrRp;         //  return pointer, b0, preserved
    ULONGLONG BrS0;         //  b1-b5, preserved
    ULONGLONG BrS1;
    ULONGLONG BrS2;
    ULONGLONG BrS3;
    ULONGLONG BrS4;
    ULONGLONG BrT0;         //  b6-b7, volatile
    ULONGLONG BrT1;

    //
    // This section is specified/returned if the ContextFlags word contains
    // the flag CONTEXT_CONTROL.
    //

    // Other application registers
    ULONGLONG ApUNAT;       //  User Nat collection register, preserved
    ULONGLONG ApLC;         //  Loop counter register, preserved
    ULONGLONG ApEC;         //  Epilog counter register, preserved
    ULONGLONG ApCCV;        //  CMPXCHG value register, volatile
    ULONGLONG ApDCR;        //  Default control register (TBD)

    // Register stack info
    ULONGLONG RsPFS;        //  Previous function state, preserved
    ULONGLONG RsBSP;        //  Backing store pointer, preserved
    ULONGLONG RsBSPSTORE;
    ULONGLONG RsRSC;        //  RSE configuration, volatile
    ULONGLONG RsRNAT;       //  RSE Nat collection register, preserved

    // Trap Status Information
    ULONGLONG StIPSR;       //  Interruption Processor Status
    ULONGLONG StIIP;        //  Interruption IP
    ULONGLONG StIFS;        //  Interruption Function State

    // iA32 related control registers
    ULONGLONG StFCR;        //  copy of Ar21
    ULONGLONG Eflag;        //  Eflag copy of Ar24
    ULONGLONG SegCSD;       //  iA32 CSDescriptor (Ar25)
    ULONGLONG SegSSD;       //  iA32 SSDescriptor (Ar26)
    ULONGLONG Cflag;        //  Cr0+Cr4 copy of Ar27
    ULONGLONG StFSR;        //  x86 FP status (copy of AR28)
    ULONGLONG StFIR;        //  x86 FP status (copy of AR29)
    ULONGLONG StFDR;        //  x86 FP status (copy of AR30)

      ULONGLONG UNUSEDPACK;   //  added to pack StFDR to 16-bytes

} CONTEXT, *PCONTEXT;

//
// Plabel descriptor structure definition
//

typedef struct _PLABEL_DESCRIPTOR {
   ULONGLONG EntryPoint;
   ULONGLONG GlobalPointer;
} PLABEL_DESCRIPTOR, *PPLABEL_DESCRIPTOR;



#endif // _IA64_


//
// Well known SID definitions for lookup.
//

typedef enum {

    WinNullSid                                  = 0,
    WinWorldSid                                 = 1,
    WinLocalSid                                 = 2,
    WinCreatorOwnerSid                          = 3,
    WinCreatorGroupSid                          = 4,
    WinCreatorOwnerServerSid                    = 5,
    WinCreatorGroupServerSid                    = 6,
    WinNtAuthoritySid                           = 7,
    WinDialupSid                                = 8,
    WinNetworkSid                               = 9,
    WinBatchSid                                 = 10,
    WinInteractiveSid                           = 11,
    WinServiceSid                               = 12,
    WinAnonymousSid                             = 13,
    WinProxySid                                 = 14,
    WinEnterpriseControllersSid                 = 15,
    WinSelfSid                                  = 16,
    WinAuthenticatedUserSid                     = 17,
    WinRestrictedCodeSid                        = 18,
    WinTerminalServerSid                        = 19,
    WinRemoteLogonIdSid                         = 20,
    WinLogonIdsSid                              = 21,
    WinLocalSystemSid                           = 22,
    WinLocalServiceSid                          = 23,
    WinNetworkServiceSid                        = 24,
    WinBuiltinDomainSid                         = 25,
    WinBuiltinAdministratorsSid                 = 26,
    WinBuiltinUsersSid                          = 27,
    WinBuiltinGuestsSid                         = 28,
    WinBuiltinPowerUsersSid                     = 29,
    WinBuiltinAccountOperatorsSid               = 30,
    WinBuiltinSystemOperatorsSid                = 31,
    WinBuiltinPrintOperatorsSid                 = 32,
    WinBuiltinBackupOperatorsSid                = 33,
    WinBuiltinReplicatorSid                     = 34,
    WinBuiltinPreWindows2000CompatibleAccessSid = 35,
    WinBuiltinRemoteDesktopUsersSid             = 36,
    WinBuiltinNetworkConfigurationOperatorsSid  = 37,
    WinAccountAdministratorSid                  = 38,
    WinAccountGuestSid                          = 39,
    WinAccountKrbtgtSid                         = 40,
    WinAccountDomainAdminsSid                   = 41,
    WinAccountDomainUsersSid                    = 42,
    WinAccountDomainGuestsSid                   = 43,
    WinAccountComputersSid                      = 44,
    WinAccountControllersSid                    = 45,
    WinAccountCertAdminsSid                     = 46,
    WinAccountSchemaAdminsSid                   = 47,
    WinAccountEnterpriseAdminsSid               = 48,
    WinAccountPolicyAdminsSid                   = 49,
    WinAccountRasAndIasServersSid               = 50,
    WinNTLMAuthenticationSid                    = 51,
    WinDigestAuthenticationSid                  = 52,
    WinSChannelAuthenticationSid                = 53,
    WinThisOrganizationSid                      = 54,
    WinOtherOrganizationSid                     = 55,
    WinBuiltinIncomingForestTrustBuildersSid    = 56,
    WinBuiltinPerfMonitoringUsersSid            = 57,
    WinBuiltinPerfLoggingUsersSid               = 58,
    WinBuiltinAuthorizationAccessSid            = 59,
    WinBuiltinTerminalServerLicenseServersSid   = 60,
    WinBuiltinDCOMUsersSid                      = 61,
    WinBuiltinIUsersSid                         = 62,
    WinIUserSid                                 = 63,
    WinBuiltinCryptoOperatorsSid                = 64,
    WinUntrustedLabelSid                        = 65,
    WinLowLabelSid                              = 66,
    WinMediumLabelSid                           = 67,
    WinHighLabelSid                             = 68,
    WinSystemLabelSid                           = 69,
    WinWriteRestrictedCodeSid                   = 70,
    WinCreatorOwnerRightsSid                    = 71,
    WinCacheablePrincipalsGroupSid              = 72,
    WinNonCacheablePrincipalsGroupSid           = 73,
    WinEnterpriseReadonlyControllersSid         = 74,
    WinAccountReadonlyControllersSid            = 75,
    WinBuiltinEventLogReadersGroup              = 76,
    WinNewEnterpriseReadonlyControllersSid      = 77,
    WinBuiltinCertSvcDComAccessGroup        = 78,
} WELL_KNOWN_SID_TYPE;

//
// Unsolicited Input is obsolete and unused.
//

#define SE_UNSOLICITED_INPUT_PRIVILEGE      (6L)

// begin_ntsecapi
#ifndef _NTLSA_IFS_


//
// All of this stuff (between the Ifndef _NTLSA_AUDIT_ and its endif) were not
// present in NTIFS prior to Windows Server 2003 SP1. All of the definitions however
// exist down to windows 2000 (except for the few exceptions noted in the code).
//

#ifndef _NTLSA_AUDIT_
#define _NTLSA_AUDIT_

/////////////////////////////////////////////////////////////////////////
//                                                                     //
// Data types related to Auditing                                      //
//                                                                     //
/////////////////////////////////////////////////////////////////////////


//
// The following enumerated type is used between the reference monitor and
// LSA in the generation of audit messages.  It is used to indicate the
// type of data being passed as a parameter from the reference monitor
// to LSA.  LSA is responsible for transforming the specified data type
// into a set of unicode strings that are added to the event record in
// the audit log.
//

typedef enum _SE_ADT_PARAMETER_TYPE {

    SeAdtParmTypeNone = 0,          //Produces 1 parameter
                                    //Received value:
                                    //
                                    //  None.
                                    //
                                    //Results in:
                                    //
                                    //  a unicode string containing "-".
                                    //
                                    //Note:  This is typically used to
                                    //       indicate that a parameter value
                                    //       was not available.
                                    //

    SeAdtParmTypeString,            //Produces 1 parameter.
                                    //Received Value:
                                    //
                                    //  Unicode String (variable length)
                                    //
                                    //Results in:
                                    //
                                    //  No transformation.  The string
                                    //  entered into the event record as
                                    //  received.
                                    //
                                    // The Address value of the audit info
                                    // should be a pointer to a UNICODE_STRING
                                    // structure.



    SeAdtParmTypeFileSpec,          //Produces 1 parameter.
                                    //Received value:
                                    //
                                    //  Unicode string containing a file or
                                    //  directory name.
                                    //
                                    //Results in:
                                    //
                                    //  Unicode string with the prefix of the
                                    //  file's path replaced by a drive letter
                                    //  if possible.
                                    //




    SeAdtParmTypeUlong,             //Produces 1 parameter
                                    //Received value:
                                    //
                                    //  Ulong
                                    //
                                    //Results in:
                                    //
                                    //  Unicode string representation of
                                    //  unsigned integer value.


    SeAdtParmTypeSid,               //Produces 1 parameter.
                                    //Received value:
                                    //
                                    //  SID (variable length)
                                    //
                                    //Results in:
                                    //
                                    //  String representation of SID
                                    //




    SeAdtParmTypeLogonId,           //Produces 4 parameters.
                                    //Received Value:
                                    //
                                    //  LUID (fixed length)
                                    //
                                    //Results in:
                                    //
                                    //  param 1: Sid string
                                    //  param 2: Username string
                                    //  param 3: domain name string
                                    //  param 4: Logon ID (Luid) string


    SeAdtParmTypeNoLogonId,         //Produces 3 parameters.
                                    //Received value:
                                    //
                                    //  None.
                                    //
                                    //Results in:
                                    //
                                    //  param 1: "-"
                                    //  param 2: "-"
                                    //  param 3: "-"
                                    //  param 4: "-"
                                    //
                                    //Note:
                                    //
                                    //  This type is used when a logon ID
                                    //  is needed, but one is not available
                                    //  to pass.  For example, if an
                                    //  impersonation logon ID is expected
                                    //  but the subject is not impersonating
                                    //  anyone.
                                    //

    SeAdtParmTypeAccessMask,        //Produces 1 parameter with formatting.
                                    //Received value:
                                    //
                                    //  ACCESS_MASK followed by
                                    //  a Unicode string.  The unicode
                                    //  string contains the name of the
                                    //  type of object the access mask
                                    //  applies to.  The event's source
                                    //  further qualifies the object type.
                                    //
                                    //Results in:
                                    //
                                    //  formatted unicode string built to
                                    //  take advantage of the specified
                                    //  source's parameter message file.
                                    //
                                    //Note:
                                    //
                                    //  An access mask containing three
                                    //  access types for a Widget object
                                    //  type (defined by the Foozle source)
                                    //  might end up looking like:
                                    //
                                    //      %%1062\n\t\t%1066\n\t\t%%601
                                    //
                                    //  The %%numbers are signals to the
                                    //  event viewer to perform parameter
                                    //  substitution before display.
                                    //



    SeAdtParmTypePrivs,             //Produces 1 parameter with formatting.
                                    //Received value:
                                    //
                                    //Results in:
                                    //
                                    //  formatted unicode string similar to
                                    //  that for access types.  Each priv
                                    //  will be formatted to be displayed
                                    //  on its own line.  E.g.,
                                    //
                                    //      %%642\n\t\t%%651\n\t\t%%655
                                    //

    SeAdtParmTypeObjectTypes,       //Produces 10 parameters with formatting.
                                    //Received value:
                                    //
                                    // Produces a list a stringized GUIDS along
                                    // with information similar to that for
                                    // an access mask.

    SeAdtParmTypeHexUlong,          //Produces 1 parameter
                                    //Received value:
                                    //
                                    //  Ulong
                                    //
                                    //Results in:
                                    //
                                    //  Unicode string representation of
                                    //  unsigned integer value in hexadecimal.

// In W2k this value did not exist, it was ParmTypeLUID

    SeAdtParmTypePtr,               //Produces 1 parameter
                                    //Received value:
                                    //
                                    //  pointer
                                    //
                                    //Results in:
                                    //
                                    //  Unicode string representation of
                                    //  unsigned integer value in hexadecimal.

//
// Everything below exists only in Windows XP and greater
//

    SeAdtParmTypeTime,              //Produces 2 parameters
                                    //Received value:
                                    //
                                    //  LARGE_INTEGER
                                    //
                                    //Results in:
                                    //
                                    // Unicode string representation of
                                    // date and time.

                                    //
    SeAdtParmTypeGuid,              //Produces 1 parameter
                                    //Received value:
                                    //
                                    //  GUID pointer
                                    //
                                    //Results in:
                                    //
                                    // Unicode string representation of GUID
                                    // {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
                                    //

//
// Everything below exists only in Windows Server 2003 and Greater
//

    SeAdtParmTypeLuid,              //
                                    //Produces 1 parameter
                                    //Received value:
                                    //
                                    // LUID
                                    //
                                    //Results in:
                                    //
                                    // Hex LUID
                                    //

    SeAdtParmTypeHexInt64,          //Produces 1 parameter
                                    //Received value:
                                    //
                                    //  64 bit integer
                                    //
                                    //Results in:
                                    //
                                    //  Unicode string representation of
                                    //  unsigned integer value in hexadecimal.

    SeAdtParmTypeStringList,        //Produces 1 parameter
                                    //Received value:
                                    //
                                    // ptr to LSAP_ADT_STRING_LIST
                                    //
                                    //Results in:
                                    //
                                    // Unicode string representation of
                                    // concatenation of the strings in the list

    SeAdtParmTypeSidList,           //Produces 1 parameter
                                    //Received value:
                                    //
                                    // ptr to LSAP_ADT_SID_LIST
                                    //
                                    //Results in:
                                    //
                                    // Unicode string representation of
                                    // concatenation of the SIDs in the list

    SeAdtParmTypeDuration,          //Produces 1 parameters
                                    //Received value:
                                    //
                                    //  LARGE_INTEGER
                                    //
                                    //Results in:
                                    //
                                    // Unicode string representation of
                                    // a duration.

    SeAdtParmTypeUserAccountControl,//Produces 3 parameters
                                    //Received value:
                                    //
                                    // old and new UserAccountControl values
                                    //
                                    //Results in:
                                    //
                                    // Unicode string representations of
                                    // the flags in UserAccountControl.
                                    // 1 - old value in hex
                                    // 2 - new value in hex
                                    // 3 - difference as strings

    SeAdtParmTypeNoUac,             //Produces 3 parameters
                                    //Received value:
                                    //
                                    // none
                                    //
                                    //Results in:
                                    //
                                    // Three dashes ('-') as unicode strings.

    SeAdtParmTypeMessage,           //Produces 1 Parameter
                                    //Received value:
                                    //
                                    //  ULONG (MessageNo from msobjs.mc)
                                    //
                                    //Results in:
                                    //
                                    // Unicode string representation of
                                    // %%MessageNo which the event viewer
                                    // will replace with the message string
                                    // from msobjs.mc

    SeAdtParmTypeDateTime,          //Produces 1 Parameter
                                    //Received value:
                                    //
                                    //  LARGE_INTEGER
                                    //
                                    //Results in:
                                    //
                                    // Unicode string representation of
                                    // date and time (in _one_ string).

    SeAdtParmTypeSockAddr,          // Produces 2 parameters
                                    //
                                    // Received value:
                                    //
                                    // pointer to SOCKADDR_IN/SOCKADDR_IN6
                                    // structure
                                    //
                                    // Results in:
                                    //
                                    // param 1: IP address string
                                    // param 2: Port number string
                                    //

//
// Everything below this exists only in Longhorn and greater
//

    SeAdtParmTypeSD,                // Produces 1 parameters
                                    //
                                    // Received value:
                                    //
                                    // pointer to SECURITY_DESCRIPTOR
                                    // structure
                                    //
                                    // Results in:
                                    //
                                    // SDDL string representation of SD
                                    //

    SeAdtParmTypeLogonHours,        // Produces 1 parameters
                                    //
                                    // Received value:
                                    //
                                    // pointer to LOGON_HOURS
                                    // structure
                                    //
                                    // Results in:
                                    //
                                    // String representation of allowed logon hours
                                    //

    SeAdtParmTypeLogonIdNoSid,      //Produces 3 parameters.
                                    //Received Value:
                                    //
                                    //  LUID (fixed length)
                                    //
                                    //Results in:
                                    //
                                    //  param 1: Username string
                                    //  param 2: domain name string
                                    //  param 3: Logon ID (Luid) string

    SeAdtParmTypeUlongNoConv,       // Produces 1 parameter.
                                    // Received Value:
                                    // Ulong
                                    //
                                    //Results in:
                                    // Not converted to string
                                    //

    SeAdtParmTypeSockAddrNoPort     // Produces 1 parameter
                                    //
                                    // Received value:
                                    //
                                    // pointer to SOCKADDR_IN/SOCKADDR_IN6
                                    // structure
                                    //
                                    // Results in:
                                    //
                                    // param 1: IPv4/IPv6 address string
                                    //

} SE_ADT_PARAMETER_TYPE, *PSE_ADT_PARAMETER_TYPE;

#ifndef GUID_DEFINED
#include <guiddef.h>
#endif /* GUID_DEFINED */

typedef struct _SE_ADT_OBJECT_TYPE {
    GUID ObjectType;
    USHORT Flags;
#define SE_ADT_OBJECT_ONLY 0x1
    USHORT Level;
    ACCESS_MASK AccessMask;
} SE_ADT_OBJECT_TYPE, *PSE_ADT_OBJECT_TYPE;

typedef struct _SE_ADT_PARAMETER_ARRAY_ENTRY {

    SE_ADT_PARAMETER_TYPE Type;
    ULONG Length;
    ULONG_PTR Data[2];
    PVOID Address;

} SE_ADT_PARAMETER_ARRAY_ENTRY, *PSE_ADT_PARAMETER_ARRAY_ENTRY;



//
// Structure that will be passed between the Reference Monitor and LSA
// to transmit auditing information.
//

#define SE_MAX_AUDIT_PARAMETERS 32
#define SE_MAX_GENERIC_AUDIT_PARAMETERS 28

typedef struct _SE_ADT_PARAMETER_ARRAY {

    ULONG CategoryId;
    ULONG AuditId;
    ULONG ParameterCount;
    ULONG Length;
    USHORT FlatSubCategoryId;
    USHORT Type;
    ULONG Flags;
    SE_ADT_PARAMETER_ARRAY_ENTRY Parameters[ SE_MAX_AUDIT_PARAMETERS ];

} SE_ADT_PARAMETER_ARRAY, *PSE_ADT_PARAMETER_ARRAY;


#define SE_ADT_PARAMETERS_SELF_RELATIVE     0x00000001
#define SE_ADT_PARAMETERS_SEND_TO_LSA       0x00000002
#define SE_ADT_PARAMETER_EXTENSIBLE_AUDIT   0x00000004
#define SE_ADT_PARAMETER_GENERIC_AUDIT      0x00000008
#define SE_ADT_PARAMETER_WRITE_SYNCHRONOUS  0x00000010


//
// This macro only existed in longhorn and after
//

#define LSAP_SE_ADT_PARAMETER_ARRAY_TRUE_SIZE(AuditParameters)    \
     ( sizeof(SE_ADT_PARAMETER_ARRAY) -                           \
       sizeof(SE_ADT_PARAMETER_ARRAY_ENTRY) *                     \
       (SE_MAX_AUDIT_PARAMETERS - AuditParameters->ParameterCount) )

#endif // _NTLSA_AUDIT_


#endif // _NTLSA_IFS_
// end_ntsecapi

#ifndef _RTL_RUN_ONCE_DEF
#define _RTL_RUN_ONCE_DEF

//
// Run once
//

#define RTL_RUN_ONCE_INIT {0}   // Static initializer

//
// Run once flags
//

#define RTL_RUN_ONCE_CHECK_ONLY     0x00000001UL
#define RTL_RUN_ONCE_ASYNC          0x00000002UL
#define RTL_RUN_ONCE_INIT_FAILED    0x00000004UL

//
// The context stored in the run once structure must leave the following number
// of low order bits unused.
//

#define RTL_RUN_ONCE_CTX_RESERVED_BITS 2

typedef union _RTL_RUN_ONCE {
    PVOID Ptr;
} RTL_RUN_ONCE, *PRTL_RUN_ONCE;

typedef
ULONG /* LOGICAL */
(NTAPI *PRTL_RUN_ONCE_INIT_FN) (
    __inout PRTL_RUN_ONCE RunOnce,
    __inout_opt PVOID Parameter,
    __deref_opt_out_opt PVOID *Context
    );

#endif // _RTL_RUN_ONCE_DEF

#if (NTDDI_VERSION >= NTDDI_LONGHORN)

NTSYSAPI
VOID
NTAPI
RtlRunOnceInitialize (
    __out PRTL_RUN_ONCE RunOnce
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlRunOnceExecuteOnce (
    __inout PRTL_RUN_ONCE RunOnce,
    __in __callback PRTL_RUN_ONCE_INIT_FN InitFn,
    __inout_opt PVOID Parameter,
    __deref_opt_out_opt PVOID *Context
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlRunOnceBeginInitialize (
    __inout PRTL_RUN_ONCE RunOnce,
    __in ULONG Flags,
    __deref_opt_out_opt PVOID *Context
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlRunOnceComplete (
    __inout PRTL_RUN_ONCE RunOnce,
    __in ULONG Flags,
    __in_opt PVOID Context
    );

#endif // NTDDI_VERSION >= NTDDI_LONGHORN


#if defined (_MSC_VER) && ( _MSC_VER >= 900 )

PVOID
_ReturnAddress (
    VOID
    );

#pragma intrinsic(_ReturnAddress)

#endif

#if (defined(_M_AMD64) || defined(_M_IA64)) && !defined(_REALLY_GET_CALLERS_CALLER_)

#define RtlGetCallersAddress(CallersAddress, CallersCaller) \
    *CallersAddress = (PVOID)_ReturnAddress(); \
    *CallersCaller = NULL;

#else

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
VOID
NTAPI
RtlGetCallersAddress(
    OUT PVOID *CallersAddress,
    OUT PVOID *CallersCaller
    );

#endif

#endif

//
// prototype for replaceable Stack Walker routine
//

typedef ULONG (NTAPI * PRTL_WALK_FRAME_CHAIN)(
    OUT PVOID *Callers,
    IN ULONG Count,
    IN ULONG Flags
    );

#if (NTDDI_VERSION >= NTDDI_WIN2K)

//
// Reserve byte 1 of the RtlWalkFrameChain flags for
// specifying a number of frames to skip.
//

#define RTL_STACK_WALKING_MODE_FRAMES_TO_SKIP_SHIFT     8

NTSYSAPI
ULONG
NTAPI
RtlWalkFrameChain (
    __out_ecount(Count - (Flags >> RTL_STACK_WALKING_MODE_FRAMES_TO_SKIP_SHIFT)) PVOID *Callers,
    __in ULONG Count,
    __in ULONG Flags
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
NTSTATUS
NTAPI
RtlCharToInteger (
    PCSZ String,
    ULONG Base,
    PULONG Value
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
VOID
NTAPI
RtlCopyString(
    PSTRING DestinationString,
    const STRING * SourceString
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
CHAR
NTAPI
RtlUpperChar (
    CHAR Character
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
LONG
NTAPI
RtlCompareString(
    const STRING * String1,
    const STRING * String2,
    BOOLEAN CaseInSensitive
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
BOOLEAN
NTAPI
RtlEqualString(
    const STRING * String1,
    const STRING * String2,
    BOOLEAN CaseInSensitive
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
VOID
NTAPI
RtlUpperString(
    PSTRING DestinationString,
    const STRING * SourceString
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
BOOLEAN
NTAPI
RtlPrefixUnicodeString(
    __in PCUNICODE_STRING String1,
    __in PCUNICODE_STRING String2,
    __in BOOLEAN CaseInSensitive
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
NTSTATUS
NTAPI
RtlUpcaseUnicodeString(
    __inout PUNICODE_STRING DestinationString,
    __in PCUNICODE_STRING SourceString,
    __in BOOLEAN AllocateDestinationString
    );
#endif

#if !defined(MIDL_PASS)
#if defined(_AMD64_) || defined(_IA64_)
//
// Large Integer divide - 64-bits / 64-bits -> 64-bits
//

DECLSPEC_DEPRECATED_DDK         // Use native __int64 math
__inline
LARGE_INTEGER
NTAPI_INLINE
RtlLargeIntegerDivide (
    LARGE_INTEGER Dividend,
    LARGE_INTEGER Divisor,
    PLARGE_INTEGER Remainder OPTIONAL
    )
{
    LARGE_INTEGER Quotient;

    Quotient.QuadPart = Dividend.QuadPart / Divisor.QuadPart;
    if (ARGUMENT_PRESENT(Remainder)) {
        Remainder->QuadPart = Dividend.QuadPart % Divisor.QuadPart;
    }

    return Quotient;
}

#else
//
// Large Integer divide - 64-bits / 64-bits -> 64-bits
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK         // Use native __int64 math
NTSYSAPI
LARGE_INTEGER
NTAPI
RtlLargeIntegerDivide (
    LARGE_INTEGER Dividend,
    LARGE_INTEGER Divisor,
    PLARGE_INTEGER Remainder
    );
#endif

#endif // defined(_AMD64_) || defined(_IA64_)
#endif // !defined(MIDL_PASS)


//
// BOOLEAN
// RtlEqualLuid(
//      PLUID L1,
//      PLUID L2
//      );

#define RtlEqualLuid(L1, L2) (((L1)->LowPart == (L2)->LowPart) && \
                              ((L1)->HighPart  == (L2)->HighPart))

//
// BOOLEAN
// RtlIsZeroLuid(
//      PLUID L1
//      );
//
#define RtlIsZeroLuid(L1) ((BOOLEAN) (((L1)->LowPart | (L1)->HighPart) == 0))



#if !defined(MIDL_PASS)

FORCEINLINE
LUID
NTAPI_INLINE
RtlConvertLongToLuid(
    LONG Long
    )
{
    LUID TempLuid;
    LARGE_INTEGER TempLi;

    TempLi.QuadPart = Long;
    TempLuid.LowPart = TempLi.u.LowPart;
    TempLuid.HighPart = TempLi.u.HighPart;
    return(TempLuid);
}

FORCEINLINE
LUID
NTAPI_INLINE
RtlConvertUlongToLuid(
    ULONG Ulong
    )
{
    LUID TempLuid;

    TempLuid.LowPart = Ulong;
    TempLuid.HighPart = 0;
    return(TempLuid);
}
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
VOID
NTAPI
RtlMapGenericMask(
    PACCESS_MASK AccessMask,
    PGENERIC_MAPPING GenericMapping
    );
#endif

//
// Routine for converting from a volume device object to a DOS name.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
NTSTATUS
NTAPI
RtlVolumeDeviceToDosName(
    IN  PVOID           VolumeDeviceObject,
    OUT PUNICODE_STRING DosName
    );
#endif

typedef struct _OSVERSIONINFOA {
    ULONG dwOSVersionInfoSize;
    ULONG dwMajorVersion;
    ULONG dwMinorVersion;
    ULONG dwBuildNumber;
    ULONG dwPlatformId;
    CHAR   szCSDVersion[ 128 ];     // Maintenance string for PSS usage
} OSVERSIONINFOA, *POSVERSIONINFOA, *LPOSVERSIONINFOA;

typedef struct _OSVERSIONINFOW {
    ULONG dwOSVersionInfoSize;
    ULONG dwMajorVersion;
    ULONG dwMinorVersion;
    ULONG dwBuildNumber;
    ULONG dwPlatformId;
    WCHAR  szCSDVersion[ 128 ];     // Maintenance string for PSS usage
} OSVERSIONINFOW, *POSVERSIONINFOW, *LPOSVERSIONINFOW, RTL_OSVERSIONINFOW, *PRTL_OSVERSIONINFOW;
#ifdef UNICODE
typedef OSVERSIONINFOW OSVERSIONINFO;
typedef POSVERSIONINFOW POSVERSIONINFO;
typedef LPOSVERSIONINFOW LPOSVERSIONINFO;
#else
typedef OSVERSIONINFOA OSVERSIONINFO;
typedef POSVERSIONINFOA POSVERSIONINFO;
typedef LPOSVERSIONINFOA LPOSVERSIONINFO;
#endif // UNICODE

typedef struct _OSVERSIONINFOEXA {
    ULONG dwOSVersionInfoSize;
    ULONG dwMajorVersion;
    ULONG dwMinorVersion;
    ULONG dwBuildNumber;
    ULONG dwPlatformId;
    CHAR   szCSDVersion[ 128 ];     // Maintenance string for PSS usage
    USHORT wServicePackMajor;
    USHORT wServicePackMinor;
    USHORT wSuiteMask;
    UCHAR wProductType;
    UCHAR wReserved;
} OSVERSIONINFOEXA, *POSVERSIONINFOEXA, *LPOSVERSIONINFOEXA;
typedef struct _OSVERSIONINFOEXW {
    ULONG dwOSVersionInfoSize;
    ULONG dwMajorVersion;
    ULONG dwMinorVersion;
    ULONG dwBuildNumber;
    ULONG dwPlatformId;
    WCHAR  szCSDVersion[ 128 ];     // Maintenance string for PSS usage
    USHORT wServicePackMajor;
    USHORT wServicePackMinor;
    USHORT wSuiteMask;
    UCHAR wProductType;
    UCHAR wReserved;
} OSVERSIONINFOEXW, *POSVERSIONINFOEXW, *LPOSVERSIONINFOEXW, RTL_OSVERSIONINFOEXW, *PRTL_OSVERSIONINFOEXW;
#ifdef UNICODE
typedef OSVERSIONINFOEXW OSVERSIONINFOEX;
typedef POSVERSIONINFOEXW POSVERSIONINFOEX;
typedef LPOSVERSIONINFOEXW LPOSVERSIONINFOEX;
#else
typedef OSVERSIONINFOEXA OSVERSIONINFOEX;
typedef POSVERSIONINFOEXA POSVERSIONINFOEX;
typedef LPOSVERSIONINFOEXA LPOSVERSIONINFOEX;
#endif // UNICODE

//
// RtlVerifyVersionInfo() conditions
//

#define VER_EQUAL                       1
#define VER_GREATER                     2
#define VER_GREATER_EQUAL               3
#define VER_LESS                        4
#define VER_LESS_EQUAL                  5
#define VER_AND                         6
#define VER_OR                          7

#define VER_CONDITION_MASK              7
#define VER_NUM_BITS_PER_CONDITION_MASK 3

//
// RtlVerifyVersionInfo() type mask bits
//

#define VER_MINORVERSION                0x0000001
#define VER_MAJORVERSION                0x0000002
#define VER_BUILDNUMBER                 0x0000004
#define VER_PLATFORMID                  0x0000008
#define VER_SERVICEPACKMINOR            0x0000010
#define VER_SERVICEPACKMAJOR            0x0000020
#define VER_SUITENAME                   0x0000040
#define VER_PRODUCT_TYPE                0x0000080

//
// RtlVerifyVersionInfo() os product type values
//

#define VER_NT_WORKSTATION              0x0000001
#define VER_NT_DOMAIN_CONTROLLER        0x0000002
#define VER_NT_SERVER                   0x0000003

//
// dwPlatformId defines:
//

#define VER_PLATFORM_WIN32s             0
#define VER_PLATFORM_WIN32_WINDOWS      1
#define VER_PLATFORM_WIN32_NT           2


//
//
// VerifyVersionInfo() macro to set the condition mask
//
// For documentation sakes here's the old version of the macro that got
// changed to call an API
// #define VER_SET_CONDITION(_m_,_t_,_c_)  _m_=(_m_|(_c_<<(1<<_t_)))
//

#define VER_SET_CONDITION(_m_,_t_,_c_)  \
        ((_m_)=VerSetConditionMask((_m_),(_t_),(_c_)))

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
ULONGLONG
NTAPI
VerSetConditionMask(
        IN  ULONGLONG   ConditionMask,
        IN  ULONG   TypeMask,
        IN  UCHAR   Condition
        );
#endif

//

//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
NTSTATUS
NTAPI
RtlGetVersion(
    OUT PRTL_OSVERSIONINFOW lpVersionInformation
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlVerifyVersionInfo(
    IN PRTL_OSVERSIONINFOEXW VersionInfo,
    IN ULONG TypeMask,
    IN ULONGLONG  ConditionMask
    );
#endif

NTSYSAPI
ULONG
NTAPI
DbgPrompt (
    __in PCCH Prompt,
    __out_bcount(Length) PCH Response,
    __in ULONG Length
    );

//

#if (NTDDI_VERSION >= NTDDI_VISTA)

NTSYSAPI
BOOLEAN
NTAPI
RtlGetProductInfo(
    __in  ULONG  OSMajorVersion,
    __in  ULONG  OSMinorVersion,
    __in  ULONG  SpMajorVersion,
    __in  ULONG  SpMinorVersion,
    __out PULONG ReturnedProductType
    );

#endif

//
// Define the various device type values.  Note that values used by Microsoft
// Corporation are in the range 0-32767, and 32768-65535 are reserved for use
// by customers.
//

#define DEVICE_TYPE ULONG

#define FILE_DEVICE_BEEP                0x00000001
#define FILE_DEVICE_CD_ROM              0x00000002
#define FILE_DEVICE_CD_ROM_FILE_SYSTEM  0x00000003
#define FILE_DEVICE_CONTROLLER          0x00000004
#define FILE_DEVICE_DATALINK            0x00000005
#define FILE_DEVICE_DFS                 0x00000006
#define FILE_DEVICE_DISK                0x00000007
#define FILE_DEVICE_DISK_FILE_SYSTEM    0x00000008
#define FILE_DEVICE_FILE_SYSTEM         0x00000009
#define FILE_DEVICE_INPORT_PORT         0x0000000a
#define FILE_DEVICE_KEYBOARD            0x0000000b
#define FILE_DEVICE_MAILSLOT            0x0000000c
#define FILE_DEVICE_MIDI_IN             0x0000000d
#define FILE_DEVICE_MIDI_OUT            0x0000000e
#define FILE_DEVICE_MOUSE               0x0000000f
#define FILE_DEVICE_MULTI_UNC_PROVIDER  0x00000010
#define FILE_DEVICE_NAMED_PIPE          0x00000011
#define FILE_DEVICE_NETWORK             0x00000012
#define FILE_DEVICE_NETWORK_BROWSER     0x00000013
#define FILE_DEVICE_NETWORK_FILE_SYSTEM 0x00000014
#define FILE_DEVICE_NULL                0x00000015
#define FILE_DEVICE_PARALLEL_PORT       0x00000016
#define FILE_DEVICE_PHYSICAL_NETCARD    0x00000017
#define FILE_DEVICE_PRINTER             0x00000018
#define FILE_DEVICE_SCANNER             0x00000019
#define FILE_DEVICE_SERIAL_MOUSE_PORT   0x0000001a
#define FILE_DEVICE_SERIAL_PORT         0x0000001b
#define FILE_DEVICE_SCREEN              0x0000001c
#define FILE_DEVICE_SOUND               0x0000001d
#define FILE_DEVICE_STREAMS             0x0000001e
#define FILE_DEVICE_TAPE                0x0000001f
#define FILE_DEVICE_TAPE_FILE_SYSTEM    0x00000020
#define FILE_DEVICE_TRANSPORT           0x00000021
#define FILE_DEVICE_UNKNOWN             0x00000022
#define FILE_DEVICE_VIDEO               0x00000023
#define FILE_DEVICE_VIRTUAL_DISK        0x00000024
#define FILE_DEVICE_WAVE_IN             0x00000025
#define FILE_DEVICE_WAVE_OUT            0x00000026
#define FILE_DEVICE_8042_PORT           0x00000027
#define FILE_DEVICE_NETWORK_REDIRECTOR  0x00000028
#define FILE_DEVICE_BATTERY             0x00000029
#define FILE_DEVICE_BUS_EXTENDER        0x0000002a
#define FILE_DEVICE_MODEM               0x0000002b
#define FILE_DEVICE_VDM                 0x0000002c
#define FILE_DEVICE_MASS_STORAGE        0x0000002d
#define FILE_DEVICE_SMB                 0x0000002e
#define FILE_DEVICE_KS                  0x0000002f
#define FILE_DEVICE_CHANGER             0x00000030
#define FILE_DEVICE_SMARTCARD           0x00000031
#define FILE_DEVICE_ACPI                0x00000032
#define FILE_DEVICE_DVD                 0x00000033
#define FILE_DEVICE_FULLSCREEN_VIDEO    0x00000034
#define FILE_DEVICE_DFS_FILE_SYSTEM     0x00000035
#define FILE_DEVICE_DFS_VOLUME          0x00000036
#define FILE_DEVICE_SERENUM             0x00000037
#define FILE_DEVICE_TERMSRV             0x00000038
#define FILE_DEVICE_KSEC                0x00000039
#define FILE_DEVICE_FIPS                0x0000003A
#define FILE_DEVICE_INFINIBAND          0x0000003B
#define FILE_DEVICE_VMBUS               0x0000003E
#define FILE_DEVICE_CRYPT_PROVIDER      0x0000003F
#define FILE_DEVICE_WPD                 0x00000040
#define FILE_DEVICE_BLUETOOTH           0x00000041

//
// Macro definition for defining IOCTL and FSCTL function control codes.  Note
// that function codes 0-2047 are reserved for Microsoft Corporation, and
// 2048-4095 are reserved for customers.
//

#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

//
// Macro to extract device type out of the device io control code
//
#define DEVICE_TYPE_FROM_CTL_CODE(ctrlCode)     (((ULONG)(ctrlCode & 0xffff0000)) >> 16)

//
// Macro to extract buffering method out of the device io control code
//
#define METHOD_FROM_CTL_CODE(ctrlCode)          ((ULONG)(ctrlCode & 3))

//
// Define the method codes for how buffers are passed for I/O and FS controls
//

#define METHOD_BUFFERED                 0
#define METHOD_IN_DIRECT                1
#define METHOD_OUT_DIRECT               2
#define METHOD_NEITHER                  3

//
// Define some easier to comprehend aliases:
//   METHOD_DIRECT_TO_HARDWARE (writes, aka METHOD_IN_DIRECT)
//   METHOD_DIRECT_FROM_HARDWARE (reads, aka METHOD_OUT_DIRECT)
//

#define METHOD_DIRECT_TO_HARDWARE       METHOD_IN_DIRECT
#define METHOD_DIRECT_FROM_HARDWARE     METHOD_OUT_DIRECT

//
// Define the access check value for any access
//
//
// The FILE_READ_ACCESS and FILE_WRITE_ACCESS constants are also defined in
// ntioapi.h as FILE_READ_DATA and FILE_WRITE_DATA. The values for these
// constants *MUST* always be in sync.
//
//
// FILE_SPECIAL_ACCESS is checked by the NT I/O system the same as FILE_ANY_ACCESS.
// The file systems, however, may add additional access checks for I/O and FS controls
// that use this value.
//


#define FILE_ANY_ACCESS                 0
#define FILE_SPECIAL_ACCESS    (FILE_ANY_ACCESS)
#define FILE_READ_ACCESS          ( 0x0001 )    // file & pipe
#define FILE_WRITE_ACCESS         ( 0x0002 )    // file & pipe


//
// The FILE_EXPECT flags will only exist for WinXP. After that they will be
// ignored and an IRP will be sent in their place.
//
#define FILE_CHARACTERISTICS_EXPECT_ORDERLY_REMOVAL     0x00000200
#define FILE_CHARACTERISTICS_EXPECT_SURPRISE_REMOVAL    0x00000300
#define FILE_CHARACTERISTICS_REMOVAL_POLICY_MASK        0x00000300

//
// flags specified here will be propagated up and down a device stack
// after FDO and all filter devices are added, but before the device
// stack is started
//

#define FILE_CHARACTERISTICS_PROPAGATED (   FILE_REMOVABLE_MEDIA   | \
                                            FILE_READ_ONLY_DEVICE  | \
                                            FILE_FLOPPY_DISKETTE   | \
                                            FILE_WRITE_ONCE_MEDIA  | \
                                            FILE_DEVICE_SECURE_OPEN  )


typedef struct _FILE_ALIGNMENT_INFORMATION {
    ULONG AlignmentRequirement;
} FILE_ALIGNMENT_INFORMATION, *PFILE_ALIGNMENT_INFORMATION;

//
// This is also used for FileNormalizedNameInformation
//

typedef struct _FILE_NAME_INFORMATION {
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

typedef struct _FILE_ATTRIBUTE_TAG_INFORMATION {
    ULONG FileAttributes;
    ULONG ReparseTag;
} FILE_ATTRIBUTE_TAG_INFORMATION, *PFILE_ATTRIBUTE_TAG_INFORMATION;

typedef struct _FILE_DISPOSITION_INFORMATION {
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;

typedef struct _FILE_END_OF_FILE_INFORMATION {
    LARGE_INTEGER EndOfFile;
} FILE_END_OF_FILE_INFORMATION, *PFILE_END_OF_FILE_INFORMATION;

typedef struct _FILE_VALID_DATA_LENGTH_INFORMATION {
    LARGE_INTEGER ValidDataLength;
} FILE_VALID_DATA_LENGTH_INFORMATION, *PFILE_VALID_DATA_LENGTH_INFORMATION;

//
// NtQuery[Set]VolumeInformationFile types:
//
//  FILE_FS_LABEL_INFORMATION
//  FILE_FS_VOLUME_INFORMATION
//  FILE_FS_SIZE_INFORMATION
//  FILE_FS_DEVICE_INFORMATION
//  FILE_FS_ATTRIBUTE_INFORMATION
//  FILE_FS_CONTROL_INFORMATION
//  FILE_FS_OBJECTID_INFORMATION
//

typedef struct _FILE_FS_LABEL_INFORMATION {
    ULONG VolumeLabelLength;
    WCHAR VolumeLabel[1];
} FILE_FS_LABEL_INFORMATION, *PFILE_FS_LABEL_INFORMATION;

typedef struct _FILE_FS_VOLUME_INFORMATION {
    LARGE_INTEGER VolumeCreationTime;
    ULONG VolumeSerialNumber;
    ULONG VolumeLabelLength;
    BOOLEAN SupportsObjects;
    WCHAR VolumeLabel[1];
} FILE_FS_VOLUME_INFORMATION, *PFILE_FS_VOLUME_INFORMATION;

typedef struct _FILE_FS_SIZE_INFORMATION {
    LARGE_INTEGER TotalAllocationUnits;
    LARGE_INTEGER AvailableAllocationUnits;
    ULONG SectorsPerAllocationUnit;
    ULONG BytesPerSector;
} FILE_FS_SIZE_INFORMATION, *PFILE_FS_SIZE_INFORMATION;

typedef struct _FILE_FS_FULL_SIZE_INFORMATION {
    LARGE_INTEGER TotalAllocationUnits;
    LARGE_INTEGER CallerAvailableAllocationUnits;
    LARGE_INTEGER ActualAvailableAllocationUnits;
    ULONG SectorsPerAllocationUnit;
    ULONG BytesPerSector;
} FILE_FS_FULL_SIZE_INFORMATION, *PFILE_FS_FULL_SIZE_INFORMATION;

typedef struct _FILE_FS_OBJECTID_INFORMATION {
    UCHAR ObjectId[16];
    UCHAR ExtendedInfo[48];
} FILE_FS_OBJECTID_INFORMATION, *PFILE_FS_OBJECTID_INFORMATION;


//
// Define segement buffer structure for scatter/gather read/write.
//

typedef union _FILE_SEGMENT_ELEMENT {
    PVOID64 Buffer;
    ULONGLONG Alignment;
}FILE_SEGMENT_ELEMENT, *PFILE_SEGMENT_ELEMENT;

//
// AVIO IOCTLS.
//

#define IOCTL_AVIO_ALLOCATE_STREAM      CTL_CODE(FILE_DEVICE_AVIO, 1, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_AVIO_FREE_STREAM          CTL_CODE(FILE_DEVICE_AVIO, 2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_AVIO_MODIFY_STREAM        CTL_CODE(FILE_DEVICE_AVIO, 3, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)


//
// Define types of bus information.
//

typedef enum _BUS_DATA_TYPE {
    ConfigurationSpaceUndefined = -1,
    Cmos,
    EisaConfiguration,
    Pos,
    CbusConfiguration,
    PCIConfiguration,
    VMEConfiguration,
    NuBusConfiguration,
    PCMCIAConfiguration,
    MPIConfiguration,
    MPSAConfiguration,
    PNPISAConfiguration,
    SgiInternalConfiguration,
    MaximumBusDataType
} BUS_DATA_TYPE, *PBUS_DATA_TYPE;

typedef struct _KEY_NAME_INFORMATION {
    ULONG   NameLength;
    WCHAR   Name[1];            // Variable length string
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

typedef struct _KEY_CACHED_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG   TitleIndex;
    ULONG   SubKeys;
    ULONG   MaxNameLen;
    ULONG   Values;
    ULONG   MaxValueNameLen;
    ULONG   MaxValueDataLen;
    ULONG   NameLength;
} KEY_CACHED_INFORMATION, *PKEY_CACHED_INFORMATION;

#define     REG_KEY_DONT_JOURNAL        1
#define     REG_KEY_DONT_VIRTUALIZE     2
#define     REG_KEY_DONT_SILENT_FAIL    4
#define     REG_KEY_RECURSE_FLAG        8

typedef struct _KEY_FLAGS_INFORMATION {
    ULONG   Wow64Flags;
    ULONG   KeyFlags;           // LSB bit set --> Key is Volatile
                                // second to LSB bit set --> Key is symlink

    ULONG   ControlFlags;       // combination of the above flags
} KEY_FLAGS_INFORMATION, *PKEY_FLAGS_INFORMATION;

typedef struct _KEY_VIRTUALIZATION_INFORMATION {
    ULONG   VirtualizationCandidate : 1; // Tells whether the key is part of the virtualization namespace scope (only HKLM\Software for now)
    ULONG   VirtualizationEnabled   : 1; // Tells whether virtualization is enabled on this key. Can be 1 only if above flag is 1.
    ULONG   VirtualTarget           : 1; // Tells if the key is a virtual key. Can be 1 only if above 2 are 0. Valid only on the virtual store key handles.
    ULONG   VirtualStore            : 1; // Tells if the key is a part of the virtual sore path. Valid only on the virtual store key handles.
    ULONG   VirtualSource           : 1; // Tells if the key has ever been virtualized, Can be 1 only if VirtualizationCandidate is 1
    ULONG   Reserved                : 27;
} KEY_VIRTUALIZATION_INFORMATION, *PKEY_VIRTUALIZATION_INFORMATION;

//
// Thread Environment Block (and portable part of Thread Information Block)
//

//
//  NT_TIB - Thread Information Block - Portable part.
//
//      This is the subsystem portable part of the Thread Information Block.
//      It appears as the first part of the TEB for all threads which have
//      a user mode component.
//
//



typedef struct _NT_TIB {
    struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID SubSystemTib;
#if defined(_MSC_EXTENSIONS)
    union {
        PVOID FiberData;
        ULONG Version;
    };
#else
    PVOID FiberData;
#endif
    PVOID ArbitraryUserPointer;
    struct _NT_TIB *Self;
} NT_TIB;
typedef NT_TIB *PNT_TIB;

//
// 32 and 64 bit specific version for wow64 and the debugger
//
typedef struct _NT_TIB32 {
    ULONG ExceptionList;
    ULONG StackBase;
    ULONG StackLimit;
    ULONG SubSystemTib;
#if defined(_MSC_EXTENSIONS)
    union {
        ULONG FiberData;
        ULONG Version;
    };
#else
    ULONG FiberData;
#endif
    ULONG ArbitraryUserPointer;
    ULONG Self;
} NT_TIB32, *PNT_TIB32;

typedef struct _NT_TIB64 {
    ULONG64 ExceptionList;
    ULONG64 StackBase;
    ULONG64 StackLimit;
    ULONG64 SubSystemTib;
#if defined(_MSC_EXTENSIONS)
    union {
        ULONG64 FiberData;
        ULONG Version;
    };
#else
    ULONG64 FiberData;
#endif
    ULONG64 ArbitraryUserPointer;
    ULONG64 Self;
} NT_TIB64, *PNT_TIB64;

//
// Process Information Classes
//

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,          // Note: this is kernel mode only
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    ProcessHandleTracing,
    ProcessIoPriority,
    ProcessExecuteFlags,
    ProcessTlsInformation,
    ProcessCookie,
    ProcessImageInformation,
    ProcessCycleTime,
    ProcessPagePriority,
    ProcessInstrumentationCallback,
    ProcessThreadStackAllocation,
    ProcessWorkingSetWatchEx,
    ProcessImageFileNameWin32,
    ProcessImageFileMapping,
    ProcessAffinityUpdateMode,
    ProcessMemoryAllocationMode,
    MaxProcessInfoClass             // MaxProcessInfoClass should always be the last enum
} PROCESSINFOCLASS;

//
// Thread Information Classes
//

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,   // Obsolete
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    ThreadBreakOnTermination,
    ThreadSwitchLegacyState,
    ThreadIsTerminated,
    ThreadLastSystemCall,
    ThreadIoPriority,
    ThreadCycleTime,
    ThreadPagePriority,
    ThreadActualBasePriority,
    ThreadTebInformation,
    ThreadCSwitchMon,
    ThreadCSwitchPmu,
    MaxThreadInfoClass
} THREADINFOCLASS;

#define THREAD_CSWITCH_PMU_DISABLE  FALSE
#define THREAD_CSWITCH_PMU_ENABLE   TRUE

//
// Process Information Structures
//

//
// Working set page priority information.
// Used with ProcessPagePriority and ThreadPagePriority
//

typedef struct _PAGE_PRIORITY_INFORMATION {
    ULONG PagePriority;
} PAGE_PRIORITY_INFORMATION, *PPAGE_PRIORITY_INFORMATION;

//
// PageFaultHistory Information
//  NtQueryInformationProcess using ProcessWorkingSetWatch
//
typedef struct _PROCESS_WS_WATCH_INFORMATION {
    PVOID FaultingPc;
    PVOID FaultingVa;
} PROCESS_WS_WATCH_INFORMATION, *PPROCESS_WS_WATCH_INFORMATION;

//
// Basic and Extended Basic Process Information
//  NtQueryInformationProcess using ProcessBasicInformation
//

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION,*PPROCESS_BASIC_INFORMATION;

typedef struct _PROCESS_EXTENDED_BASIC_INFORMATION {
    SIZE_T Size;    // Must be set to structure size on input
    PROCESS_BASIC_INFORMATION BasicInfo;
    union {
        ULONG Flags;
        struct {
            ULONG IsProtectedProcess : 1;
            ULONG IsWow64Process : 1;
            ULONG IsProcessDeleting : 1;
            ULONG IsCrossSessionCreate : 1;
            ULONG SpareBits : 28;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} PROCESS_EXTENDED_BASIC_INFORMATION, *PPROCESS_EXTENDED_BASIC_INFORMATION;


//
// Process Device Map information
//  NtQueryInformationProcess using ProcessDeviceMap
//  NtSetInformationProcess using ProcessDeviceMap
//

typedef struct _PROCESS_DEVICEMAP_INFORMATION {
    union {
        struct {
            HANDLE DirectoryHandle;
        } Set;
        struct {
            ULONG DriveMap;
            UCHAR DriveType[ 32 ];
        } Query;
    } DUMMYUNIONNAME;
} PROCESS_DEVICEMAP_INFORMATION, *PPROCESS_DEVICEMAP_INFORMATION;

typedef struct _PROCESS_DEVICEMAP_INFORMATION_EX {
    union {
        struct {
            HANDLE DirectoryHandle;
        } Set;
        struct {
            ULONG DriveMap;
            UCHAR DriveType[ 32 ];
        } Query;
    } DUMMYUNIONNAME;
    ULONG Flags;    // specifies that the query type
} PROCESS_DEVICEMAP_INFORMATION_EX, *PPROCESS_DEVICEMAP_INFORMATION_EX;

//
// PROCESS_DEVICEMAP_INFORMATION_EX flags
//
#define PROCESS_LUID_DOSDEVICES_ONLY 0x00000001

//
// Multi-User Session specific Process Information
//  NtQueryInformationProcess using ProcessSessionInformation
//

typedef struct _PROCESS_SESSION_INFORMATION {
    ULONG SessionId;
} PROCESS_SESSION_INFORMATION, *PPROCESS_SESSION_INFORMATION;

typedef struct _PROCESS_HANDLE_TRACING_ENABLE {
    ULONG Flags;
} PROCESS_HANDLE_TRACING_ENABLE, *PPROCESS_HANDLE_TRACING_ENABLE;

typedef struct _PROCESS_HANDLE_TRACING_ENABLE_EX {
    ULONG Flags;
    ULONG TotalSlots;
} PROCESS_HANDLE_TRACING_ENABLE_EX, *PPROCESS_HANDLE_TRACING_ENABLE_EX;


#define PROCESS_HANDLE_TRACING_MAX_STACKS 16

typedef struct _PROCESS_HANDLE_TRACING_ENTRY {
    HANDLE Handle;
    CLIENT_ID ClientId;
    ULONG Type;
    PVOID Stacks[PROCESS_HANDLE_TRACING_MAX_STACKS];
} PROCESS_HANDLE_TRACING_ENTRY, *PPROCESS_HANDLE_TRACING_ENTRY;

typedef struct _PROCESS_HANDLE_TRACING_QUERY {
    HANDLE Handle;
    ULONG  TotalTraces;
    PROCESS_HANDLE_TRACING_ENTRY HandleTrace[1];
} PROCESS_HANDLE_TRACING_QUERY, *PPROCESS_HANDLE_TRACING_QUERY;

//
// Process Quotas
//  NtQueryInformationProcess using ProcessQuotaLimits
//  NtQueryInformationProcess using ProcessPooledQuotaLimits
//  NtSetInformationProcess using ProcessQuotaLimits
//



typedef struct _QUOTA_LIMITS {
    SIZE_T PagedPoolLimit;
    SIZE_T NonPagedPoolLimit;
    SIZE_T MinimumWorkingSetSize;
    SIZE_T MaximumWorkingSetSize;
    SIZE_T PagefileLimit;
    LARGE_INTEGER TimeLimit;
} QUOTA_LIMITS, *PQUOTA_LIMITS;

#define QUOTA_LIMITS_HARDWS_MIN_ENABLE  0x00000001
#define QUOTA_LIMITS_HARDWS_MIN_DISABLE 0x00000002
#define QUOTA_LIMITS_HARDWS_MAX_ENABLE  0x00000004
#define QUOTA_LIMITS_HARDWS_MAX_DISABLE 0x00000008
#define QUOTA_LIMITS_USE_DEFAULT_LIMITS 0x00000010

typedef union _RATE_QUOTA_LIMIT {
    ULONG RateData;
    struct {
        ULONG RatePercent : 7;
        ULONG Reserved0   : 25;
    } DUMMYSTRUCTNAME;
} RATE_QUOTA_LIMIT, *PRATE_QUOTA_LIMIT;

typedef struct _QUOTA_LIMITS_EX {
    SIZE_T PagedPoolLimit;
    SIZE_T NonPagedPoolLimit;
    SIZE_T MinimumWorkingSetSize;
    SIZE_T MaximumWorkingSetSize;
    SIZE_T PagefileLimit;               // Limit expressed in pages
    LARGE_INTEGER TimeLimit;
    SIZE_T WorkingSetLimit;             // Limit expressed in pages
    SIZE_T Reserved2;
    SIZE_T Reserved3;
    SIZE_T Reserved4;
    ULONG  Flags;
    RATE_QUOTA_LIMIT CpuRateLimit;
} QUOTA_LIMITS_EX, *PQUOTA_LIMITS_EX;



//
// Process I/O Counters
//  NtQueryInformationProcess using ProcessIoCounters
//


typedef struct _IO_COUNTERS {
    ULONGLONG  ReadOperationCount;
    ULONGLONG  WriteOperationCount;
    ULONGLONG  OtherOperationCount;
    ULONGLONG ReadTransferCount;
    ULONGLONG WriteTransferCount;
    ULONGLONG OtherTransferCount;
} IO_COUNTERS;
typedef IO_COUNTERS *PIO_COUNTERS;



//
// Process Virtual Memory Counters
//  NtQueryInformationProcess using ProcessVmCounters
//

typedef struct _VM_COUNTERS {
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
} VM_COUNTERS;
typedef VM_COUNTERS *PVM_COUNTERS;

typedef struct _VM_COUNTERS_EX {
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivateUsage;
} VM_COUNTERS_EX;
typedef VM_COUNTERS_EX *PVM_COUNTERS_EX;

//
// Process Pooled Quota Usage and Limits
//  NtQueryInformationProcess using ProcessPooledUsageAndLimits
//

typedef struct _POOLED_USAGE_AND_LIMITS {
    SIZE_T PeakPagedPoolUsage;
    SIZE_T PagedPoolUsage;
    SIZE_T PagedPoolLimit;
    SIZE_T PeakNonPagedPoolUsage;
    SIZE_T NonPagedPoolUsage;
    SIZE_T NonPagedPoolLimit;
    SIZE_T PeakPagefileUsage;
    SIZE_T PagefileUsage;
    SIZE_T PagefileLimit;
} POOLED_USAGE_AND_LIMITS;
typedef POOLED_USAGE_AND_LIMITS *PPOOLED_USAGE_AND_LIMITS;

//
// Process Security Context Information
//  NtSetInformationProcess using ProcessAccessToken
// PROCESS_SET_ACCESS_TOKEN access to the process is needed
// to use this info level.
//

typedef struct _PROCESS_ACCESS_TOKEN {

    //
    // Handle to Primary token to assign to the process.
    // TOKEN_ASSIGN_PRIMARY access to this token is needed.
    //

    HANDLE Token;

    //
    // Handle to the initial thread of the process.
    // A process's access token can only be changed if the process has
    // no threads or a single thread that has not yet begun execution.
    //
    // N.B. This field is unused.
    //

    HANDLE Thread;

} PROCESS_ACCESS_TOKEN, *PPROCESS_ACCESS_TOKEN;

//
// Process Exception Port Information
//  NtSetInformationProcess using ProcessExceptionPort
// PROCESS_SET_PORT access to the process is needed
// to use this info level.
//

#define PROCESS_EXCEPTION_PORT_ALL_STATE_BITS     0x00000003UL
#define PROCESS_EXCEPTION_PORT_ALL_STATE_FLAGS    ((ULONG_PTR)((1UL << PROCESS_EXCEPTION_PORT_ALL_STATE_BITS) - 1))

typedef struct _PROCESS_EXCEPTION_PORT {

    //
    // Handle to the exception port. No particular access required.
    //

    IN HANDLE ExceptionPortHandle;

    //
    // Miscellaneous state flags to be cached along with the exception
    // port in the kernel.
    //

    IN OUT ULONG StateFlags;

} PROCESS_EXCEPTION_PORT, *PPROCESS_EXCEPTION_PORT;

//
// Process/Thread System and User Time
//  NtQueryInformationProcess using ProcessTimes
//  NtQueryInformationThread using ThreadTimes
//

typedef struct _KERNEL_USER_TIMES {
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
} KERNEL_USER_TIMES;
typedef KERNEL_USER_TIMES *PKERNEL_USER_TIMES;


__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenProcess (
    __out PHANDLE ProcessHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PCLIENT_ID ClientId
    );


__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationProcess (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount_opt(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
    );

#define NTKERNELAPI DECLSPEC_IMPORT

#if defined(_X86_)

#if (NTDDI_VERSION >= NTDDI_WIN2K)
_DECL_HAL_KE_IMPORT
KIRQL
KeRaiseIrqlToDpcLevel (
    VOID
    );
#endif



#if (NTDDI_VERSION >= NTDDI_WIN2K)
_DECL_HAL_KE_IMPORT
KIRQL
KeRaiseIrqlToSynchLevel (
    VOID
    );
#endif


#if defined(_NTDRIVER_) || defined(_NTDDK_) || defined(_NTIFS_)



#define KeQueryTickCount(CurrentCount) { \
    KSYSTEM_TIME volatile *_TickCount = *((PKSYSTEM_TIME *)(&KeTickCount)); \
    for (;;) {                                                              \
        (CurrentCount)->HighPart = _TickCount->High1Time;                   \
        (CurrentCount)->LowPart = _TickCount->LowPart;                      \
        if ((CurrentCount)->HighPart == _TickCount->High2Time) break;       \
        YieldProcessor();                                                   \
    }                                                                       \
}



#else


VOID
NTAPI
KeQueryTickCount (
    OUT PLARGE_INTEGER CurrentCount
    );

#endif // defined(_NTDRIVER_) || defined(_NTDDK_) || defined(_NTIFS_)



//
// Processor Control Region Structure Definition
//

#define PCR_MINOR_VERSION 1
#define PCR_MAJOR_VERSION 1

typedef struct _KPCR {

//
// Start of the architecturally defined section of the PCR. This section
// may be directly addressed by vendor/platform specific HAL code and will
// not change from version to version of NT.
//
// Certain fields in the TIB are not used in kernel mode. These include the
// stack limit, subsystem TIB, fiber data, arbitrary user pointer, and the
// self address of then PCR itself (another field has been added for that
// purpose). Therefore, these fields are overlaid with other data to get
// better cache locality.
//

    union {
        NT_TIB  NtTib;
        struct {
            struct _EXCEPTION_REGISTRATION_RECORD *Used_ExceptionList;
            PVOID Used_StackBase;
            PVOID Spare2;
            PVOID TssCopy;
            ULONG ContextSwitches;
            KAFFINITY SetMemberCopy;
            PVOID Used_Self;
        };
    };

    struct _KPCR *SelfPcr;              // flat address of this PCR
    struct _KPRCB *Prcb;                // pointer to Prcb
    KIRQL   Irql;                       // do not use 3 bytes after this as
                                        // HALs assume they are zero.
    ULONG   IRR;
    ULONG   IrrActive;
    ULONG   IDR;
    PVOID   KdVersionBlock;

    struct _KIDTENTRY *IDT;
    struct _KGDTENTRY *GDT;
    struct _KTSS      *TSS;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    KAFFINITY SetMember;
    ULONG   StallScaleFactor;
    UCHAR   SpareUnused;
    UCHAR   Number;



    UCHAR   Spare0;
    UCHAR   SecondLevelCacheAssociativity;
    ULONG   VdmAlert;
    ULONG   KernelReserved[14];         // For use by the kernel
    ULONG   SecondLevelCacheSize;
    ULONG   HalReserved[16];            // For use by Hal


} KPCR, *PKPCR;

//
// Define the number of bits to shift to right justify the Page Directory Index
// field of a PTE.
//

#define PDI_SHIFT_X86    22
#define PDI_SHIFT_X86PAE 21

#if !defined (_X86PAE_)
#define PDI_SHIFT PDI_SHIFT_X86
#else
#define PDI_SHIFT PDI_SHIFT_X86PAE
#define PPI_SHIFT 30
#endif

#define GUARD_PAGE_SIZE   (PAGE_SIZE * 1)

//
// Define the number of bits to shift to right justify the Page Table Index
// field of a PTE.
//

#define PTI_SHIFT 12

//
// Define the highest user address and user probe address.
//

extern NTKERNELAPI PVOID MmHighestUserAddress;
extern NTKERNELAPI PVOID MmSystemRangeStart;
extern NTKERNELAPI ULONG MmUserProbeAddress;

#define MM_HIGHEST_USER_ADDRESS MmHighestUserAddress
#define MM_SYSTEM_RANGE_START MmSystemRangeStart

#if defined(_LOCAL_COPY_USER_PROBE_ADDRESS_)

#define MM_USER_PROBE_ADDRESS _LOCAL_COPY_USER_PROBE_ADDRESS_

extern ULONG _LOCAL_COPY_USER_PROBE_ADDRESS_;

#else

#define MM_USER_PROBE_ADDRESS MmUserProbeAddress

#endif

#define MM_KSEG0_BASE       MM_SYSTEM_RANGE_START
#define MM_SYSTEM_SPACE_END 0xFFFFFFFF

//
// The lowest user address reserves the low 64k.
//

#define MM_LOWEST_USER_ADDRESS (PVOID)0x10000

//
// The lowest address for system space.
//

#if !defined (_X86PAE_)
#define MM_LOWEST_SYSTEM_ADDRESS (PVOID)0xC0800000
#else
#define MM_LOWEST_SYSTEM_ADDRESS (PVOID)0xC0C00000
#endif


//
// Prototypes for architectural specific versions of Exi386 Api
//

//
// Interlocked result type is portable, but its values are machine specific.
// Constants for value are in i386.h, mips.h, etc.
//

typedef enum _INTERLOCKED_RESULT {
    ResultNegative = RESULT_NEGATIVE,
    ResultZero     = RESULT_ZERO,
    ResultPositive = RESULT_POSITIVE
} INTERLOCKED_RESULT;

NTKERNELAPI
INTERLOCKED_RESULT
FASTCALL
Exfi386InterlockedIncrementLong (
    IN LONG volatile *Addend
    );

NTKERNELAPI
INTERLOCKED_RESULT
FASTCALL
Exfi386InterlockedDecrementLong (
    IN LONG volatile *Addend
    );

NTKERNELAPI
ULONG
FASTCALL
Exfi386InterlockedExchangeUlong (
    IN ULONG volatile *Target,
    IN ULONG Value
    );


//
// Turn these instrinsics off until the compiler can handle them
//

#if (_MSC_FULL_VER > 13009037)

LONG
_InterlockedOr (
    IN OUT LONG volatile *Target,
    IN LONG Set
    );

#pragma intrinsic(_InterlockedOr)

#define InterlockedOr _InterlockedOr
#define InterlockedOrAffinity InterlockedOr

LONG
_InterlockedAnd (
    IN OUT LONG volatile *Target,
    IN LONG Set
    );

#pragma intrinsic(_InterlockedAnd)

#define InterlockedAnd _InterlockedAnd
#define InterlockedAndAffinity InterlockedAnd

LONG
_InterlockedXor (
    IN OUT LONG volatile *Target,
    IN LONG Set
    );

#pragma intrinsic(_InterlockedXor)

#define InterlockedXor _InterlockedXor

#if !defined(_WINBASE_) && !defined(NONTOSPINTERLOCK)

FORCEINLINE
LONGLONG
_InterlockedAnd64 (
    IN OUT LONGLONG volatile *Destination,
    IN LONGLONG Value
    )
{
    LONGLONG Old;

    do {
        Old = *Destination;
    } while (InterlockedCompareExchange64(Destination,
                                          Old & Value,
                                          Old) != Old);

    return Old;
}

#define InterlockedAnd64 _InterlockedAnd64

LONGLONG
FORCEINLINE
_InterlockedOr64 (
    IN OUT LONGLONG volatile *Destination,
    IN LONGLONG Value
    )
{
    LONGLONG Old;

    do {
        Old = *Destination;
    } while (InterlockedCompareExchange64(Destination,
                                          Old | Value,
                                          Old) != Old);

    return Old;
}

#define InterlockedOr64 _InterlockedOr64

FORCEINLINE
LONGLONG
_InterlockedXor64 (
    IN OUT LONGLONG volatile *Destination,
    IN LONGLONG Value
    )
{
    LONGLONG Old;

    do {
        Old = *Destination;
    } while (InterlockedCompareExchange64(Destination,
                                          Old ^ Value,
                                          Old) != Old);

    return Old;
}

#define InterlockedXor64 _InterlockedXor64

LONGLONG
FORCEINLINE
_InterlockedIncrement64 (
    IN OUT LONGLONG volatile *Addend
    )
{
    LONGLONG Old;

    do {
        Old = *Addend;
    } while (InterlockedCompareExchange64(Addend,
                                          Old + 1,
                                          Old) != Old);

    return Old + 1;
}

#define InterlockedIncrement64 _InterlockedIncrement64

FORCEINLINE
LONGLONG
_InterlockedDecrement64 (
    IN OUT LONGLONG volatile *Addend
    )
{
    LONGLONG Old;

    do {
        Old = *Addend;
    } while (InterlockedCompareExchange64(Addend,
                                          Old - 1,
                                          Old) != Old);

    return Old - 1;
}

#define InterlockedDecrement64 _InterlockedDecrement64

FORCEINLINE
LONGLONG
_InterlockedExchange64 (
    IN OUT LONGLONG volatile *Target,
    IN LONGLONG Value
    )
{
    LONGLONG Old;

    do {
        Old = *Target;
    } while (InterlockedCompareExchange64(Target,
                                          Value,
                                          Old) != Old);

    return Old;
}

#define InterlockedExchange64 _InterlockedExchange64

FORCEINLINE
LONGLONG
_InterlockedExchangeAdd64 (
    IN OUT LONGLONG volatile *Addend,
    IN LONGLONG Value
    )
{
    LONGLONG Old;

    do {
        Old = *Addend;
    } while (InterlockedCompareExchange64(Addend,
                                          Old + Value,
                                          Old) != Old);

    return Old;
}

#define InterlockedExchangeAdd64 _InterlockedExchangeAdd64

#endif // !defined(_WINBASE_) && !defined(NONTOSPINTERLOCK)

#else // compiler version

FORCEINLINE
LONG
InterlockedAnd (
    IN OUT LONG volatile *Target,
    LONG Set
    )
{
    LONG i;
    LONG j;

    j = *Target;
    do {
        i = j;
        j = InterlockedCompareExchange(Target,
                                       i & Set,
                                       i);

    } while (i != j);

    return j;
}

FORCEINLINE
LONG
InterlockedOr (
    IN OUT LONG volatile *Target,
    IN LONG Set
    )
{
    LONG i;
    LONG j;

    j = *Target;
    do {
        i = j;
        j = InterlockedCompareExchange(Target,
                                       i | Set,
                                       i);

    } while (i != j);

    return j;
}

#endif // compiler version


#if !defined(MIDL_PASS) && defined(_M_IX86)

//
// i386 function definitions
//



#if _MSC_VER >= 1200
#pragma warning(push)
#endif
#pragma warning(disable:4035)               // re-enable below

#define _PCR   fs:[0]

//
// Get the current processor number
//

FORCEINLINE
ULONG
NTAPI
KeGetCurrentProcessorNumber(VOID)
{
#if (_MSC_FULL_VER >= 13012035)
    return (ULONG) __readfsbyte (FIELD_OFFSET (KPCR, Number));
#else
    __asm {  movzx eax, _PCR KPCR.Number  }
#endif
}


#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning(default:4035)
#endif


#endif // !defined(MIDL_PASS) && defined(_M_IX86)


#endif // defined(_X86_)


// Use the following for kernel mode runtime checks of X86 system architecture

#ifdef _X86_

#ifdef IsNEC_98
#undef IsNEC_98
#endif

#ifdef IsNotNEC_98
#undef IsNotNEC_98
#endif

#ifdef SetNEC_98
#undef SetNEC_98
#endif

#ifdef SetNotNEC_98
#undef SetNotNEC_98
#endif

#define IsNEC_98     (SharedUserData->AlternativeArchitecture == NEC98x86)
#define IsNotNEC_98  (SharedUserData->AlternativeArchitecture != NEC98x86)
#define SetNEC_98    SharedUserData->AlternativeArchitecture = NEC98x86
#define SetNotNEC_98 SharedUserData->AlternativeArchitecture = StandardDesign

#endif

#if defined(_AMD64_)

//
// Processor Control Region Structure Definition
//

#define PCR_MINOR_VERSION 1
#define PCR_MAJOR_VERSION 1

typedef struct _KPCR {

//
// Start of the architecturally defined section of the PCR. This section
// may be directly addressed by vendor/platform specific HAL code and will
// not change from version to version of NT.
//
// Certain fields in the TIB are not used in kernel mode. These include the
// exception list, stack base, stack limit, subsystem TIB, fiber data, and
// the arbitrary user pointer. Therefore, these fields are overlaid with
// other data to get better cache locality.
//
// N.B. The offset to the PRCB in the PCR is fixed for all time.
//

    union {
        NT_TIB NtTib;
        struct {
            union _KGDTENTRY64 *GdtBase;
            struct _KTSS64 *TssBase;
            ULONG64 UserRsp;
            struct _KPCR *Self;
            struct _KPRCB *CurrentPrcb;
            PKSPIN_LOCK_QUEUE LockArray;
            PVOID Used_Self;
        };
    };

    union _KIDTENTRY64 *IdtBase;
    ULONG64 Unused[2];
    KIRQL Irql;
    UCHAR SecondLevelCacheAssociativity;
    UCHAR ObsoleteNumber;
    UCHAR Fill0;
    ULONG Unused0[3];
    USHORT MajorVersion;
    USHORT MinorVersion;
    ULONG StallScaleFactor;
    PVOID Unused1[3];

    ULONG KernelReserved[15];
    ULONG SecondLevelCacheSize;
    ULONG HalReserved[16];
    ULONG Unused2;
    PVOID KdVersionBlock;
    PVOID Unused3;
    ULONG PcrAlign1[24];


} KPCR, *PKPCR;

//
// Exception frame
//
//  This frame is established when handling an exception. It provides a place
//  to save all nonvolatile registers. The volatile registers will already
//  have been saved in a trap frame.
//
// N.B. The exception frame has a built in exception record capable of
//      storing information for four parameter values. This exception
//      record is used exclusively within the trap handling code.
//

typedef struct _KEXCEPTION_FRAME {

//
// Home address for the parameter registers.
//

    ULONG64 P1Home;
    ULONG64 P2Home;
    ULONG64 P3Home;
    ULONG64 P4Home;
    ULONG64 P5;

//
// Kernel callout initial stack value.
//

    ULONG64 InitialStack;

//
// Saved nonvolatile floating registers.
//

    M128A Xmm6;
    M128A Xmm7;
    M128A Xmm8;
    M128A Xmm9;
    M128A Xmm10;
    M128A Xmm11;
    M128A Xmm12;
    M128A Xmm13;
    M128A Xmm14;
    M128A Xmm15;

//
// Kernel callout frame variables.
//

    ULONG64 TrapFrame;
    ULONG64 CallbackStack;
    ULONG64 OutputBuffer;
    ULONG64 OutputLength;

//
// Saved MXCSR when a thread is interrupted in kernel mode via a dispatch
// interrupt.
//

    ULONG64 MxCsr;

//
// Saved nonvolatile register - not always saved.
//

    ULONG64 Rbp;

//
// Saved nonvolatile registers.
//

    ULONG64 Rbx;
    ULONG64 Rdi;
    ULONG64 Rsi;
    ULONG64 R12;
    ULONG64 R13;
    ULONG64 R14;
    ULONG64 R15;

//
// EFLAGS and return address.
//

    ULONG64 Return;
} KEXCEPTION_FRAME, *PKEXCEPTION_FRAME;

//
// Trap frame
//
// This frame is established when handling a trap. It provides a place to
// save all volatile registers. The nonvolatile registers are saved in an
// exception frame or through the normal C calling conventions for saved
// registers.
//

typedef struct _KTRAP_FRAME {

//
// Home address for the parameter registers.
//

    ULONG64 P1Home;
    ULONG64 P2Home;
    ULONG64 P3Home;
    ULONG64 P4Home;
    ULONG64 P5;

//
// Previous processor mode (system services only) and previous IRQL
// (interrupts only).
//

    KPROCESSOR_MODE PreviousMode;
    KIRQL PreviousIrql;

//
// Page fault load/store indicator.
//

    UCHAR FaultIndicator;

//
// Exception active indicator.
//
//    0 - interrupt frame.
//    1 - exception frame.
//    2 - service frame.
//

    UCHAR ExceptionActive;

//
// Floating point state.
//

    ULONG MxCsr;

//
//  Volatile registers.
//
// N.B. These registers are only saved on exceptions and interrupts. They
//      are not saved for system calls.
//

    ULONG64 Rax;
    ULONG64 Rcx;
    ULONG64 Rdx;
    ULONG64 R8;
    ULONG64 R9;
    ULONG64 R10;
    ULONG64 R11;

//
// Gsbase is only used if the previous mode was kernel.
//
// GsSwap is only used if the previous mode was user.
//

    union {
        ULONG64 GsBase;
        ULONG64 GsSwap;
    };

//
// Volatile floating registers.
//
// N.B. These registers are only saved on exceptions and interrupts. They
//      are not saved for system calls.
//

    M128A Xmm0;
    M128A Xmm1;
    M128A Xmm2;
    M128A Xmm3;
    M128A Xmm4;
    M128A Xmm5;

//
// First parameter, page fault address, context record address if user APC
// bypass, or time stamp value.
//

    union {
        ULONG64 FaultAddress;
        ULONG64 ContextRecord;
        ULONG64 TimeStampCKCL;
    };

//
//  Debug registers.
//

    ULONG64 Dr0;
    ULONG64 Dr1;
    ULONG64 Dr2;
    ULONG64 Dr3;
    ULONG64 Dr6;
    ULONG64 Dr7;

//
// Special debug registers.
//
// N.B. Either AMD64 or EM64T information is stored in the following locations.

    union {
        struct {
            ULONG64 DebugControl;
            ULONG64 LastBranchToRip;
            ULONG64 LastBranchFromRip;
            ULONG64 LastExceptionToRip;
            ULONG64 LastExceptionFromRip;
        };

        struct {
            ULONG64 LastBranchControl;
            ULONG LastBranchMSR;
        };
    };

//
//  Segment registers
//

    USHORT SegDs;
    USHORT SegEs;
    USHORT SegFs;
    USHORT SegGs;

//
// Previous trap frame address.
//

    ULONG64 TrapFrame;

//
// Saved nonvolatile registers RBX, RDI and RSI. These registers are only
// saved in system service trap frames.
//

    ULONG64 Rbx;
    ULONG64 Rdi;
    ULONG64 Rsi;

//
// Saved nonvolatile register RBP. This register is used as a frame
// pointer during trap processing and is saved in all trap frames.
//

    ULONG64 Rbp;

//
// Information pushed by hardware.
//
// N.B. The error code is not always pushed by hardware. For those cases
//      where it is not pushed by hardware a dummy error code is allocated
//      on the stack.
//

    union {
        ULONG64 ErrorCode;
        ULONG64 ExceptionFrame;
        ULONG64 TimeStampKlog;
    };

    ULONG64 Rip;
    USHORT SegCs;
    UCHAR Fill0;
    UCHAR Logging;
    USHORT Fill1[2];
    ULONG EFlags;
    ULONG Fill2;
    ULONG64 Rsp;
    USHORT SegSs;
    USHORT Fill3;

//
// Copy of the global patch cycle at the time of the fault. Filled in by the
// invalid opcode and general protection fault routines.
//

    LONG CodePatchCycle;
} KTRAP_FRAME, *PKTRAP_FRAME;


#define PXE_BASE          0xFFFFF6FB7DBED000UI64
#define PXE_SELFMAP       0xFFFFF6FB7DBEDF68UI64
#define PPE_BASE          0xFFFFF6FB7DA00000UI64
#define PDE_BASE          0xFFFFF6FB40000000UI64
#define PTE_BASE          0xFFFFF68000000000UI64

#define PXE_TOP           0xFFFFF6FB7DBEDFFFUI64
#define PPE_TOP           0xFFFFF6FB7DBFFFFFUI64
#define PDE_TOP           0xFFFFF6FB7FFFFFFFUI64
#define PTE_TOP           0xFFFFF6FFFFFFFFFFUI64

#define PDE_KTBASE_AMD64  PPE_BASE

#define PTI_SHIFT 12
#define PDI_SHIFT 21
#define PPI_SHIFT 30
#define PXI_SHIFT 39

#define PTE_PER_PAGE 512
#define PDE_PER_PAGE 512
#define PPE_PER_PAGE 512
#define PXE_PER_PAGE 512

#define PTI_MASK_AMD64 (PTE_PER_PAGE - 1)
#define PDI_MASK_AMD64 (PDE_PER_PAGE - 1)
#define PPI_MASK (PPE_PER_PAGE - 1)
#define PXI_MASK (PXE_PER_PAGE - 1)

#define GUARD_PAGE_SIZE (PAGE_SIZE * 2)

//
// Define the last branch control MSR address.
//

extern NTKERNELAPI ULONG KeLastBranchMSR;

//
// Define the highest user address and user probe address.
//

extern NTKERNELAPI PVOID MmHighestUserAddress;
extern NTKERNELAPI PVOID MmSystemRangeStart;
extern NTKERNELAPI ULONG64 MmUserProbeAddress;

#define MM_HIGHEST_USER_ADDRESS MmHighestUserAddress
#define MM_SYSTEM_RANGE_START MmSystemRangeStart

//
// Allow non-kernel components to capture the user probe address and use a
// local copy for efficiency.
//

#if defined(_LOCAL_COPY_USER_PROBE_ADDRESS_)

#define MM_USER_PROBE_ADDRESS _LOCAL_COPY_USER_PROBE_ADDRESS_

extern ULONG64 _LOCAL_COPY_USER_PROBE_ADDRESS_;

#else

#define MM_USER_PROBE_ADDRESS MmUserProbeAddress

#endif

//
// The lowest user address reserves the low 64k.
//

#define MM_LOWEST_USER_ADDRESS (PVOID)(LONG_PTR)0x10000

//
// The lowest address for system space.
//

#define MM_LOWEST_SYSTEM_ADDRESS (PVOID)0xFFFF080000000000


//
// Intrinsic functions
//

#if defined(_M_AMD64) && !defined(RC_INVOKED)  && !defined(MIDL_PASS)

//
// The following routines are provided for backward compatibility with old
// code. They are no longer the preferred way to accomplish these functions.
//

#if PRAGMA_DEPRECATED_DDK
#pragma deprecated(ExInterlockedIncrementLong)      // Use InterlockedIncrement
#pragma deprecated(ExInterlockedDecrementLong)      // Use InterlockedDecrement
#pragma deprecated(ExInterlockedExchangeUlong)      // Use InterlockedExchange
#endif

#define RESULT_ZERO 0
#define RESULT_NEGATIVE 1
#define RESULT_POSITIVE 2

typedef enum _INTERLOCKED_RESULT {
    ResultNegative = RESULT_NEGATIVE,
    ResultZero = RESULT_ZERO,
    ResultPositive = RESULT_POSITIVE
} INTERLOCKED_RESULT;

#define ExInterlockedDecrementLong(Addend, Lock)                            \
    _ExInterlockedDecrementLong(Addend)

__forceinline
LONG
_ExInterlockedDecrementLong (
    IN OUT PLONG Addend
    )

{

    LONG Result;

    Result = InterlockedDecrement(Addend);
    if (Result < 0) {
        return ResultNegative;

    } else if (Result > 0) {
        return ResultPositive;

    } else {
        return ResultZero;
    }
}

#define ExInterlockedIncrementLong(Addend, Lock)                            \
    _ExInterlockedIncrementLong(Addend)

__forceinline
LONG
_ExInterlockedIncrementLong (
    IN OUT PLONG Addend
    )

{

    LONG Result;

    Result = InterlockedIncrement(Addend);
    if (Result < 0) {
        return ResultNegative;

    } else if (Result > 0) {
        return ResultPositive;

    } else {
        return ResultZero;
    }
}

#define ExInterlockedExchangeUlong(Target, Value, Lock)                     \
    _ExInterlockedExchangeUlong(Target, Value)

__forceinline
ULONG
_ExInterlockedExchangeUlong (
    IN OUT PULONG Target,
    IN ULONG Value
    )

{

    return (ULONG)InterlockedExchange((PLONG)Target, (LONG)Value);
}

#endif // defined(_M_AMD64) && !defined(RC_INVOKED)  && !defined(MIDL_PASS)


#if !defined(MIDL_PASS) && defined(_M_AMD64)

//
// AMD646 function prototype definitions
//


//
// Get address of current processor block.
//

__forceinline
PKPCR
KeGetPcr (
    VOID
    )

{
    return (PKPCR)__readgsqword(FIELD_OFFSET(KPCR, Self));
}


//
// Get the current processor number
//

#if (NTDDI_VERSION >= NTDDI_VISTA)
__forceinline
ULONG
KeGetCurrentProcessorNumber (
    VOID
    )

{

    return (ULONG)__readgsword(0x184);
}

#else

__forceinline
ULONG
KeGetCurrentProcessorNumber (
    VOID
    )

{

    return (ULONG)__readgsbyte(0x184);
}
#endif


#endif // !defined(MIDL_PASS) && defined(_M_AMD64)


#endif // defined(_AMD64_)


//
// Platform specific kernel fucntions to raise and lower IRQL.
//


#if defined(_AMD64_) && !defined(MIDL_PASS)

__forceinline
KIRQL
KeRaiseIrqlToDpcLevel (
    VOID
    )

/*++

Routine Description:

    This function raises the current IRQL to DPC_LEVEL and returns the
    previous IRQL.

Arguments:

    None.

Return Value:

    The previous IRQL is retured as the function value.

--*/

{

    return KfRaiseIrql(DISPATCH_LEVEL);
}

__forceinline
KIRQL
KeRaiseIrqlToSynchLevel (
    VOID
    )

/*++

Routine Description:

    This function raises the current IRQL to SYNCH_LEVEL and returns the
    previous IRQL.

Arguments:

Return Value:

    The previous IRQL is retured as the function value.

--*/

{

    return KfRaiseIrql(12);
}


#endif // defined(_AMD64_) && !defined(MIDL_PASS)


#if defined(_IA64_)

//
// IA64 specific interlocked operation result values.
//

#define RESULT_ZERO 0
#define RESULT_NEGATIVE 1
#define RESULT_POSITIVE 2

//
// Interlocked result type is portable, but its values are machine specific.
// Constants for values are in i386.h, mips.h, etc.
//

typedef enum _INTERLOCKED_RESULT {
    ResultNegative = RESULT_NEGATIVE,
    ResultZero     = RESULT_ZERO,
    ResultPositive = RESULT_POSITIVE
} INTERLOCKED_RESULT;

//
// Convert portable interlock interfaces to architecture specific interfaces.
//

#if PRAGMA_DEPRECATED_DDK
#pragma deprecated(ExInterlockedIncrementLong)      // Use InterlockedIncrement
#pragma deprecated(ExInterlockedDecrementLong)      // Use InterlockedDecrement
#pragma deprecated(ExInterlockedExchangeUlong)      // Use InterlockedExchange
#endif

#define ExInterlockedIncrementLong(Addend, Lock) \
    ExIa64InterlockedIncrementLong(Addend)

#define ExInterlockedDecrementLong(Addend, Lock) \
    ExIa64InterlockedDecrementLong(Addend)

#define ExInterlockedExchangeUlong(Target, Value, Lock) \
    ExIa64InterlockedExchangeUlong(Target, Value)

NTKERNELAPI
INTERLOCKED_RESULT
ExIa64InterlockedIncrementLong (
    IN PLONG Addend
    );

NTKERNELAPI
INTERLOCKED_RESULT
ExIa64InterlockedDecrementLong (
    IN PLONG Addend
    );

NTKERNELAPI
ULONG
ExIa64InterlockedExchangeUlong (
    IN PULONG Target,
    IN ULONG Value
    );

//
// Get address of processor control region.
//

#define KeGetPcr() PCR

//
// Get address of current kernel thread object.
//

#if defined(_M_IA64)
#define KeGetCurrentThread() PCR->CurrentThread
#endif

//
// Get current processor number.
//

#define KeGetCurrentProcessorNumber() ((ULONG)(PCR->Number))

//
// Get data cache fill size.
//

#if PRAGMA_DEPRECATED_DDK
#pragma deprecated(KeGetDcacheFillSize)      // Use GetDmaAlignment
#endif

#define KeGetDcacheFillSize() PCR->DcacheFillSize

//
// Exception frame
//
//  This frame is established when handling an exception. It provides a place
//  to save all preserved registers. The volatile registers will already
//  have been saved in a trap frame. Also used as part of switch frame built
//  at thread switch.
//
//  The frame is 16-byte aligned to maintain 16-byte alignment for the stack,
//

typedef struct _KEXCEPTION_FRAME {


    // Preserved application registers
    ULONGLONG ApEC;       // epilogue count
    ULONGLONG ApLC;       // loop count
    ULONGLONG IntNats;    // Nats for S0-S3; i.e. ar.UNAT after spill

    // Preserved (saved) interger registers, s0-s3
    ULONGLONG IntS0;
    ULONGLONG IntS1;
    ULONGLONG IntS2;
    ULONGLONG IntS3;

    // Preserved (saved) branch registers, bs0-bs4
    ULONGLONG BrS0;
    ULONGLONG BrS1;
    ULONGLONG BrS2;
    ULONGLONG BrS3;
    ULONGLONG BrS4;

    // Preserved (saved) floating point registers, f2 - f5, f16 - f31
    FLOAT128 FltS0;
    FLOAT128 FltS1;
    FLOAT128 FltS2;
    FLOAT128 FltS3;
    FLOAT128 FltS4;
    FLOAT128 FltS5;
    FLOAT128 FltS6;
    FLOAT128 FltS7;
    FLOAT128 FltS8;
    FLOAT128 FltS9;
    FLOAT128 FltS10;
    FLOAT128 FltS11;
    FLOAT128 FltS12;
    FLOAT128 FltS13;
    FLOAT128 FltS14;
    FLOAT128 FltS15;
    FLOAT128 FltS16;
    FLOAT128 FltS17;
    FLOAT128 FltS18;
    FLOAT128 FltS19;


} KEXCEPTION_FRAME, *PKEXCEPTION_FRAME;

//
// Trap frame
//  This frame is established when handling a trap. It provides a place to
//  save all volatile registers. The nonvolatile registers are saved in an
//  exception frame or through the normal C calling conventions for saved
//  registers.  Its size must be a multiple of 16 bytes.
//
//  N.B - the 16-byte alignment is required to maintain the stack alignment.
//

#define KTRAP_FRAME_ARGUMENTS (8 * 8)       // up to 8 in-memory syscall args


typedef struct _KTRAP_FRAME {

    //
    // Reserved for additional memory arguments and stack scratch area
    // The size of Reserved[] must be a multiple of 16 bytes.
    //

    ULONGLONG Reserved[(KTRAP_FRAME_ARGUMENTS+16)/8];

    // Temporary (volatile) FP registers - f6-f15 (don't use f32+ in kernel)
    FLOAT128 FltT0;
    FLOAT128 FltT1;
    FLOAT128 FltT2;
    FLOAT128 FltT3;
    FLOAT128 FltT4;
    FLOAT128 FltT5;
    FLOAT128 FltT6;
    FLOAT128 FltT7;
    FLOAT128 FltT8;
    FLOAT128 FltT9;

    // Temporary (volatile) interger registers
    ULONGLONG IntGp;    // global pointer (r1)
    ULONGLONG IntT0;
    ULONGLONG IntT1;
                        // The following 4 registers fill in space of preserved  (S0-S3) to align Nats
    ULONGLONG ApUNAT;   // ar.UNAT on kernel entry
    ULONGLONG ApCCV;    // ar.CCV
    ULONGLONG SegCSD;   // Second register for 16 byte values
    ULONGLONG Preds;    // Predicates

    ULONGLONG IntV0;    // return value (r8)
    ULONGLONG IntT2;
    ULONGLONG IntT3;
    ULONGLONG IntT4;
    ULONGLONG IntSp;    // stack pointer (r12)
    ULONGLONG IntTeb;   // teb (r13)
    ULONGLONG IntT5;
    ULONGLONG IntT6;
    ULONGLONG IntT7;
    ULONGLONG IntT8;
    ULONGLONG IntT9;
    ULONGLONG IntT10;
    ULONGLONG IntT11;
    ULONGLONG IntT12;
    ULONGLONG IntT13;
    ULONGLONG IntT14;
    ULONGLONG IntT15;
    ULONGLONG IntT16;
    ULONGLONG IntT17;
    ULONGLONG IntT18;
    ULONGLONG IntT19;
    ULONGLONG IntT20;
    ULONGLONG IntT21;
    ULONGLONG IntT22;

    ULONGLONG IntNats;  // Temporary (volatile) registers' Nats directly from ar.UNAT at point of spill

    ULONGLONG BrRp;     // Return pointer on kernel entry

    ULONGLONG BrT0;     // Temporary (volatile) branch registers (b6-b7)
    ULONGLONG BrT1;

    // Register stack info
    ULONGLONG RsRSC;    // RSC on kernel entry
    ULONGLONG RsBSP;    // BSP on kernel entry
    ULONGLONG RsBSPSTORE; // User BSP Store at point of switch to kernel backing store
    ULONGLONG RsRNAT;   // old RNAT at point of switch to kernel backing store
    ULONGLONG RsPFS;    // PFS on kernel entry

    // Trap Status Information
    ULONGLONG StIPSR;   // Interruption Processor Status Register
    ULONGLONG StIIP;    // Interruption IP
    ULONGLONG StIFS;    // Interruption Function State
    ULONGLONG StFPSR;   // FP status
    ULONGLONG StISR;    // Interruption Status Register
    ULONGLONG StIFA;    // Interruption Data Address
    ULONGLONG StIIPA;   // Last executed bundle address
    ULONGLONG StIIM;    // Interruption Immediate
    ULONGLONG StIHA;    // Interruption Hash Address

    ULONG OldIrql;      // Previous Irql.
    ULONG PreviousMode; // Previous Mode.
    ULONGLONG TrapFrame;// Previous Trap Frame

    //
    // Exception record
    //
    UCHAR ExceptionRecord[(sizeof(EXCEPTION_RECORD) + 15) & (~15)];

    // End of frame marker (for debugging)

    ULONGLONG NewBSP;  // NewBSP  When a stack switch occur this is the value of the new BSP
    ULONGLONG EOFMarker;

    ULONGLONG SegSSD;   // IA32 SSDescriptor (Ar26)

} KTRAP_FRAME, *PKTRAP_FRAME;

//
// OS_MCA, OS_INIT HandOff State definitions
//
// Note: The following definitions *must* match the definions of the
//       corresponding SAL Revision Hand-Off structures.
//

typedef struct _SAL_HANDOFF_STATE   {
    ULONGLONG     PalProcEntryPoint;
    ULONGLONG     SalProcEntryPoint;
    ULONGLONG     SalGlobalPointer;
     LONGLONG     RendezVousResult;
    ULONGLONG     SalReturnAddress;
    ULONGLONG     MinStateSavePtr;
} SAL_HANDOFF_STATE, *PSAL_HANDOFF_STATE;

typedef struct _OS_HANDOFF_STATE    {
    ULONGLONG     Result;
    ULONGLONG     SalGlobalPointer;
    ULONGLONG     MinStateSavePtr;
    ULONGLONG     SalReturnAddress;
    ULONGLONG     NewContextFlag;
} OS_HANDOFF_STATE, *POS_HANDOFF_STATE;

//
// per processor OS_MCA and OS_INIT resource structure
//


#define SER_EVENT_STACK_FRAME_ENTRIES    8

typedef struct _SAL_EVENT_RESOURCES {

    SAL_HANDOFF_STATE   SalToOsHandOff;
    OS_HANDOFF_STATE    OsToSalHandOff;
    PVOID               StateDump;
    ULONGLONG           StateDumpPhysical;
    PVOID               BackStore;
    ULONGLONG           BackStoreLimit;
    PVOID               Stack;
    ULONGLONG           StackLimit;
    PULONGLONG          PTOM;
    ULONGLONG           StackFrame[SER_EVENT_STACK_FRAME_ENTRIES];
    PVOID               EventPool;
    ULONG               EventPoolSize;
    ULONGLONG           PoisonPageAddress;
} SAL_EVENT_RESOURCES, *PSAL_EVENT_RESOURCES;

//
// Define Processor Control Region Structure.
//

#define PCR_MINOR_VERSION 1
#define PCR_MAJOR_VERSION 1

typedef struct _KPCR {

//
// Major and minor version numbers of the PCR.
//
    ULONG MinorVersion;
    ULONG MajorVersion;

//
// Start of the architecturally defined section of the PCR. This section
// may be directly addressed by vendor/platform specific HAL code and will
// not change from version to version of NT.
//

//
// First and second level cache parameters.
//

    ULONG FirstLevelDcacheSize;
    ULONG FirstLevelDcacheFillSize;
    ULONG FirstLevelIcacheSize;
    ULONG FirstLevelIcacheFillSize;
    ULONG SecondLevelDcacheSize;
    ULONG SecondLevelDcacheFillSize;
    ULONG SecondLevelIcacheSize;
    ULONG SecondLevelIcacheFillSize;

//
// Data cache alignment and fill size used for cache flushing and alignment.
// These fields are set to the larger of the first and second level data
// cache fill sizes.
//

    ULONG DcacheAlignment;
    ULONG DcacheFillSize;

//
// Instruction cache alignment and fill size used for cache flushing and
// alignment. These fields are set to the larger of the first and second
// level data cache fill sizes.
//

    ULONG IcacheAlignment;
    ULONG IcacheFillSize;

//
// Processor identification from PrId register.
//

    ULONG ProcessorId;

//
// Profiling data.
//

    ULONG ProfileInterval;
    ULONG ProfileCount;

//
// Stall execution count and scale factor.
//

    ULONG StallExecutionCount;
    ULONG StallScaleFactor;

    ULONG InterruptionCount;

//
// Space reserved for the system.
//

    ULONGLONG   SystemReserved[6];

//
// Space reserved for the HAL
//

    ULONGLONG   HalReserved[64];

//
// IRQL mapping tables.
//

    UCHAR IrqlMask[64];
    UCHAR IrqlTable[64];

//
// External Interrupt vectors.
//

    PKINTERRUPT_ROUTINE InterruptRoutine[MAXIMUM_VECTOR];

//
// Reserved interrupt vector mask.
//

    ULONG ReservedVectors;

//
// Processor affinity mask.
//

    KAFFINITY SetMember;

//
// Complement of the processor affinity mask.
//

    KAFFINITY NotMember;

//
// Pointer to processor control block.
//

    struct _KPRCB *Prcb;

//
//  Shadow copy of Prcb->CurrentThread for fast access
//

    struct _KTHREAD *CurrentThread;

//
// Processor number.
//

    CCHAR Number;                        // Processor Number



    CCHAR PollSlot;                      // Used by the clock routine track when we should break in.
    UCHAR KernelDebugActive;             // debug register active in kernel flag
    UCHAR CurrentIrql;                   // Current IRQL
    union {
        USHORT SoftwareInterruptPending; // Software Interrupt Pending Flag
        struct {
            UCHAR ApcInterrupt;          // 0x01 if APC int pending
            UCHAR DispatchInterrupt;     // 0x01 if dispatch int pending
        };
    };

//
// Address of per processor SAPIC EOI Table
//

    PVOID       EOITable;

//
// IA-64 Machine Check Events trackers
//

    UCHAR       InOsMca;
    UCHAR       InOsInit;
    UCHAR       InOsCmc;
    UCHAR       InOsCpe;
    ULONG       InOsULONG_Spare; // Spare ULONG
    PSAL_EVENT_RESOURCES OsMcaResourcePtr;
    PSAL_EVENT_RESOURCES OsInitResourcePtr;

    UCHAR AlternateStack;
    UCHAR Pad[7];

//
// End of the architecturally defined section of the PCR. This section
// may be directly addressed by vendor/platform specific HAL code and will
// not change from version to version of NT.
//


} KPCR, *PKPCR;


NTKERNELAPI
KIRQL
KeRaiseIrqlToDpcLevel (
    VOID
    );

NTKERNELAPI
KIRQL
KeRaiseIrqlToSynchLevel (
    VOID
    );


//
// The highest user address reserves 64K bytes for a guard page. This
// the probing of address from kernel mode to only have to check the
// starting address for structures of 64k bytes or less.
//

extern NTKERNELAPI PVOID MmHighestUserAddress;
extern NTKERNELAPI PVOID MmSystemRangeStart;
extern NTKERNELAPI ULONG_PTR MmUserProbeAddress;


#define MM_HIGHEST_USER_ADDRESS MmHighestUserAddress
#define MM_USER_PROBE_ADDRESS MmUserProbeAddress
#define MM_SYSTEM_RANGE_START MmSystemRangeStart

#define MM_KSEG0_BASE 0xE000000080000000UI64
#define MM_SYSTEM_SPACE_END (KADDRESS_BASE + 0x70000000000UI64)

//
// The lowest user address reserves the low 64k.
//

#define MM_LOWEST_USER_ADDRESS  (PVOID)((ULONG_PTR)(UADDRESS_BASE+0x00010000))

#endif // defined(_IA64_)

//
// Firmware Table provider definitions
//

typedef enum _SYSTEM_FIRMWARE_TABLE_ACTION {
    SystemFirmwareTable_Enumerate,
    SystemFirmwareTable_Get
} SYSTEM_FIRMWARE_TABLE_ACTION;

typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION {
    ULONG                           ProviderSignature;
    SYSTEM_FIRMWARE_TABLE_ACTION    Action;
    ULONG                           TableID;
    ULONG                           TableBufferLength;
    UCHAR                           TableBuffer[ANYSIZE_ARRAY];
} SYSTEM_FIRMWARE_TABLE_INFORMATION, *PSYSTEM_FIRMWARE_TABLE_INFORMATION;

typedef NTSTATUS (__cdecl *PFNFTH)(PSYSTEM_FIRMWARE_TABLE_INFORMATION);

typedef struct _SYSTEM_FIRMWARE_TABLE_HANDLER {
    ULONG       ProviderSignature;
    BOOLEAN     Register;
    PFNFTH      FirmwareTableHandler;
    PVOID       DriverObject;
} SYSTEM_FIRMWARE_TABLE_HANDLER, *PSYSTEM_FIRMWARE_TABLE_HANDLER;

//
// Timer APC routine definition.
//

typedef
VOID
(*PTIMER_APC_ROUTINE) (
    __in PVOID TimerContext,
    __in ULONG TimerLowValue,
    __in LONG TimerHighValue
    );


//
//  Driver Verifier Definitions
//

typedef ULONG_PTR (*PDRIVER_VERIFIER_THUNK_ROUTINE) (
    IN PVOID Context
    );

//
//  This structure is passed in by drivers that want to thunk callers of
//  their exports.
//

typedef struct _DRIVER_VERIFIER_THUNK_PAIRS {
    PDRIVER_VERIFIER_THUNK_ROUTINE  PristineRoutine;
    PDRIVER_VERIFIER_THUNK_ROUTINE  NewRoutine;
} DRIVER_VERIFIER_THUNK_PAIRS, *PDRIVER_VERIFIER_THUNK_PAIRS;

//
//  Driver Verifier flags.
//

#define DRIVER_VERIFIER_SPECIAL_POOLING             0x0001
#define DRIVER_VERIFIER_FORCE_IRQL_CHECKING         0x0002
#define DRIVER_VERIFIER_INJECT_ALLOCATION_FAILURES  0x0004
#define DRIVER_VERIFIER_TRACK_POOL_ALLOCATIONS      0x0008
#define DRIVER_VERIFIER_IO_CHECKING                 0x0010


//
// Define data shared between kernel and user mode.
//
// N.B. User mode has read only access to this data
//
#ifdef _MAC
#pragma warning( disable : 4121)
#endif

#define MAX_WOW64_SHARED_ENTRIES 16

//
// WARNING: This structure must have exactly the same layout for 32- and
//    64-bit systems. The layout of this structure cannot change and new
//    fields can only be added at the end of the structure (unless a gap
//    can be exploited). Deprecated fields cannot be deleted. Platform
//    specific fields are included on all systems.
//
//    Layout exactness is required for Wow64 support of 32-bit applications
//    on Win64 systems.
//
//    The layout itself cannot change since this structure has been exported
//    in ntddk, ntifs.h, and nthal.h for some time.
//
// Define NX support policy values.
//

#define NX_SUPPORT_POLICY_ALWAYSOFF 0
#define NX_SUPPORT_POLICY_ALWAYSON 1
#define NX_SUPPORT_POLICY_OPTIN 2
#define NX_SUPPORT_POLICY_OPTOUT 3

//
// Global shared data flags and manipulation macros.
//

#define SHARED_GLOBAL_FLAGS_ERROR_PORT_V        0x0
#define SHARED_GLOBAL_FLAGS_ERROR_PORT          (1UL << SHARED_GLOBAL_FLAGS_ERROR_PORT_V)

#define SHARED_GLOBAL_FLAGS_ELEVATION_ENABLED_V 0x1
#define SHARED_GLOBAL_FLAGS_ELEVATION_ENABLED   (1UL << SHARED_GLOBAL_FLAGS_ELEVATION_ENABLED_V)

#define SHARED_GLOBAL_FLAGS_VIRT_ENABLED_V      0x2
#define SHARED_GLOBAL_FLAGS_VIRT_ENABLED        (1UL << SHARED_GLOBAL_FLAGS_VIRT_ENABLED_V)

#define SHARED_GLOBAL_FLAGS_INSTALLER_DETECT_ENABLED_V  0x3
#define SHARED_GLOBAL_FLAGS_INSTALLER_DETECT_ENABLED    \
    (1UL << SHARED_GLOBAL_FLAGS_INSTALLER_DETECT_ENABLED_V)

#define SHARED_GLOBAL_FLAGS_SYSTEM_DLL_RELOCATED_V      0x4
#define SHARED_GLOBAL_FLAGS_SYSTEM_DLL_RELOCATED        \
    (1UL << SHARED_GLOBAL_FLAGS_SYSTEM_DLL_RELOCATED_V)

#define SHARED_GLOBAL_FLAGS_DYNAMIC_PROC_ENABLED_V      0x5
#define SHARED_GLOBAL_FLAGS_DYNAMIC_PROC_ENABLED        \
    (1UL << SHARED_GLOBAL_FLAGS_DYNAMIC_PROC_ENABLED_V)

#define SHARED_GLOBAL_FLAGS_SEH_VALIDATION_ENABLED_V    0x6
#define SHARED_GLOBAL_FLAGS_SEH_VALIDATION_ENABLED        \
    (1UL << SHARED_GLOBAL_FLAGS_SEH_VALIDATION_ENABLED_V)

#define EX_INIT_BITS(Flags, Bit) \
    *((Flags)) |= (Bit)             // Safe to use before concurrently accessible

#define EX_TEST_SET_BIT(Flags, Bit) \
    InterlockedBitTestAndSet ((PLONG)(Flags), (Bit))

#define EX_TEST_CLEAR_BIT(Flags, Bit) \
    InterlockedBitTestAndReset ((PLONG)(Flags), (Bit))

typedef struct _KUSER_SHARED_DATA {

    //
    // Current low 32-bit of tick count and tick count multiplier.
    //
    // N.B. The tick count is updated each time the clock ticks.
    //

    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;

    //
    // Current 64-bit interrupt time in 100ns units.
    //

    volatile KSYSTEM_TIME InterruptTime;

    //
    // Current 64-bit system time in 100ns units.
    //

    volatile KSYSTEM_TIME SystemTime;

    //
    // Current 64-bit time zone bias.
    //

    volatile KSYSTEM_TIME TimeZoneBias;

    //
    // Support image magic number range for the host system.
    //
    // N.B. This is an inclusive range.
    //

    USHORT ImageNumberLow;
    USHORT ImageNumberHigh;

    //
    // Copy of system root in unicode.
    //

    WCHAR NtSystemRoot[260];

    //
    // Maximum stack trace depth if tracing enabled.
    //

    ULONG MaxStackTraceDepth;

    //
    // Crypto exponent value.
    //

    ULONG CryptoExponent;

    //
    // Time zone ID.
    //

    ULONG TimeZoneId;
    ULONG LargePageMinimum;
    ULONG Reserved2[7];

    //
    // Product type.
    //

    NT_PRODUCT_TYPE NtProductType;
    BOOLEAN ProductTypeIsValid;

    //
    // three bytes of padding here -- offsets 0x269, 0x26A, 0x26B
    //

    //
    // The NT Version.
    //
    // N. B. Note that each process sees a version from its PEB, but if the
    //       process is running with an altered view of the system version,
    //       the following two fields are used to correctly identify the
    //       version
    //

    ULONG NtMajorVersion;
    ULONG NtMinorVersion;

    //
    // Processor features.
    //

    BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];

    //
    // Reserved fields - do not use.
    //

    ULONG Reserved1;
    ULONG Reserved3;

    //
    // Time slippage while in debugger.
    //

    volatile ULONG TimeSlip;

    //
    // Alternative system architecture, e.g., NEC PC98xx on x86.
    //

    ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;

    //
    // four bytes of padding here -- offsets 0x2c4, 0x2c5, 0x2c6, 0x2c7
    //

    //
    // If the system is an evaluation unit, the following field contains the
    // date and time that the evaluation unit expires. A value of 0 indicates
    // that there is no expiration. A non-zero value is the UTC absolute time
    // that the system expires.
    //

    LARGE_INTEGER SystemExpirationDate;

    //
    // Suite support.
    //

    ULONG SuiteMask;

    //
    // TRUE if a kernel debugger is connected/enabled.
    //

    BOOLEAN KdDebuggerEnabled;

    //
    // NX support policy.
    //

    UCHAR NXSupportPolicy;

    //
    // two bytes of padding here -- offsets 0x2d6, 0x2d7
    //

    //
    // Current console session Id. Always zero on non-TS systems.
    //

    volatile ULONG ActiveConsoleId;

    //
    // Force-dismounts cause handles to become invalid. Rather than always
    // probe handles, a serial number of dismounts is maintained that clients
    // can use to see if they need to probe handles.
    //

    volatile ULONG DismountCount;

    //
    // This field indicates the status of the 64-bit COM+ package on the
    // system. It indicates whether the Itermediate Language (IL) COM+
    // images need to use the 64-bit COM+ runtime or the 32-bit COM+ runtime.
    //

    ULONG ComPlusPackage;

    //
    // Time in tick count for system-wide last user input across all terminal
    // sessions. For MP performance, it is not updated all the time (e.g. once
    // a minute per session). It is used for idle detection.
    //

    ULONG LastSystemRITEventTickCount;

    //
    // Number of physical pages in the system. This can dynamically change as
    // physical memory can be added or removed from a running system.
    //

    ULONG NumberOfPhysicalPages;

    //
    // True if the system was booted in safe boot mode.
    //

    BOOLEAN SafeBootMode;

    //
    // three bytes of padding here -- offsets 0x2ed, 0x2ee, 0x2ef
    //

#if 0 // pre-Vista
    ULONG TraceLogging;
#endif

    //
    // This is a packed bitfield that contains various flags concerning
    // the system state. They must be manipulated using interlocked
    // operations.
    //

    union {
        ULONG SharedDataFlags;
        struct {

            //
            // The following bit fields are for the debugger only. Do not use.
            // Use the bit definitions instead.
            //

            ULONG DbgErrorPortPresent       : 1;
            ULONG DbgElevationEnabled       : 1;
            ULONG DbgVirtEnabled            : 1;
            ULONG DbgInstallerDetectEnabled : 1;

            ULONG DbgSystemDllRelocated     : 1;
            ULONG DbgDynProcessorEnabled    : 1;
            ULONG DbgSEHValidationEnabled   : 1;
            ULONG SpareBits                 : 25;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    //
    // Depending on the processor, the code for fast system call will differ,
    // Stub code is provided pointers below to access the appropriate code.
    //
    // N.B. The following two fields are only used on 32-bit systems.
    //

    ULONGLONG TestRetInstruction;
    ULONG SystemCall;
    ULONG SystemCallReturn;
    ULONGLONG SystemCallPad[3];

    //
    // The 64-bit tick count.
    //

    union {
        volatile KSYSTEM_TIME TickCount;
        volatile ULONG64 TickCountQuad;
    } DUMMYUNIONNAME2;

    //
    // four bytes of padding here, why? Offsets 0x32c, 0x32d, 0x32e, 0x32f
    //

    //
    // Cookie for encoding pointers system wide.
    //

    ULONG Cookie;

    //
    // Client id of the process having the focus in the current
    // active console session id.
    //

    LONGLONG ConsoleSessionForegroundProcessId;

    //
    // Shared information for Wow64 processes.
    //

    ULONG Wow64SharedInformation[MAX_WOW64_SHARED_ENTRIES];

    //
    // The following field is used for ETW user mode global logging
    // (UMGL).
    //

    USHORT UserModeGlobalLogger[8];
    ULONG HeapTracingPid[2];
    ULONG CritSecTracingPid[2];

    //
    // Settings that can enable the use of Image File Execution Options
    // from HKCU in addition to the original HKLM.
    //

    ULONG ImageFileExecutionOptions;

#if 0
    //
    // pre-Vista Service Pack 1, four bytes of padding here -- offsets 0x3a4, 0x3a5, 0x3a6, 0x3a7
    //

#else
    //
    // Generation of the kernel structure holding system language information
    //
    ULONG LangGenerationCount;
#endif

    //
    // This represents the affinity of active processors in the system.
    // This is updated by the kernel as processors are added\removed from
    // the system.
    //

    union {
        ULONGLONG AffinityPad;
        KAFFINITY ActiveProcessorAffinity;
    } DUMMYUNIONNAME3;

    //
    // Current 64-bit interrupt time bias in 100ns units.
    //

    volatile ULONG64 InterruptTimeBias;

} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;

//
// Mostly enforce earlier comment about the stability and
// architecture-neutrality of this struct.
//
#if !defined(__midl) && !defined(MIDL_PASS)
//
// The overall size can change, but it must be the same for all architectures.
//
C_ASSERT(sizeof(KUSER_SHARED_DATA) == 0x3B8);

C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TickCountLowDeprecated) == 0x0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TickCountMultiplier) == 0x4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, InterruptTime) == 0x08);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemTime) == 0x014);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TimeZoneBias) == 0x020);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ImageNumberLow) == 0x02c);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ImageNumberHigh) == 0x02e);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtSystemRoot) == 0x030);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, MaxStackTraceDepth) == 0x238);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, CryptoExponent) == 0x23c);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TimeZoneId) == 0x240);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, LargePageMinimum) == 0x244);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Reserved2) == 0x248);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtProductType) == 0x264);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ProductTypeIsValid) == 0x268);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtMajorVersion) == 0x26c);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtMinorVersion) == 0x270);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ProcessorFeatures) == 0x274);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Reserved1) == 0x2b4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Reserved3) == 0x2b8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TimeSlip) == 0x2bc);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, AlternativeArchitecture) == 0x2c0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemExpirationDate) == 0x2c8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SuiteMask) == 0x2d0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, KdDebuggerEnabled) == 0x2d4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NXSupportPolicy) == 0x2d5);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ActiveConsoleId) == 0x2d8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, DismountCount) == 0x2dc);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ComPlusPackage) == 0x2e0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, LastSystemRITEventTickCount) == 0x2e4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NumberOfPhysicalPages) == 0x2e8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SafeBootMode) == 0x2ec);
#if 0 // pre-Vista
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TraceLogging) == 0x2f0);
#else
#if defined(_MSC_EXTENSIONS)
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SharedDataFlags) == 0x2f0);
#endif
#endif
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TestRetInstruction) == 0x2f8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemCall) == 0x300);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemCallReturn) == 0x304);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemCallPad) == 0x308);
#if defined(_MSC_EXTENSIONS)
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TickCount) == 0x320);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TickCountQuad) == 0x320);
#endif
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Cookie) == 0x330);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ConsoleSessionForegroundProcessId) == 0x338);
#if 0 // pre-Vista
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Wow64SharedInformation) == 0x334);
#else
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Wow64SharedInformation) == 0x340);
#endif
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, UserModeGlobalLogger) == 0x380);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, HeapTracingPid) == 0x390);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, CritSecTracingPid) == 0x398);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ImageFileExecutionOptions) == 0x3a0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, LangGenerationCount) == 0x3a4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, InterruptTimeBias) == 0x3b0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, UserModeGlobalLogger) == 0x380);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, HeapTracingPid) == 0x390);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, CritSecTracingPid) == 0x398);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ImageFileExecutionOptions) == 0x3a0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, LangGenerationCount) == 0x3a4);
#if defined(_MSC_EXTENSIONS)
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, AffinityPad) == 0x3a8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ActiveProcessorAffinity) == 0x3a8);
#endif
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, InterruptTimeBias) == 0x3b0);
#endif /* __midl | MIDL_PASS */

#ifdef _MAC
#pragma warning(default:4121)
#endif

#define CmResourceTypeMaximum             8
//
// Declaration of the structure for the PcCard ISA IRQ map
//

typedef struct _CM_PCCARD_DEVICE_DATA {
    UCHAR Flags;
    UCHAR ErrorCode;
    USHORT Reserved;
    ULONG BusData;
    ULONG DeviceId;
    ULONG LegacyBaseAddress;
    UCHAR IRQMap[16];
} CM_PCCARD_DEVICE_DATA, *PCM_PCCARD_DEVICE_DATA;

// Definitions for Flags

#define PCCARD_MAP_ERROR        0x01
#define PCCARD_DEVICE_PCI       0x10

#define PCCARD_SCAN_DISABLED    0x01
#define PCCARD_MAP_ZERO         0x02
#define PCCARD_NO_TIMER         0x03
#define PCCARD_NO_PIC           0x04
#define PCCARD_NO_LEGACY_BASE   0x05
#define PCCARD_DUP_LEGACY_BASE  0x06
#define PCCARD_NO_CONTROLLERS   0x07

#ifndef _ARC_DDK_
#define _ARC_DDK_

//
// Define configuration routine types.
//
// Configuration information.
//

typedef enum _CONFIGURATION_TYPE {
    ArcSystem,
    CentralProcessor,
    FloatingPointProcessor,
    PrimaryIcache,
    PrimaryDcache,
    SecondaryIcache,
    SecondaryDcache,
    SecondaryCache,
    EisaAdapter,
    TcAdapter,
    ScsiAdapter,
    DtiAdapter,
    MultiFunctionAdapter,
    DiskController,
    TapeController,
    CdromController,
    WormController,
    SerialController,
    NetworkController,
    DisplayController,
    ParallelController,
    PointerController,
    KeyboardController,
    AudioController,
    OtherController,
    DiskPeripheral,
    FloppyDiskPeripheral,
    TapePeripheral,
    ModemPeripheral,
    MonitorPeripheral,
    PrinterPeripheral,
    PointerPeripheral,
    KeyboardPeripheral,
    TerminalPeripheral,
    OtherPeripheral,
    LinePeripheral,
    NetworkPeripheral,
    SystemMemory,
    DockingInformation,
    RealModeIrqRoutingTable,
    RealModePCIEnumeration,
    MaximumType
} CONFIGURATION_TYPE, *PCONFIGURATION_TYPE;

#endif // _ARC_DDK_

//
// Several routines have an architecture specific implementation. Generate
// an error if a supported target is not defined.
//

#if !(defined(_X86_) || defined(_AMD64_) || defined(_IA64_))

#error "No target architecture defined"

#endif

//

#if defined(_X86_) || defined(_AMD64_)

#define PAUSE_PROCESSOR YieldProcessor();

#elif defined(_IA64_)

#define PAUSE_PROCESSOR __yield();

#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
KeSetImportanceDpc (
    __inout PRKDPC Dpc,
    __in KDPC_IMPORTANCE Importance
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
KeSetTargetProcessorDpc (
    __inout PRKDPC Dpc,
    __in CCHAR Number
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
LONG
KePulseEvent (
    __inout PRKEVENT Event,
    __in KPRIORITY Increment,
    __in BOOLEAN Wait
    );
#endif



#define MAXIMUM_EXPANSION_SIZE (KERNEL_LARGE_STACK_SIZE - (PAGE_SIZE / 2))

typedef
VOID
(NTAPI *PEXPAND_STACK_CALLOUT) (
    __in_opt PVOID Parameter
    );

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
NTKERNELAPI
NTSTATUS
KeExpandKernelStackAndCallout (
    __in PEXPAND_STACK_CALLOUT Callout,
    __in_opt PVOID Parameter,
    __in SIZE_T Size
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
LONG
KeSetBasePriorityThread (
    __inout PKTHREAD Thread,
    __in LONG Increment
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
KeEnterCriticalRegion (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
KeLeaveCriticalRegion (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
NTKERNELAPI
VOID
KeEnterGuardedRegion (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
NTKERNELAPI
VOID
KeLeaveGuardedRegion (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
BOOLEAN
KeAreApcsDisabled (
    VOID
    );
#endif



#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
DECLSPEC_NORETURN
VOID
NTAPI
KeBugCheck (
    __in ULONG BugCheckCode
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WS03)
NTKERNELAPI
BOOLEAN
KeInvalidateAllCaches (
    VOID
    );
#endif

NTKERNELAPI
VOID
FASTCALL
KeInvalidateRangeAllCaches (
    __in PVOID BaseAddress,
    __in ULONG Length
    );


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
KAFFINITY
KeQueryActiveProcessors (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
ULONG
KeQueryActiveProcessorCount (
    __out_opt PKAFFINITY ActiveProcessors
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
ULONG
KeQueryMaximumProcessorCount (
    VOID
    );
#endif


#if defined(POOL_TAGGING)
#define ExFreePool(a) ExFreePoolWithTag(a,0)
#endif

//
// If high order bit in Pool tag is set, then must use ExFreePoolWithTag to free
//

#define PROTECTED_POOL 0x80000000

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
DECLSPEC_NORETURN
VOID
ExRaiseDatatypeMisalignment (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
DECLSPEC_NORETURN
VOID
ExRaiseAccessViolation (
    VOID
    );
#endif

//
// Zone Allocation
//

typedef struct _ZONE_SEGMENT_HEADER {
    SINGLE_LIST_ENTRY SegmentList;
    PVOID Reserved;
} ZONE_SEGMENT_HEADER, *PZONE_SEGMENT_HEADER;

typedef struct _ZONE_HEADER {
    SINGLE_LIST_ENTRY FreeList;
    SINGLE_LIST_ENTRY SegmentList;
    ULONG BlockSize;
    ULONG TotalSegmentSize;
} ZONE_HEADER, *PZONE_HEADER;


#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK
NTKERNELAPI
NTSTATUS
ExInitializeZone(
    __out PZONE_HEADER Zone,
    __in ULONG BlockSize,
    __inout PVOID InitialSegment,
    __in ULONG InitialSegmentSize
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK
NTKERNELAPI
NTSTATUS
ExExtendZone(
    __inout PZONE_HEADER Zone,
    __inout PVOID Segment,
    __in ULONG SegmentSize
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK
NTKERNELAPI
NTSTATUS
ExInterlockedExtendZone(
    __inout PZONE_HEADER Zone,
    __inout PVOID Segment,
    __in ULONG SegmentSize,
    __inout PKSPIN_LOCK Lock
    );
#endif

//++
//
// PVOID
// ExAllocateFromZone(
//     IN PZONE_HEADER Zone
//     )
//
// Routine Description:
//
//     This routine removes an entry from the zone and returns a pointer to it.
//
// Arguments:
//
//     Zone - Pointer to the zone header controlling the storage from which the
//         entry is to be allocated.
//
// Return Value:
//
//     The function value is a pointer to the storage allocated from the zone.
//
//--
#if PRAGMA_DEPRECATED_DDK
#pragma deprecated(ExAllocateFromZone)
#endif
#define ExAllocateFromZone(Zone) \
    (PVOID)((Zone)->FreeList.Next); \
    if ( (Zone)->FreeList.Next ) (Zone)->FreeList.Next = (Zone)->FreeList.Next->Next


//++
//
// PVOID
// ExFreeToZone(
//     IN PZONE_HEADER Zone,
//     IN PVOID Block
//     )
//
// Routine Description:
//
//     This routine places the specified block of storage back onto the free
//     list in the specified zone.
//
// Arguments:
//
//     Zone - Pointer to the zone header controlling the storage to which the
//         entry is to be inserted.
//
//     Block - Pointer to the block of storage to be freed back to the zone.
//
// Return Value:
//
//     Pointer to previous block of storage that was at the head of the free
//         list.  NULL implies the zone went from no available free blocks to
//         at least one free block.
//
//--

#if PRAGMA_DEPRECATED_DDK
#pragma deprecated(ExFreeToZone)
#endif
#define ExFreeToZone(Zone,Block)                                    \
    ( ((PSINGLE_LIST_ENTRY)(Block))->Next = (Zone)->FreeList.Next,  \
      (Zone)->FreeList.Next = ((PSINGLE_LIST_ENTRY)(Block)),        \
      ((PSINGLE_LIST_ENTRY)(Block))->Next                           \
    )

//++
//
// BOOLEAN
// ExIsFullZone(
//     IN PZONE_HEADER Zone
//     )
//
// Routine Description:
//
//     This routine determines if the specified zone is full or not.  A zone
//     is considered full if the free list is empty.
//
// Arguments:
//
//     Zone - Pointer to the zone header to be tested.
//
// Return Value:
//
//     TRUE if the zone is full and FALSE otherwise.
//
//--

#if PRAGMA_DEPRECATED_DDK
#pragma deprecated(ExIsFullZone)
#endif
#define ExIsFullZone(Zone) \
    ( (Zone)->FreeList.Next == (PSINGLE_LIST_ENTRY)NULL )

//++
//
// PVOID
// ExInterlockedAllocateFromZone(
//     IN PZONE_HEADER Zone,
//     IN PKSPIN_LOCK Lock
//     )
//
// Routine Description:
//
//     This routine removes an entry from the zone and returns a pointer to it.
//     The removal is performed with the specified lock owned for the sequence
//     to make it MP-safe.
//
// Arguments:
//
//     Zone - Pointer to the zone header controlling the storage from which the
//         entry is to be allocated.
//
//     Lock - Pointer to the spin lock which should be obtained before removing
//         the entry from the allocation list.  The lock is released before
//         returning to the caller.
//
// Return Value:
//
//     The function value is a pointer to the storage allocated from the zone.
//
//--

#if PRAGMA_DEPRECATED_DDK
#pragma deprecated(ExInterlockedAllocateFromZone)
#endif
#define ExInterlockedAllocateFromZone(Zone,Lock) \
    (PVOID) ExInterlockedPopEntryList( &(Zone)->FreeList, Lock )

//++
//
// PVOID
// ExInterlockedFreeToZone(
//     IN PZONE_HEADER Zone,
//     IN PVOID Block,
//     IN PKSPIN_LOCK Lock
//     )
//
// Routine Description:
//
//     This routine places the specified block of storage back onto the free
//     list in the specified zone.  The insertion is performed with the lock
//     owned for the sequence to make it MP-safe.
//
// Arguments:
//
//     Zone - Pointer to the zone header controlling the storage to which the
//         entry is to be inserted.
//
//     Block - Pointer to the block of storage to be freed back to the zone.
//
//     Lock - Pointer to the spin lock which should be obtained before inserting
//         the entry onto the free list.  The lock is released before returning
//         to the caller.
//
// Return Value:
//
//     Pointer to previous block of storage that was at the head of the free
//         list.  NULL implies the zone went from no available free blocks to
//         at least one free block.
//
//--

#if PRAGMA_DEPRECATED_DDK
#pragma deprecated(ExInterlockedFreeToZone)
#endif
#define ExInterlockedFreeToZone(Zone,Block,Lock) \
    ExInterlockedPushEntryList( &(Zone)->FreeList, ((PSINGLE_LIST_ENTRY) (Block)), Lock )


//++
//
// BOOLEAN
// ExIsObjectInFirstZoneSegment(
//     IN PZONE_HEADER Zone,
//     IN PVOID Object
//     )
//
// Routine Description:
//
//     This routine determines if the specified pointer lives in the zone.
//
// Arguments:
//
//     Zone - Pointer to the zone header controlling the storage to which the
//         object may belong.
//
//     Object - Pointer to the object in question.
//
// Return Value:
//
//     TRUE if the Object came from the first segment of zone.
//
//--

#if PRAGMA_DEPRECATED_DDK
#pragma deprecated(ExIsObjectInFirstZoneSegment)
#endif
#define ExIsObjectInFirstZoneSegment(Zone,Object) ((BOOLEAN)     \
    (((PUCHAR)(Object) >= (PUCHAR)(Zone)->SegmentList.Next) &&   \
     ((PUCHAR)(Object) < (PUCHAR)(Zone)->SegmentList.Next +      \
                         (Zone)->TotalSegmentSize))              \
)

//
//  ntddk.h stole the entrypoints we wanted so fix them up here.
//

#if PRAGMA_DEPRECATED_DDK
#pragma deprecated(ExInitializeResource)            // use ExInitializeResourceLite
#pragma deprecated(ExAcquireResourceShared)         // use ExAcquireResourceSharedLite
#pragma deprecated(ExAcquireResourceExclusive)      // use ExAcquireResourceExclusiveLite
#pragma deprecated(ExReleaseResourceForThread)      // use ExReleaseResourceForThreadLite
#pragma deprecated(ExConvertExclusiveToShared)      // use ExConvertExclusiveToSharedLite
#pragma deprecated(ExDeleteResource)                // use ExDeleteResourceLite
#pragma deprecated(ExIsResourceAcquiredExclusive)   // use ExIsResourceAcquiredExclusiveLite
#pragma deprecated(ExIsResourceAcquiredShared)      // use ExIsResourceAcquiredSharedLite
#pragma deprecated(ExIsResourceAcquired)            // use ExIsResourceAcquiredSharedLite
#endif
#define ExInitializeResource ExInitializeResourceLite
#define ExAcquireResourceShared ExAcquireResourceSharedLite
#define ExAcquireResourceExclusive ExAcquireResourceExclusiveLite
#define ExReleaseResourceForThread ExReleaseResourceForThreadLite
#define ExConvertExclusiveToShared ExConvertExclusiveToSharedLite
#define ExDeleteResource ExDeleteResourceLite
#define ExIsResourceAcquiredExclusive ExIsResourceAcquiredExclusiveLite
#define ExIsResourceAcquiredShared ExIsResourceAcquiredSharedLite
#define ExIsResourceAcquired ExIsResourceAcquiredSharedLite


//
// UUID Generation
//

typedef GUID UUID;

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
ExUuidCreate(
    __out UUID *Uuid
    );
#endif

//
// Priority increment definitions.  The comment for each definition gives
// the names of the system services that use the definition when satisfying
// a wait.
//

//
// Priority increment used when satisfying a wait on an executive event
// (NtPulseEvent and NtSetEvent)
//

#define EVENT_INCREMENT                 1

//
// Priority increment when no I/O has been done.  This is used by device
// and file system drivers when completing an IRP (IoCompleteRequest).
//

#define IO_NO_INCREMENT                 0


//
// Priority increment for completing CD-ROM I/O.  This is used by CD-ROM device
// and file system drivers when completing an IRP (IoCompleteRequest)
//

#define IO_CD_ROM_INCREMENT             1

//
// Priority increment for completing disk I/O.  This is used by disk device
// and file system drivers when completing an IRP (IoCompleteRequest)
//

#define IO_DISK_INCREMENT               1



//
// Priority increment for completing keyboard I/O.  This is used by keyboard
// device drivers when completing an IRP (IoCompleteRequest)
//

#define IO_KEYBOARD_INCREMENT           6


//
// Priority increment for completing mailslot I/O.  This is used by the mail-
// slot file system driver when completing an IRP (IoCompleteRequest).
//

#define IO_MAILSLOT_INCREMENT           2


//
// Priority increment for completing mouse I/O.  This is used by mouse device
// drivers when completing an IRP (IoCompleteRequest)
//

#define IO_MOUSE_INCREMENT              6


//
// Priority increment for completing named pipe I/O.  This is used by the
// named pipe file system driver when completing an IRP (IoCompleteRequest).
//

#define IO_NAMED_PIPE_INCREMENT         2

//
// Priority increment for completing network I/O.  This is used by network
// device and network file system drivers when completing an IRP
// (IoCompleteRequest).
//

#define IO_NETWORK_INCREMENT            2


//
// Priority increment for completing parallel I/O.  This is used by parallel
// device drivers when completing an IRP (IoCompleteRequest)
//

#define IO_PARALLEL_INCREMENT           1

//
// Priority increment for completing serial I/O.  This is used by serial device
// drivers when completing an IRP (IoCompleteRequest)
//

#define IO_SERIAL_INCREMENT             2

//
// Priority increment for completing sound I/O.  This is used by sound device
// drivers when completing an IRP (IoCompleteRequest)
//

#define IO_SOUND_INCREMENT              8

//
// Priority increment for completing video I/O.  This is used by video device
// drivers when completing an IRP (IoCompleteRequest)
//

#define IO_VIDEO_INCREMENT              1

//
// Priority increment used when satisfying a wait on an executive semaphore
// (NtReleaseSemaphore)
//

#define SEMAPHORE_INCREMENT             1


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
MmIsThisAnNtAsSystem (
    VOID
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
MmMapUserAddressesToPage (
    __in_bcount(NumberOfBytes) PVOID BaseAddress,
    __in SIZE_T NumberOfBytes,
    __in PVOID PageAddress
    );
#endif


typedef struct _PHYSICAL_MEMORY_RANGE {
    PHYSICAL_ADDRESS BaseAddress;
    LARGE_INTEGER NumberOfBytes;
} PHYSICAL_MEMORY_RANGE, *PPHYSICAL_MEMORY_RANGE;

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
MmAddPhysicalMemory (
    __in PPHYSICAL_ADDRESS StartAddress,
    __inout PLARGE_INTEGER NumberOfBytes
    );
#endif

typedef NTSTATUS (*PMM_ROTATE_COPY_CALLBACK_FUNCTION) (
    __in PMDL DestinationMdl,
    __in PMDL SourceMdl,
    __in PVOID Context
    );

typedef enum _MM_ROTATE_DIRECTION {
    MmToFrameBuffer,
    MmToFrameBufferNoCopy,
    MmToRegularMemory,
    MmToRegularMemoryNoCopy,
    MmMaximumRotateDirection
} MM_ROTATE_DIRECTION, *PMM_ROTATE_DIRECTION;

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSTATUS
MmRotatePhysicalView (
    __in PVOID VirtualAddress,
    __inout PSIZE_T NumberOfBytes,
    __in_opt PMDLX NewMdl,
    __in MM_ROTATE_DIRECTION Direction,
    __in PMM_ROTATE_COPY_CALLBACK_FUNCTION CopyFunction,
    __in_opt PVOID Context
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
MmRemovePhysicalMemory (
    __in PPHYSICAL_ADDRESS StartAddress,
    __inout PLARGE_INTEGER NumberOfBytes
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PPHYSICAL_MEMORY_RANGE
MmGetPhysicalMemoryRanges (
    VOID
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
__out_bcount_opt (NumberOfBytes) PVOID
MmMapVideoDisplay (
    __in PHYSICAL_ADDRESS PhysicalAddress,
    __in SIZE_T NumberOfBytes,
    __in MEMORY_CACHING_TYPE CacheType
     );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
MmUnmapVideoDisplay (
     __in_bcount (NumberOfBytes) PVOID BaseAddress,
     __in SIZE_T NumberOfBytes
     );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PHYSICAL_ADDRESS
MmGetPhysicalAddress (
    __in PVOID BaseAddress
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PVOID
MmGetVirtualForPhysical (
    __in PHYSICAL_ADDRESS PhysicalAddress
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
__bcount (NumberOfBytes) PVOID
MmAllocateContiguousMemory (
    __in SIZE_T NumberOfBytes,
    __in PHYSICAL_ADDRESS HighestAcceptableAddress
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
__out_bcount_opt (NumberOfBytes) PVOID
MmAllocateContiguousMemorySpecifyCache (
    __in SIZE_T NumberOfBytes,
    __in PHYSICAL_ADDRESS LowestAcceptableAddress,
    __in PHYSICAL_ADDRESS HighestAcceptableAddress,
    __in_opt PHYSICAL_ADDRESS BoundaryAddressMultiple,
    __in MEMORY_CACHING_TYPE CacheType
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)

typedef ULONG NODE_REQUIREMENT;

#define MM_ANY_NODE_OK          0x80000000

NTKERNELAPI
__out_bcount_opt (NumberOfBytes) PVOID
MmAllocateContiguousMemorySpecifyCacheNode (
    __in SIZE_T NumberOfBytes,
    __in PHYSICAL_ADDRESS LowestAcceptableAddress,
    __in PHYSICAL_ADDRESS HighestAcceptableAddress,
    __in_opt PHYSICAL_ADDRESS BoundaryAddressMultiple,
    __in MEMORY_CACHING_TYPE CacheType,
    __in NODE_REQUIREMENT PreferredNode
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
MmFreeContiguousMemory (
    __in PVOID BaseAddress
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
MmFreeContiguousMemorySpecifyCache (
    __in_bcount (NumberOfBytes) PVOID BaseAddress,
    __in SIZE_T NumberOfBytes,
    __in MEMORY_CACHING_TYPE CacheType
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
__out_bcount_opt (NumberOfBytes) PVOID
MmAllocateNonCachedMemory (
    __in SIZE_T NumberOfBytes
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
MmFreeNonCachedMemory (
    __in_bcount (NumberOfBytes) PVOID BaseAddress,
    __in SIZE_T NumberOfBytes
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
MmIsAddressValid (
    __in PVOID VirtualAddress
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK
NTKERNELAPI
BOOLEAN
MmIsNonPagedSystemAddressValid (
    __in PVOID VirtualAddress
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
MmLockPagableSectionByHandle (
    __in PVOID ImageSectionHandle
    );
#endif


//
// Note that even though this function prototype
// says "HANDLE", MmSecureVirtualMemory does NOT return
// anything resembling a Win32-style handle.  The return
// value from this function can ONLY be used with MmUnsecureVirtualMemory.
//
#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
HANDLE
MmSecureVirtualMemory (
    __in_data_source(USER_MODE) __out_validated(MEMORY) __in_bcount (Size) PVOID Address,
    __in  __in_data_source(USER_MODE) SIZE_T Size,
    __in ULONG ProbeMode
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
MmUnsecureVirtualMemory (
    __in HANDLE SecureHandle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
MmMapViewInSystemSpace (
    __in PVOID Section,
    __deref_out_bcount (*ViewSize) PVOID *MappedBase,
    __inout PSIZE_T ViewSize
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
MmUnmapViewInSystemSpace (
    __in PVOID MappedBase
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
MmMapViewInSessionSpace (
    __in PVOID Section,
    __deref_out_bcount (*ViewSize) PVOID *MappedBase,
    __inout PSIZE_T ViewSize
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
MmUnmapViewInSessionSpace (
    __in PVOID MappedBase
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WS03)
NTKERNELAPI
NTSTATUS
MmCreateMirror (
    VOID
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
SeSinglePrivilegeCheck(
    __in LUID PrivilegeValue,
    __in KPROCESSOR_MODE PreviousMode
    );
#endif


extern NTKERNELAPI PEPROCESS PsInitialSystemProcess;


#if !defined(_PSGETCURRENTTHREAD_)

#define _PSGETCURRENTTHREAD_

FORCEINLINE
PETHREAD
PsGetCurrentThread (
    VOID
    )

/*++

Routine Description:

    This function returns a pointer to the current executive thread object.

Arguments:

    None.

Return Value:

    A pointer to the current executive thread object.

--*/

{

    return (PETHREAD)KeGetCurrentThread();
}

#endif


typedef
VOID
(*PCREATE_PROCESS_NOTIFY_ROUTINE)(
    IN HANDLE ParentId,
    IN HANDLE ProcessId,
    IN BOOLEAN Create
    );

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
PsSetCreateProcessNotifyRoutine(
    __in PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine,
    __in BOOLEAN Remove
    );
#endif

typedef struct _PS_CREATE_NOTIFY_INFO {
    __in SIZE_T Size;
    union {
        __in ULONG Flags;
        struct {
            __in ULONG FileOpenNameAvailable : 1;
            __in ULONG Reserved : 31;
        };
    };
    __in HANDLE ParentProcessId;
    __in CLIENT_ID CreatingThreadId;
    __inout struct _FILE_OBJECT *FileObject;
    __in PCUNICODE_STRING ImageFileName;
    __in_opt PCUNICODE_STRING CommandLine;
    __inout NTSTATUS CreationStatus;
} PS_CREATE_NOTIFY_INFO, *PPS_CREATE_NOTIFY_INFO;

typedef
VOID
(*PCREATE_PROCESS_NOTIFY_ROUTINE_EX) (
    __inout PEPROCESS Process,
    __in HANDLE ProcessId,
    __in_opt PPS_CREATE_NOTIFY_INFO CreateInfo
    );

#if (NTDDI_VERSION >= NTDDI_VISTASP1)
NTKERNELAPI
NTSTATUS
PsSetCreateProcessNotifyRoutineEx (
    __in PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
    __in BOOLEAN Remove
    );
#endif

typedef
VOID
(*PCREATE_THREAD_NOTIFY_ROUTINE)(
    IN HANDLE ProcessId,
    IN HANDLE ThreadId,
    IN BOOLEAN Create
    );

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
PsSetCreateThreadNotifyRoutine(
    __in PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
PsRemoveCreateThreadNotifyRoutine (
    __in PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
    );
#endif

//
// Structures for Load Image Notify
//

#define IMAGE_ADDRESSING_MODE_32BIT     3

typedef struct _IMAGE_INFO {
    union {
        ULONG Properties;
        struct {
            ULONG ImageAddressingMode  : 8;  // Code addressing mode
            ULONG SystemModeImage      : 1;  // System mode image
            ULONG ImageMappedToAllPids : 1;  // Image mapped into all processes
            ULONG ExtendedInfoPresent  : 1;  // IMAGE_INFO_EX available
            ULONG Reserved             : 21;
        };
    };
    PVOID       ImageBase;
    ULONG       ImageSelector;
    SIZE_T      ImageSize;
    ULONG       ImageSectionNumber;
} IMAGE_INFO, *PIMAGE_INFO;

typedef struct _IMAGE_INFO_EX {
    SIZE_T              Size;
    IMAGE_INFO          ImageInfo;
    struct _FILE_OBJECT *FileObject;
} IMAGE_INFO_EX, *PIMAGE_INFO_EX;

typedef
VOID
(*PLOAD_IMAGE_NOTIFY_ROUTINE)(
    IN PUNICODE_STRING FullImageName,
    IN HANDLE ProcessId,                // pid into which image is being mapped
    IN PIMAGE_INFO ImageInfo
    );

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
PsSetLoadImageNotifyRoutine(
    __in PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
PsRemoveLoadImageNotifyRoutine(
    __in PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
HANDLE
PsGetCurrentProcessId(
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
HANDLE
PsGetCurrentThreadId(
    VOID
    );
#endif



#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
PsGetVersion(
    __out_opt PULONG MajorVersion,
    __out_opt PULONG MinorVersion,
    __out_opt PULONG BuildNumber,
    __out_opt PUNICODE_STRING CSDVersion
    );
#endif

//
// Prefetch information.
//

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
BOOLEAN
PsSetCurrentThreadPrefetching (
    __in BOOLEAN Prefetching
    );

NTKERNELAPI
BOOLEAN
PsIsCurrentThreadPrefetching (
    VOID
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
LONGLONG
PsGetProcessCreateTimeQuadPart(
    __in PEPROCESS Process
    );
#endif
#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
HANDLE
PsGetProcessId(
    __in PEPROCESS Process
    );

NTKERNELAPI
HANDLE
PsGetThreadId(
    __in PETHREAD Thread
     );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03)
NTKERNELAPI
HANDLE
PsGetThreadProcessId(
    __in PETHREAD Thread
    );
#endif

//
// Directory control minor function codes
//

#define IRP_MN_QUERY_DIRECTORY          0x01
#define IRP_MN_NOTIFY_CHANGE_DIRECTORY  0x02

//
// File system control minor function codes.  Note that "user request" is
// assumed to be zero by both the I/O system and file systems.  Do not change
// this value.
//

#define IRP_MN_USER_FS_REQUEST          0x00
#define IRP_MN_MOUNT_VOLUME             0x01
#define IRP_MN_VERIFY_VOLUME            0x02
#define IRP_MN_LOAD_FILE_SYSTEM         0x03
#define IRP_MN_TRACK_LINK               0x04    // To be obsoleted soon
#define IRP_MN_KERNEL_CALL              0x04

//
// Lock control minor function codes
//

#define IRP_MN_LOCK                     0x01
#define IRP_MN_UNLOCK_SINGLE            0x02
#define IRP_MN_UNLOCK_ALL               0x03
#define IRP_MN_UNLOCK_ALL_BY_KEY        0x04

//
// Flush minor function codes
//

#define IRP_MN_FLUSH_AND_PURGE          0x01

//
// Read and Write minor function codes for file systems supporting Lan Manager
// software.  All of these subfunction codes are invalid if the file has been
// opened with FO_NO_INTERMEDIATE_BUFFERING.  They are also invalid in combi-
// nation with synchronous calls (Irp Flag or file open option).
//
// Note that "normal" is assumed to be zero by both the I/O system and file
// systems.  Do not change this value.
//

#define IRP_MN_NORMAL                   0x00
#define IRP_MN_DPC                      0x01
#define IRP_MN_MDL                      0x02
#define IRP_MN_COMPLETE                 0x04
#define IRP_MN_COMPRESSED               0x08

#define IRP_MN_MDL_DPC                  (IRP_MN_MDL | IRP_MN_DPC)
#define IRP_MN_COMPLETE_MDL             (IRP_MN_COMPLETE | IRP_MN_MDL)
#define IRP_MN_COMPLETE_MDL_DPC         (IRP_MN_COMPLETE_MDL | IRP_MN_DPC)

#define IRP_MN_QUERY_LEGACY_BUS_INFORMATION 0x18

#define IO_CHECK_CREATE_PARAMETERS      0x0200
#define IO_ATTACH_DEVICE                0x0400

//
//  This flag is only meaningful to IoCreateFileSpecifyDeviceObjectHint.
//  FileHandles created using IoCreateFileSpecifyDeviceObjectHint with this
//  flag set will bypass ShareAccess checks on this file.
//

#define IO_IGNORE_SHARE_ACCESS_CHECK    0x0800  // Ignores share access checks on opens.

//
// Define callout routine type for use in IoQueryDeviceDescription().
//

typedef NTSTATUS (*PIO_QUERY_DEVICE_ROUTINE)(
    IN PVOID Context,
    IN PUNICODE_STRING PathName,
    IN INTERFACE_TYPE BusType,
    IN ULONG BusNumber,
    IN PKEY_VALUE_FULL_INFORMATION *BusInformation,
    IN CONFIGURATION_TYPE ControllerType,
    IN ULONG ControllerNumber,
    IN PKEY_VALUE_FULL_INFORMATION *ControllerInformation,
    IN CONFIGURATION_TYPE PeripheralType,
    IN ULONG PeripheralNumber,
    IN PKEY_VALUE_FULL_INFORMATION *PeripheralInformation
    );


// Defines the order of the information in the array of
// PKEY_VALUE_FULL_INFORMATION.
//

typedef enum _IO_QUERY_DEVICE_DATA_FORMAT {
    IoQueryDeviceIdentifier = 0,
    IoQueryDeviceConfigurationData,
    IoQueryDeviceComponentInformation,
    IoQueryDeviceMaxData
} IO_QUERY_DEVICE_DATA_FORMAT, *PIO_QUERY_DEVICE_DATA_FORMAT;

//
// Define driver reinitialization routine type.
//

typedef
VOID
DRIVER_REINITIALIZE (
    __in struct _DRIVER_OBJECT *DriverObject,
    __in_opt PVOID Context,
    __in ULONG Count
    );

typedef DRIVER_REINITIALIZE *PDRIVER_REINITIALIZE;


typedef struct _CONTROLLER_OBJECT {
    CSHORT Type;
    CSHORT Size;
    PVOID ControllerExtension;
    KDEVICE_QUEUE DeviceWaitQueue;

    ULONG Spare1;
    LARGE_INTEGER Spare2;

} CONTROLLER_OBJECT, *PCONTROLLER_OBJECT;

#define DO_VERIFY_VOLUME                0x00000002
#define DO_BUFFERED_IO                  0x00000004
#define DO_EXCLUSIVE                    0x00000008
#define DO_DIRECT_IO                    0x00000010
#define DO_MAP_IO_BUFFER                0x00000020
#define DO_DEVICE_HAS_NAME              0x00000040
#define DO_DEVICE_INITIALIZING          0x00000080
#define DO_SYSTEM_BOOT_PARTITION        0x00000100
#define DO_LONG_TERM_REQUESTS           0x00000200
#define DO_NEVER_LAST_DEVICE            0x00000400
#define DO_SHUTDOWN_REGISTERED          0x00000800
#define DO_BUS_ENUMERATED_DEVICE        0x00001000
#define DO_POWER_PAGABLE                0x00002000
#define DO_POWER_INRUSH                 0x00004000
#define DO_LOW_PRIORITY_FILESYSTEM      0x00010000
#define DO_SUPPORTS_TRANSACTIONS        0x00040000
#define DO_FORCE_NEITHER_IO             0x00080000
#define DRVO_REINIT_REGISTERED          0x00000008
#define DRVO_INITIALIZED                0x00000010
#define DRVO_BOOTREINIT_REGISTERED      0x00000020
#define DRVO_LEGACY_RESOURCES           0x00000040

//
// The following structure is used by drivers that are initializing to
// determine the number of devices of a particular type that have already
// been initialized.  It is also used to track whether or not the AtDisk
// address range has already been claimed.  Finally, it is used by the
// NtQuerySystemInformation system service to return device type counts.
//

typedef struct _CONFIGURATION_INFORMATION {

    //
    // This field indicates the total number of disks in the system.  This
    // number should be used by the driver to determine the name of new
    // disks.  This field should be updated by the driver as it finds new
    // disks.
    //

    ULONG DiskCount;                // Count of hard disks thus far
    ULONG FloppyCount;              // Count of floppy disks thus far
    ULONG CdRomCount;               // Count of CD-ROM drives thus far
    ULONG TapeCount;                // Count of tape drives thus far
    ULONG ScsiPortCount;            // Count of SCSI port adapters thus far
    ULONG SerialCount;              // Count of serial devices thus far
    ULONG ParallelCount;            // Count of parallel devices thus far

    //
    // These next two fields indicate ownership of one of the two IO address
    // spaces that are used by WD1003-compatable disk controllers.
    //

    BOOLEAN AtDiskPrimaryAddressClaimed;    // 0x1F0 - 0x1FF
    BOOLEAN AtDiskSecondaryAddressClaimed;  // 0x170 - 0x17F

    //
    // Indicates the structure version, as anything value belong this will have been added.
    // Use the structure size as the version.
    //

    ULONG Version;

    //
    // Indicates the total number of medium changer devices in the system.
    // This field will be updated by the drivers as it determines that
    // new devices have been found and will be supported.
    //

    ULONG MediumChangerCount;

} CONFIGURATION_INFORMATION, *PCONFIGURATION_INFORMATION;

#if !(defined(USE_DMA_MACROS) && (defined(_NTDDK_) || defined(_NTDRIVER_)) || defined(_WDM_INCLUDED_))

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use AllocateAdapterChannel
NTKERNELAPI
NTSTATUS
IoAllocateAdapterChannel(
    __in PADAPTER_OBJECT AdapterObject,
    __in PDEVICE_OBJECT DeviceObject,
    __in ULONG NumberOfMapRegisters,
    __in PDRIVER_CONTROL ExecutionRoutine,
    __in PVOID Context
    );
#endif

#endif // !(defined(USE_DMA_MACROS) && (defined(_NTDDK_) || defined(_NTDRIVER_)) || defined(_WDM_INCLUDED_))

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
IoAllocateController(
    __in PCONTROLLER_OBJECT ControllerObject,
    __in PDEVICE_OBJECT DeviceObject,
    __in PDRIVER_CONTROL ExecutionRoutine,
    __in_opt PVOID Context
    );
#endif

//++
//
// VOID
// IoAssignArcName(
//     IN PUNICODE_STRING ArcName,
//     IN PUNICODE_STRING DeviceName
//     )
//
// Routine Description:
//
//     This routine is invoked by drivers of bootable media to create a symbolic
//     link between the ARC name of their device and its NT name.  This allows
//     the system to determine which device in the system was actually booted
//     from since the ARC firmware only deals in ARC names, and NT only deals
//     in NT names.
//
// Arguments:
//
//     ArcName - Supplies the Unicode string representing the ARC name.
//
//     DeviceName - Supplies the name to which the ARCname refers.
//
// Return Value:
//
//     None.
//
//--

#define IoAssignArcName( ArcName, DeviceName ) (  \
    IoCreateSymbolicLink( (ArcName), (DeviceName) ) )

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use Pnp or IoReprtDetectedDevice
NTKERNELAPI
NTSTATUS
IoAssignResources (
    __in PUNICODE_STRING RegistryPath,
    __in_opt PUNICODE_STRING DriverClassName,
    __in PDRIVER_OBJECT DriverObject,
    __in_opt PDEVICE_OBJECT DeviceObject,
    __in_opt PIO_RESOURCE_REQUIREMENTS_LIST RequestedResources,
    __inout PCM_RESOURCE_LIST *AllocatedResources
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use IoAttachDeviceToDeviceStack
NTKERNELAPI
NTSTATUS
IoAttachDeviceByPointer(
    __in PDEVICE_OBJECT SourceDevice,
    __in PDEVICE_OBJECT TargetDevice
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PCONTROLLER_OBJECT
IoCreateController(
    __in ULONG Size
    );
#endif


//++
//
// VOID
// IoDeassignArcName(
//     IN PUNICODE_STRING ArcName
//     )
//
// Routine Description:
//
//     This routine is invoked by drivers to deassign an ARC name that they
//     created to a device.  This is generally only called if the driver is
//     deleting the device object, which means that the driver is probably
//     unloading.
//
// Arguments:
//
//     ArcName - Supplies the ARC name to be removed.
//
// Return Value:
//
//     None.
//
//--

#define IoDeassignArcName( ArcName ) (  \
    IoDeleteSymbolicLink( (ArcName) ) )

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
IoDeleteController(
    __in PCONTROLLER_OBJECT ControllerObject
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
IoFreeController(
    __in PCONTROLLER_OBJECT ControllerObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PCONFIGURATION_INFORMATION
IoGetConfigurationInformation( VOID );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PDEVICE_OBJECT
IoGetDeviceToVerify(
    __in PETHREAD Thread
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PGENERIC_MAPPING
IoGetFileObjectGenericMapping(
    VOID
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
IoCancelFileOpen(
    __in PDEVICE_OBJECT  DeviceObject,
    __in PFILE_OBJECT    FileObject
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PIRP
IoMakeAssociatedIrp(
    __in PIRP Irp,
    __in CCHAR StackSize
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use IoGetDeviceProperty
NTKERNELAPI
NTSTATUS
IoQueryDeviceDescription(
    __in_opt PINTERFACE_TYPE BusType,
    __in_opt PULONG BusNumber,
    __in_opt PCONFIGURATION_TYPE ControllerType,
    __in_opt PULONG ControllerNumber,
    __in_opt PCONFIGURATION_TYPE PeripheralType,
    __in_opt PULONG PeripheralNumber,
    __in PIO_QUERY_DEVICE_ROUTINE CalloutRoutine,
    __inout_opt PVOID Context
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
IoRaiseHardError(
    __in PIRP Irp,
    __in_opt PVPB Vpb,
    __in PDEVICE_OBJECT RealDeviceObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
IoRaiseInformationalHardError(
    __in NTSTATUS ErrorStatus,
    __in_opt PUNICODE_STRING String,
    __in_opt PKTHREAD Thread
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
IoSetThreadHardErrorMode(
    __in BOOLEAN EnableHardErrors
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
IoRegisterBootDriverReinitialization(
    __in PDRIVER_OBJECT DriverObject,
    __in PDRIVER_REINITIALIZE DriverReinitializationRoutine,
    __in_opt PVOID Context
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
IoRegisterDriverReinitialization(
    __in PDRIVER_OBJECT DriverObject,
    __in PDRIVER_REINITIALIZE DriverReinitializationRoutine,
    __in_opt PVOID Context
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use IoReportResourceForDetection
NTKERNELAPI
NTSTATUS
IoReportResourceUsage(
    __in_opt PUNICODE_STRING DriverClassName,
    __in  PDRIVER_OBJECT DriverObject,
    __in_opt PCM_RESOURCE_LIST DriverList,
    __in_opt ULONG DriverListSize,
    __in  PDEVICE_OBJECT DeviceObject,
    __in_opt PCM_RESOURCE_LIST DeviceList,
    __in_opt ULONG DeviceListSize,
    __in  BOOLEAN OverrideConflict,
    __out PBOOLEAN ConflictDetected
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
BOOLEAN
IoTranslateBusAddress(
    __in  INTERFACE_TYPE InterfaceType,
    __in  ULONG BusNumber,
    __in  PHYSICAL_ADDRESS BusAddress,
    __inout PULONG AddressSpace,
    __out PPHYSICAL_ADDRESS TranslatedAddress
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
IoSetHardErrorOrVerifyDevice(
    __in PIRP Irp,
    __in PDEVICE_OBJECT DeviceObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
VOID
FASTCALL
HalExamineMBR(
    IN PDEVICE_OBJECT DeviceObject,
    IN ULONG SectorSize,
    IN ULONG MBRTypeIdentifier,
    OUT PVOID *Buffer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
DECLSPEC_DEPRECATED_DDK                 // Use IoReadPartitionTableEx
NTKERNELAPI
NTSTATUS
FASTCALL
IoReadPartitionTable(
    __in  PDEVICE_OBJECT DeviceObject,
    __in  ULONG SectorSize,
    __in  BOOLEAN ReturnRecognizedPartitions,
    __out struct _DRIVE_LAYOUT_INFORMATION **PartitionBuffer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
DECLSPEC_DEPRECATED_DDK                 // Use IoSetPartitionInformationEx
NTKERNELAPI
NTSTATUS
FASTCALL
IoSetPartitionInformation(
    __in PDEVICE_OBJECT DeviceObject,
    __in ULONG SectorSize,
    __in ULONG PartitionNumber,
    __in ULONG PartitionType
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WINXP)
DECLSPEC_DEPRECATED_DDK                 // Use IoWritePartitionTableEx
NTKERNELAPI
NTSTATUS
FASTCALL
IoWritePartitionTable(
    __in PDEVICE_OBJECT DeviceObject,
    __in ULONG SectorSize,
    __in ULONG SectorsPerTrack,
    __in ULONG NumberOfHeads,
    __in struct _DRIVE_LAYOUT_INFORMATION *PartitionBuffer
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoCreateDisk(
    __in PDEVICE_OBJECT DeviceObject,
    __in_opt struct _CREATE_DISK* Disk
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoReadPartitionTableEx(
    __in PDEVICE_OBJECT DeviceObject,
    __out struct _DRIVE_LAYOUT_INFORMATION_EX** DriveLayout
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoWritePartitionTableEx(
    __in PDEVICE_OBJECT DeviceObject,
    __in_xcount(FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry[0])) struct _DRIVE_LAYOUT_INFORMATION_EX* DriveLayout
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoSetPartitionInformationEx(
    __in PDEVICE_OBJECT DeviceObject,
    __in ULONG PartitionNumber,
    __in struct _SET_PARTITION_INFORMATION_EX* PartitionInfo
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
NTSTATUS
IoUpdateDiskGeometry(
    __in PDEVICE_OBJECT DeviceObject,
    __in struct _DISK_GEOMETRY_EX* OldDiskGeometry,
    __in struct _DISK_GEOMETRY_EX* NewDiskGeometry
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoVerifyPartitionTable(
    __in PDEVICE_OBJECT DeviceObject,
    __in BOOLEAN FixErrors
    );
#endif

typedef struct _DISK_SIGNATURE {
    ULONG PartitionStyle;
    union {
        struct {
            ULONG Signature;
            ULONG CheckSum;
        } Mbr;

        struct {
            GUID DiskId;
        } Gpt;
    };
} DISK_SIGNATURE, *PDISK_SIGNATURE;

#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoReadDiskSignature(
    __in  PDEVICE_OBJECT DeviceObject,
    __in  ULONG BytesPerSector,
    __out PDISK_SIGNATURE Signature
    );
#endif



#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoVolumeDeviceToDosName(
    __in  PVOID           VolumeDeviceObject,
    __out PUNICODE_STRING DosName
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WINXP)
NTKERNELAPI
NTSTATUS
IoSetSystemPartition(
    __in PUNICODE_STRING VolumeNameString
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
IoCreateFileSpecifyDeviceObjectHint(
    __out PHANDLE FileHandle,
    __in  ACCESS_MASK DesiredAccess,
    __in  POBJECT_ATTRIBUTES ObjectAttributes,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in_opt PLARGE_INTEGER AllocationSize,
    __in  ULONG FileAttributes,
    __in  ULONG ShareAccess,
    __in  ULONG Disposition,
    __in  ULONG CreateOptions,
    __in_opt PVOID EaBuffer,
    __in  ULONG EaLength,
    __in  CREATE_FILE_TYPE CreateFileType,
    __in_opt PVOID InternalParameters,
    __in  ULONG Options,
    __in_opt PVOID DeviceObject
    );
#endif

typedef struct _TXN_PARAMETER_BLOCK {

    USHORT Length;              // sizeof( TXN_PARAMETER_BLOCK )
    USHORT TxFsContext;         // this is mini version of the requested file
    PVOID  TransactionObject;   // referenced pointer to KTRANSACTION

} TXN_PARAMETER_BLOCK, *PTXN_PARAMETER_BLOCK;

//
//  This value should be used in the TxFsContext member of the
//  TXN_PARAMETER_BLOCK in the absence of a specific miniversion.
//

#define TXF_MINIVERSION_DEFAULT_VIEW        (0xFFFE)

#if (NTDDI_VERSION >= NTDDI_VISTA)
PTXN_PARAMETER_BLOCK
IoGetTransactionParameterBlock (
    __in PFILE_OBJECT FileObject
    );
#endif

typedef struct _IO_DRIVER_CREATE_CONTEXT {
    CSHORT Size;
    struct _ECP_LIST *ExtraCreateParameter;
    PVOID DeviceObjectHint;
    PTXN_PARAMETER_BLOCK TxnParameters;
} IO_DRIVER_CREATE_CONTEXT, *PIO_DRIVER_CREATE_CONTEXT;

VOID
FORCEINLINE
IoInitializeDriverCreateContext(
    PIO_DRIVER_CREATE_CONTEXT DriverContext
    )
{
    // Initialize the context
    RtlZeroMemory(DriverContext, sizeof(IO_DRIVER_CREATE_CONTEXT));
    DriverContext->Size = sizeof(IO_DRIVER_CREATE_CONTEXT);
}

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
NTSTATUS
IoCreateFileEx(
    __out PHANDLE FileHandle,
    __in  ACCESS_MASK DesiredAccess,
    __in  POBJECT_ATTRIBUTES ObjectAttributes,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in_opt PLARGE_INTEGER AllocationSize,
    __in  ULONG FileAttributes,
    __in  ULONG ShareAccess,
    __in  ULONG Disposition,
    __in  ULONG CreateOptions,
    __in_opt PVOID EaBuffer,
    __in  ULONG EaLength,
    __in  CREATE_FILE_TYPE CreateFileType,
    __in_opt PVOID InternalParameters,
    __in  ULONG Options,
    __in_opt PIO_DRIVER_CREATE_CONTEXT DriverContext
    );

NTSTATUS
IoSetIrpExtraCreateParameter(
    __inout PIRP Irp,
    __in struct _ECP_LIST *ExtraCreateParameter
    );

VOID
IoClearIrpExtraCreateParameter(
    __inout PIRP Irp
    );

NTSTATUS
IoGetIrpExtraCreateParameter(
    __in PIRP Irp,
    __deref_out struct _ECP_LIST **ExtraCreateParameter
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
IoAttachDeviceToDeviceStackSafe(
    __in  PDEVICE_OBJECT SourceDevice,
    __in  PDEVICE_OBJECT TargetDevice,
    __deref_out PDEVICE_OBJECT *AttachedToDeviceObject
    );
#endif



#if (NTDDI_VERSION >= NTDDI_WIN2KSP3)
NTKERNELAPI
BOOLEAN
IoIsFileOriginRemote(
    __in PFILE_OBJECT FileObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2KSP3)
NTKERNELAPI
NTSTATUS
IoSetFileOrigin(
    __in PFILE_OBJECT FileObject,
    __in BOOLEAN Remote
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
BOOLEAN
IoIsFileObjectIgnoringSharing (
  __in PFILE_OBJECT FileObject
);
#endif


#if (NTDDI_VERSION >= NTDDI_WS03)
NTKERNELAPI
IO_PAGING_PRIORITY
FASTCALL
IoGetPagingIoPriority(
    __in PIRP Irp
    );
#endif


typedef struct _AGP_TARGET_BUS_INTERFACE_STANDARD {
    //
    // generic interface header
    //
    USHORT Size;
    USHORT Version;
    PVOID Context;
    PINTERFACE_REFERENCE InterfaceReference;
    PINTERFACE_DEREFERENCE InterfaceDereference;

    //
    // config munging routines
    //
    PGET_SET_DEVICE_DATA SetBusData;
    PGET_SET_DEVICE_DATA GetBusData;
    UCHAR CapabilityID;  // 2 (AGPv2 host) or new 0xE (AGPv3 bridge)

} AGP_TARGET_BUS_INTERFACE_STANDARD, *PAGP_TARGET_BUS_INTERFACE_STANDARD;


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
IoReportDetectedDevice(
    __in PDRIVER_OBJECT DriverObject,
    __in INTERFACE_TYPE LegacyBusType,
    __in ULONG BusNumber,
    __in ULONG SlotNumber,
    __in_opt PCM_RESOURCE_LIST ResourceList,
    __in_opt PIO_RESOURCE_REQUIREMENTS_LIST ResourceRequirements,
    __in BOOLEAN ResourceAssigned,
    __deref_inout_opt PDEVICE_OBJECT *DeviceObject
    );
#endif

//
// Device location interface declarations
//
typedef
NTSTATUS
(*PGET_LOCATION_STRING) (
    __inout_opt PVOID Context,
    __deref_out PWCHAR *LocationStrings
    );

typedef struct _PNP_LOCATION_INTERFACE {
    //
    // generic interface header
    //
    USHORT Size;
    USHORT Version;
    PVOID Context;
    PINTERFACE_REFERENCE InterfaceReference;
    PINTERFACE_DEREFERENCE InterfaceDereference;

    //
    // interface specific entry
    //
    PGET_LOCATION_STRING GetLocationString;

} PNP_LOCATION_INTERFACE, *PPNP_LOCATION_INTERFACE;

//
// Resource arbiter declarations
//

typedef enum _ARBITER_ACTION {
    ArbiterActionTestAllocation,
    ArbiterActionRetestAllocation,
    ArbiterActionCommitAllocation,
    ArbiterActionRollbackAllocation,
    ArbiterActionQueryAllocatedResources,
    ArbiterActionWriteReservedResources,
    ArbiterActionQueryConflict,
    ArbiterActionQueryArbitrate,
    ArbiterActionAddReserved,
    ArbiterActionBootAllocation
} ARBITER_ACTION, *PARBITER_ACTION;

typedef struct _ARBITER_CONFLICT_INFO {
    //
    // The device object owning the device that is causing the conflict
    //
    PDEVICE_OBJECT OwningObject;

    //
    // The start of the conflicting range
    //
    ULONGLONG Start;

    //
    // The end of the conflicting range
    //
    ULONGLONG End;

} ARBITER_CONFLICT_INFO, *PARBITER_CONFLICT_INFO;

//
// The parameters for those actions
//

typedef struct _ARBITER_TEST_ALLOCATION_PARAMETERS {

    //
    // Doubly linked list of ARBITER_LIST_ENTRY's
    //
    IN OUT PLIST_ENTRY ArbitrationList;

    //
    // The size of the AllocateFrom array
    //
    IN ULONG AllocateFromCount;

    //
    // Array of resource descriptors describing the resources available
    // to the arbiter for it to arbitrate
    //
    IN PCM_PARTIAL_RESOURCE_DESCRIPTOR AllocateFrom;

} ARBITER_TEST_ALLOCATION_PARAMETERS, *PARBITER_TEST_ALLOCATION_PARAMETERS;


typedef struct _ARBITER_RETEST_ALLOCATION_PARAMETERS {

    //
    // Doubly linked list of ARBITER_LIST_ENTRY's
    //
    IN OUT PLIST_ENTRY ArbitrationList;

    //
    // The size of the AllocateFrom array
    //
    IN ULONG AllocateFromCount;

    //
    // Array of resource descriptors describing the resources available
    // to the arbiter for it to arbitrate
    //
    IN PCM_PARTIAL_RESOURCE_DESCRIPTOR AllocateFrom;

} ARBITER_RETEST_ALLOCATION_PARAMETERS, *PARBITER_RETEST_ALLOCATION_PARAMETERS;

typedef struct _ARBITER_BOOT_ALLOCATION_PARAMETERS {

    //
    // Doubly linked list of ARBITER_LIST_ENTRY's
    //
    IN OUT PLIST_ENTRY ArbitrationList;

} ARBITER_BOOT_ALLOCATION_PARAMETERS, *PARBITER_BOOT_ALLOCATION_PARAMETERS;


typedef struct _ARBITER_QUERY_ALLOCATED_RESOURCES_PARAMETERS {

    //
    // The resources that are currently allocated
    //
    OUT PCM_PARTIAL_RESOURCE_LIST *AllocatedResources;

} ARBITER_QUERY_ALLOCATED_RESOURCES_PARAMETERS, *PARBITER_QUERY_ALLOCATED_RESOURCES_PARAMETERS;

typedef struct _ARBITER_QUERY_CONFLICT_PARAMETERS {

    //
    // This is the device we are trying to find a conflict for
    //
    IN PDEVICE_OBJECT PhysicalDeviceObject;

    //
    // This is the resource to find the conflict for
    //
    IN PIO_RESOURCE_DESCRIPTOR ConflictingResource;

    //
    // Number of devices conflicting on the resource
    //
    OUT PULONG ConflictCount;

    //
    // Pointer to array describing the conflicting device objects and ranges
    //
    OUT PARBITER_CONFLICT_INFO *Conflicts;

} ARBITER_QUERY_CONFLICT_PARAMETERS, *PARBITER_QUERY_CONFLICT_PARAMETERS;

typedef struct _ARBITER_QUERY_ARBITRATE_PARAMETERS {

    //
    // Doubly linked list of ARBITER_LIST_ENTRY's - should have
    // only one entry
    //
    IN PLIST_ENTRY ArbitrationList;

} ARBITER_QUERY_ARBITRATE_PARAMETERS, *PARBITER_QUERY_ARBITRATE_PARAMETERS;

typedef struct _ARBITER_ADD_RESERVED_PARAMETERS {

    //
    // Doubly linked list of ARBITER_LIST_ENTRY's - should have
    // only one entry
    //
    IN PDEVICE_OBJECT ReserveDevice;

} ARBITER_ADD_RESERVED_PARAMETERS, *PARBITER_ADD_RESERVED_PARAMETERS;


typedef struct _ARBITER_PARAMETERS {

    union {

        ARBITER_TEST_ALLOCATION_PARAMETERS              TestAllocation;
        ARBITER_RETEST_ALLOCATION_PARAMETERS            RetestAllocation;
        ARBITER_BOOT_ALLOCATION_PARAMETERS              BootAllocation;
        ARBITER_QUERY_ALLOCATED_RESOURCES_PARAMETERS    QueryAllocatedResources;
        ARBITER_QUERY_CONFLICT_PARAMETERS               QueryConflict;
        ARBITER_QUERY_ARBITRATE_PARAMETERS              QueryArbitrate;
        ARBITER_ADD_RESERVED_PARAMETERS                 AddReserved;

    } Parameters;

} ARBITER_PARAMETERS, *PARBITER_PARAMETERS;

typedef enum _ARBITER_REQUEST_SOURCE {

    ArbiterRequestUndefined = -1,
    ArbiterRequestLegacyReported,   // IoReportResourceUsage
    ArbiterRequestHalReported,      // IoReportHalResourceUsage
    ArbiterRequestLegacyAssigned,   // IoAssignResources
    ArbiterRequestPnpDetected,      // IoReportResourceForDetection
    ArbiterRequestPnpEnumerated     // IRP_MN_QUERY_RESOURCE_REQUIREMENTS

} ARBITER_REQUEST_SOURCE;


typedef enum _ARBITER_RESULT {

    ArbiterResultUndefined = -1,
    ArbiterResultSuccess,
    ArbiterResultExternalConflict, // This indicates that the request can never be solved for devices in this list
    ArbiterResultNullRequest       // The request was for length zero and thus no translation should be attempted

} ARBITER_RESULT;

//
// ARBITER_FLAG_BOOT_CONFIG - this indicates that the request is for the
// resources assigned by the firmware/BIOS.  It should be succeeded even if
// it conflicts with another devices boot config.
//

#define ARBITER_FLAG_BOOT_CONFIG 0x00000001

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
IoReportResourceForDetection(
    __in PDRIVER_OBJECT DriverObject,
    __in_bcount_opt(DriverListSize) PCM_RESOURCE_LIST DriverList,
    __in_opt ULONG DriverListSize,
    __in_opt PDEVICE_OBJECT DeviceObject,
    __in_bcount_opt(DeviceListSize) PCM_RESOURCE_LIST DeviceList,
    __in_opt ULONG DeviceListSize,
    __out PBOOLEAN ConflictDetected
    );
#endif

typedef struct _ARBITER_LIST_ENTRY {

    //
    // This is a doubly linked list of entries for easy sorting
    //
    LIST_ENTRY ListEntry;

    //
    // The number of alternative allocation
    //
    ULONG AlternativeCount;

    //
    // Pointer to an array of resource descriptors for the possible allocations
    //
    PIO_RESOURCE_DESCRIPTOR Alternatives;

    //
    // The device object of the device requesting these resources.
    //
    PDEVICE_OBJECT PhysicalDeviceObject;

    //
    // Indicates where the request came from
    //
    ARBITER_REQUEST_SOURCE RequestSource;

    //
    // Flags these indicate a variety of things (use ARBITER_FLAG_*)
    //
    ULONG Flags;

    //
    // Space to aid the arbiter in processing the list it is initialized to 0 when
    // the entry is created.  The system will not attempt to interpret it.
    //
    LONG_PTR WorkSpace;

    //
    // Interface Type, Slot Number and Bus Number from Resource Requirements list,
    // used only for reverse identification.
    //
    INTERFACE_TYPE InterfaceType;
    ULONG SlotNumber;
    ULONG BusNumber;

    //
    // A pointer to a descriptor to indicate the resource that was allocated.
    // This is allocated by the system and filled in by the arbiter in response to an
    // ArbiterActionTestAllocation.
    //
    PCM_PARTIAL_RESOURCE_DESCRIPTOR Assignment;

    //
    // Pointer to the alternative that was chosen from to provide the assignment.
    // This is filled in by the arbiter in response to an ArbiterActionTestAllocation.
    //
    PIO_RESOURCE_DESCRIPTOR SelectedAlternative;

    //
    // The result of the operation
    // This is filled in by the arbiter in response to an ArbiterActionTestAllocation.
    //
    ARBITER_RESULT Result;

} ARBITER_LIST_ENTRY, *PARBITER_LIST_ENTRY;

//
// The arbiter's entry point
//

typedef
NTSTATUS
(*PARBITER_HANDLER) (
    __inout_opt PVOID Context,
    __in ARBITER_ACTION Action,
    __inout PARBITER_PARAMETERS Parameters
    );

//
// Arbiter interface
//

#define ARBITER_PARTIAL   0x00000001


typedef struct _ARBITER_INTERFACE {

    //
    // Generic interface header
    //
    USHORT Size;
    USHORT Version;
    PVOID Context;
    PINTERFACE_REFERENCE InterfaceReference;
    PINTERFACE_DEREFERENCE InterfaceDereference;

    //
    // Entry point to the arbiter
    //
    PARBITER_HANDLER ArbiterHandler;

    //
    // Other information about the arbiter, use ARBITER_* flags
    //
    ULONG Flags;

} ARBITER_INTERFACE, *PARBITER_INTERFACE;

//
// The directions translation can take place in
//

typedef enum _RESOURCE_TRANSLATION_DIRECTION {
    TranslateChildToParent,
    TranslateParentToChild
} RESOURCE_TRANSLATION_DIRECTION;

//
// Translation functions
//

typedef
NTSTATUS
(*PTRANSLATE_RESOURCE_HANDLER)(
    __inout_opt PVOID Context,
    __in PCM_PARTIAL_RESOURCE_DESCRIPTOR Source,
    __in RESOURCE_TRANSLATION_DIRECTION Direction,
    __in_opt ULONG AlternativesCount,
    __in_ecount_opt(AlternativesCount) IO_RESOURCE_DESCRIPTOR Alternatives[],
    __in PDEVICE_OBJECT PhysicalDeviceObject,
    __out PCM_PARTIAL_RESOURCE_DESCRIPTOR Target
);

typedef
NTSTATUS
(*PTRANSLATE_RESOURCE_REQUIREMENTS_HANDLER)(
    __inout_opt PVOID Context,
    __in PIO_RESOURCE_DESCRIPTOR Source,
    __in PDEVICE_OBJECT PhysicalDeviceObject,
    __out PULONG TargetCount,
    __out_ecount(TargetCount) PIO_RESOURCE_DESCRIPTOR *Target
);

//
// Translator Interface
//

typedef struct _TRANSLATOR_INTERFACE {
    USHORT Size;
    USHORT Version;
    PVOID Context;
    PINTERFACE_REFERENCE InterfaceReference;
    PINTERFACE_DEREFERENCE InterfaceDereference;
    PTRANSLATE_RESOURCE_HANDLER TranslateResources;
    PTRANSLATE_RESOURCE_REQUIREMENTS_HANDLER TranslateResourceRequirements;
} TRANSLATOR_INTERFACE, *PTRANSLATOR_INTERFACE;

//
// The following function prototypes are for HAL routines with a prefix of Hal.
//
// General functions.
//

typedef
BOOLEAN
(*PHAL_RESET_DISPLAY_PARAMETERS) (
    __in ULONG Columns,
    __in ULONG Rows
    );

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK
NTHALAPI
VOID
HalAcquireDisplayOwnership (
    __in PHAL_RESET_DISPLAY_PARAMETERS ResetDisplayParameters
    );
#endif

#if defined(_IA64_)

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use GetDmaRequirement
NTHALAPI
ULONG
HalGetDmaAlignmentRequirement (
    VOID
    );
#endif

#endif

#if defined(_M_IX86) || defined(_M_AMD64)

#define HalGetDmaAlignmentRequirement() 1L
#endif

//
// I/O driver configuration functions.
//
#if !defined(NO_LEGACY_DRIVERS)
#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use Pnp or IoReportDetectedDevice
NTHALAPI
NTSTATUS
HalAssignSlotResources (
    __in PUNICODE_STRING RegistryPath,
    __in PUNICODE_STRING DriverClassName OPTIONAL,
    __in PDRIVER_OBJECT DriverObject,
    __in PDEVICE_OBJECT DeviceObject,
    __in INTERFACE_TYPE BusType,
    __in ULONG BusNumber,
    __in ULONG SlotNumber,
    __inout PCM_RESOURCE_LIST *AllocatedResources
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use Pnp or IoReportDetectedDevice
NTHALAPI
ULONG
HalGetInterruptVector (
    __in INTERFACE_TYPE  InterfaceType,
    __in ULONG BusNumber,
    __in ULONG BusInterruptLevel,
    __in ULONG BusInterruptVector,
    __out PKIRQL Irql,
    __out PKAFFINITY Affinity
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use IRP_MN_QUERY_INTERFACE and IRP_MN_READ_CONFIG
NTHALAPI
ULONG
HalSetBusData (
    __in BUS_DATA_TYPE BusDataType,
    __in ULONG BusNumber,
    __in ULONG SlotNumber,
    __in_bcount(Length) PVOID Buffer,
    __in ULONG Length
    );
#endif

#endif // NO_LEGACY_DRIVERS

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use IRP_MN_QUERY_INTERFACE and IRP_MN_READ_CONFIG
NTHALAPI
ULONG
HalSetBusDataByOffset (
    __in BUS_DATA_TYPE BusDataType,
    __in ULONG BusNumber,
    __in ULONG SlotNumber,
    __in_bcount(Length) PVOID Buffer,
    __in ULONG Offset,
    __in ULONG Length
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use IRP_MN_QUERY_INTERFACE and IRP_MN_READ_CONFIG
NTHALAPI
BOOLEAN
HalTranslateBusAddress (
    __in INTERFACE_TYPE  InterfaceType,
    __in ULONG BusNumber,
    __in PHYSICAL_ADDRESS BusAddress,
    __inout PULONG AddressSpace,
    __out PPHYSICAL_ADDRESS TranslatedAddress
    );
#endif

//
// Values for AddressSpace parameter of HalTranslateBusAddress
//
//      0x0         - Memory space
//      0x1         - Port space
//      0x2 - 0x1F  - Address spaces specific for Alpha
//                      0x2 - UserMode view of memory space
//                      0x3 - UserMode view of port space
//                      0x4 - Dense memory space
//                      0x5 - reserved
//                      0x6 - UserMode view of dense memory space
//                      0x7 - 0x1F - reserved
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTHALAPI
PVOID
HalAllocateCrashDumpRegisters (
    __in PADAPTER_OBJECT AdapterObject,
    __inout PULONG NumberOfMapRegisters
    );
#endif

#if !defined(NO_LEGACY_DRIVERS)
#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use IRP_MN_QUERY_INTERFACE and IRP_MN_READ_CONFIG
NTHALAPI
ULONG
HalGetBusData (
    __in BUS_DATA_TYPE BusDataType,
    __in ULONG BusNumber,
    __in ULONG SlotNumber,
    __out_bcount(Length) PVOID Buffer,
    __in ULONG Length
    );
#endif
#endif // NO_LEGACY_DRIVERS

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use IRP_MN_QUERY_INTERFACE and IRP_MN_READ_CONFIG
NTHALAPI
ULONG
HalGetBusDataByOffset (
    __in BUS_DATA_TYPE BusDataType,
    __in ULONG BusNumber,
    __in ULONG SlotNumber,
    __out_bcount(Length) PVOID Buffer,
    __in ULONG Offset,
    __in ULONG Length
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use IoGetDmaAdapter
NTHALAPI
PADAPTER_OBJECT
HalGetAdapter (
    __in PDEVICE_DESCRIPTION DeviceDescription,
    __out PULONG NumberOfMapRegisters
    );
#endif

//
// System beep functions.
//
#if !defined(NO_LEGACY_DRIVERS)
#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK
NTHALAPI
BOOLEAN
HalMakeBeep(
    __in ULONG Frequency
    );
#endif
#endif // NO_LEGACY_DRIVERS

//
// The following function prototypes are for HAL routines with a prefix of Io.
//
// DMA adapter object functions.
//

typedef
PBUS_HANDLER
(FASTCALL *pHalHandlerForBus) (
    __in INTERFACE_TYPE InterfaceType,
    __in ULONG          BusNumber
    );
typedef
VOID
(FASTCALL *pHalReferenceBusHandler) (
    __in PBUS_HANDLER   BusHandler
    );

//-----------------------------------------------------------------------------
//      HAL Function dispatch
//

typedef enum _HAL_QUERY_INFORMATION_CLASS {
    HalInstalledBusInformation,
    HalProfileSourceInformation,
    HalInformationClassUnused1,
    HalPowerInformation,
    HalProcessorSpeedInformation,
    HalCallbackInformation,
    HalMapRegisterInformation,
    HalMcaLogInformation,               // Machine Check Abort Information
    HalFrameBufferCachingInformation,
    HalDisplayBiosInformation,
    HalProcessorFeatureInformation,
    HalNumaTopologyInterface,
    HalErrorInformation,                // General MCA, CMC, CPE Error Information.
    HalCmcLogInformation,               // Processor Corrected Machine Check Information
    HalCpeLogInformation,               // Corrected Platform Error Information
    HalQueryMcaInterface,
    HalQueryAMLIIllegalIOPortAddresses,
    HalQueryMaxHotPlugMemoryAddress,
    HalPartitionIpiInterface,
    HalPlatformInformation,
    HalQueryProfileSourceList,
    HalInitLogInformation,
    HalFrequencyInformation,
    HalProcessorBrandString
    // information levels >= 0x8000000 reserved for OEM use
} HAL_QUERY_INFORMATION_CLASS, *PHAL_QUERY_INFORMATION_CLASS;


typedef enum _HAL_SET_INFORMATION_CLASS {
    HalProfileSourceInterval,
    HalProfileSourceInterruptHandler,  // Register performance monitor interrupt callback
    HalMcaRegisterDriver,              // Register Machine Check Abort driver
    HalKernelErrorHandler,
    HalCmcRegisterDriver,              // Register Processor Corrected Machine Check driver
    HalCpeRegisterDriver,              // Register Corrected Platform  Error driver
    HalMcaLog,
    HalCmcLog,
    HalCpeLog,
    HalGenerateCmcInterrupt,           // Used to test CMC
    HalProfileSourceTimerHandler,      // Resister profile timer interrupt callback
    HalEnlightenment,
    HalProfileDpgoSourceInterruptHandler  // Register performance monitor interrupt callback for dpgo
} HAL_SET_INFORMATION_CLASS, *PHAL_SET_INFORMATION_CLASS;



typedef
NTSTATUS
(*pHalQuerySystemInformation)(
    __in HAL_QUERY_INFORMATION_CLASS  InformationClass,
    __in ULONG     BufferSize,
    __inout PVOID Buffer,
    __out PULONG   ReturnedLength
    );


typedef
NTSTATUS
(*pHalSetSystemInformation)(
    __in HAL_SET_INFORMATION_CLASS    InformationClass,
    __in ULONG     BufferSize,
    __in PVOID     Buffer
    );


typedef
VOID
(FASTCALL *pHalExamineMBR)(
    __in PDEVICE_OBJECT DeviceObject,
    __in ULONG SectorSize,
    __in ULONG MBRTypeIdentifier,
    __out PVOID *Buffer
    );

typedef
VOID
(FASTCALL *pHalIoAssignDriveLetters)(
    __in struct _LOADER_PARAMETER_BLOCK *LoaderBlock,
    __in PSTRING NtDeviceName,
    __out PUCHAR NtSystemPath,
    __out PSTRING NtSystemPathString
    );

typedef
NTSTATUS
(FASTCALL *pHalIoReadPartitionTable)(
    __in PDEVICE_OBJECT DeviceObject,
    __in ULONG SectorSize,
    __in BOOLEAN ReturnRecognizedPartitions,
    __out struct _DRIVE_LAYOUT_INFORMATION **PartitionBuffer
    );

typedef
NTSTATUS
(FASTCALL *pHalIoSetPartitionInformation)(
    __in PDEVICE_OBJECT DeviceObject,
    __in ULONG SectorSize,
    __in ULONG PartitionNumber,
    __in ULONG PartitionType
    );

typedef
NTSTATUS
(FASTCALL *pHalIoWritePartitionTable)(
    __in PDEVICE_OBJECT DeviceObject,
    __in ULONG SectorSize,
    __in ULONG SectorsPerTrack,
    __in ULONG NumberOfHeads,
    __in struct _DRIVE_LAYOUT_INFORMATION *PartitionBuffer
    );

typedef
NTSTATUS
(*pHalQueryBusSlots)(
    __in PBUS_HANDLER         BusHandler,
    __in ULONG                BufferSize,
    __out PULONG              SlotNumbers,
    __out PULONG              ReturnedLength
    );

typedef
NTSTATUS
(*pHalInitPnpDriver)(
    VOID
    );


typedef struct _PM_DISPATCH_TABLE {
    ULONG   Signature;
    ULONG   Version;
    PVOID   Function[1];
} PM_DISPATCH_TABLE, *PPM_DISPATCH_TABLE;



typedef
NTSTATUS
(*pHalInitPowerManagement)(
    __in PPM_DISPATCH_TABLE  PmDriverDispatchTable,
    __out PPM_DISPATCH_TABLE *PmHalDispatchTable
    );


typedef
struct _DMA_ADAPTER *
(*pHalGetDmaAdapter)(
    __in PVOID Context,
    __in struct _DEVICE_DESCRIPTION *DeviceDescriptor,
    __out PULONG NumberOfMapRegisters
    );


typedef
NTSTATUS
(*pHalGetInterruptTranslator)(
    __in INTERFACE_TYPE ParentInterfaceType,
    __in ULONG ParentBusNumber,
    __in INTERFACE_TYPE BridgeInterfaceType,
    __in USHORT Size,
    __in USHORT Version,
    __out PTRANSLATOR_INTERFACE Translator,
    __out PULONG BridgeBusNumber
    );


typedef
BOOLEAN
(*pHalTranslateBusAddress)(
    __in INTERFACE_TYPE  InterfaceType,
    __in ULONG BusNumber,
    __in PHYSICAL_ADDRESS BusAddress,
    __inout PULONG AddressSpace,
    __out PPHYSICAL_ADDRESS TranslatedAddress
    );

typedef
NTSTATUS
(*pHalAssignSlotResources) (
    __in PUNICODE_STRING RegistryPath,
    __in PUNICODE_STRING DriverClassName OPTIONAL,
    __in PDRIVER_OBJECT DriverObject,
    __in PDEVICE_OBJECT DeviceObject,
    __in INTERFACE_TYPE BusType,
    __in ULONG BusNumber,
    __in ULONG SlotNumber,
    __inout PCM_RESOURCE_LIST *AllocatedResources
    );

typedef
VOID
(*pHalHaltSystem) (
    VOID
    );

typedef
BOOLEAN
(*pHalResetDisplay) (
    VOID
    );



typedef struct _MAP_REGISTER_ENTRY {
    PVOID   MapRegister;
    BOOLEAN WriteToDevice;
} MAP_REGISTER_ENTRY, *PMAP_REGISTER_ENTRY;




typedef
UCHAR
(*pHalVectorToIDTEntry) (
    ULONG Vector
);

typedef
BOOLEAN
(*pHalFindBusAddressTranslation) (
    __in PHYSICAL_ADDRESS BusAddress,
    __inout PULONG AddressSpace,
    __out PPHYSICAL_ADDRESS TranslatedAddress,
    __inout PULONG_PTR Context,
    __in BOOLEAN NextBus
    );

typedef
NTSTATUS
(*pHalStartMirroring)(
    VOID
    );

typedef
NTSTATUS
(*pHalEndMirroring)(
    __in ULONG PassNumber
    );

typedef
NTSTATUS
(*pHalMirrorPhysicalMemory)(
    __in PHYSICAL_ADDRESS PhysicalAddress,
    __in LARGE_INTEGER NumberOfBytes
    );

typedef
NTSTATUS
(*pHalMirrorVerify)(
    __in PHYSICAL_ADDRESS PhysicalAddress,
    __in LARGE_INTEGER NumberOfBytes
    );


typedef struct {
    UCHAR     Type;  //CmResourceType
    BOOLEAN   Valid;
    UCHAR     Reserved[2];
    PUCHAR    TranslatedAddress;
    ULONG     Length;
} DEBUG_DEVICE_ADDRESS, *PDEBUG_DEVICE_ADDRESS;

typedef struct {
    PHYSICAL_ADDRESS  Start;
    PHYSICAL_ADDRESS  MaxEnd;
    PVOID             VirtualAddress;
    ULONG             Length;
    BOOLEAN           Cached;
    BOOLEAN           Aligned;
} DEBUG_MEMORY_REQUIREMENTS, *PDEBUG_MEMORY_REQUIREMENTS;

typedef struct {
    ULONG     Bus;
    USHORT    Segment;
    ULONG     Slot;
    USHORT    VendorID;
    USHORT    DeviceID;
    UCHAR     BaseClass;
    UCHAR     SubClass;
    UCHAR     ProgIf;
    BOOLEAN   Initialized;
    BOOLEAN   Configured;
    DEBUG_DEVICE_ADDRESS BaseAddress[6];
    DEBUG_MEMORY_REQUIREMENTS   Memory;
} DEBUG_DEVICE_DESCRIPTOR, *PDEBUG_DEVICE_DESCRIPTOR;



typedef
NTSTATUS
(*pKdSetupPciDeviceForDebugging)(
    __in     PVOID                     LoaderBlock,   OPTIONAL
    __inout PDEBUG_DEVICE_DESCRIPTOR  PciDevice
);

typedef
NTSTATUS
(*pKdReleasePciDeviceForDebugging)(
    __inout PDEBUG_DEVICE_DESCRIPTOR  PciDevice
);

typedef
PVOID
(*pKdGetAcpiTablePhase0)(
    __in struct _LOADER_PARAMETER_BLOCK *LoaderBlock,
    __in ULONG Signature
    );

typedef
VOID
(*pKdCheckPowerButton)(
    VOID
    );

typedef
VOID
(*pHalEndOfBoot)(
    VOID
    );

typedef
ULONG
(*pHalGetInterruptVector)(
    __in INTERFACE_TYPE InterfaceType,
    __in ULONG BusNumber,
    __in ULONG BusInterruptLevel,
    __in ULONG BusInterruptVector,
    __out PKIRQL Irql,
    __out PKAFFINITY Affinity
    );

typedef
NTSTATUS
(*pHalGetVectorInput)(
    __in ULONG Vector,
    __in KAFFINITY Affinity,
    __out PULONG Input,
    __out PKINTERRUPT_POLARITY Polarity
    );

typedef
PVOID
(*pKdMapPhysicalMemory64)(
    __in PHYSICAL_ADDRESS PhysicalAddress,
    __in ULONG NumberPages,
    __in BOOLEAN FlushCurrentTLB
    );

typedef
VOID
(*pKdUnmapVirtualAddress)(
    __in PVOID VirtualAddress,
    __in ULONG NumberPages,
    __in BOOLEAN FlushCurrentTLB
    );

typedef
ULONG
(*pKdGetPciDataByOffset)(
    __in ULONG BusNumber,
    __in ULONG SlotNumber,
    __out_bcount(Length) PVOID Buffer,
    __in ULONG Offset,
    __in ULONG Length
    );

typedef
ULONG
(*pKdSetPciDataByOffset)(
    __in ULONG BusNumber,
    __in ULONG SlotNumber,
    __in_bcount(Length) PVOID Buffer,
    __in ULONG Offset,
    __in ULONG Length
    );

typedef
NTSTATUS
(*pHalLoadMicrocode)(
    __in PVOID ImageHandle
    );

typedef
NTSTATUS
(*pHalUnloadMicrocode)(
    VOID
    );

typedef
NTSTATUS
(*pHalPostMicrocodeUpdate)(
    VOID
    );

typedef
NTSTATUS
(*pHalAllocateMessageTarget)(
    __in PDEVICE_OBJECT Owner,
    __in KAFFINITY ProcessorSet,
    __in ULONG NumberOfIdtEntries,
    __in KINTERRUPT_MODE Mode,
    __in BOOLEAN ShareVector,
    __out PULONG Vector,
    __out PKIRQL Irql,
    __out PULONG IdtEntry
    );

typedef
VOID
(*pHalFreeMessageTarget)(
    __in PDEVICE_OBJECT Owner,
    __in ULONG Vector,
    __in KAFFINITY ProcessorSet
    );

typedef
PVOID
(*pHalGetAcpiTable)(
    __in ULONG Signature,
    __in_opt PCSTR OemId,
    __in_opt PCSTR OemTableId
    );

#if defined(_IA64_)
typedef
NTSTATUS
(*pHalGetErrorCapList)(
    __inout PULONG CapsListLength,
    __inout_bcount(*CapsListLength) PUCHAR ErrorCapList
    );

typedef
NTSTATUS
(*pHalInjectError)(
    __in ULONG BufferLength,
    __in_bcount(BufferLength) PUCHAR Buffer
    );
#endif

typedef
VOID
(*PCI_ERROR_HANDLER_CALLBACK)(
    VOID
    );

typedef
VOID
(*pHalSetPciErrorHandlerCallback)(
    __in PCI_ERROR_HANDLER_CALLBACK Callback
    );




typedef struct {
    ULONG                           Version;
    pHalQuerySystemInformation      HalQuerySystemInformation;
    pHalSetSystemInformation        HalSetSystemInformation;
    pHalQueryBusSlots               HalQueryBusSlots;
    ULONG                           Spare1;
    pHalExamineMBR                  HalExamineMBR;
    pHalIoAssignDriveLetters        HalIoAssignDriveLetters;
    pHalIoReadPartitionTable        HalIoReadPartitionTable;
    pHalIoSetPartitionInformation   HalIoSetPartitionInformation;
    pHalIoWritePartitionTable       HalIoWritePartitionTable;

    pHalHandlerForBus               HalReferenceHandlerForBus;
    pHalReferenceBusHandler         HalReferenceBusHandler;
    pHalReferenceBusHandler         HalDereferenceBusHandler;

    pHalInitPnpDriver               HalInitPnpDriver;
    pHalInitPowerManagement         HalInitPowerManagement;

    pHalGetDmaAdapter               HalGetDmaAdapter;
    pHalGetInterruptTranslator      HalGetInterruptTranslator;

    pHalStartMirroring              HalStartMirroring;
    pHalEndMirroring                HalEndMirroring;
    pHalMirrorPhysicalMemory        HalMirrorPhysicalMemory;
    pHalEndOfBoot                   HalEndOfBoot;
    pHalMirrorVerify                HalMirrorVerify;

    pHalGetAcpiTable                HalGetCachedAcpiTable;
    pHalSetPciErrorHandlerCallback  HalSetPciErrorHandlerCallback;

#if defined(_IA64_)
    pHalGetErrorCapList             HalGetErrorCapList;
    pHalInjectError                 HalInjectError;
#endif

} HAL_DISPATCH, *PHAL_DISPATCH;



#if defined(_NTDRIVER_) || defined(_NTDDK_) || defined(_NTIFS_) || defined(_NTHAL_)

extern  PHAL_DISPATCH   HalDispatchTable;
#define HALDISPATCH     HalDispatchTable

#else

extern  HAL_DISPATCH    HalDispatchTable;
#define HALDISPATCH     (&HalDispatchTable)

#endif

#define HAL_DISPATCH_VERSION        3

#define HalDispatchTableVersion         HALDISPATCH->Version
#define HalQuerySystemInformation       HALDISPATCH->HalQuerySystemInformation
#define HalSetSystemInformation         HALDISPATCH->HalSetSystemInformation
#define HalQueryBusSlots                HALDISPATCH->HalQueryBusSlots

#define HalReferenceHandlerForBus       HALDISPATCH->HalReferenceHandlerForBus
#define HalReferenceBusHandler          HALDISPATCH->HalReferenceBusHandler
#define HalDereferenceBusHandler        HALDISPATCH->HalDereferenceBusHandler

#define HalInitPnpDriver                HALDISPATCH->HalInitPnpDriver
#define HalInitPowerManagement          HALDISPATCH->HalInitPowerManagement

#define HalGetDmaAdapter                HALDISPATCH->HalGetDmaAdapter
#define HalGetInterruptTranslator       HALDISPATCH->HalGetInterruptTranslator

#define HalStartMirroring               HALDISPATCH->HalStartMirroring
#define HalEndMirroring                 HALDISPATCH->HalEndMirroring
#define HalMirrorPhysicalMemory         HALDISPATCH->HalMirrorPhysicalMemory
#define HalEndOfBoot                    HALDISPATCH->HalEndOfBoot
#define HalMirrorVerify                 HALDISPATCH->HalMirrorVerify

#define HalGetCachedAcpiTable           HALDISPATCH->HalGetCachedAcpiTable
#define HalSetPciErrorHandlerCallback   HALDISPATCH->HalSetPciErrorHandlerCallback

#if defined(_IA64_)
#define HalGetErrorCapList              HALDISPATCH->HalGetErrorCapList
#define HalInjectError                  HALDISPATCH->HalInjectError
#endif


//
// HAL System Information Structures.
//

// for the information class "HalInstalledBusInformation"
typedef struct _HAL_BUS_INFORMATION{
    INTERFACE_TYPE  BusType;
    BUS_DATA_TYPE   ConfigurationType;
    ULONG           BusNumber;
    ULONG           Reserved;
} HAL_BUS_INFORMATION, *PHAL_BUS_INFORMATION;

// for the information class "HalProfileSourceInformation"
typedef struct _HAL_PROFILE_SOURCE_INFORMATION {
    KPROFILE_SOURCE Source;
    BOOLEAN Supported;
    ULONG Interval;
} HAL_PROFILE_SOURCE_INFORMATION, *PHAL_PROFILE_SOURCE_INFORMATION;

// for the information class "HalProfileSourceInformation"
typedef struct _HAL_PROFILE_SOURCE_INFORMATION_EX {
    KPROFILE_SOURCE Source;
    BOOLEAN         Supported;
    ULONG_PTR       Interval;
    ULONG_PTR       DefInterval;
    ULONG_PTR       MaxInterval;
    ULONG_PTR       MinInterval;
} HAL_PROFILE_SOURCE_INFORMATION_EX, *PHAL_PROFILE_SOURCE_INFORMATION_EX;

// for the information class "HalProfileSourceInterval"
typedef struct _HAL_PROFILE_SOURCE_INTERVAL {
    KPROFILE_SOURCE Source;
    ULONG_PTR Interval;
} HAL_PROFILE_SOURCE_INTERVAL, *PHAL_PROFILE_SOURCE_INTERVAL;

// for the information class "HalQueryProfileSourceList"
typedef struct _HAL_PROFILE_SOURCE_LIST {
    KPROFILE_SOURCE Source;
    PWSTR Description;
} HAL_PROFILE_SOURCE_LIST, *PHAL_PROFILE_SOURCE_LIST;

// for the information class "HalDispayBiosInformation"
typedef enum _HAL_DISPLAY_BIOS_INFORMATION {
    HalDisplayInt10Bios,
    HalDisplayEmulatedBios,
    HalDisplayNoBios
} HAL_DISPLAY_BIOS_INFORMATION, *PHAL_DISPLAY_BIOS_INFORMATION;

// for the information class "HalPowerInformation"
typedef struct _HAL_POWER_INFORMATION {
    ULONG   TBD;
} HAL_POWER_INFORMATION, *PHAL_POWER_INFORMATION;

// for the information class "HalProcessorSpeedInformation"
typedef struct _HAL_PROCESSOR_SPEED_INFO {
    ULONG   ProcessorSpeed;
} HAL_PROCESSOR_SPEED_INFORMATION, *PHAL_PROCESSOR_SPEED_INFORMATION;

// for the information class "HalCallbackInformation"
typedef struct _HAL_CALLBACKS {
    PCALLBACK_OBJECT  SetSystemInformation;
    PCALLBACK_OBJECT  BusCheck;
} HAL_CALLBACKS, *PHAL_CALLBACKS;

// for the information class "HalProcessorFeatureInformation"
typedef struct _HAL_PROCESSOR_FEATURE {
    ULONG UsableFeatureBits;
} HAL_PROCESSOR_FEATURE;


typedef
NTSTATUS
(*PHALIOREADWRITEHANDLER)(
    __in      BOOLEAN fRead,
    __in      ULONG dwAddr,
    __in      ULONG dwSize,
    __inout  PULONG pdwData
    );



// for the information class "HalQueryIllegalIOPortAddresses"
typedef struct _HAL_AMLI_BAD_IO_ADDRESS_LIST
{
    ULONG                   BadAddrBegin;
    ULONG                   BadAddrSize;
    ULONG                   OSVersionTrigger;
    PHALIOREADWRITEHANDLER  IOHandler;
} HAL_AMLI_BAD_IO_ADDRESS_LIST, *PHAL_AMLI_BAD_IO_ADDRESS_LIST;




#if defined(_X86_) || defined(_IA64_) || defined(_AMD64_)

//
// HalQueryMcaInterface
//

typedef
VOID
(*PHALMCAINTERFACELOCK)(
    VOID
    );

typedef
VOID
(*PHALMCAINTERFACEUNLOCK)(
    VOID
    );

typedef
NTSTATUS
(*PHALMCAINTERFACEREADREGISTER)(
    __in     UCHAR    BankNumber,
    __inout PVOID    Exception
    );


typedef struct _HAL_MCA_INTERFACE {
    PHALMCAINTERFACELOCK            Lock;
    PHALMCAINTERFACEUNLOCK          Unlock;
    PHALMCAINTERFACEREADREGISTER    ReadRegister;
} HAL_MCA_INTERFACE;

typedef enum {
    ApicDestinationModePhysical = 1,
    ApicDestinationModeLogicalFlat,
    ApicDestinationModeLogicalClustered,
    ApicDestinationModeUnknown
} HAL_APIC_DESTINATION_MODE, *PHAL_APIC_DESTINATION_MODE;


#if defined(_AMD64_)

struct _KTRAP_FRAME;
struct _KEXCEPTION_FRAME;

typedef
ERROR_SEVERITY
(*PDRIVER_EXCPTN_CALLBACK) (
    __in PVOID Context,
    __in struct _KTRAP_FRAME *TrapFrame,
    __in struct _KEXCEPTION_FRAME *ExceptionFrame,
    __in PMCA_EXCEPTION Exception
);

#endif

#if defined(_X86_) || defined(_IA64_)

typedef
#if defined(_IA64_)
ERROR_SEVERITY
#else
VOID
#endif
(*PDRIVER_EXCPTN_CALLBACK) (
    __in PVOID Context,
    __in PMCA_EXCEPTION BankLog
);

#endif

typedef PDRIVER_EXCPTN_CALLBACK  PDRIVER_MCA_EXCEPTION_CALLBACK;


//
// Structure to record the callbacks from driver
//

typedef struct _MCA_DRIVER_INFO {
    PDRIVER_MCA_EXCEPTION_CALLBACK ExceptionCallback;
    PKDEFERRED_ROUTINE             DpcCallback;
    PVOID                          DeviceContext;
} MCA_DRIVER_INFO, *PMCA_DRIVER_INFO;



typedef struct _HAL_ERROR_INFO {
    ULONG     Version;                 // Version of this structure
    ULONG     InitMaxSize;             // Maximum size of the INIT record.
    ULONG     McaMaxSize;              // Maximum size of a Machine Check Abort record
    ULONG     McaPreviousEventsCount;  // Flag indicating previous or early-boot MCA event logs.
    ULONG     McaCorrectedEventsCount; // Number of corrected MCA events since boot.      approx.
    ULONG     McaKernelDeliveryFails;  // Number of Kernel callback failures.             approx.
    ULONG     McaDriverDpcQueueFails;  // Number of OEM MCA Driver Dpc queueing failures. approx.
    ULONG     McaReserved;
    ULONG     CmcMaxSize;              // Maximum size of a Corrected Machine  Check record
    ULONG     CmcPollingInterval;      // In units of seconds
    ULONG     CmcInterruptsCount;      // Number of CMC interrupts.                       approx.
    ULONG     CmcKernelDeliveryFails;  // Number of Kernel callback failures.             approx.
    ULONG     CmcDriverDpcQueueFails;  // Number of OEM CMC Driver Dpc queueing failures. approx.
    ULONG     CmcGetStateFails;        // Number of failures in getting  the log from FW.
    ULONG     CmcClearStateFails;      // Number of failures in clearing the log from FW.
    ULONG     CmcReserved;
    ULONGLONG CmcLogId;                // Last seen record identifier.
    ULONG     CpeMaxSize;              // Maximum size of a Corrected Platform Event record
    ULONG     CpePollingInterval;      // In units of seconds
    ULONG     CpeInterruptsCount;      // Number of CPE interrupts.                       approx.
    ULONG     CpeKernelDeliveryFails;  // Number of Kernel callback failures.             approx.
    ULONG     CpeDriverDpcQueueFails;  // Number of OEM CPE Driver Dpc queueing failures. approx.
    ULONG     CpeGetStateFails;        // Number of failures in getting  the log from FW.
    ULONG     CpeClearStateFails;      // Number of failures in clearing the log from FW.
    ULONG     CpeInterruptSources;     // Number of SAPIC Platform Interrupt Sources
    ULONGLONG CpeLogId;                // Last seen record identifier.
    ULONGLONG KernelReserved[4];
} HAL_ERROR_INFO, *PHAL_ERROR_INFO;



#define HAL_MCE_INTERRUPTS_BASED ((ULONG)-1)
#define HAL_MCE_DISABLED          ((ULONG)0)

//
// Known values for HAL_ERROR_INFO.CmcPollingInterval.
//

#define HAL_CMC_INTERRUPTS_BASED  HAL_MCE_INTERRUPTS_BASED
#define HAL_CMC_DISABLED          HAL_MCE_DISABLED

//
// Known values for HAL_ERROR_INFO.CpePollingInterval.
//

#define HAL_CPE_INTERRUPTS_BASED  HAL_MCE_INTERRUPTS_BASED
#define HAL_CPE_DISABLED          HAL_MCE_DISABLED

#define HAL_MCA_INTERRUPTS_BASED  HAL_MCE_INTERRUPTS_BASED
#define HAL_MCA_DISABLED          HAL_MCE_DISABLED



//
// Driver Callback type for the information class "HalCmcRegisterDriver"
//

typedef
VOID
(*PDRIVER_CMC_EXCEPTION_CALLBACK) (
    __in PVOID            Context,
    __in PCMC_EXCEPTION   CmcLog
);

//
// Driver Callback type for the information class "HalCpeRegisterDriver"
//

typedef
VOID
(*PDRIVER_CPE_EXCEPTION_CALLBACK) (
    __in PVOID            Context,
    __in PCPE_EXCEPTION   CmcLog
);


//
//
// Structure to record the callbacks from driver
//

typedef struct _CMC_DRIVER_INFO {
    PDRIVER_CMC_EXCEPTION_CALLBACK ExceptionCallback;
    PKDEFERRED_ROUTINE             DpcCallback;
    PVOID                          DeviceContext;
} CMC_DRIVER_INFO, *PCMC_DRIVER_INFO;

typedef struct _CPE_DRIVER_INFO {
    PDRIVER_CPE_EXCEPTION_CALLBACK ExceptionCallback;
    PKDEFERRED_ROUTINE             DpcCallback;
    PVOID                          DeviceContext;
} CPE_DRIVER_INFO, *PCPE_DRIVER_INFO;



#endif // defined(_X86_) || defined(_IA64_) || defined(_AMD64_)



#if defined(_IA64_)

typedef
NTSTATUS
(*HALSENDCROSSPARTITIONIPI)(
    __in USHORT ProcessorID,
    __in UCHAR  HardwareVector
    );

typedef
NTSTATUS
(*HALRESERVECROSSPARTITIONINTERRUPTVECTOR)(
    __out PULONG Vector,
    __out PKIRQL Irql,
    __inout PKAFFINITY Affinity,
    __out PUCHAR HardwareVector
    );

typedef
VOID
(*HALFREECROSSPARTITIONINTERRUPTVECTOR)(
    __in ULONG Vector,
    __in KAFFINITY Affinity
    );

typedef struct _HAL_CROSS_PARTITION_IPI_INTERFACE {
    HALSENDCROSSPARTITIONIPI HalSendCrossPartitionIpi;
    HALRESERVECROSSPARTITIONINTERRUPTVECTOR HalReserveCrossPartitionInterruptVector;
    HALFREECROSSPARTITIONINTERRUPTVECTOR HalFreeCrossPartitionInterruptVector;
} HAL_CROSS_PARTITION_IPI_INTERFACE;

#define HAL_CROSS_PARTITION_IPI_INTERFACE_MINIMUM_SIZE \
    FIELD_OFFSET(HAL_CROSS_PARTITION_IPI_INTERFACE,    \
                 HalFreeCrossPartitionInterruptVector)

#endif

typedef struct _HAL_PLATFORM_INFORMATION {
    ULONG PlatformFlags;
} HAL_PLATFORM_INFORMATION, *PHAL_PLATFORM_INFORMATION;



//
// These platform flags are carried over from the IPPT table
// definition if appropriate.
//

#define HAL_PLATFORM_DISABLE_WRITE_COMBINING      0x01L
#define HAL_PLATFORM_DISABLE_PTCG                 0x04L
#define HAL_PLATFORM_DISABLE_UC_MAIN_MEMORY       0x08L
#define HAL_PLATFORM_ENABLE_WRITE_COMBINING_MMIO  0x10L
#define HAL_PLATFORM_ACPI_TABLES_CACHED           0x20L



#if defined(_WIN64)

//
// Use __inline DMA macros (hal.h)
//
#ifndef USE_DMA_MACROS
#define USE_DMA_MACROS
#endif

//
// Only PnP drivers!
//
#ifndef NO_LEGACY_DRIVERS
#define NO_LEGACY_DRIVERS
#endif

#endif // _WIN64

#if defined(USE_DMA_MACROS) && !defined(_NTHAL_) && (defined(_NTDDK_) || defined(_NTDRIVER_)) || defined(_WDM_INCLUDED_)

#else

//
// DMA adapter object functions.
//
#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use AllocateAdapterChannel
NTHALAPI
NTSTATUS
HalAllocateAdapterChannel(
    __in PADAPTER_OBJECT AdapterObject,
    __in PWAIT_CONTEXT_BLOCK Wcb,
    __in ULONG NumberOfMapRegisters,
    __in PDRIVER_CONTROL ExecutionRoutine
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use AllocateCommonBuffer
NTHALAPI
PVOID
HalAllocateCommonBuffer(
    __in PADAPTER_OBJECT AdapterObject,
    __in ULONG Length,
    __out PPHYSICAL_ADDRESS LogicalAddress,
    __in BOOLEAN CacheEnabled
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use FreeCommonBuffer
NTHALAPI
VOID
HalFreeCommonBuffer(
    __in PADAPTER_OBJECT AdapterObject,
    __in ULONG Length,
    __in PHYSICAL_ADDRESS LogicalAddress,
    __in PVOID VirtualAddress,
    __in BOOLEAN CacheEnabled
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use ReadDmaCounter
NTHALAPI
ULONG
HalReadDmaCounter(
    __in PADAPTER_OBJECT AdapterObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use FlushAdapterBuffers
NTHALAPI
BOOLEAN
IoFlushAdapterBuffers(
    __in PADAPTER_OBJECT AdapterObject,
    __in PMDL Mdl,
    __in PVOID MapRegisterBase,
    __in PVOID CurrentVa,
    __in ULONG Length,
    __in BOOLEAN WriteToDevice
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use FreeAdapterChannel
NTHALAPI
VOID
IoFreeAdapterChannel(
    __in PADAPTER_OBJECT AdapterObject
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use FreeMapRegisters
NTHALAPI
VOID
IoFreeMapRegisters(
   __in PADAPTER_OBJECT AdapterObject,
   __in PVOID MapRegisterBase,
   __in ULONG NumberOfMapRegisters
   );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use MapTransfer
NTHALAPI
PHYSICAL_ADDRESS
IoMapTransfer(
    __in PADAPTER_OBJECT AdapterObject,
    __in PMDL Mdl,
    __in PVOID MapRegisterBase,
    __in PVOID CurrentVa,
    __inout PULONG Length,
    __in BOOLEAN WriteToDevice
    );
#endif

#endif // USE_DMA_MACROS && (_NTDDK_ || _NTDRIVER_)



#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK
NTSTATUS
HalGetScatterGatherList (               // Use GetScatterGatherList
    __in PADAPTER_OBJECT DmaAdapter,
    __in PDEVICE_OBJECT DeviceObject,
    __in PMDL Mdl,
    __in PVOID CurrentVa,
    __in ULONG Length,
    __in PDRIVER_LIST_CONTROL ExecutionRoutine,
    __in PVOID Context,
    __in BOOLEAN WriteToDevice
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use PutScatterGatherList
VOID
HalPutScatterGatherList (
    __in PADAPTER_OBJECT DmaAdapter,
    __in PSCATTER_GATHER_LIST ScatterGather,
    __in BOOLEAN WriteToDevice
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
DECLSPEC_DEPRECATED_DDK                 // Use PutDmaAdapter
VOID
HalPutDmaAdapter(
    __in PADAPTER_OBJECT DmaAdapter
    );
#endif

NTHALAPI
VOID
HalBugCheckSystem(
    __in PVOID ErrorRecord
    );


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
PoSetSystemState (
    __in EXECUTION_STATE Flags
    );
#endif



#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PVOID
PoRegisterSystemState (
    __inout_opt PVOID StateHandle,
    __in EXECUTION_STATE Flags
    );
#endif



typedef
VOID
(*PREQUEST_POWER_COMPLETE) (
    __in PDEVICE_OBJECT DeviceObject,
    __in UCHAR MinorFunction,
    __in POWER_STATE PowerState,
    __in_opt PVOID Context,
    __in PIO_STATUS_BLOCK IoStatus
    );

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
PoRequestPowerIrp (
    __in PDEVICE_OBJECT DeviceObject,
    __in UCHAR MinorFunction,
    __in POWER_STATE PowerState,
    __in_opt PREQUEST_POWER_COMPLETE CompletionFunction,
    __in_opt PVOID Context,
    __out_opt PIRP *Irp
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
VOID
PoSetSystemWake (
    __inout PIRP Irp
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
BOOLEAN
PoGetSystemWake (
    __in PIRP Irp
    );
#endif


#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
PoUnregisterSystemState (
    __in PVOID StateHandle
    );
#endif



#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
POWER_STATE
PoSetPowerState (
    __in PDEVICE_OBJECT   DeviceObject,
    __in POWER_STATE_TYPE Type,
    __in POWER_STATE      State
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
NTSTATUS
PoCallDriver (
    __in PDEVICE_OBJECT DeviceObject,
    __inout PIRP        Irp
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
VOID
PoStartNextPowerIrp(
    __in PIRP   Irp
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
PULONG
PoRegisterDeviceForIdleDetection (
    __in PDEVICE_OBJECT     DeviceObject,
    __in ULONG              ConservationIdleTime,
    __in ULONG              PerformanceIdleTime,
    __in DEVICE_POWER_STATE State
    );
#endif

#define PoSetDeviceBusy(IdlePointer) \
    *IdlePointer = 0

#if (NTDDI_VERSION >= NTDDI_WIN6SP1)
NTKERNELAPI
VOID
PoSetDeviceBusyEx (
    __inout PULONG IdlePointer
    );
#endif

typedef NTSTATUS (*PPOWER_SETTING_CALLBACK) (
    IN LPCGUID SettingGuid,
    IN PVOID Value,
    IN ULONG ValueLength,
    IN PVOID Context
);

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
NTSTATUS
PoRegisterPowerSettingCallback (
    __in_opt PDEVICE_OBJECT         DeviceObject,
    __in LPCGUID                    SettingGuid,
    __in PPOWER_SETTING_CALLBACK    Callback,
    __in_opt PVOID                  Context,
    __out_opt PVOID                 * Handle
    );
#endif

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTKERNELAPI
NTSTATUS
PoUnregisterPowerSettingCallback(
    __inout PVOID   Handle
    );
#endif

//
// \Callback\PowerState values
//

#define PO_CB_SYSTEM_POWER_POLICY       0
#define PO_CB_AC_STATUS                 1
#define PO_CB_BUTTON_COLLISION          2
#define PO_CB_SYSTEM_STATE_LOCK         3
#define PO_CB_LID_SWITCH_STATE          4
#define PO_CB_PROCESSOR_POWER_POLICY    5

//
// Determine if there is a complete device failure on an error.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTKERNELAPI
BOOLEAN
FsRtlIsTotalDeviceFailure(
    __in NTSTATUS Status
    );
#endif


//
// AGP Capabilities
//
typedef struct _PCI_AGP_CAPABILITY {

    PCI_CAPABILITIES_HEADER Header;

    USHORT  Minor:4;
    USHORT  Major:4;
    USHORT  Rsvd1:8;

    struct _PCI_AGP_STATUS {
        ULONG   Rate:3;
        ULONG   Agp3Mode:1;
        ULONG   FastWrite:1;
        ULONG   FourGB:1;
        ULONG   HostTransDisable:1;
        ULONG   Gart64:1;
        ULONG   ITA_Coherent:1;
        ULONG   SideBandAddressing:1;                   // SBA
        ULONG   CalibrationCycle:3;
        ULONG   AsyncRequestSize:3;
        ULONG   Rsvd1:1;
        ULONG   Isoch:1;
        ULONG   Rsvd2:6;
        ULONG   RequestQueueDepthMaximum:8;             // RQ
    } AGPStatus;

    struct _PCI_AGP_COMMAND {
        ULONG   Rate:3;
        ULONG   Rsvd1:1;
        ULONG   FastWriteEnable:1;
        ULONG   FourGBEnable:1;
        ULONG   Rsvd2:1;
        ULONG   Gart64:1;
        ULONG   AGPEnable:1;
        ULONG   SBAEnable:1;
        ULONG   CalibrationCycle:3;
        ULONG   AsyncReqSize:3;
        ULONG   Rsvd3:8;
        ULONG   RequestQueueDepth:8;
    } AGPCommand;

} PCI_AGP_CAPABILITY, *PPCI_AGP_CAPABILITY;

//
// An AGPv3 Target must have an extended capability,
// but it's only present for a Master when the Isoch
// bit is set in its status register
//
typedef enum _EXTENDED_AGP_REGISTER {
    IsochStatus,
    AgpControl,
    ApertureSize,
    AperturePageSize,
    GartLow,
    GartHigh,
    IsochCommand
} EXTENDED_AGP_REGISTER, *PEXTENDED_AGP_REGISTER;

typedef struct _PCI_AGP_ISOCH_STATUS {
    ULONG ErrorCode: 2;
    ULONG Rsvd1: 1;
    ULONG Isoch_L: 3;
    ULONG Isoch_Y: 2;
    ULONG Isoch_N: 8;
    ULONG Rsvd2: 16;
} PCI_AGP_ISOCH_STATUS, *PPCI_AGP_ISOCH_STATUS;

typedef struct _PCI_AGP_CONTROL {
    ULONG Rsvd1: 7;
    ULONG GTLB_Enable: 1;
    ULONG AP_Enable: 1;
    ULONG CAL_Disable: 1;
    ULONG Rsvd2: 22;
} PCI_AGP_CONTROL, *PPCI_AGP_CONTROL;

typedef struct _PCI_AGP_APERTURE_PAGE_SIZE {
    USHORT PageSizeMask: 11;
    USHORT Rsvd1: 1;
    USHORT PageSizeSelect: 4;
} PCI_AGP_APERTURE_PAGE_SIZE, *PPCI_AGP_APERTURE_PAGE_SIZE;

typedef struct _PCI_AGP_ISOCH_COMMAND {
    USHORT Rsvd1: 6;
    USHORT Isoch_Y: 2;
    USHORT Isoch_N: 8;
} PCI_AGP_ISOCH_COMMAND, *PPCI_AGP_ISOCH_COMMAND;

typedef struct PCI_AGP_EXTENDED_CAPABILITY {

    PCI_AGP_ISOCH_STATUS IsochStatus;

//
// Target only ----------------<<-begin->>
//
    PCI_AGP_CONTROL AgpControl;
    USHORT ApertureSize;
    PCI_AGP_APERTURE_PAGE_SIZE AperturePageSize;
    ULONG GartLow;
    ULONG GartHigh;
//
// ------------------------------<<-end->>
//

    PCI_AGP_ISOCH_COMMAND IsochCommand;

} PCI_AGP_EXTENDED_CAPABILITY, *PPCI_AGP_EXTENDED_CAPABILITY;


#define PCI_AGP_RATE_1X     0x1
#define PCI_AGP_RATE_2X     0x2
#define PCI_AGP_RATE_4X     0x4


//
// PCI-X Bridge Capability
//

//
// Values for BusModeFrequency in the SecondaryStatus register
//
#define PCIX_MODE_CONVENTIONAL_PCI  0x0
#define PCIX_MODE1_66MHZ            0x1
#define PCIX_MODE1_100MHZ           0x2
#define PCIX_MODE1_133MHZ           0x3
#define PCIX_MODE2_266_66MHZ        0x9
#define PCIX_MODE2_266_100MHZ       0xA
#define PCIX_MODE2_266_133MHZ       0xB
#define PCIX_MODE2_533_66MHZ        0xD
#define PCIX_MODE2_533_100MHZ       0xE
#define PCIX_MODE2_533_133MHZ       0xF

//
// Values for the Version in the SecondaryStatus register
//
#define PCIX_VERSION_MODE1_ONLY     0x0
#define PCIX_VERSION_MODE2_ECC      0x1
#define PCIX_VERSION_DUAL_MODE_ECC  0x2

typedef struct _PCIX_BRIDGE_CAPABILITY {

    PCI_CAPABILITIES_HEADER Header;

    union {
        struct {
            USHORT Bus64Bit:1;
            USHORT Bus133MHzCapable:1;
            USHORT SplitCompletionDiscarded:1;
            USHORT UnexpectedSplitCompletion:1;
            USHORT SplitCompletionOverrun:1;
            USHORT SplitRequestDelayed:1;
            USHORT BusModeFrequency:4;  // PCIX_MODE_x
            USHORT Rsvd:2;
            USHORT Version:2;           // PCIX_VERSION_x
            USHORT Bus266MHzCapable:1;
            USHORT Bus533MHzCapable:1;
        } DUMMYSTRUCTNAME;
        USHORT AsUSHORT;
    } SecondaryStatus;

    union {
        struct {
            ULONG FunctionNumber:3;
            ULONG DeviceNumber:5;
            ULONG BusNumber:8;
            ULONG Device64Bit:1;
            ULONG Device133MHzCapable:1;
            ULONG SplitCompletionDiscarded:1;
            ULONG UnexpectedSplitCompletion:1;
            ULONG SplitCompletionOverrun:1;
            ULONG SplitRequestDelayed:1;
            ULONG Rsvd:7;
            ULONG DIMCapable:1;
            ULONG Device266MHzCapable:1;
            ULONG Device533MHzCapable:1;
        } DUMMYSTRUCTNAME;
        ULONG AsULONG;
    } BridgeStatus;

    USHORT UpstreamSplitTransactionCapacity;
    USHORT UpstreamSplitTransactionLimit;

    USHORT DownstreamSplitTransactionCapacity;
    USHORT DownstreamSplitTransactionLimit;

    union {
        struct {
            ULONG SelectSecondaryRegisters:1;
            ULONG ErrorPresentInOtherBank:1;
            ULONG AdditionalCorrectableError:1;
            ULONG AdditionalUncorrectableError:1;
            ULONG ErrorPhase:3;
            ULONG ErrorCorrected:1;
            ULONG Syndrome:8;
            ULONG ErrorFirstCommand:4;
            ULONG ErrorSecondCommand:4;
            ULONG ErrorUpperAttributes:4;
            ULONG ControlUpdateEnable:1;
            ULONG Rsvd:1;
            ULONG DisableSingleBitCorrection:1;
            ULONG EccMode:1;
        } DUMMYSTRUCTNAME;
        ULONG AsULONG;
    } EccControlStatus;

    ULONG EccFirstAddress;
    ULONG EccSecondAddress;
    ULONG EccAttribute;

} PCIX_BRIDGE_CAPABILITY, *PPCIX_BRIDGE_CAPABILITY;

//
// PCI to PCI Bridge Subsystem ID Capability
//
typedef struct _PCI_SUBSYSTEM_IDS_CAPABILITY {

    PCI_CAPABILITIES_HEADER Header;
    USHORT Reserved;
    USHORT SubVendorID;
    USHORT SubSystemID;

} PCI_SUBSYSTEM_IDS_CAPABILITY, *PPCI_SUBSYSTEM_IDS_CAPABILITY;

//
// _OSC is used by OSPM to query the capabilities of a device and to
// communicate the features supported by the device driver to the platform.
// The _OSC interface for PCI host bridge devices that originate PCI, PCI-X or
// PCI Express hierarchies is identified by a UUID of {33db4d5b-1ff7-401c-9657-
// 7441c03dd766}. A revision ID of 1 indicates that the capabilities buffer is
// composed of 3 DWORDs.
// The first DWORD is common across all OSC implementations and includes status
// and error information.
// The second DWORD (Support Field) provides information regarding OS supported
// features.
// The third DWORD (Control Field) is used to submit request for control of
// associated features. If any bits in the control field are returned cleared,
// then the respective feature is unsupported by the platform and must not be
// enabled.
// According to the PCI Firmware Specification a machine with multiple host
// bridge devices should report the same capabilities for all host bridges
// and also negotiate control of the features in the same way.
//

#define OSC_FIRMWARE_FAILURE                            0x02
#define OSC_UNRECOGNIZED_UUID                           0x04
#define OSC_UNRECOGNIZED_REVISION                       0x08
#define OSC_CAPABILITIES_MASKED                         0x10

#define PCI_ROOT_BUS_OSC_METHOD_CAPABILITY_REVISION     0x01

//
// The following declarations pertain to the second and third DWORD in
// evaluation of _OSC for PCI host bridge devices.
//

typedef struct _PCI_ROOT_BUS_OSC_SUPPORT_FIELD {
    union {
        struct {
            ULONG ExtendedConfigOpRegions:1;
            ULONG ActiveStatePowerManagement:1;
            ULONG ClockPowerManagement:1;
            ULONG SegmentGroups:1;
            ULONG MessageSignaledInterrupts:1;
            ULONG WindowsHardwareErrorArchitecture:1;
            ULONG Reserved:26;
        } DUMMYSTRUCTNAME;
        ULONG AsULONG;
    } u;
} PCI_ROOT_BUS_OSC_SUPPORT_FIELD, *PPCI_ROOT_BUS_OSC_SUPPORT_FIELD;

typedef struct _PCI_ROOT_BUS_OSC_CONTROL_FIELD {
    union {
        struct {
            ULONG ExpressNativeHotPlug:1;
            ULONG ShpcNativeHotPlug:1;
            ULONG ExpressNativePME:1;
            ULONG ExpressAdvancedErrorReporting:1;
            ULONG ExpressCapabilityStructure:1;
            ULONG Reserved:27;
        } DUMMYSTRUCTNAME;
        ULONG AsULONG;
    } u;
} PCI_ROOT_BUS_OSC_CONTROL_FIELD, *PPCI_ROOT_BUS_OSC_CONTROL_FIELD;

//
// An enumerator for the PCI physical and electrical interface.
//

typedef enum _PCI_HARDWARE_INTERFACE {

    PciConventional,
    PciXMode1,
    PciXMode2,
    PciExpress

} PCI_HARDWARE_INTERFACE, *PPCI_HARDWARE_INTERFACE;

typedef enum {

    BusWidth32Bits,
    BusWidth64Bits

} PCI_BUS_WIDTH;

typedef struct _PCI_ROOT_BUS_HARDWARE_CAPABILITY {

    //
    // Describes the secondary side of a PCI root bus.
    //

    PCI_HARDWARE_INTERFACE SecondaryInterface;

    //
    // These additional capabilities are available when each of the following
    // is true.
    // 1. The secondary side of a PCI root bus operates in conventional or
    //    PCI-X mode.
    // 2. The PCI root bus has a hardware ID or compatible ID of PNP0A03.
    // 3. A _DSM function 4 is defined for the root bus.
    //

    struct {

        //
        // This boolean indicates if the remaining fields describing the bus
        // capabilities are valid or not.
        //

        BOOLEAN BusCapabilitiesFound;


        //
        // Provides information on current and supported speeds/modes.
        //

        ULONG CurrentSpeedAndMode;
        ULONG SupportedSpeedsAndModes;

        //
        // Describes the root bus capability on forwarding of Device ID message
        // transactions.
        //

        BOOLEAN DeviceIDMessagingCapable;

        //
        // Provides the width for a PCI interface.
        //

        PCI_BUS_WIDTH SecondaryBusWidth;
    } DUMMYSTRUCTNAME;

    //
    // Fields describing features supported as well as control for them from
    // the bios.
    //

    PCI_ROOT_BUS_OSC_SUPPORT_FIELD OscFeatureSupport;
    PCI_ROOT_BUS_OSC_CONTROL_FIELD OscControlRequest;
    PCI_ROOT_BUS_OSC_CONTROL_FIELD OscControlGranted;

} PCI_ROOT_BUS_HARDWARE_CAPABILITY, *PPCI_ROOT_BUS_HARDWARE_CAPABILITY;

//
// PCI Express Capability
//

typedef union _PCI_EXPRESS_CAPABILITIES_REGISTER {

    struct {

        USHORT CapabilityVersion:4;
        USHORT DeviceType:4;               // PCI_EXPRESS_DEVICE_TYPE
        USHORT SlotImplemented:1;
        USHORT InterruptMessageNumber:5;
        USHORT Rsvd:2;
    } DUMMYSTRUCTNAME;

    USHORT AsUSHORT;

} PCI_EXPRESS_CAPABILITIES_REGISTER, *PPCI_EXPRESS_CAPABILITIES_REGISTER;

typedef union _PCI_EXPRESS_DEVICE_CAPABILITIES_REGISTER {

    struct {

        ULONG MaxPayloadSizeSupported:3;     // EXPRESS_MAX_PAYLOAD_SIZE
        ULONG PhantomFunctionsSupported:2;
        ULONG ExtendedTagSupported:1;
        ULONG L0sAcceptableLatency:3;        // EXPRESS_L0S_LATENCY
        ULONG L1AcceptableLatency:3;         // EXPRESS_L1_LATENCY
        ULONG Undefined:3;
        ULONG RoleBasedErrorReporting:1;
        ULONG Rsvd1:2;
        ULONG CapturedSlotPowerLimit:8;
        ULONG CapturedSlotPowerLimitScale:2;
        ULONG Rsvd2:4;
    } DUMMYSTRUCTNAME;

    ULONG AsULONG;

} PCI_EXPRESS_DEVICE_CAPABILITIES_REGISTER, *PPCI_EXPRESS_DEVICE_CAPABILITIES_REGISTER;

typedef union _PCI_EXPRESS_DEVICE_CONTROL_REGISTER {

    struct {

        USHORT CorrectableErrorEnable:1;
        USHORT NonFatalErrorEnable:1;
        USHORT FatalErrorEnable:1;
        USHORT UnsupportedRequestErrorEnable:1;
        USHORT EnableRelaxedOrder:1;
        USHORT MaxPayloadSize:3;                 // EXPRESS_MAX_PAYLOAD_SIZE
        USHORT ExtendedTagEnable:1;
        USHORT PhantomFunctionsEnable:1;
        USHORT AuxPowerEnable:1;
        USHORT NoSnoopEnable:1;
        USHORT MaxReadRequestSize:3;             // EXPRESS_MAX_PAYLOAD_SIZE
        USHORT BridgeConfigRetryEnable:1;
    } DUMMYSTRUCTNAME;

    USHORT AsUSHORT;

} PCI_EXPRESS_DEVICE_CONTROL_REGISTER, *PPCI_EXPRESS_DEVICE_CONTROL_REGISTER;

typedef union _PCI_EXPRESS_DEVICE_STATUS_REGISTER {

    struct {

        USHORT CorrectableErrorDetected:1;
        USHORT NonFatalErrorDetected:1;
        USHORT FatalErrorDetected:1;
        USHORT UnsupportedRequestDetected:1;
        USHORT AuxPowerDetected:1;
        USHORT TransactionsPending:1;
        USHORT Rsvd:10;
    } DUMMYSTRUCTNAME;

    USHORT AsUSHORT;

} PCI_EXPRESS_DEVICE_STATUS_REGISTER, *PPCI_EXPRESS_DEVICE_STATUS_REGISTER;

typedef union _PCI_EXPRESS_LINK_CAPABILITIES_REGISTER {

    struct {

        ULONG MaximumLinkSpeed:4;
        ULONG MaximumLinkWidth:6;
        ULONG ActiveStatePMSupport:2;   // EXPRESS_ASPM_CONFIG
        ULONG L0sExitLatency:3;         // EXPRESS_L0S_LATENCY
        ULONG L1ExitLatency:3;          // EXPRESS_L1_LATENCY
        ULONG ClockPowerManagement:1;
        ULONG SurpriseDownErrorReportingCapable:1;
        ULONG DataLinkLayerActiveReportingCapable:1;
        ULONG Rsvd:3;
        ULONG PortNumber:8;
    } DUMMYSTRUCTNAME;

    ULONG AsULONG;

} PCI_EXPRESS_LINK_CAPABILITIES_REGISTER, *PPCI_EXPRESS_LINK_CAPABILITIES_REGISTER;

typedef union _PCI_EXPRESS_LINK_CONTROL_REGISTER {

    struct {

        USHORT ActiveStatePMControl:2;    // EXPRESS_ASPM_CONFIG
        USHORT Rsvd1:1;
        USHORT ReadCompletionBoundary:1;  // EXPRESS_RCB
        USHORT LinkDisable:1;
        USHORT RetrainLink:1;
        USHORT CommonClockConfig:1;
        USHORT ExtendedSynch:1;
        USHORT EnableClockPowerManagement:1;
        USHORT Rsvd2:7;
    } DUMMYSTRUCTNAME;

    USHORT AsUSHORT;

} PCI_EXPRESS_LINK_CONTROL_REGISTER, *PPCI_EXPRESS_LINK_CONTROL_REGISTER;

typedef union _PCI_EXPRESS_LINK_STATUS_REGISTER {

    struct {

        USHORT LinkSpeed:4;
        USHORT LinkWidth:6;
        USHORT Undefined:1;
        USHORT LinkTraining:1;
        USHORT SlotClockConfig:1;
        USHORT DataLinkLayerActive:1;
        USHORT Rsvd:2;
    } DUMMYSTRUCTNAME;

    USHORT AsUSHORT;

} PCI_EXPRESS_LINK_STATUS_REGISTER, *PPCI_EXPRESS_LINK_STATUS_REGISTER;

typedef union _PCI_EXPRESS_SLOT_CAPABILITIES_REGISTER {

    struct {

        ULONG AttentionButtonPresent:1;
        ULONG PowerControllerPresent:1;
        ULONG MRLSensorPresent:1;
        ULONG AttentionIndicatorPresent:1;
        ULONG PowerIndicatorPresent:1;
        ULONG HotPlugSurprise:1;
        ULONG HotPlugCapable:1;
        ULONG SlotPowerLimit:8;
        ULONG SlotPowerLimitScale:2;
        ULONG ElectromechanicalLockPresent:1;
        ULONG NoCommandCompletedSupport:1;
        ULONG PhysicalSlotNumber:13;
    } DUMMYSTRUCTNAME;

    ULONG AsULONG;

} PCI_EXPRESS_SLOT_CAPABILITIES_REGISTER, *PPCI_EXPRESS_SLOT_CAPABILITIES_REGISTER;

typedef union _PCI_EXPRESS_SLOT_CONTROL_REGISTER {

    struct {

        USHORT AttentionButtonEnable:1;
        USHORT PowerFaultDetectEnable:1;
        USHORT MRLSensorEnable:1;
        USHORT PresenceDetectEnable:1;
        USHORT CommandCompletedEnable:1;
        USHORT HotPlugInterruptEnable:1;
        USHORT AttentionIndicatorControl:2;  // EXPRESS_INDICATOR_STATE
        USHORT PowerIndicatorControl:2;      // EXPRESS_INDICATOR_STATE
        USHORT PowerControllerControl:1;     // EXPRESS_POWER_STATE
        USHORT ElectromechanicalLockControl:1;
        USHORT DataLinkStateChangeEnable:1;
        USHORT Rsvd:3;
    } DUMMYSTRUCTNAME;

    USHORT AsUSHORT;

} PCI_EXPRESS_SLOT_CONTROL_REGISTER, *PPCI_EXPRESS_SLOT_CONTROL_REGISTER;

typedef union _PCI_EXPRESS_SLOT_STATUS_REGISTER {

    struct {

        USHORT AttentionButtonPressed:1;
        USHORT PowerFaultDetected:1;
        USHORT MRLSensorChanged:1;
        USHORT PresenceDetectChanged:1;
        USHORT CommandCompleted:1;
        USHORT MRLSensorState:1;        // EXPRESS_MRL_STATE
        USHORT PresenceDetectState:1;   // EXPRESS_CARD_PRESENCE
        USHORT ElectromechanicalLockEngaged:1;
        USHORT DataLinkStateChanged:1;
        USHORT Rsvd:7;
    } DUMMYSTRUCTNAME;

    USHORT AsUSHORT;

} PCI_EXPRESS_SLOT_STATUS_REGISTER, *PPCI_EXPRESS_SLOT_STATUS_REGISTER;

typedef union _PCI_EXPRESS_ROOT_CONTROL_REGISTER {

    struct {

        USHORT CorrectableSerrEnable:1;
        USHORT NonFatalSerrEnable:1;
        USHORT FatalSerrEnable:1;
        USHORT PMEInterruptEnable:1;
        USHORT CRSSoftwareVisibilityEnable:1;
        USHORT Rsvd:11;
    } DUMMYSTRUCTNAME;

    USHORT AsUSHORT;

} PCI_EXPRESS_ROOT_CONTROL_REGISTER, *PPCI_EXPRESS_ROOT_CONTROL_REGISTER;

typedef union _PCI_EXPRESS_ROOT_CAPABILITIES_REGISTER {

    struct {

        USHORT CRSSoftwareVisibility:1;
        USHORT Rsvd:15;
    } DUMMYSTRUCTNAME;

    USHORT AsUSHORT;

} PCI_EXPRESS_ROOT_CAPABILITIES_REGISTER, *PPCI_EXPRESS_ROOT_CAPABILITIES_REGISTER;

typedef union _PCI_EXPRESS_ROOT_STATUS_REGISTER {

    struct {

        ULONG PMERequestorId:16;  // PCI_EXPRESS_REQUESTOR_ID
        ULONG PMEStatus:1;
        ULONG PMEPending:1;
        ULONG Rsvd:14;
    } DUMMYSTRUCTNAME;

    ULONG AsULONG;

} PCI_EXPRESS_ROOT_STATUS_REGISTER, *PPCI_EXPRESS_ROOT_STATUS_REGISTER;

//
// PCI Express Capability
//

typedef struct _PCI_EXPRESS_CAPABILITY {

    PCI_CAPABILITIES_HEADER Header;
    PCI_EXPRESS_CAPABILITIES_REGISTER ExpressCapabilities;

    PCI_EXPRESS_DEVICE_CAPABILITIES_REGISTER DeviceCapabilities;

    PCI_EXPRESS_DEVICE_CONTROL_REGISTER DeviceControl;
    PCI_EXPRESS_DEVICE_STATUS_REGISTER DeviceStatus;

    PCI_EXPRESS_LINK_CAPABILITIES_REGISTER LinkCapabilities;

    PCI_EXPRESS_LINK_CONTROL_REGISTER LinkControl;
    PCI_EXPRESS_LINK_STATUS_REGISTER LinkStatus;

    PCI_EXPRESS_SLOT_CAPABILITIES_REGISTER SlotCapabilities;

    PCI_EXPRESS_SLOT_CONTROL_REGISTER SlotControl;
    PCI_EXPRESS_SLOT_STATUS_REGISTER SlotStatus;

    PCI_EXPRESS_ROOT_CONTROL_REGISTER RootControl;
    PCI_EXPRESS_ROOT_CAPABILITIES_REGISTER RootCapabilities;

    PCI_EXPRESS_ROOT_STATUS_REGISTER RootStatus;

} PCI_EXPRESS_CAPABILITY, *PPCI_EXPRESS_CAPABILITY;

typedef enum {

    MRLClosed = 0,
    MRLOpen

} PCI_EXPRESS_MRL_STATE;

typedef enum {

    SlotEmpty = 0,
    CardPresent

} PCI_EXPRESS_CARD_PRESENCE;

typedef enum {

    IndicatorOn = 1,
    IndicatorBlink,
    IndicatorOff

} PCI_EXPRESS_INDICATOR_STATE;

typedef enum {

    PowerOn = 0,
    PowerOff

} PCI_EXPRESS_POWER_STATE;

typedef enum {

    L0sEntrySupport = 1,
    L0sAndL1EntrySupport = 3

} PCI_EXPRESS_ASPM_SUPPORT;

typedef enum {

    L0sAndL1EntryDisabled,
    L0sEntryEnabled,
    L1EntryEnabled,
    L0sAndL1EntryEnabled

} PCI_EXPRESS_ASPM_CONTROL;

typedef enum {

    L0s_Below64ns = 0,
    L0s_64ns_128ns,
    L0s_128ns_256ns,
    L0s_256ns_512ns,
    L0s_512ns_1us,
    L0s_1us_2us,
    L0s_2us_4us,
    L0s_Above4us

} PCI_EXPRESS_L0s_EXIT_LATENCY;

typedef enum {

    L1_Below1us = 0,
    L1_1us_2us,
    L1_2us_4us,
    L1_4us_8us,
    L1_8us_16us,
    L1_16us_32us,
    L1_32us_64us,
    L1_Above64us

} PCI_EXPRESS_L1_EXIT_LATENCY;

typedef enum {

    PciExpressEndpoint = 0,
    PciExpressLegacyEndpoint,
    PciExpressRootPort = 4,
    PciExpressUpstreamSwitchPort,
    PciExpressDownstreamSwitchPort,
    PciExpressToPciXBridge,
    PciXToExpressBridge,
    PciExpressRootComplexIntegratedEndpoint,
    PciExpressRootComplexEventCollector

} PCI_EXPRESS_DEVICE_TYPE;

typedef enum {

    MaxPayload128Bytes = 0,
    MaxPayload256Bytes,
    MaxPayload512Bytes,
    MaxPayload1024Bytes,
    MaxPayload2048Bytes,
    MaxPayload4096Bytes

} PCI_EXPRESS_MAX_PAYLOAD_SIZE;

typedef union _PCI_EXPRESS_PME_REQUESTOR_ID {

    struct {

        USHORT FunctionNumber:3;
        USHORT DeviceNumber:5;
        USHORT BusNumber:8;
    } DUMMYSTRUCTNAME;

    USHORT AsUSHORT;

} PCI_EXPRESS_PME_REQUESTOR_ID, *PPCI_EXPRESS_PME_REQUESTOR_ID;


//
// Portable portion of HAL & HAL bus extender definitions for BUSHANDLER
// BusData for installed PCI buses.
//

typedef VOID
(*PciPin2Line) (
    IN struct _BUS_HANDLER  *BusHandler,
    IN struct _BUS_HANDLER  *RootHandler,
    IN PCI_SLOT_NUMBER      SlotNumber,
    IN PPCI_COMMON_CONFIG   PciData
    );

typedef VOID
(*PciLine2Pin) (
    IN struct _BUS_HANDLER  *BusHandler,
    IN struct _BUS_HANDLER  *RootHandler,
    IN PCI_SLOT_NUMBER      SlotNumber,
    IN PPCI_COMMON_CONFIG   PciNewData,
    IN PPCI_COMMON_CONFIG   PciOldData
    );

typedef VOID
(*PciReadWriteConfig) (
    IN struct _BUS_HANDLER *BusHandler,
    IN PCI_SLOT_NUMBER Slot,
    IN PVOID Buffer,
    IN ULONG Offset,
    IN ULONG Length
    );

#define PCI_DATA_TAG            ' ICP'
#define PCI_DATA_VERSION        1

typedef struct _PCIBUSDATA {
    ULONG                   Tag;
    ULONG                   Version;
    PciReadWriteConfig      ReadConfig;
    PciReadWriteConfig      WriteConfig;
    PciPin2Line             Pin2Line;
    PciLine2Pin             Line2Pin;
    PCI_SLOT_NUMBER         ParentSlot;
    PVOID                   Reserved[4];
} PCIBUSDATA, *PPCIBUSDATA;


#ifndef _PCIINTRF_X_
#define _PCIINTRF_X_

//
// PCI Bus interface
//

typedef ULONG (*PCI_READ_WRITE_CONFIG)(
    IN PVOID Context,
    IN ULONG BusOffset,
    IN ULONG Slot,
    IN PVOID Buffer,
    IN ULONG Offset,
    IN ULONG Length
    );

typedef VOID (*PCI_PIN_TO_LINE)(
    IN PVOID Context,
    IN PPCI_COMMON_CONFIG PciData
    );

typedef VOID (*PCI_LINE_TO_PIN)(
    IN PVOID Context,
    IN PPCI_COMMON_CONFIG PciNewData,
    IN PPCI_COMMON_CONFIG PciOldData
    );

typedef VOID (*PCI_ROOT_BUS_CAPABILITY) (
    __in PVOID Context,
    __out PPCI_ROOT_BUS_HARDWARE_CAPABILITY HardwareCapability
    );

typedef VOID (*PCI_EXPRESS_WAKE_CONTROL) (
    __in PVOID Context,
    __in BOOLEAN EnableWake
    );

typedef struct _PCI_BUS_INTERFACE_STANDARD {
    //
    // generic interface header
    //
    USHORT Size;
    USHORT Version;
    PVOID Context;
    PINTERFACE_REFERENCE InterfaceReference;
    PINTERFACE_DEREFERENCE InterfaceDereference;
    //
    // standard PCI bus interfaces
    //
    PCI_READ_WRITE_CONFIG ReadConfig;
    PCI_READ_WRITE_CONFIG WriteConfig;
    PCI_PIN_TO_LINE PinToLine;
    PCI_LINE_TO_PIN LineToPin;
    PCI_ROOT_BUS_CAPABILITY RootBusCapability;
    PCI_EXPRESS_WAKE_CONTROL ExpressWakeControl;

} PCI_BUS_INTERFACE_STANDARD, *PPCI_BUS_INTERFACE_STANDARD;

#define PCI_BUS_INTERFACE_STANDARD_VERSION 1


#endif

//
// Define exported ZwXxx routines to device drivers.
//

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
NTSTATUS
NTAPI
ZwSetInformationThread (
    __in HANDLE ThreadHandle,
    __in THREADINFOCLASS ThreadInformationClass,
    __in_bcount(ThreadInformationLength) PVOID ThreadInformation,
    __in ULONG ThreadInformationLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSTATUS
ZwCreateTimer (
    __out PHANDLE TimerHandle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in TIMER_TYPE TimerType
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSTATUS
ZwOpenTimer (
    __out PHANDLE TimerHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSTATUS
ZwCancelTimer (
    __in HANDLE TimerHandle,
    __out_opt PBOOLEAN CurrentState
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSTATUS
ZwSetTimer (
    __in HANDLE TimerHandle,
    __in PLARGE_INTEGER DueTime,
    __in_opt PTIMER_APC_ROUTINE TimerApcRoutine,
    __in_opt PVOID TimerContext,
    __in BOOLEAN ResumeTimer,
    __in_opt LONG Period,
    __out_opt PBOOLEAN PreviousState
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryVolumeInformationFile(
    __in HANDLE FileHandle,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __out_bcount(Length) PVOID FsInformation,
    __in ULONG Length,
    __in FS_INFORMATION_CLASS FsInformationClass
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
NTSTATUS
NTAPI
ZwDeviceIoControlFile(
    __in HANDLE FileHandle,
    __in_opt HANDLE Event,
    __in_opt PIO_APC_ROUTINE ApcRoutine,
    __in_opt PVOID ApcContext,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in ULONG IoControlCode,
    __in_bcount_opt(InputBufferLength) PVOID InputBuffer,
    __in ULONG InputBufferLength,
    __out_bcount_opt(OutputBufferLength) PVOID OutputBuffer,
    __in ULONG OutputBufferLength
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
NTSTATUS
NTAPI
ZwDisplayString(
    __in PUNICODE_STRING String
    );
#endif

#if (NTDDI_VERSION >= NTDDI_WIN2K)
NTSYSAPI
NTSTATUS
NTAPI
ZwPowerInformation(
    __in POWER_INFORMATION_LEVEL InformationLevel,
    __in_bcount_opt(InputBufferLength) PVOID InputBuffer,
    __in ULONG InputBufferLength,
    __out_bcount_opt(OutputBufferLength) PVOID OutputBuffer,
    __in ULONG OutputBufferLength
    );
#endif


NTSYSAPI
NTSTATUS
NTAPI
ZwAllocateLocallyUniqueId(
    __out PLUID Luid
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwTerminateProcess (
    __in_opt HANDLE ProcessHandle,
    __in NTSTATUS ExitStatus
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenProcess (
    __out PHANDLE ProcessHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PCLIENT_ID ClientId
    );


//
// Windows Error Record Creator GUID.
//

DEFINE_GUID( WHEA_RECORD_CREATOR_GUID,
    0xcf07c4bd,0xb789,0x4e18,0xb3,0xc4,0x1f,0x73,0x2c,0xb5,0x71,0x31 );

//
// Error notification type GUIDs.
//

DEFINE_GUID( CMC_NOTIFY_TYPE_GUID,
    0x2dce8bb1,0xbdd7,0x450e,0xb9,0xad,0x9c,0xf4,0xeb,0xd4,0xf8,0x90 );
DEFINE_GUID( CPE_NOTIFY_TYPE_GUID,
    0x4e292f96,0xd843,0x4a55,0xa8,0xc2,0xd4,0x81,0xf2,0x7e,0xbe,0xee );
DEFINE_GUID( MCE_NOTIFY_TYPE_GUID,
    0xe8f56ffe,0x919c,0x4cc5,0xba,0x88,0x65,0xab,0xe1,0x49,0x13,0xbb );
DEFINE_GUID( PCIe_NOTIFY_TYPE_GUID,
    0xcf93c01f,0x1a16,0x4dfc,0xb8,0xbc,0x9c,0x4d,0xaf,0x67,0xc1,0x04 );
DEFINE_GUID( INIT_NOTIFY_TYPE_GUID,
    0xcc5263e8,0x9308,0x454a,0x89,0xd0,0x34,0x0b,0xd3,0x9b,0xc9,0x8e );
DEFINE_GUID( NMI_NOTIFY_TYPE_GUID,
    0x5bad89ff,0xb7e6,0x42c9,0x81,0x4a,0xcf,0x24,0x85,0xd6,0xe9,0x8a );
DEFINE_GUID( BOOT_NOTIFY_TYPE_GUID,
    0x3d61a466,0xab40,0x409a,0xa6,0x98,0xf3,0x62,0xd4,0x64,0xb3,0x8f );
DEFINE_GUID( GENERIC_NOTIFY_TYPE_GUID,
    0x3e62a467,0xab40,0x409a,0xa6,0x98,0xf3,0x62,0xd4,0x64,0xb3,0x8f );

//
// Error Section type GUIDs.
//

DEFINE_GUID( PROCESSOR_GENERIC_SECTION_GUID,
    0x9876ccad,0x47b4,0x4bdb,0xb6,0x5e,0x16,0xf1,0x93,0xc4,0xf3,0xdb );
DEFINE_GUID( X86_PROCESSOR_SPECIFIC_SECTION_GUID,
    0xdc3ea0b0,0xa144,0x4797,0xb9,0x5b,0x53,0xfa,0x24,0x2b,0x6e,0x1d );
DEFINE_GUID( IPF_PROCESSOR_SPECIFIC_SECTION_GUID,
    0xe429faf1,0x3cb7,0x11d4,0xbc,0xa7,0x00,0x80,0xc7,0x3c,0x88,0x81 );
DEFINE_GUID( X64_PROCESSOR_SPECIFIC_SECTION_GUID,
    0x390f56d5,0xca86,0x4649,0x95,0xc4,0x73,0xa4,0x08,0xae,0x58,0x34 );
DEFINE_GUID( PLATFORM_MEMORY_SECTION_GUID,
    0xa5bc1114,0x6f64,0x4ede,0xb8,0x63,0x3e,0x83,0xed,0x7c,0x83,0xb1 );
DEFINE_GUID( PCIEXPRESS_SECTION_GUID,
    0xd995e954,0xbbc1,0x430f,0xad,0x91,0xb4,0x4d,0xcb,0x3c,0x6f,0x35 );
DEFINE_GUID( PCIX_BUS_SECTION_GUID,
    0xc5753963,0x3b84,0x4095,0xbf,0x78,0xed,0xda,0xd3,0xf9,0xc9,0xdd );
DEFINE_GUID( PCIX_COMPONENT_SECTION_GUID,
    0xeb5e4685,0xca66,0x4769,0xb6,0xa2,0x26,0x06,0x8b,0x00,0x13,0x26 );
DEFINE_GUID( NMI_SECTION_GUID,
    0xe71254e7,0xc1b9,0x4940,0xab,0x76,0x90,0x97,0x03,0xa4,0x32,0x0f );
DEFINE_GUID( GENERIC_SECTION_GUID,
    0xe71254e8,0xc1b9,0x4940,0xab,0x76,0x90,0x97,0x03,0xa4,0x32,0x0f );
DEFINE_GUID( WHEA_PACKET_SECTION_GUID,
    0xe71254e9,0xc1b9,0x4940,0xab,0x76,0x90,0x97,0x03,0xa4,0x32,0x0f );
DEFINE_GUID( PLATFORM_CACHE_SECTION_GUID,
    0x59a0a229,0x9399,0x4140,0x85,0xb3,0x06,0xd4,0x8a,0x9e,0x00,0x60 );
DEFINE_GUID( IPF_SAL_RECORD_REFERENCE_SECTION_GUID,
    0x81212A96,0x09ED,0x4996,0x94,0x71,0x8D,0x72,0x9C,0x8E,0x69,0xED );

//
// Processor error check section GUIDs.
//

DEFINE_GUID( WHEA_CACHECHECK_GUID,
    0xA55701F5,0xE3EF,0x43de,0xAC,0x72,0x24,0x9B,0x57,0x3F,0xAD,0x2C );
DEFINE_GUID( WHEA_TLBCHECK_GUID,
    0xFC06B535,0x5E1F,0x4562,0x9F,0x25,0x0A,0x3B,0x9A,0xDB,0x63,0xC3 );
DEFINE_GUID( WHEA_BUSCHECK_GUID,
    0x1CF3F8B3,0xC5B1,0x49A2,0xAA,0x59,0x5E,0xEF,0x92,0xFF,0xA6,0x3C );
DEFINE_GUID( WHEA_MSCHECK_GUID,
    0x48AB7F57,0xDC34,0x4F6C,0xA7,0xD3,0xB0,0xB5,0xB0,0xA7,0x43,0x14 );

#define WHEA_PHYSICAL_ADDRESS LARGE_INTEGER

//;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
//
// The following definitions and structures are used to describe platform-
// implemented hardware error sources to the OS.
//
//;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

//
//
// This enumeration defines the various types of error sources a platform can
// expose to the OS.
//

typedef enum _WHEA_ERROR_SOURCE_TYPE {
    WheaErrSrcTypeMCE       = 0x00,   // Machine Check Exception
    WheaErrSrcTypeCMC       = 0x01,   // Corrected Machine Check
    WheaErrSrcTypeCPE       = 0x02,   // Corrected Platform Error
    WheaErrSrcTypeNMI       = 0x03,   // Non-Maskable Interrupt
    WheaErrSrcTypePCIe      = 0x04,   // PCI Express Error
    WheaErrSrcTypeGeneric   = 0x05,   // Other types of error sources
    WheaErrSrcTypeINIT      = 0x06,   // IA64 INIT Error Source
    WheaErrSrcTypeBOOT      = 0x07,   // BOOT Error Source
    WheaErrSrcTypeSCIGeneric= 0x08,   // SCI-based generic error source
    WheaErrSrcTypeIPFMCA    = 0x09,   // IPF MCA
    WheaErrSrcTypeIPFCMC    = 0x0a,   // IPF CMC
    WheaErrSrcTypeIPFCPE    = 0x0b,   // IPF CPE
    WheaErrSrcTypeMax       = 0x0c
} WHEA_ERROR_SOURCE_TYPE, *PWHEA_ERROR_SOURCE_TYPE;

//
// The information encoded within an error source's status registers is
// encoded in one of the following standardized formats.
//

typedef enum _WHEA_RAW_DATA_FORMAT {
    WheaRawDataFormatIPFSalRecord = 0x00,
    WheaRawDataFormatIA32MCA,
    WheaRawDataFormatIntel64MCA,
    WheaRawDataFormatAMD64MCA,
    WheaRawDataFormatMemory,
    WheaRawDataFormatPCIExpress,
    WheaRawDataFormatNMIPort,
    WheaRawDataFormatPCIXBus,
    WheaRawDataFormatPCIXDevice,
    WheaRawDataFormatGeneric,
    WheaRawDataFormatMax
} WHEA_RAW_DATA_FORMAT, *PWHEA_RAW_DATA_FORMAT;

//
// Error sources have a runtime state associated with them. The following are
// the valid states for an error source.
//

typedef enum _WHEA_ERROR_SOURCE_STATE {
    WheaErrSrcStateStopped = 0x01,
    WheaErrSrcStateStarted = 0x02
} WHEA_ERROR_SOURCE_STATE, *PWHEA_ERROR_SOURCE_STATE;

#define WHEA_ERROR_SOURCE_DESCRIPTOR_VERSION_10          10

#define WHEA_MAX_MC_BANKS                                32

#define WHEA_ERROR_SOURCE_FLAG_FIRMWAREFIRST             0x00000001
#define WHEA_ERROR_SOURCE_FLAG_GLOBAL                    0x00000002
#define WHEA_ERROR_SOURCE_FLAG_DEFAULTSOURCE             0x80000000

#define WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_XPFMCE         0
#define WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_XPFCMC         1
#define WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_XPFNMI         2
#define WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_IPFMCA         3
#define WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_IPFCMC         4
#define WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_IPFCPE         5
#define WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_AERROOTPORT    6
#define WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_AERENDPOINT    7
#define WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_AERBRIDGE      8
#define WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_GENERIC        9

#define WHEA_XPF_MC_BANK_STATUSFORMAT_IA32MCA            0
#define WHEA_XPF_MC_BANK_STATUSFORMAT_Intel64MCA         1
#define WHEA_XPF_MC_BANK_STATUSFORMAT_AMD64MCA           2

#define WHEA_NOTIFICATION_TYPE_POLLED                    0
#define WHEA_NOTIFICATION_TYPE_EXTERNALINTERRUPT         1
#define WHEA_NOTIFICATION_TYPE_LOCALINTERRUPT            2
#define WHEA_NOTIFICATION_TYPE_SCI                       3
#define WHEA_NOTIFICATION_TYPE_NMI                       4

#include <pshpack1.h>

typedef union _WHEA_NOTIFICATION_FLAGS {
    struct {
        USHORT PollIntervalRW:1;
        USHORT SwitchToPollingThresholdRW:1;
        USHORT SwitchToPollingWindowRW:1;
        USHORT ErrorThresholdRW:1;
        USHORT ErrorThresholdWindowRW:1;
        USHORT Reserved:11;
    } DUMMYSTRUCTNAME;
    USHORT AsUSHORT;
} WHEA_NOTIFICATION_FLAGS, *PWHEA_NOTIFICATION_FLAGS;

typedef union _XPF_MC_BANK_FLAGS {
    struct {
        UCHAR ClearOnInitializationRW:1;
        UCHAR ControlDataRW:1;
        UCHAR Reserved:6;
    } DUMMYSTRUCTNAME;
    UCHAR AsUCHAR;
} XPF_MC_BANK_FLAGS, *PXPF_MC_BANK_FLAGS;

typedef union _XPF_MCE_FLAGS {
    struct {
        ULONG MCG_CapabilityRW:1;
        ULONG MCG_GlobalControlRW:1;
        ULONG Reserved:30;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} XPF_MCE_FLAGS, *PXPF_MCE_FLAGS;

typedef union _AER_ROOTPORT_DESCRIPTOR_FLAGS {
    struct {
        USHORT UncorrectableErrorMaskRW:1;
        USHORT UncorrectableErrorSeverityRW:1;
        USHORT CorrectableErrorMaskRW:1;
        USHORT AdvancedCapsAndControlRW:1;
        USHORT RootErrorCommandRW:1;
        USHORT Reserved:11;
    } DUMMYSTRUCTNAME;
    USHORT AsUSHORT;
} AER_ROOTPORT_DESCRIPTOR_FLAGS, *PAER_ROOTPORT_DESCRIPTOR_FLAGS;

typedef union _AER_ENDPOINT_DESCRIPTOR_FLAGS {
    struct {
        USHORT UncorrectableErrorMaskRW:1;
        USHORT UncorrectableErrorSeverityRW:1;
        USHORT CorrectableErrorMaskRW:1;
        USHORT AdvancedCapsAndControlRW:1;
        USHORT Reserved:12;
    } DUMMYSTRUCTNAME;
    USHORT AsUSHORT;
} AER_ENDPOINT_DESCRIPTOR_FLAGS, *PAER_ENDPOINT_DESCRIPTOR_FLAGS;

typedef union _AER_BRIDGE_DESCRIPTOR_FLAGS {
    struct {
        USHORT UncorrectableErrorMaskRW:1;
        USHORT UncorrectableErrorSeverityRW:1;
        USHORT CorrectableErrorMaskRW:1;
        USHORT AdvancedCapsAndControlRW:1;
        USHORT SecondaryUncorrectableErrorMaskRW:1;
        USHORT SecondaryUncorrectableErrorSevRW:1;
        USHORT SecondaryCapsAndControlRW:1;
        USHORT Reserved:9;
    } DUMMYSTRUCTNAME;
    USHORT AsUSHORT;
} AER_BRIDGE_DESCRIPTOR_FLAGS, *PAER_BRIDGE_DESCRIPTOR_FLAGS;

//
// The following structure is used to describe how a given error source reports
// errors to the OS.
//

typedef struct _WHEA_NOTIFICATION_DESCRIPTOR {
    UCHAR Type;
    UCHAR Length;
    WHEA_NOTIFICATION_FLAGS Flags;

    union {
        struct {
            ULONG PollInterval;
        } Polled;

        struct {
            ULONG PollInterval;
            ULONG Vector;
            ULONG SwitchToPollingThreshold;
            ULONG SwitchToPollingWindow;
            ULONG ErrorThreshold;
            ULONG ErrorThresholdWindow;
        } Interrupt;

        struct {
            ULONG PollInterval;
            ULONG Vector;
            ULONG SwitchToPollingThreshold;
            ULONG SwitchToPollingWindow;
            ULONG ErrorThreshold;
            ULONG ErrorThresholdWindow;
        } LocalInterrupt;

        struct {
            ULONG PollInterval;
            ULONG Vector;
            ULONG SwitchToPollingThreshold;
            ULONG SwitchToPollingWindow;
            ULONG ErrorThreshold;
            ULONG ErrorThresholdWindow;
        } Sci;

        struct {
            ULONG PollInterval;
            ULONG Vector;
            ULONG SwitchToPollingThreshold;
            ULONG SwitchToPollingWindow;
            ULONG ErrorThreshold;
            ULONG ErrorThresholdWindow;
        } Nmi;
    } u;
} WHEA_NOTIFICATION_DESCRIPTOR, *PWHEA_NOTIFICATION_DESCRIPTOR;

//
// The following structure describes an XPF machine check bank. It identifies
// the bank with a BankNumber and it contains information that is used to
// configure the bank. MCE and CMC error sources make use of this descriptor
// to describe and configure each bank.
//

typedef struct _WHEA_XPF_MC_BANK_DESCRIPTOR {
    UCHAR BankNumber;
    BOOLEAN ClearOnInitialization;
    UCHAR StatusDataFormat;
    XPF_MC_BANK_FLAGS Flags;
    ULONG ControlMsr;
    ULONG StatusMsr;
    ULONG AddressMsr;
    ULONG MiscMsr;
    ULONGLONG ControlData;
} WHEA_XPF_MC_BANK_DESCRIPTOR, *PWHEA_XPF_MC_BANK_DESCRIPTOR;

//
// The following structure describes an XPF platform's machine check exception
// error source mechanism. The information represented in this structure tells
// the OS how to configure the platform's MCE error source.
//

typedef struct _WHEA_XPF_MCE_DESCRIPTOR {
    USHORT Type;
    UCHAR Enabled;
    UCHAR NumberOfBanks;
    XPF_MCE_FLAGS Flags;
    ULONGLONG MCG_Capability;
    ULONGLONG MCG_GlobalControl;
    WHEA_XPF_MC_BANK_DESCRIPTOR Banks[WHEA_MAX_MC_BANKS];
} WHEA_XPF_MCE_DESCRIPTOR, *PWHEA_XPF_MCE_DESCRIPTOR;

//
// The following structure describes an XPF platform's corrected machine check
// error source mechanism. The information represented in this structure tells
// the OS how to configure the platform's CMC error source.
//

typedef struct _WHEA_XPF_CMC_DESCRIPTOR {
    USHORT Type;
    BOOLEAN Enabled;
    UCHAR NumberOfBanks;
    ULONG Reserved;
    WHEA_NOTIFICATION_DESCRIPTOR Notify;
    WHEA_XPF_MC_BANK_DESCRIPTOR Banks[WHEA_MAX_MC_BANKS];
} WHEA_XPF_CMC_DESCRIPTOR, *PWHEA_XPF_CMC_DESCRIPTOR;

typedef struct _WHEA_PCI_SLOT_NUMBER {
    union {
        struct {
            ULONG DeviceNumber:5;
            ULONG FunctionNumber:3;
            ULONG Reserved:24;
        } bits;
        ULONG AsULONG;
    } u;
} WHEA_PCI_SLOT_NUMBER, *PWHEA_PCI_SLOT_NUMBER;

//
// The following structure describes an XPF platform's non-maskable interrupt
// error source mechanism. The information represented in this structure tells
// the OS how to configure the platform's NMI error source.
//

typedef struct _WHEA_XPF_NMI_DESCRIPTOR {
    USHORT Type;
    BOOLEAN Enabled;
} WHEA_XPF_NMI_DESCRIPTOR, *PWHEA_XPF_NMI_DESCRIPTOR;

//
// The following structure describes a platform's PCI Express AER root port
// error source. The information represented in this structure tells the OS how
// to configure the root port's AER settings.
//

typedef struct _WHEA_AER_ROOTPORT_DESCRIPTOR {
    USHORT Type;
    BOOLEAN Enabled;
    UCHAR Reserved;
    ULONG BusNumber;
    WHEA_PCI_SLOT_NUMBER Slot;
    USHORT DeviceControl;
    AER_ROOTPORT_DESCRIPTOR_FLAGS Flags;
    ULONG UncorrectableErrorMask;
    ULONG UncorrectableErrorSeverity;
    ULONG CorrectableErrorMask;
    ULONG AdvancedCapsAndControl;
    ULONG RootErrorCommand;
} WHEA_AER_ROOTPORT_DESCRIPTOR, *PWHEA_AER_ROOTPORT_DESCRIPTOR;

//
// The following structure describes a platform's PCI Express AER endpoint
// error source. The information represented in this structure tells the OS how
// to configure the device's AER settings.
//

typedef struct _WHEA_AER_ENDPOINT_DESCRIPTOR {
    USHORT Type;
    BOOLEAN Enabled;
    UCHAR Reserved;
    ULONG BusNumber;
    WHEA_PCI_SLOT_NUMBER Slot;
    USHORT DeviceControl;
    AER_ENDPOINT_DESCRIPTOR_FLAGS Flags;
    ULONG UncorrectableErrorMask;
    ULONG UncorrectableErrorSeverity;
    ULONG CorrectableErrorMask;
    ULONG AdvancedCapsAndControl;
} WHEA_AER_ENDPOINT_DESCRIPTOR, *PWHEA_AER_ENDPOINT_DESCRIPTOR;

//
// The following structure describes a platform's PCI Express AER bridge
// error source. The information represented in this structure tells the OS how
// to configure the bridge's AER settings.
//

typedef struct _WHEA_AER_BRIDGE_DESCRIPTOR {
    USHORT Type;
    BOOLEAN Enabled;
    UCHAR Reserved;
    ULONG BusNumber;
    WHEA_PCI_SLOT_NUMBER Slot;
    USHORT DeviceControl;
    AER_BRIDGE_DESCRIPTOR_FLAGS Flags;
    ULONG UncorrectableErrorMask;
    ULONG UncorrectableErrorSeverity;
    ULONG CorrectableErrorMask;
    ULONG AdvancedCapsAndControl;
    ULONG SecondaryUncorrectableErrorMask;
    ULONG SecondaryUncorrectableErrorSev;
    ULONG SecondaryCapsAndControl;
} WHEA_AER_BRIDGE_DESCRIPTOR, *PWHEA_AER_BRIDGE_DESCRIPTOR;

//
// The following structure describes a generic error source to the OS. Using
// the information in this structure the OS is able to configure a handler for
// the generic error source.
//

typedef struct _WHEA_GENERIC_ERROR_DESCRIPTOR {

    //
    // Type is WHEA_ERROR_SOURCE_DESCRIPTOR_TYPE_GENERIC.
    //

    USHORT Type;

    //
    // This field is reserved.
    //

    UCHAR Reserved;

    //
    // Indicates whether the generic error source is to be enabled.
    //

    UCHAR Enabled;

    //
    // Length of the error status block.
    //

    ULONG ErrStatusBlockLength;

    //
    // If this generic error source relates back to another error source, keep
    // it's identifier here.
    //

    ULONG RelatedErrorSourceId;

    //
    // The following 5 fields have the same layout as a GEN_ADDR structure. They
    // describe the address at which the OS reads error status information
    // from the error source.
    //

    UCHAR ErrStatusAddressSpaceID;
    UCHAR ErrStatusAddressBitWidth;
    UCHAR ErrStatusAddressBitOffset;
    UCHAR ErrStatusAddressAccessSize;
    WHEA_PHYSICAL_ADDRESS ErrStatusAddress;

    //
    // Notify describes how the generic error source notifies the OS that error
    // information is available.
    //

    WHEA_NOTIFICATION_DESCRIPTOR Notify;

} WHEA_GENERIC_ERROR_DESCRIPTOR, *PWHEA_GENERIC_ERROR_DESCRIPTOR;

typedef struct _WHEA_IPF_MCA_DESCRIPTOR {
    USHORT Type;
    UCHAR Enabled;
    UCHAR Reserved;
} WHEA_IPF_MCA_DESCRIPTOR, *PWHEA_IPF_MCA_DESCRIPTOR;

typedef struct _WHEA_IPF_CMC_DESCRIPTOR {
    USHORT Type;
    UCHAR Enabled;
    UCHAR Reserved;
} WHEA_IPF_CMC_DESCRIPTOR, *PWHEA_IPF_CMC_DESCRIPTOR;

typedef struct _WHEA_IPF_CPE_DESCRIPTOR {
    USHORT Type;
    UCHAR Enabled;
    UCHAR Reserved;
} WHEA_IPF_CPE_DESCRIPTOR, *PWHEA_IPF_CPE_DESCRIPTOR;

//
// This structure describes a hardware error source.
//

typedef struct _WHEA_ERROR_SOURCE_DESCRIPTOR {
    ULONG Length;                                              // +00 (0)
    ULONG Version;                                             // +04 (4)
    WHEA_ERROR_SOURCE_TYPE Type;                               // +08 (8)
    WHEA_ERROR_SOURCE_STATE State;                             // +0C (12)
    ULONG MaxRawDataLength;                                    // +10 (16)
    ULONG NumRecordsToPreallocate;                             // +14 (20)
    ULONG MaxSectionsPerRecord;                                // +18 (24)
    ULONG ErrorSourceId;                                       // +1C (28)
    ULONG PlatformErrorSourceId;                               // +20 (32)
    ULONG Flags;                                               // +24 (36)

    union {                                                    // +28 (40)
        WHEA_XPF_MCE_DESCRIPTOR XpfMceDescriptor;
        WHEA_XPF_CMC_DESCRIPTOR XpfCmcDescriptor;
        WHEA_XPF_NMI_DESCRIPTOR XpfNmiDescriptor;
        WHEA_IPF_MCA_DESCRIPTOR IpfMcaDescriptor;
        WHEA_IPF_CMC_DESCRIPTOR IpfCmcDescriptor;
        WHEA_IPF_CPE_DESCRIPTOR IpfCpeDescriptor;
        WHEA_AER_ROOTPORT_DESCRIPTOR AerRootportDescriptor;
        WHEA_AER_ENDPOINT_DESCRIPTOR AerEndpointDescriptor;
        WHEA_AER_BRIDGE_DESCRIPTOR AerBridgeDescriptor;
        WHEA_GENERIC_ERROR_DESCRIPTOR GenErrDescriptor;
    } Info;

} WHEA_ERROR_SOURCE_DESCRIPTOR, *PWHEA_ERROR_SOURCE_DESCRIPTOR;

typedef union _WHEA_REVISION {
    struct {
        UCHAR MinorRevision;
        UCHAR MajorRevision;
    } DUMMYSTRUCTNAME;
    USHORT AsUSHORT;
} WHEA_REVISION, *PWHEA_REVISION;

//
// These are the different types of hardware that can report errors.
//
typedef enum _WHEA_ERROR_TYPE {
    WheaErrTypeProcessor = 0,
    WheaErrTypeMemory,
    WheaErrTypePCIExpress,
    WheaErrTypeNMI,
    WheaErrTypePCIXBus,
    WheaErrTypePCIXDevice,
    WheaErrTypeGeneric
} WHEA_ERROR_TYPE, *PWHEA_ERROR_TYPE;

//
// WHEA_ERROR_SEVERITY enumeration defines the valid severity levels of a
// reported hardware error.
//

typedef enum _WHEA_ERROR_SEVERITY {
    WheaErrSevRecoverable = 0,
    WheaErrSevFatal       = 1,
    WheaErrSevCorrected   = 2,
    WheaErrSevNone        = 3
} WHEA_ERROR_SEVERITY, *PWHEA_ERROR_SEVERITY;

//
// Error Status Structure
//

#define ERRTYP_INTERNAL                 0x01 // 1
#define ERRTYP_BUS                      0x10 // 16
#define ERRTYP_MEM                      0x04 // 4
#define ERRTYP_TLB                      0x05 // 5
#define ERRTYP_CACHE                    0x06 // 6
#define ERRTYP_FUNCTION                 0x07 // 7
#define ERRTYP_SELFTEST                 0x08 // 8
#define ERRTYP_FLOW                     0x09 // 9
#define ERRTYP_MAP                      0x11 // 17
#define ERRTYP_IMPROPER                 0x12 // 18
#define ERRTYP_UNIMPL                   0x13 // 19
#define ERRTYP_LOSSOFLOCKSTEP           0x14 // 20
#define ERRTYP_RESPONSE                 0x15 // 21
#define ERRTYP_PARITY                   0x16 // 22
#define ERRTYP_PROTOCOL                 0x17 // 23
#define ERRTYP_PATHERROR                0x18 // 24
#define ERRTYP_TIMEOUT                  0x19 // 25
#define ERRTYP_POISONED                 0x1A // 26

typedef union _WHEA_ERROR_STATUS {
    ULONGLONG ErrorStatus;
    struct {
        ULONGLONG Reserved1:8;
        ULONGLONG ErrorType:8;
        ULONGLONG Address:1;
        ULONGLONG Control:1;
        ULONGLONG Data:1;
        ULONGLONG Responder:1;
        ULONGLONG Requester:1;
        ULONGLONG FirstError:1;
        ULONGLONG Overflow:1;
        ULONGLONG Reserved2:41;
    } DUMMYSTRUCTNAME;
} WHEA_ERROR_STATUS, *PWHEA_ERROR_STATUS;

//
// Processor generic error section.
//

#define GENPROC_PROCTYPE_XPF                 0
#define GENPROC_PROCTYPE_IPF                 1

#define GENPROC_PROCISA_X86                  0
#define GENPROC_PROCISA_IPF                  1
#define GENPROC_PROCISA_X64                  2

#define GENPROC_PROCERRTYPE_UNKNOWN          0
#define GENPROC_PROCERRTYPE_CACHE            1
#define GENPROC_PROCERRTYPE_TLB              2
#define GENPROC_PROCERRTYPE_BUS              4
#define GENPROC_PROCERRTYPE_MAE              8

#define GENPROC_OP_GENERIC                   0
#define GENPROC_OP_DATAREAD                  1
#define GENPROC_OP_DATAWRITE                 2
#define GENPROC_OP_INSTRUCTIONEXE            3

#define GENPROC_FLAGS_RESTARTABLE            0x01
#define GENPROC_FLAGS_PRECISEIP              0x02
#define GENPROC_FLAGS_OVERFLOW               0x04
#define GENPROC_FLAGS_CORRECTED              0x08

typedef union _WHEA_PROCESSOR_FAMILY_INFO {
    struct {
        ULONG Stepping:4;
        ULONG Model:4;
        ULONG Family:4;
        ULONG ProcessorType:2;
        ULONG Reserved1:2;
        ULONG ExtendedModel:4;
        ULONG ExtendedFamily:8;
        ULONG Reserved2:4;
        ULONG Reserved3;
    } DUMMYSTRUCTNAME;
    ULONGLONG AsULONGLONG;
} WHEA_PROCESSOR_FAMILY_INFO, *PWHEA_PROCESSOR_FAMILY_INFO;

typedef union _WHEA_GENERIC_PROCESSOR_ERROR_VALIDBITS {
    struct {
        ULONGLONG ProcessorType:1;
        ULONGLONG InstructionSet:1;
        ULONGLONG ErrorType:1;
        ULONGLONG Operation:1;
        ULONGLONG Flags:1;
        ULONGLONG Level:1;
        ULONGLONG CPUVersion:1;
        ULONGLONG CPUBrandString:1;
        ULONGLONG ProcessorId:1;
        ULONGLONG TargetAddress:1;
        ULONGLONG RequesterId:1;
        ULONGLONG ResponderId:1;
        ULONGLONG InstructionPointer:1;
        ULONGLONG Reserved:51;
    } DUMMYSTRUCTNAME;
    ULONGLONG ValidBits;
} WHEA_GENERIC_PROCESSOR_ERROR_VALIDBITS,
  *PWHEA_GENERIC_PROCESSOR_ERROR_VALIDBITS;

typedef struct _WHEA_GENERIC_PROCESSOR_ERROR {
    WHEA_GENERIC_PROCESSOR_ERROR_VALIDBITS ValidBits; // +0x00 (00)
    UCHAR ProcessorType;                              // +0x08 (08)
    UCHAR InstructionSet;                             // +0x09 (09)
    UCHAR ErrorType;                                  // +0x0A (10)
    UCHAR Operation;                                  // +0x0B (11)
    UCHAR Flags;                                      // +0x0C (12)
    UCHAR Level;                                      // +0x0D (13)
    USHORT Reserved;                                  // +0x0E (14)
    ULONGLONG CPUVersion;                             // +0x10 (16)
    UCHAR CPUBrandString[128];                        // +0x18 (24)
    ULONGLONG ProcessorId;                            // +0x98 (152)
    ULONGLONG TargetAddress;                          // +0xA0 (160)
    ULONGLONG RequesterId;                            // +0xA8 (168)
    ULONGLONG ResponderId;                            // +0xB0 (176)
    ULONGLONG InstructionPointer;                     // +0xB8 (184)
                                                      // +0xC0 (192)
} WHEA_GENERIC_PROCESSOR_ERROR, *PWHEA_GENERIC_PROCESSOR_ERROR;

//
// IA32/X64 Processor Cache Check Structure
//

#define XPF_CACHE_CHECK_TRANSACTIONTYPE_INSTRUCTION     0
#define XPF_CACHE_CHECK_TRANSACTIONTYPE_DATAACCESS      1
#define XPF_CACHE_CHECK_TRANSACTIONTYPE_GENERIC         2

#define XPF_CACHE_CHECK_OPERATION_GENERIC               0
#define XPF_CACHE_CHECK_OPERATION_GENREAD               1
#define XPF_CACHE_CHECK_OPERATION_GENWRITE              2
#define XPF_CACHE_CHECK_OPERATION_DATAREAD              3
#define XPF_CACHE_CHECK_OPERATION_DATAWRITE             4
#define XPF_CACHE_CHECK_OPERATION_INSTRUCTIONFETCH      5
#define XPF_CACHE_CHECK_OPERATION_PREFETCH              6
#define XPF_CACHE_CHECK_OPERATION_EVICTION              7
#define XPF_CACHE_CHECK_OPERATION_SNOOP                 8

typedef union _WHEA_XPF_CACHE_CHECK {
    struct {
        ULONGLONG TransactionTypeValid:1;
        ULONGLONG OperationValid:1;
        ULONGLONG LevelValid:1;
        ULONGLONG ProcessorContextCorruptValid:1;
        ULONGLONG UncorrectedValid:1;
        ULONGLONG PreciseIPValid:1;
        ULONGLONG RestartableIPValid:1;
        ULONGLONG OverflowValid:1;
        ULONGLONG ReservedValid:8;
    ULONGLONG TransactionType:2;
    ULONGLONG Operation:4;
    ULONGLONG Level:3;
    ULONGLONG ProcessorContextCorrupt:1;
    ULONGLONG Uncorrected:1;
    ULONGLONG PreciseIP:1;
    ULONGLONG RestartableIP:1;
    ULONGLONG Overflow:1;
        ULONGLONG Reserved:34;
    } DUMMYSTRUCTNAME;
    ULONGLONG XpfCacheCheck;
} WHEA_XPF_CACHE_CHECK, *PWHEA_XPF_CACHE_CHECK;

//
// IA32/X64 Processor TLB Check Structure
//

#define XPF_TLB_CHECK_TRANSACTIONTYPE_INSTRUCTION     0
#define XPF_TLB_CHECK_TRANSACTIONTYPE_DATAACCESS      1
#define XPF_TLB_CHECK_TRANSACTIONTYPE_GENERIC         2

#define XPF_TLB_CHECK_OPERATION_GENERIC               0
#define XPF_TLB_CHECK_OPERATION_GENREAD               1
#define XPF_TLB_CHECK_OPERATION_GENWRITE              2
#define XPF_TLB_CHECK_OPERATION_DATAREAD              3
#define XPF_TLB_CHECK_OPERATION_DATAWRITE             4
#define XPF_TLB_CHECK_OPERATION_INSTRUCTIONFETCH      5
#define XPF_TLB_CHECK_OPERATION_PREFETCH              6

typedef union _WHEA_XPF_TLB_CHECK {
    struct {
        ULONGLONG TransactionTypeValid:1;
        ULONGLONG OperationValid:1;
        ULONGLONG LevelValid:1;
        ULONGLONG ProcessorContextCorruptValid:1;
        ULONGLONG UncorrectedValid:1;
        ULONGLONG PreciseIPValid:1;
        ULONGLONG RestartableIPValid:1;
        ULONGLONG OverflowValid:1;
        ULONGLONG ReservedValid:8;
    ULONGLONG TransactionType:2;
    ULONGLONG Operation:4;
    ULONGLONG Level:3;
    ULONGLONG ProcessorContextCorrupt:1;
    ULONGLONG Uncorrected:1;
    ULONGLONG PreciseIP:1;
    ULONGLONG RestartableIP:1;
    ULONGLONG Overflow:1;
    ULONGLONG Reserved:34;
    } DUMMYSTRUCTNAME;
    ULONGLONG XpfTLBCheck;
} WHEA_XPF_TLB_CHECK, *PWHEA_XPF_TLB_CHECK;

//
// IA32/X64 Processor Bus Check Structure
//

#define XPF_BUS_CHECK_TRANSACTIONTYPE_INSTRUCTION     0
#define XPF_BUS_CHECK_TRANSACTIONTYPE_DATAACCESS      1
#define XPF_BUS_CHECK_TRANSACTIONTYPE_GENERIC         2

#define XPF_BUS_CHECK_OPERATION_GENERIC               0
#define XPF_BUS_CHECK_OPERATION_GENREAD               1
#define XPF_BUS_CHECK_OPERATION_GENWRITE              2
#define XPF_BUS_CHECK_OPERATION_DATAREAD              3
#define XPF_BUS_CHECK_OPERATION_DATAWRITE             4
#define XPF_BUS_CHECK_OPERATION_INSTRUCTIONFETCH      5
#define XPF_BUS_CHECK_OPERATION_PREFETCH              6

#define XPF_BUS_CHECK_PARTICIPATION_PROCORIGINATED    0
#define XPF_BUS_CHECK_PARTICIPATION_PROCRESPONDED     1
#define XPF_BUS_CHECK_PARTICIPATION_PROCOBSERVED      2
#define XPF_BUS_CHECK_PARTICIPATION_GENERIC           3

#define XPF_BUS_CHECK_ADDRESS_MEMORY                  0
#define XPF_BUS_CHECK_ADDRESS_RESERVED                1
#define XPF_BUS_CHECK_ADDRESS_IO                      2
#define XPF_BUS_CHECK_ADDRESS_OTHER                   3

typedef union _WHEA_XPF_BUS_CHECK {
    struct {
        ULONGLONG TransactionTypeValid:1;
        ULONGLONG OperationValid:1;
        ULONGLONG LevelValid:1;
        ULONGLONG ProcessorContextCorruptValid:1;
        ULONGLONG UncorrectedValid:1;
        ULONGLONG PreciseIPValid:1;
        ULONGLONG RestartableIPValid:1;
        ULONGLONG OverflowValid:1;
        ULONGLONG ParticipationValid:1;
        ULONGLONG TimeoutValid:1;
        ULONGLONG AddressSpaceValid:1;
        ULONGLONG ReservedValid:5;
    ULONGLONG TransactionType:2;
    ULONGLONG Operation:4;
    ULONGLONG Level:3;
    ULONGLONG ProcessorContextCorrupt:1;
    ULONGLONG Uncorrected:1;
    ULONGLONG PreciseIP:1;
    ULONGLONG RestartableIP:1;
    ULONGLONG Overflow:1;
    ULONGLONG Participation:2;
    ULONGLONG Timeout:1;
    ULONGLONG AddressSpace:2;
    ULONGLONG Reserved:29;
    } DUMMYSTRUCTNAME;
    ULONGLONG XpfBusCheck;
} WHEA_XPF_BUS_CHECK, *PWHEA_XPF_BUS_CHECK;

//
// IA32/X64 Micro-Architecture Specific Check Structure
//

#define XPF_MS_CHECK_ERRORTYPE_NOERROR               0
#define XPF_MS_CHECK_ERRORTYPE_UNCLASSIFIED          1
#define XPF_MS_CHECK_ERRORTYPE_MCROMPARITY           2
#define XPF_MS_CHECK_ERRORTYPE_EXTERNAL              3
#define XPF_MS_CHECK_ERRORTYPE_FRC                   4
#define XPF_MS_CHECK_ERRORTYPE_INTERNALUNCLASSIFIED  5

typedef union _WHEA_XPF_MS_CHECK {
    struct {
        ULONGLONG ErrorTypeValid:1;
        ULONGLONG ProcessorContextCorruptValid:1;
        ULONGLONG UncorrectedValid:1;
        ULONGLONG PreciseIPValid:1;
        ULONGLONG RestartableIPValid:1;
        ULONGLONG OverflowValid:1;
        ULONGLONG ReservedValue:10;
        ULONGLONG ErrorType:3;
        ULONGLONG ProcessorContextCorrupt:1;
        ULONGLONG Uncorrected:1;
        ULONGLONG PreciseIP:1;
        ULONGLONG RestartableIP:1;
        ULONGLONG Overflow:1;
        ULONGLONG Reserved:40;
    } DUMMYSTRUCTNAME;
    ULONGLONG XpfMsCheck;
} WHEA_XPF_MS_CHECK, *PWHEA_XPF_MS_CHECK;

//
// IA32/X64 Processor Error Information
//

typedef union _WHEA_XPF_PROCESSOR_ERROR_VALIDBITS {
    struct {
        ULONGLONG LocalAPICId:1;
        ULONGLONG CpuId:1;
        ULONGLONG ProcInfoCount:6;
        ULONGLONG ContextInfoCount:6;
        ULONGLONG Reserved:50;
    } DUMMYSTRUCTNAME;
    ULONGLONG ValidBits;
} WHEA_XPF_PROCESSOR_ERROR_VALIDBITS, *PWHEA_XPF_PROCESSOR_ERROR_VALIDBITS;

typedef struct _WHEA_XPF_PROCESSOR_ERROR {
    WHEA_XPF_PROCESSOR_ERROR_VALIDBITS ValidBits;
    ULONGLONG LocalAPICId;
    UCHAR CpuId[48];
    UCHAR VariableInfo[1];
} WHEA_XPF_PROCESSOR_ERROR, *PWHEA_XPF_PROCESSOR_ERROR;

typedef union _WHEA_XPF_PROCINFO_VALIDBITS {
    struct {
        ULONGLONG CheckInfo:1;
        ULONGLONG TargetId:1;
        ULONGLONG RequesterId:1;
        ULONGLONG ResponderId:1;
        ULONGLONG InstructionPointer:1;
        ULONGLONG Reserved:59;
    } DUMMYSTRUCTNAME;
    ULONGLONG ValidBits;
} WHEA_XPF_PROCINFO_VALIDBITS, *PWHEA_XPF_PROCINFO_VALIDBITS;

typedef struct _WHEA_XPF_PROCINFO {
    GUID CheckInfoId;
    WHEA_XPF_PROCINFO_VALIDBITS ValidBits;
    union {
        WHEA_XPF_BUS_CHECK BusCheck;
        WHEA_XPF_CACHE_CHECK CacheCheck;
        WHEA_XPF_MS_CHECK MsCheck;
        WHEA_XPF_TLB_CHECK TlbCheck;
        ULONGLONG AsULONGLONG;
    } CheckInfo;
    ULONGLONG TargetId;
    ULONGLONG RequesterId;
    ULONGLONG ResponderId;
    ULONGLONG InstructionPointer;
} WHEA_XPF_PROCINFO, *PWHEA_XPF_PROCINFO;

//
// IA32/X64 Process Context Structure
//

#define XPF_CONTEXT_INFO_UNCLASSIFIEDDATA       0
#define XPF_CONTEXT_INFO_MSRREGISTERS           1
#define XPF_CONTEXT_INFO_32BITCONTEXT           2
#define XPF_CONTEXT_INFO_64BITCONTEXT           3
#define XPF_CONTEXT_INFO_FXSAVE                 4
#define XPF_CONTEXT_INFO_32BITDEBUGREGS         5
#define XPF_CONTEXT_INFO_64BITDEBUGREGS         6
#define XPF_CONTEXT_INFO_MMREGISTERS            7

typedef struct _WHEA_XPF_CONTEXT_INFO {
    USHORT RegisterContextType;
    USHORT RegisterDataSize;
    ULONG MSRAddress;
    ULONGLONG MmRegisterAddress;
    UCHAR RegisterData[1];
} WHEA_XPF_CONTEXT_INFO, *PWHEA_XPF_CONTEXT_INFO;

typedef struct _WHEA_X86_REGISTER_STATE {
    ULONG Eax;        // +00 (00)
    ULONG Ebx;        // +04 (04)
    ULONG Ecx;        // +08 (08)
    ULONG Edx;        // +0C (12)
    ULONG Esi;        // +10 (16)
    ULONG Edi;        // +14 (20)
    ULONG Ebp;        // +18 (24)
    ULONG Esp;        // +1C (28)
    USHORT Cs;        // +20 (32)
    USHORT Ds;        // +22 (34)
    USHORT Ss;        // +24 (36)
    USHORT Es;        // +26 (38)
    USHORT Fs;        // +28 (40)
    USHORT Gs;        // +2A (42)
    ULONG Eflags;     // +2C (44)
    ULONG Eip;        // +30 (48)
    ULONG Cr0;        // +34 (52)
    ULONG Cr1;        // +38 (56)
    ULONG Cr2;        // +3C (60)
    ULONG Cr3;        // +40 (64)
    ULONG Cr4;        // +44 (68)
    ULONGLONG Gdtr;   // +48 (72)
    ULONGLONG Idtr;   // +50 (80)
    USHORT Ldtr;      // +58 (88)
    USHORT Tr;        // +5A (90)
                      // +5C (92)
} WHEA_X86_REGISTER_STATE, *PWHEA_X86_REGISTER_STATE;

typedef struct _WHEA128A {
    ULONGLONG Low;
    LONGLONG High;
} WHEA128A, *PWHEA128A;

#if defined(_MSC_VER)
#if (_MSC_VER >= 1200)
#pragma warning(push)
#pragma warning(disable:4324) // structure padded due to __declspec(align())
#endif
#endif

typedef struct _WHEA_X64_REGISTER_STATE {
    ULONGLONG     Rax;            // +00 (00)
    ULONGLONG     Rbx;            // +08 (08)
    ULONGLONG     Rcx;            // +10 (16)
    ULONGLONG     Rdx;            // +18 (24)
    ULONGLONG     Rsi;            // +20 (32)
    ULONGLONG     Rdi;            // +28 (40)
    ULONGLONG     Rbp;            // +30 (48)
    ULONGLONG     Rsp;            // +38 (56)
    ULONGLONG     R8;             // +40 (64)
    ULONGLONG     R9;             // +48 (72)
    ULONGLONG     R10;            // +50 (80)
    ULONGLONG     R11;            // +58 (88)
    ULONGLONG     R12;            // +60 (96)
    ULONGLONG     R13;            // +68 (104)
    ULONGLONG     R14;            // +70 (112)
    ULONGLONG     R15;            // +78 (120)
    USHORT      Cs;               // +80 (128)
    USHORT      Ds;               // +82 (130)
    USHORT      Ss;               // +84 (132)
    USHORT      Es;               // +86 (134)
    USHORT      Fs;               // +88 (136)
    USHORT      Gs;               // +8A (138)
    USHORT      Reserved;         // +8C (140)
    ULONGLONG     Rflags;         // +90 (144)
    ULONGLONG     Eip;            // +98 (152)
    ULONGLONG     Cr0;            // +A0 (160)
    ULONGLONG     Cr1;            // +A8 (168)
    ULONGLONG     Cr2;            // +B0 (176)
    ULONGLONG     Cr3;            // +B8 (184)
    ULONGLONG     Cr4;            // +C0 (192)
    ULONGLONG     Cr8;            // +C8 (200)
    WHEA128A    Gdtr;             // +D0 (208)
    WHEA128A    Idtr;             // +E0 (224)
    USHORT      Ldtr;             // +F0 (240)
    USHORT      Tr;               // +F2 (242)
                                  // +F4 (244)
} WHEA_X64_REGISTER_STATE, *PWHEA_X64_REGISTER_STATE;

#if defined(_MSC_VER)
#if (_MSC_VER >= 1200)
#pragma warning(pop)
#endif
#endif

//
// Platform Memory Error
//

typedef union _WHEA_MEMORY_ERROR_VALIDBITS {
    struct {
        ULONGLONG ErrorStatus:1;
        ULONGLONG PhysicalAddress:1;
        ULONGLONG PhysicalAddressMask:1;
        ULONGLONG Node:1;
        ULONGLONG Card:1;
        ULONGLONG Module:1;
        ULONGLONG Bank:1;
        ULONGLONG Device:1;
        ULONGLONG Row:1;
        ULONGLONG Column:1;
        ULONGLONG BitPosition:1;
        ULONGLONG RequesterId:1;
        ULONGLONG ResponderId:1;
        ULONGLONG TargetId:1;
        ULONGLONG ErrorType:1;
        ULONGLONG Reserved:49;
    } DUMMYSTRUCTNAME;
    ULONGLONG ValidBits;
} WHEA_MEMORY_ERROR_VALIDBITS, *PWHEA_MEMORY_ERROR_VALIDBITS;

#define WHEA_MEMERRTYPE_UNKNOWN                 0x00
#define WHEA_MEMERRTYPE_NOERROR                 0x01
#define WHEA_MEMERRTYPE_SINGLEBITECC            0x02
#define WHEA_MEMERRTYPE_MULTIBITECC             0x03
#define WHEA_MEMERRTYPE_SINGLESYMCHIPKILL       0x04
#define WHEA_MEMERRTYPE_MULTISYMCHIPKILL        0x05
#define WHEA_MEMERRTYPE_MASTERABORT             0x06
#define WHEA_MEMERRTYPE_TARGETABORT             0x07
#define WHEA_MEMERRTYPE_PARITYERROR             0x08
#define WHEA_MEMERRTYPE_WATCHDOGTIMEOUT         0x09
#define WHEA_MEMERRTYPE_INVALIDADDRESS          0x0A
#define WHEA_MEMERRTYPE_MIRRORBROKEN            0x0B
#define WHEA_MEMERRTYPE_MEMORYSPARING           0x0C

typedef struct _WHEA_MEMORY_ERROR {
    WHEA_MEMORY_ERROR_VALIDBITS ValidBits; // 0x00 (00)
    WHEA_ERROR_STATUS ErrorStatus;         // 0x08 (08)
    ULONGLONG PhysicalAddress;             // 0x10 (16)
    ULONGLONG PhysicalAddressMask;         // 0x18 (24)
    USHORT Node;                           // 0x20 (32)
    USHORT Card;                           // 0x22 (34)
    USHORT Module;                         // 0x24 (36)
    USHORT Bank;                           // 0x26 (38)
    USHORT Device;                         // 0x28 (40)
    USHORT Row;                            // 0x2A (42)
    USHORT Column;                         // 0x2C (44)
    USHORT BitPosition;                    // 0x2E (46)
    ULONGLONG RequesterId;                 // 0x30 (48)
    ULONGLONG ResponderId;                 // 0x38 (56)
    ULONGLONG TargetId;                    // 0x40 (64)
    UCHAR ErrorType;                       // 0x48 (72)
                                           // 0x49 (73)
} WHEA_MEMORY_ERROR, *PWHEA_MEMORY_ERROR;

//
// NMI Error.
//

typedef union _WHEA_NMI_ERROR_FLAGS {
    struct {
        ULONG HypervisorError:1;
        ULONG Reserved:31;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_NMI_ERROR_FLAGS, *PWHEA_NMI_ERROR_FLAGS;

typedef struct _WHEA_NMI_ERROR {
    UCHAR Data[8];                         // 0x00 (00)
    WHEA_NMI_ERROR_FLAGS Flags;            // 0x08 (08)
                                           // 0x0C (12)
} WHEA_NMI_ERROR, *PWHEA_NMI_ERROR;

//
// PCI Express Error
//

typedef union _WHEA_PCIEXPRESS_ERROR_VALIDBITS {
    struct {
        ULONGLONG PortType:1;
        ULONGLONG Version:1;
        ULONGLONG CommandStatus:1;
        ULONGLONG DeviceId:1;
        ULONGLONG DeviceSerialNumber:1;
        ULONGLONG BridgeControlStatus:1;
        ULONGLONG ExpressCapability:1;
        ULONGLONG AerInfo:1;
        ULONGLONG Reserved:56;
    } DUMMYSTRUCTNAME;
    ULONGLONG ValidBits;
} WHEA_PCIEXPRESS_ERROR_VALIDBITS, *PWHEA_PCIEXPRESS_ERROR_VALIDBITS;

typedef struct _WHEA_PCIEXPRESS_DEVICE_ID {
    USHORT VendorID;                         // 0x00 (00)
    USHORT DeviceID;                         // 0x02 (02)
    ULONG ClassCode:24;                      // 0x04 (04)
    ULONG FunctionNumber:8;                  // 0x07 (07)
    ULONG DeviceNumber:8;                    // 0x08 (08)
    ULONG Segment:16;                        // 0x09 (09)
    ULONG PrimaryBusNumber:8;                // 0x0B (11)
    ULONG SecondaryBusNumber:8;              // 0x0C (12)
    ULONG Reserved1:2;                       // 0x0D (13)
    ULONG SlotNumber:14;                     // 0x0E (14)
    ULONG Reserved2:8;                       // 0x0F (15)
                                             // 0x10 (16)
} WHEA_PCIEXPRESS_DEVICE_ID, *PWHEA_PCIEXPRESS_DEVICE_ID;

typedef union _WHEA_PCIEXPRESS_VERSION {
    struct {
        UCHAR MinorVersion;
        UCHAR MajorVersion;
        USHORT Reserved;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_PCIEXPRESS_VERSION, *PWHEA_PCIEXPRESS_VERSION;

typedef union _WHEA_PCIEXPRESS_COMMAND_STATUS {
    struct {
        USHORT Command;
        USHORT Status;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_PCIEXPRESS_COMMAND_STATUS, *PWHEA_PCIEXPRESS_COMMAND_STATUS;

typedef union _WHEA_PCIEXPRESS_BRIDGE_CONTROL_STATUS {
    struct {
        USHORT BridgeSecondaryStatus;
        USHORT BridgeControl;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_PCIEXPRESS_BRIDGE_CONTROL_STATUS,
    *PWHEA_PCIEXPRESS_BRIDGE_CONTROL_STATUS;

typedef enum {
    WheaPciExpressEndpoint = 0,
    WheaPciExpressLegacyEndpoint,
    WheaPciExpressRootPort = 4,
    WheaPciExpressUpstreamSwitchPort,
    WheaPciExpressDownstreamSwitchPort,
    WheaPciExpressToPciXBridge,
    WheaPciXToExpressBridge,
    WheaPciExpressRootComplexIntegratedEndpoint,
    WheaPciExpressRootComplexEventCollector
} WHEA_PCIEXPRESS_DEVICE_TYPE;

typedef struct _WHEA_PCIEXPRESS_ERROR {
    WHEA_PCIEXPRESS_ERROR_VALIDBITS ValidBits;                 // 0x00 (00)
    WHEA_PCIEXPRESS_DEVICE_TYPE PortType;                      // 0x08 (08)
    WHEA_PCIEXPRESS_VERSION Version;                           // 0x0C (12)
    WHEA_PCIEXPRESS_COMMAND_STATUS CommandStatus;              // 0x10 (16)
    ULONG Reserved;                                            // 0x14 (20)
    WHEA_PCIEXPRESS_DEVICE_ID DeviceId;                        // 0x18 (24)
    ULONGLONG DeviceSerialNumber;                              // 0x28 (40)
    WHEA_PCIEXPRESS_BRIDGE_CONTROL_STATUS BridgeControlStatus; // 0x30 (48)
    UCHAR ExpressCapability[60];                               // 0x34 (52)
    UCHAR AerInfo[96];                                         // 0x70 (112)
                                                               // 0xD0 (208)
} WHEA_PCIEXPRESS_ERROR, *PWHEA_PCIEXPRESS_ERROR;

//
// PCI/PCI-X Bus Error
//

#define PCIXBUS_ERRTYPE_UNKNOWN             0x0000
#define PCIXBUS_ERRTYPE_DATAPARITY          0x0001
#define PCIXBUS_ERRTYPE_SYSTEM              0x0002
#define PCIXBUS_ERRTYPE_MASTERABORT         0x0003
#define PCIXBUS_ERRTYPE_BUSTIMEOUT          0x0004
#define PCIXBUS_ERRTYPE_MASTERDATAPARITY    0x0005
#define PCIXBUS_ERRTYPE_ADDRESSPARITY       0x0006
#define PCIXBUS_ERRTYPE_COMMANDPARITY       0x0007

typedef union _WHEA_PCIXBUS_ERROR_VALIDBITS {
    struct {
        ULONGLONG ErrorStatus:1;
        ULONGLONG ErrorType:1;
        ULONGLONG BusId:1;
        ULONGLONG BusAddress:1;
        ULONGLONG BusData:1;
        ULONGLONG BusCommand:1;
        ULONGLONG RequesterId:1;
        ULONGLONG CompleterId:1;
        ULONGLONG TargetId:1;
        ULONGLONG Reserved:55;
    } DUMMYSTRUCTNAME;
    ULONGLONG ValidBits;
} WHEA_PCIXBUS_ERROR_VALIDBITS, *PWHEA_PCIXBUS_ERROR_VALIDBITS;

typedef union _WHEA_PCIXBUS_ID {
    struct {
        UCHAR BusNumber;
        UCHAR BusSegment;
    } DUMMYSTRUCTNAME;
    USHORT AsUSHORT;
} WHEA_PCIXBUS_ID, *PWHEA_PCIXBUS_ID;

typedef union _WHEA_PCIXBUS_COMMAND {
    struct {
        ULONGLONG Command:56;
        ULONGLONG PCIXCommand:1;
        ULONGLONG Reserved:7;
    } DUMMYSTRUCTNAME;
    ULONGLONG AsULONGLONG;
} WHEA_PCIXBUS_COMMAND, *PWHEA_PCIXBUS_COMMAND;

typedef struct _WHEA_PCIXBUS_ERROR {
    WHEA_PCIXBUS_ERROR_VALIDBITS ValidBits;         // 0x00 (00)
    WHEA_ERROR_STATUS ErrorStatus;                  // 0x08 (08)
    USHORT ErrorType;                               // 0x10 (16)
    WHEA_PCIXBUS_ID BusId;                          // 0x12 (18)
    ULONG Reserved;                                 // 0x14 (20)
    ULONGLONG BusAddress;                           // 0x18 (24)
    ULONGLONG BusData;                              // 0x20 (32)
    WHEA_PCIXBUS_COMMAND BusCommand;                // 0x28 (40)
    ULONGLONG RequesterId;                          // 0x30 (48)
    ULONGLONG CompleterId;                          // 0x38 (56)
    ULONGLONG TargetId;                             // 0x40 (64)
                                                    // 0x48 (72)
} WHEA_PCIXBUS_ERROR, *PWHEA_PCIXBUS_ERROR;

//
// PCI/PCI_X Component Error
//

typedef union _WHEA_PCIXDEVICE_ERROR_VALIDBITS {
    struct {
        ULONGLONG ErrorStatus:1;
        ULONGLONG IdInfo:1;
        ULONGLONG MemoryNumber:1;
        ULONGLONG IoNumber:1;
        ULONGLONG RegisterDataPairs:1;
        ULONGLONG Reserved:59;
    } DUMMYSTRUCTNAME;
    ULONGLONG ValidBits;
} WHEA_PCIXDEVICE_ERROR_VALIDBITS, *PWHEA_PCIXDEVICE_ERROR_VALIDBITS;

typedef struct _WHEA_PCIXDEVICE_ID {
    USHORT VendorId;
    USHORT DeviceId;
    ULONG ClassCode:24;
    ULONG FunctionNumber:8;
    ULONG DeviceNumber:8;
    ULONG BusNumber:8;
    ULONG SegmentNumber:8;
    ULONG Reserved1:8;
    ULONG Reserved2;
} WHEA_PCIXDEVICE_ID, *PWHEA_PCIXDEVICE_ID;

typedef struct WHEA_PCIXDEVICE_REGISTER_PAIR {
    ULONGLONG Register;
    ULONGLONG Data;
} WHEA_PCIXDEVICE_REGISTER_PAIR, *PWHEA_PCIXDEVICE_REGISTER_PAIR;

typedef struct _WHEA_PCIXDEVICE_ERROR {
    WHEA_PCIXDEVICE_ERROR_VALIDBITS ValidBits;          // 0x00 (00)
    WHEA_ERROR_STATUS ErrorStatus;                      // 0x08 (08)
    WHEA_PCIXDEVICE_ID IdInfo;                          // 0x10 (16)
    ULONG MemoryNumber;                                 // 0x20 (32)
    ULONG IoNumber;                                     // 0x24 (36)
    WHEA_PCIXDEVICE_REGISTER_PAIR RegisterDataPairs[4]; // 0x28 (42)
                                                        // 0x8C (140)
} WHEA_PCIXDEVICE_ERROR, *PWHEA_PCIXDEVICE_ERROR;

//
// Firmware reference.
//

#define WHEA_FIRMWARE_RECORD_TYPE_IPFSAL 0

typedef struct _WHEA_FIRMWARE_RECORD {
    UCHAR Type;
    UCHAR Reserved[7];
    ULONGLONG FirmwareRecordId;
} WHEA_FIRMWARE_RECORD, *PWHEA_FIRMWARE_RECORD;

//
// All generic error status blocks must have the following format.
//

typedef union _WHEA_GENERIC_ERROR_BLOCKSTATUS {
    struct {
        ULONG UncorrectableError:1;
        ULONG CorrectableError:1;
        ULONG MultipleUncorrectableErrors:1;
        ULONG MultipleCorrectableErrors:1;
        ULONG ErrorDataEntryCount:10;
        ULONG Reserved:18;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_GENERIC_ERROR_BLOCKSTATUS, *PWHEA_GENERIC_ERROR_BLOCKSTATUS;

typedef struct _WHEA_GENERIC_ERROR {
    WHEA_GENERIC_ERROR_BLOCKSTATUS BlockStatus;
    ULONG RawDataOffset;
    ULONG RawDataLength;
    ULONG DataLength;
    WHEA_ERROR_SEVERITY ErrorSeverity;
    UCHAR Data[1];
} WHEA_GENERIC_ERROR, *PWHEA_GENERIC_ERROR;

typedef struct _WHEA_GENERIC_ERROR_DATA_ENTRY {
    GUID SectionType;
    WHEA_ERROR_SEVERITY ErrorSeverity;
    WHEA_REVISION Revision;
    UCHAR ValidBits;
    UCHAR Flags;
    ULONG ErrorDataLength;
    GUID FRUId;
    UCHAR FRUText[20];
    UCHAR Data[1];
} WHEA_GENERIC_ERROR_DATA_ENTRY, *PWHEA_GENERIC_ERROR_DATA_ENTRY;

typedef union _WHEA_BOOT_ERROR_VALIDBITS {
    struct {
        UCHAR FRUId:1;
        UCHAR FRUString:1;
        UCHAR ErrorData:1;
        UCHAR Reserved:5;
    } DUMMYSTRUCTNAME;
    UCHAR AsUCHAR;
} WHEA_BOOT_ERROR_VALIDBITS, *PWHEA_BOOT_ERROR_VALIDBITS;

#define WHEA_BOOT_ERROR_DESCRIPTION_UNKNOWN      0
#define WHEA_BOOT_ERROR_DESCRIPTION_FWRESET      1
#define WHEA_BOOT_ERROR_DESCRIPTION_SPRESET      2
#define WHEA_BOOT_ERROR_DESCRIPTION_HUNGSYSTEM   3

#define WHEA_BOOT_ERROR_TYPE_PROCESSOR           0x00
#define WHEA_BOOT_ERROR_TYPE_MEMORY              0x01
#define WHEA_BOOT_ERROR_TYPE_PCIEXPRESS          0x02
#define WHEA_BOOT_ERROR_TYPE_NMI                 0x03
#define WHEA_BOOT_ERROR_TYPE_PCIXBUS             0x04
#define WHEA_BOOT_ERROR_TYPE_PCIXDEVICE          0x05
#define WHEA_BOOT_ERROR_TYPE_GENERIC             0x06

typedef struct _WHEA_BOOT_ERROR_STATUS {
    UCHAR ErrorPresent;
    WHEA_BOOT_ERROR_VALIDBITS ValidBits;
    UCHAR ErrorDescription;
    UCHAR Reserved;
    ULONG ErrorDataLength;
    GUID Type;
    UCHAR FRUId[16];
    UCHAR FRUString[24];
    UCHAR ErrorData[1];
} WHEA_BOOT_ERROR_STATUS, *PWHEA_BOOT_ERROR_STATUS;

#define WHEA_ERROR_PKT_SIGNATURE 'tPrE'
#define WHEA_ERROR_PKT_VERSION   2

#define WHEA_ERROR_PKT_FLAGS_PREVERROR             0x00000001
#define WHEA_ERROR_PKT_FLAGS_CPUVALID              0x00000002
#define WHEA_ERROR_PKT_FLAGS_HVERROR               0x00000004
#define WHEA_ERROR_PKT_FLAGS_SIMULATED             0x00000008

typedef union _WHEA_ERROR_PACKET_FLAGS {
    struct {
        ULONG PreviousError:1;
        ULONG CpuValid:1;
        ULONG HypervisorError:1;
        ULONG Simulated:1;
        ULONG Reserved:28;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_ERROR_PACKET_FLAGS, *PWHEA_ERROR_PACKET_FLAGS;

typedef struct _WHEA_ERROR_PACKET {

    ULONG                   Signature;                  // +0x00 (0)
    WHEA_ERROR_PACKET_FLAGS Flags;                      // +0x04 (4)
    ULONG                   Size;                       // +0x08 (8)
    ULONG                   RawDataLength;              // +0x0C (12)
    ULONGLONG               Reserved1;                  // +0x10 (16)
    ULONGLONG               Context;                    // +0x18 (24)
    WHEA_ERROR_TYPE         ErrorType;                  // +0x20 (32)
    WHEA_ERROR_SEVERITY     ErrorSeverity;              // +0x24 (36)
    ULONG                   ErrorSourceId;              // +0x28 (40)
    WHEA_ERROR_SOURCE_TYPE  ErrorSourceType;            // +0x2C (44)
    ULONG                   Reserved2;                  // +0x30 (48)
    ULONG                   Version;                    // +0x34 (52)
    ULONGLONG               Cpu;                        // +0x38 (56)

    union {                                             // +0x40 (64)
        WHEA_GENERIC_PROCESSOR_ERROR ProcessorError;
        WHEA_MEMORY_ERROR            MemoryError;
        WHEA_NMI_ERROR               NmiError;
        WHEA_PCIEXPRESS_ERROR        PciExpressError;
        WHEA_PCIXBUS_ERROR           PciXBusError;
        WHEA_PCIXDEVICE_ERROR        PciXDeviceError;
    } u;

    WHEA_RAW_DATA_FORMAT     RawDataFormat;             // +0x110 (272)
    ULONG                    RawDataOffset;             // +0x114 (276)
    UCHAR                    RawData[1];               // +0x118 (280)

} WHEA_ERROR_PACKET, *PWHEA_ERROR_PACKET;

#define WHEA_ERROR_PACKET_LENGTH FIELD_OFFSET(WHEA_ERROR_PACKET, RawData)

typedef USHORT WHEA_ERROR_RECORD_ID, *PWHEA_ERROR_RECORD_ID;

//
// An error section descriptor provides key information about an error section
// contained in an error record.
//

#define WHEA_SECTION_DESCRIPTOR_FLAGS_PRIMARY            0x00000001
#define WHEA_SECTION_DESCRIPTOR_FLAGS_CONTAINMENTWRN     0x00000002
#define WHEA_SECTION_DESCRIPTOR_FLAGS_RESET              0x00000004
#define WHEA_SECTION_DESCRIPTOR_FLAGS_THRESHOLDEXCEEDED  0x00000008
#define WHEA_SECTION_DESCRIPTOR_FLAGS_RESOURCENA         0x00000010
#define WHEA_SECTION_DESCRIPTOR_FLAGS_LATENTERROR        0x00000020

#define WHEA_SECTION_DESCRIPTOR_REVISION                 0x0201

typedef union _WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS {
    struct {
        ULONG Primary:1;
        ULONG ContainmentWarning:1;
        ULONG Reset:1;
        ULONG ThresholdExceeded:1;
        ULONG ResourceNotAvailable:1;
        ULONG LatentError:1;
        ULONG Reserved:26;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS,
    *PWHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS;

typedef union _WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS {
    struct {
        UCHAR FRUId:1;
        UCHAR FRUText:1;
        UCHAR Reserved:6;
    } DUMMYSTRUCTNAME;
    UCHAR AsUCHAR;
} WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS,
    *PWHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS;

typedef struct _WHEA_ERROR_RECORD_SECTION_DESCRIPTOR {
    ULONG SectionOffset;                                       // +0x00
    ULONG SectionLength;                                       // +0x04
    WHEA_REVISION Revision;                                    // +0x08
    WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS ValidBits;  // +0x0A
    UCHAR Reserved;                                            // +0x0B
    WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS Flags;          // +0x0C
    GUID SectionType;                                          // +0x10
    GUID FRUId;                                                // +0x20
    WHEA_ERROR_SEVERITY SectionSeverity;                       // +0x30
    CCHAR FRUText[20];                                         // +0x34
                                                               // +0x48
} WHEA_ERROR_RECORD_SECTION_DESCRIPTOR, *PWHEA_ERROR_RECORD_SECTION_DESCRIPTOR;

//
// Information used by the error record serialization interface.
//

typedef union _WHEA_PERSISTENCE_INFO {
    struct {
        ULONGLONG Signature:16;
        ULONGLONG Length:24;
        ULONGLONG Identifier:16;
        ULONGLONG Attributes:2;
        ULONGLONG DoNotLog:1;
        ULONGLONG Reserved:5;
    } DUMMYSTRUCTNAME;
    ULONGLONG AsULONGLONG;
} WHEA_PERSISTENCE_INFO, *PWHEA_PERSISTENCE_INFO;

#define WHEA_ERROR_RECORD_FLAGS_RECOVERED            0x00000001
#define WHEA_ERROR_RECORD_FLAGS_PREVIOUSERROR        0x00000002
#define WHEA_ERROR_RECORD_FLAGS_SIMULATED            0x00000004

typedef union _WHEA_ERROR_RECORD_HEADER_FLAGS {
    struct {
        ULONG Recovered:1;
        ULONG PreviousError:1;
        ULONG Simulated:1;
        ULONG Reserved:29;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_ERROR_RECORD_HEADER_FLAGS, *PWHEA_ERROR_RECORD_HEADER_FLAGS;

#define WHEA_ERROR_RECORD_VALID_PLATFORMID           0x00000001
#define WHEA_ERROR_RECORD_VALID_TIMESTAMP            0x00000002
#define WHEA_ERROR_RECORD_VALID_PARTITIONID          0x00000004

typedef union _WHEA_ERROR_RECORD_HEADER_VALIDBITS {
    struct {
        ULONG Timestamp:1;
        ULONG PlatformId:1;
        ULONG PartitionId:1;
        ULONG Reserved:29;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_ERROR_RECORD_HEADER_VALIDBITS, *PWHEA_ERROR_RECORD_HEADER_VALIDBITS;

typedef union _WHEA_TIMESTAMP {
    struct {
        ULONGLONG Seconds:8;
        ULONGLONG Minutes:8;
        ULONGLONG Hours:8;
        ULONGLONG Reserved:8;
        ULONGLONG Day:8;
        ULONGLONG Month:8;
        ULONGLONG Year:8;
        ULONGLONG Century:8;
    } DUMMYSTRUCTNAME;
    LARGE_INTEGER AsLARGE_INTEGER;
} WHEA_TIMESTAMP, *PWHEA_TIMESTAMP;

#define WHEA_ERROR_RECORD_REVISION                   0x0201

//
// The error record header provides key information about a hardware error
// condition. A record consists of the header plus at least one section. There
// can be multiple sections, describing a given error conditions.
//

typedef struct _WHEA_ERROR_RECORD_HEADER {
    ULONG Signature;                                 // +0x00
    WHEA_REVISION Revision;                          // +0x04
    ULONG SignatureEnd;                              // +0x06 Must be 0xFFFFFFFF
    USHORT SectionCount;                             // +0x0A
    WHEA_ERROR_SEVERITY Severity;                    // +0x0C
    WHEA_ERROR_RECORD_HEADER_VALIDBITS ValidBits;    // +0x10
    ULONG Length;                                    // +0x14
    WHEA_TIMESTAMP Timestamp;                        // +0x18
    GUID PlatformId;                                 // +0x20
    GUID PartitionId;                                // +0x30
    GUID CreatorId;                                  // +0x40
    GUID NotifyType;                                 // +0x50
    ULONGLONG RecordId;                              // +0x60
    WHEA_ERROR_RECORD_HEADER_FLAGS Flags;            // +0x68
    WHEA_PERSISTENCE_INFO PersistenceInfo;           // +0x6C
    UCHAR Reserved[12];                              // +0x74
                                                     // +0x80
} WHEA_ERROR_RECORD_HEADER, *PWHEA_ERROR_RECORD_HEADER;

//
// Common hardware error record. An error record is expected to contain at
// least one section.
//
typedef struct _WHEA_ERROR_RECORD {
    WHEA_ERROR_RECORD_HEADER              Header;
    WHEA_ERROR_RECORD_SECTION_DESCRIPTOR  SectionDescriptor[1];
} WHEA_ERROR_RECORD, *PWHEA_ERROR_RECORD;
#include <poppack.h>

#define WHEA_ERROR_RECORD_SIGNATURE 'REPC'

#define WheaIsPreviousError(_record_) \
    ((_record_)->Header.Flags & WHEA_ERROR_RECORD_FLAGS_PREVIOUSERROR)

typedef
NTSTATUS
(*WHEA_ERROR_SOURCE_INITIALIZER)(
    __in ULONG Phase,
    __inout PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource,
    __inout_opt PVOID Context
    );

NTSTATUS
WheaReportHwError(
    __inout PWHEA_ERROR_PACKET ErrPkt
    );

NTKERNELAPI
NTSTATUS
WheaAddErrorSource(
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource,
    __in_opt PVOID Context
    );

NTKERNELAPI
NTSTATUS
WheaRemoveErrorSource(
    __in HANDLE Handle
    );

NTSTATUS
WheaRegisterErrSrcInitializer(
    __in WHEA_ERROR_SOURCE_TYPE ErrorSource,
    __in WHEA_ERROR_SOURCE_INITIALIZER Initializer
    );

PWHEA_ERROR_SOURCE_DESCRIPTOR
WheaGetErrorSource (
    __in ULONG ErrorSourceId
    );

FORCEINLINE
PWHEA_ERROR_PACKET
WheaGetErrPacketFromErrRecord (
    __in PWHEA_ERROR_RECORD Record
    )
{

    GUID Guid;
    ULONG Offset;
    PWHEA_ERROR_PACKET Packet;
    ULONG SectionNumber;
    ULONG Size;
    GUID WheaPktSectionType = WHEA_PACKET_SECTION_GUID;

    NT_ASSERT(Record->Header.Signature == WHEA_ERROR_RECORD_SIGNATURE);
    if (Record->Header.Signature != WHEA_ERROR_RECORD_SIGNATURE) {
        return NULL;
    }

    Size = (sizeof(WHEA_ERROR_RECORD_HEADER)) +
            (sizeof(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR) *
             Record->Header.SectionCount);

    if (Record->Header.Length < Size) {
        return NULL;
    }

    for (SectionNumber = 0;
         SectionNumber < Record->Header.SectionCount;
         SectionNumber += 1) {

        RtlCopyMemory(&Guid,
                      &Record->SectionDescriptor[SectionNumber].SectionType,
                      sizeof(GUID));

        if (RtlCompareMemory(&Guid, &WheaPktSectionType, sizeof(GUID)) ==
            sizeof(GUID)) {

            Offset = Record->SectionDescriptor[SectionNumber].SectionOffset;
            Size = (Offset +
                    Record->SectionDescriptor[SectionNumber].SectionLength);

            if (Record->Header.Length < Size) {
                return NULL;
            }

            Packet = (PWHEA_ERROR_PACKET)((PUCHAR)Record + Offset);
            NT_ASSERT(Packet->Signature == WHEA_ERROR_PKT_SIGNATURE);
            return Packet;
        }
    }

    return NULL;
}

#define INJECT_ERRTYPE_PROCESSOR_CORRECTABLE                    0x00000001
#define INJECT_ERRTYPE_PROCESSOR_UNCORRECTABLENONFATAL          0x00000002
#define INJECT_ERRTYPE_PROCESSOR_UNCORRECTABLEFATAL             0x00000004
#define INJECT_ERRTYPE_MEMORY_CORRECTABLE                       0x00000008
#define INJECT_ERRTYPE_MEMORY_UNCORRECTABLENONFATAL             0x00000010
#define INJECT_ERRTYPE_MEMORY_UNCORRECTABLEFATAL                0x00000020
#define INJECT_ERRTYPE_PCIEXPRESS_CORRECTABLE                   0x00000040
#define INJECT_ERRTYPE_PCIEXPRESS_UNCORRECTABLENONFATAL         0x00000080
#define INJECT_ERRTYPE_PCIEXPRESS_UNCORRECTABLEFATAL            0x00000100
#define INJECT_ERRTYPE_PLATFORM_CORRECTABLE                     0x00000200
#define INJECT_ERRTYPE_PLATFORM_UNCORRECTABLENONFATAL           0x00000400
#define INJECT_ERRTYPE_PLATFORM_UNCORRECTABLEFATAL              0x00000800

//
// This union is used to communicate the platform's error injection capabilities
// to the OS.
//

typedef union _WHEA_ERROR_INJECTION_CAPABILITIES {
    struct {
        ULONG ProcessorCorrectable:1;                   // 0x00000001
        ULONG ProcessorUncorrectableNonFatal:1;         // 0x00000002
        ULONG ProcessorUncorrectableFatal:1;            // 0x00000004
        ULONG MemoryCorrectable:1;                      // 0x00000008
        ULONG MemoryUncorrectableNonFatal:1;            // 0x00000010
        ULONG MemoryUncorrectableFatal:1;               // 0x00000020
        ULONG PCIExpressCorrectable:1;                  // 0x00000040
        ULONG PCIExpressUncorrectableNonFatal:1;        // 0x00000080
        ULONG PCIExpressUncorrectableFatal:1;           // 0x00000100
        ULONG PlatformCorrectable:1;                    // 0x00000200
        ULONG PlatformUncorrectableNonFatal:1;          // 0x00000400
        ULONG PlatformUncorrectableFatal:1;             // 0x00000800
        ULONG IA64Corrected:1;                          // 0x00001000
        ULONG IA64Recoverable:1;                        // 0x00002000
        ULONG IA64Fatal:1;                              // 0x00004000
        ULONG IA64RecoverableCache:1;                   // 0x00008000
        ULONG IA64RecoverableRegFile:1;                 // 0x00010000
        ULONG Reserved:15;
    } DUMMYSTRUCTNAME;
    ULONG AsULONG;
} WHEA_ERROR_INJECTION_CAPABILITIES, *PWHEA_ERROR_INJECTION_CAPABILITIES;

#define PshedFADiscovery              0x00000001
#define PshedFAErrorSourceControl     0x00000002
#define PshedFAErrorRecordPersistence 0x00000004
#define PshedFAErrorInfoRetrieval     0x00000008
#define PshedFAErrorRecovery          0x00000010
#define PshedFAErrorInjection         0x00000020

typedef
NTSTATUS
(*PSHED_PI_GET_ALL_ERROR_SOURCES) (
    __inout_opt PVOID PluginContext,
    __inout PULONG Count,
    __inout_bcount(*Length) PWHEA_ERROR_SOURCE_DESCRIPTOR *ErrorSrcs,
    __inout PULONG Length
    );

typedef
NTSTATUS
(*PSHED_PI_GET_ERROR_SOURCE_INFO) (
    __inout_opt PVOID PluginContext,
    __inout PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

typedef
NTSTATUS
(*PSHED_PI_SET_ERROR_SOURCE_INFO) (
    __inout_opt PVOID PluginContext,
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

typedef
NTSTATUS
 (*PSHED_PI_ENABLE_ERROR_SOURCE) (
    __inout_opt PVOID PluginContext,
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

typedef
NTSTATUS
 (*PSHED_PI_DISABLE_ERROR_SOURCE) (
    __inout_opt PVOID PluginContext,
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

typedef
NTSTATUS
(*PSHED_PI_WRITE_ERROR_RECORD) (
    __inout_opt PVOID PluginContext,
    __in ULONG Flags,
    __in ULONG RecordLength,
    __in_bcount(RecordLength) PWHEA_ERROR_RECORD ErrorRecord
    );

typedef
NTSTATUS
(*PSHED_PI_READ_ERROR_RECORD) (
    __inout_opt PVOID PluginContext,
    __in ULONG Flags,
    __in ULONGLONG ErrorRecordId,
    __out PULONGLONG NextErrorRecordId,
    __inout PULONG RecordLength,
    __out_bcount(*RecordLength) PWHEA_ERROR_RECORD ErrorRecord
    );

typedef
NTSTATUS
(*PSHED_PI_CLEAR_ERROR_RECORD) (
    __inout_opt PVOID PluginContext,
    __in ULONG Flags,
    __in ULONGLONG ErrorRecordId
    );

typedef
NTSTATUS
(*PSHED_PI_RETRIEVE_ERROR_INFO) (
    __inout_opt PVOID PluginContext,
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource,
    __in ULONGLONG BufferLength,
    __inout_bcount(BufferLength) PWHEA_ERROR_PACKET Packet
    );

typedef
NTSTATUS
(*PSHED_PI_FINALIZE_ERROR_RECORD) (
    __inout_opt PVOID PluginContext,
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource,
    __in ULONG BufferLength,
    __inout_bcount(BufferLength) PWHEA_ERROR_RECORD ErrorRecord
    );

typedef
NTSTATUS
(*PSHED_PI_CLEAR_ERROR_STATUS) (
    __inout_opt PVOID PluginContext,
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource,
    __in ULONG BufferLength,
    __in_bcount(BufferLength) PWHEA_ERROR_RECORD ErrorRecord
    );

typedef
NTSTATUS
(*PSHED_PI_ATTEMPT_ERROR_RECOVERY) (
    __inout_opt PVOID PluginContext,
    __in ULONG BufferLength,
    __in_bcount(BufferLength) PWHEA_ERROR_RECORD ErrorRecord
    );

typedef
NTSTATUS
(*PSHED_PI_GET_INJECTION_CAPABILITIES) (
    __inout_opt PVOID PluginContext,
    __out PWHEA_ERROR_INJECTION_CAPABILITIES Capabilities
    );

typedef
NTSTATUS
(*PSHED_PI_INJECT_ERROR) (
    __inout_opt PVOID PluginContext,
    __in ULONGLONG ErrorType,
    __in ULONGLONG Parameter1,
    __in ULONGLONG Parameter2,
    __in ULONGLONG Parameter3,
    __in ULONGLONG Parameter4
    );

typedef struct _WHEA_PSHED_PLUGIN_CALLBACKS {
    PSHED_PI_GET_ALL_ERROR_SOURCES GetAllErrorSources;
    PVOID Reserved;
    PSHED_PI_GET_ERROR_SOURCE_INFO GetErrorSourceInfo;
    PSHED_PI_SET_ERROR_SOURCE_INFO SetErrorSourceInfo;
    PSHED_PI_ENABLE_ERROR_SOURCE EnableErrorSource;
    PSHED_PI_DISABLE_ERROR_SOURCE DisableErrorSource;
    PSHED_PI_WRITE_ERROR_RECORD WriteErrorRecord;
    PSHED_PI_READ_ERROR_RECORD ReadErrorRecord;
    PSHED_PI_CLEAR_ERROR_RECORD ClearErrorRecord;
    PSHED_PI_RETRIEVE_ERROR_INFO RetrieveErrorInfo;
    PSHED_PI_FINALIZE_ERROR_RECORD FinalizeErrorRecord;
    PSHED_PI_CLEAR_ERROR_STATUS ClearErrorStatus;
    PSHED_PI_ATTEMPT_ERROR_RECOVERY AttemptRecovery;
    PSHED_PI_GET_INJECTION_CAPABILITIES GetInjectionCapabilities;
    PSHED_PI_INJECT_ERROR InjectError;
} WHEA_PSHED_PLUGIN_CALLBACKS,
 *PWHEA_PSHED_PLUGIN_CALLBACKS;

#define WHEA_PLUGIN_REGISTRATION_PACKET_VERSION 0x00010000

typedef struct _WHEA_PSHED_PLUGIN_REGISTRATION_PACKET {
    ULONG Length;
    ULONG Version;
    PVOID Context;
    ULONG FunctionalAreaMask;
    ULONG Reserved;
    WHEA_PSHED_PLUGIN_CALLBACKS Callbacks;
} WHEA_PSHED_PLUGIN_REGISTRATION_PACKET,
  *PWHEA_PSHED_PLUGIN_REGISTRATION_PACKET;

typedef struct _WHEA_PSHED_INIT_PACKET {
    ULONG Size;
    ULONG Version;
} WHEA_PSHED_INIT_PACKET, *PWHEA_PSHED_INIT_PACKET;

#define WHEA_WRITE_FLAG_DUMMY 0x00000001

PVOID
PshedAllocateMemory (
    __in ULONG Size
    );

NTSTATUS
PshedAttemptErrorRecovery(
    __inout PWHEA_ERROR_RECORD ErrorRecord
    );

VOID
PshedBugCheckSystem(
    __in PWHEA_ERROR_RECORD ErrorRecord
    );

NTSTATUS
PshedClearErrorRecord(
    __in ULONG Flags,
    __in ULONGLONG RecordId
    );

NTSTATUS
PshedDisableErrorSource (
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

NTSTATUS
PshedEnableErrorSource (
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

NTSTATUS
PshedFinalizeErrorRecord(
    __inout PWHEA_ERROR_RECORD ErrorRecord,
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

VOID
PshedFreeMemory (
    __in PVOID Address
    );

NTSTATUS
PshedGetAllErrorSources (
    __out PULONG ErrorSourceCount,
    __inout_bcount(*Length) PUCHAR *Buffer,
    __inout PULONG Length
    );

NTSTATUS
PshedGetBootErrorPacket (
    __out PULONG BootPacketLength,
    __out PWHEA_ERROR_PACKET *BootPacket
    );

NTSTATUS
PshedGetErrorSourceInfo (
    __in WHEA_ERROR_SOURCE_TYPE ErrorSource,
    __inout PWHEA_ERROR_SOURCE_DESCRIPTOR Descriptor
    );

NTSTATUS
PshedGetInjectionCapabilities (
    __out PWHEA_ERROR_INJECTION_CAPABILITIES Capabilities
    );

VOID
PshedHandleCorrectedError (
    __in PWHEA_ERROR_PACKET Packet
    );

NTSTATUS
PshedInjectError (
    __in ULONG ErrorType,
    __in ULONGLONG Parameter1,
    __in ULONGLONG Parameter2,
    __in ULONGLONG Parameter3,
    __in ULONGLONG Parameter4
    );

BOOLEAN
PshedIsSystemWheaEnabled (
    VOID
    );

NTSTATUS
PshedReadErrorRecord(
    __in ULONG Flags,
    __in ULONGLONG ErrorRecordId,
    __out PULONGLONG NextErrorRecordId,
    __out PULONG RecordLength,
    __out_bcount(*RecordLength) PWHEA_ERROR_RECORD *ErrorRecord
    );

NTSTATUS
PshedRegisterPlugin (
    __inout PWHEA_PSHED_PLUGIN_REGISTRATION_PACKET Packet
    );

NTSTATUS
PshedRetrieveErrorInfo (
    __inout PWHEA_ERROR_PACKET ErrorPkt,
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

NTSTATUS
PshedSetErrorSourceInfo (
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource
    );

BOOLEAN
PshedSynchronizeExecution (
    __in PWHEA_ERROR_SOURCE_DESCRIPTOR ErrorSource,
    __in PKSYNCHRONIZE_ROUTINE SynchronizeRoutine,
    __in PVOID SynchronizeContext
    );

NTSTATUS
PshedWriteErrorRecord(
    __in ULONG Flags,
    __in ULONG RecordLength,
    __in_bcount(RecordLength) PWHEA_ERROR_RECORD ErrorRecord
    );



#ifdef __cplusplus
}
#endif

#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning(default:4115)
#pragma warning(default:4201)
#pragma warning(default:4214)
#endif

#endif // _NTDDK_


