/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#ifndef _GO_DEFINES_H_
#define _GO_DEFINES_H_

#include <cstdint>

#define  go_iota 0

typedef enum _go_kind_t: uint8_t {
	kindBool = 1 + go_iota,
	kindInt,
	kindInt8,
	kindInt16,
	kindInt32,
	kindInt64,
	kindUint,
	kindUint8,
	kindUint16,
	kindUint32,
	kindUint64,
	kindUintptr,
	kindFloat32,
	kindFloat64,
	kindComplex64,
	kindComplex128,
	kindArray,
	kindChan,
	kindFunc,
	kindInterface,
	kindMap,
	kindPtr,
	kindSlice,
	kindString,
	kindStruct,
	kindUnsafePointer,

	kindDirectIface = 1 << 5,
	kindGCProg      = 1 << 6,
	kindMask        = (1 << 5) - 1
} go_kind_t;

typedef struct _go_slice_t {
    void* data;
    int64_t len;
    int64_t cap;
} go_slice_t;

typedef struct _go_type_t{
    void* size;
    void* ptrdata;
    uint32_t hash;
    uint8_t tflag;
    uint8_t align;
    uint8_t fieldAlign;
    uint8_t kind;
    void* equal;
    void* gcdata;
    int32_t str;
    int32_t ptrToThis;
} go_type_t;

typedef struct _go_name_t{
	// bytes *byte
	uint8_t *byte;
} go_name_t;

typedef struct _go_struct_type_t{
	// rtype
	go_type_t typ;
	// pkgPath name
	go_name_t pkgPath;
	// fields  []structField // sorted by offset
	go_slice_t fields;
} go_struct_type_t;

typedef struct _go_struct_field_t{
	// name       name
	go_name_t name;
	// typ        *_type
	go_type_t* typ;
	// offsetAnon uintptr
	void* offsetAnon;
} go_struct_field_t;

// ancestorInfo records details of where a goroutine was started.
typedef struct _go_ancestor_info_t {
	// pcs  []uintptr // pcs from the stack of this goroutine
    go_slice_t pcs;
	// goid int64     // goroutine id of this goroutine; original goroutine possibly dead
    int64_t goid;
	// gopc uintptr   // pc of go statement that created this goroutine
    void* gopc;
} go_ancestor_info_t;

typedef struct _go_string_t {
    void* data;
    int64_t len;
} go_string_t;

typedef struct _go_bitvector_t {
	int32_t n;
	uint8_t* bytedata;
} go_bitvector_t;

typedef struct _go_map_t {
    // count     int // # live cells == size of map.  Must be first (used by len() builtin)
    int64_t count;
	// flags     uint8
    uint8_t flags; 
	// B         uint8  // log_2 of # of buckets (can hold up to loadFactor * 2^B items)
    uint8_t B;
	// noverflow uint16 // approximate number of overflow buckets; see incrnoverflow for details
    uint16_t noverflow;
	// hash0     uint32 // hash seed
    uint32_t hash0;

	// buckets    unsafe.Pointer // array of 2^B Buckets. may be nil if count==0.
    void* buckets;
	// oldbuckets unsafe.Pointer // previous bucket array of half the size, non-nil only when growing
    void* oldbuckets;
	// nevacuate  uintptr        // progress counter for evacuation (buckets less than this have been evacuated)
    void* nevacuate;
	// extra *mapextra // optional fields
    void* extra;
} go_map_t;

// typedef struct _go_type_name_t {
//     uint8_t* data;
// } go_type_name_t;

typedef struct _go_sync_mutex_t {
    int32_t state;
    uint32_t sema;
} go_sync_mutex_t;

typedef struct _go_moduledata_t {
    // pclntable    []byte
	go_slice_t pclntable;
    // ftab         []functab
	go_slice_t ftab;
	// filetab      []uint32
	go_slice_t filetab;
    // findfunctab  uintptr
	void* findfunctab;
	// minpc, maxpc uintptr
    void* minpc;
    void* maxpc;

	// text, etext           uintptr
    void* text;
    void* etext;
	// noptrdata, enoptrdata uintptr
    void* noptrdata;
    void* enoptrdata;
	// data, edata           uintptr
    void* data;
    void* edata;
	// bss, ebss             uintptr
    void* bss;
    void* ebss;
	// noptrbss, enoptrbss   uintptr
    void* noptrbss;
    void* enoptrbss;
	// end, gcdata, gcbss    uintptr
	void* end;
    void* gcdata;
    void* gcbss;
    // types, etypes         uintptr
    void* types;
    void* etypes;

	// textsectmap []textsect
    go_slice_t textsectmap;
	// typelinks   []int32 // offsets from types
    go_slice_t typelinks;
	// itablinks   []*itab
    go_slice_t itablinks;

	// ptab []ptabEntry
    go_slice_t ptab;

	// pluginpath string
    go_string_t pluginpath;
	// pkghashes  []modulehash
    go_slice_t pkghashes;

	// modulename   string
    go_string_t modulename;
	// modulehashes []modulehash
    go_slice_t modulehashes;

	// hasmain uint8 // 1 if module contains the main function, 0 otherwise
    uint8_t hasmain;

	// gcdatamask, gcbssmask bitvector
    go_bitvector_t gcdatamask;
    go_bitvector_t gcbssmask;

	// typemap map[typeOff]*_type // offset to *_rtype in previous module
    go_map_t typemap;
	// bad bool // module failed to load and should be ignored
    bool bad;
	// next *moduledata
    struct _go_moduledata_t* next;
} go_moduledata_t;

typedef struct _go_stack_t {
    // lo uintptr
    void* lo;
	// hi uintptr
    void* hi;
} go_stack_t;

typedef struct _go_gobuf_t {
	// // The offsets of sp, pc, and g are known to (hard-coded in) libmach.
	// //
	// // ctxt is unusual with respect to GC: it may be a
	// // heap-allocated funcval, so GC needs to track it, but it
	// // needs to be set and cleared from assembly, where it's
	// // difficult to have write barriers. However, ctxt is really a
	// // saved, live register, and we only ever exchange it between
	// // the real register and the gobuf. Hence, we treat it as a
	// // root during stack scanning, which means assembly that saves
	// // and restores it doesn't need write barriers. It's still
	// // typed as a pointer so that any other writes from Go get
	// // write barriers.
	// sp   uintptr
    void* sp;
	// pc   uintptr
    void* pc;
	// g    guintptr
    void* g;
	// ctxt unsafe.Pointer
    void* ctxt;
	// ret  sys.Uintreg
    void* ret;
	// lr   uintptr
    void* lr;
	// bp   uintptr // for GOEXPERIMENT=framepointer
    void* bp;
} go_gobuf_t;

typedef struct _go_g_t {
    // // Stack parameters.
	// // stack describes the actual stack memory: [stack.lo, stack.hi).
	// // stackguard0 is the stack pointer compared in the Go stack growth prologue.
	// // It is stack.lo+StackGuard normally, but can be StackPreempt to trigger a preemption.
	// // stackguard1 is the stack pointer compared in the C stack growth prologue.
	// // It is stack.lo+StackGuard on g0 and gsignal stacks.
	// // It is ~0 on other goroutine stacks, to trigger a call to morestackc (and crash).
	// stack       stack   // offset known to runtime/cgo
    go_stack_t stack;
	// stackguard0 uintptr // offset known to liblink
    void* stackguard0;
	// stackguard1 uintptr // offset known to liblink
    void* stackguard1;

	// _panic       *_panic // innermost panic - offset known to liblink
    void* _panic;
	// _defer       *_defer // innermost defer
    void* _defer;
	// m            *m      // current m; offset known to arm liblink
	void* m;
    // sched        gobuf
    go_gobuf_t sched;
	// syscallsp    uintptr        // if status==Gsyscall, syscallsp = sched.sp to use during gc
	void* syscallsp;
    // syscallpc    uintptr        // if status==Gsyscall, syscallpc = sched.pc to use during gc
	void* syscallpc;
    // stktopsp     uintptr        // expected sp at top of stack, to check in traceback
	void* stktopsp;
    // param        unsafe.Pointer // passed parameter on wakeup
	void* param;
    // atomicstatus uint32
    uint32_t atomicstatus;
	// stackLock    uint32 // sigprof/scang lock; TODO: fold in to atomicstatus
	uint32_t stackLock;
    // goid         int64
	int64_t goid;
    // schedlink    guintptr
    void* schedlink;
	// waitsince    int64      // approx time when the g become blocked
    int64_t waitsince;
	// waitreason   waitReason // if status==Gwaiting
    uint8_t waitreason;

	// preempt       bool // preemption signal, duplicates stackguard0 = stackpreempt
    bool preempt;
	// preemptStop   bool // transition to _Gpreempted on preemption; otherwise, just deschedule
    bool preemptStop;
	// preemptShrink bool // shrink stack at synchronous safe point
    bool preemptShrink;

	// // asyncSafePoint is set if g is stopped at an asynchronous
	// // safe point. This means there are frames on the stack
	// // without precise pointer information.
	// asyncSafePoint bool
    bool asyncSafePoint;

	// paniconfault bool // panic (instead of crash) on unexpected fault address
    bool paniconfault;
	// gcscandone   bool // g has scanned stack; protected by _Gscan bit in status
    bool gcscandone;
	// throwsplit   bool // must not split stack
    bool throwsplit;
	// // activeStackChans indicates that there are unlocked channels
	// // pointing into this goroutine's stack. If true, stack
	// // copying needs to acquire channel locks to protect these
	// // areas of the stack.
	// activeStackChans bool
    bool activeStackChans;
	// // parkingOnChan indicates that the goroutine is about to
	// // park on a chansend or chanrecv. Used to signal an unsafe point
	// // for stack shrinking. It's a boolean value, but is updated atomically.
	// parkingOnChan uint8
    uint8_t parkingOnChan;

	// raceignore     int8     // ignore race detection events
    int8_t raceignore;
	// sysblocktraced bool     // StartTrace has emitted EvGoInSyscall about this goroutine
    bool sysblocktraced;
	// sysexitticks   int64    // cputicks when syscall has returned (for tracing)
    int64_t sysexitticks;
	// traceseq       uint64   // trace event sequencer
    uint64_t traceseq;
	// tracelastp     puintptr // last P emitted an event for this goroutine
    void* tracelastp;
	// lockedm        muintptr
	void* lockedm;
    // sig            uint32
	uint32_t sig;
    // writebuf       []byte
	go_slice_t writebuf;
    // sigcode0       uintptr
    void* sigcode0;
	// sigcode1       uintptr
    void* sigcode1;
	// sigpc          uintptr
    void* sigpc;
	// gopc           uintptr         // pc of go statement that created this goroutine
	void* gopc;
    // ancestors      *[]ancestorInfo // ancestor information goroutine(s) that created this goroutine (only used if debug.tracebackancestors)
	go_slice_t* ancestors;
    // startpc        uintptr         // pc of goroutine function
    void* startpc;
	// racectx        uintptr
    void* racectx;
	// waiting        *sudog         // sudog structures this g is waiting on (that have a valid elem ptr); in lock order
	void* waiting;
    // cgoCtxt        []uintptr      // cgo traceback context
    go_slice_t cgoCtxt;
	// labels         unsafe.Pointer // profiler labels
    void* labels;
	// timer          *timer         // cached timer for time.Sleep
    void* timer;
	// selectDone     uint32         // are we participating in a select and did someone win the race?
    uint32_t selectDone;

	// // Per-G GC state

	// // gcAssistBytes is this G's GC assist credit in terms of
	// // bytes allocated. If this is positive, then the G has credit
	// // to allocate gcAssistBytes bytes without assisting. If this
	// // is negative, then the G must correct this by performing
	// // scan work. We track this in bytes to make it fast to update
	// // and check for debt in the malloc hot path. The assist ratio
	// // determines how this corresponds to scan work debt.
	// gcAssistBytes int64
    int64_t gcAssistBytes;
} go_g_t;

typedef struct _go_sudog_t {
	// The following fields are protected by the hchan.lock of the
	// channel this sudog is blocking on. shrinkstack depends on
	// this for sudogs involved in channel ops.

	void* g; 

	void* next;
	void* prev;
	void* elem; // data element (may point to stack)

	// The following fields are never accessed concurrently.
	// For channels, waitlink is only accessed by g.
	// For semaphores, all fields (including the ones above)
	// are only accessed when holding a semaRoot lock.

	int64_t acquiretime;
	int64_t releasetime;
	uint32_t ticket;

	// isSelect indicates g is participating in a select, so
	// g.selectDone must be CAS'd to win the wake-up race.
	bool isSelect;

	void* parent; // semaRoot binary tree
	void* waitlink; // g.waiting list or semaRoot
	void* waittail; // semaRoot
	void* c; // channel
} go_sudog_t;

typedef struct _go_waitq_t {
	go_sudog_t* first;
	go_sudog_t* last;
} go_waitq_t;

typedef struct _go_runtime_mutex_t {
	int64_t rank;
	int64_t pad;
	void* key;
} go_runtime_mutex_t;

typedef struct _go_hchan_t {
	int64_t qcount;           // total data in the queue
	int64_t dataqsiz;           // size of the circular queue
	void* buf; // points to an array of dataqsiz elements
	uint16_t elemsize;
	uint32_t closed;
	void* elemtype; // element type
	uint64_t sendx;   // send index
	uint64_t recvx;   // receive index
	go_waitq_t recvq;  // list of recv waiters
	go_waitq_t sendq;  // list of send waiters

	// lock protects all fields in hchan, as well as several
	// fields in sudogs blocked on this channel.
	//
	// Do not change another G's status while holding this lock
	// (in particular, do not ready a G), as this can deadlock
	// with stack shrinking.
	go_runtime_mutex_t lock;
} go_hchan_t;



#endif // _GO_DEFINES_H_