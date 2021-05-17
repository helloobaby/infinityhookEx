/*
*	Module Name:
*		infinityhook.cpp
*
*	Abstract:
*		The implementation details of infinity hook.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*
*	Special thanks to Nemanja (Nemi) Mulasmajic <nm@triplefault.io>
*	for his help with the POC.
*
*/

#include "stdafx.h"
#include "infinityhook.h"
#include "img.h"
#include "mm.h"



//
// Used internally for IfhpModifyTraceSettings.
//
enum CKCL_TRACE_OPERATION
{
	CKCL_TRACE_START,
	CKCL_TRACE_SYSCALL,
	CKCL_TRACE_END
};

//
// To enable/disable tracing on the circular kernel context logger.
//
typedef struct _CKCL_TRACE_PROPERIES: EVENT_TRACE_PROPERTIES
{
	ULONG64					Unknown[3];
	UNICODE_STRING			ProviderName;
} CKCL_TRACE_PROPERTIES, *PCKCL_TRACE_PROPERTIES;

static BOOLEAN IfhpResolveSymbols();

static NTSTATUS IfhpModifyTraceSettings(
	_In_ CKCL_TRACE_OPERATION Operation);

static ULONG64 IfhpInternalGetCpuClock();



//
// Works from Windows 7+. You can backport this to Vista if you
// include an OS check and add the Vista appropriate signature.
//
UCHAR EtwpDebuggerDataPattern[] = 
{ 
	0x2c, 
	0x08, 
	0x04, 
	0x38, 
	0x0c 
};


static ZWTRACECONTROL pZwTraceControl = nullptr;

//
// _WMI_LOGGER_CONTEXT.GetCpuClock.
//

#ifdef v7_7601
#define OFFSET_WMI_LOGGER_CONTEXT_CPU_CYCLE_CLOCK 0x18
#else
#define OFFSET_WMI_LOGGER_CONTEXT_CPU_CYCLE_CLOCK 0x28
#endif
//
// _KPCR.Prcb.RspBase.
//
#define OFFSET_KPCR_RSP_BASE 0x1A8

//
// _KPCR.Prcb.CurrentThread. 
//
#define OFFSET_KPCR_CURRENT_THREAD 0x188

//
// _KTHREAD.SystemCallNumber.
//
#ifdef v7_7601
#define OFFSET_KTHREAD_SYSTEM_CALL_NUMBER 0x1F8
#else
#define OFFSET_KTHREAD_SYSTEM_CALL_NUMBER 0x80
#endif // v7_7601



//
// EtwpDebuggerData silos.
//
#define OFFSET_ETW_DEBUGGER_DATA_SILO 0x10

//
// The index of the circular kernel context logger.
//
#define INDEX_CKCL_LOGGER 2

//
// Magic values on the stack. We use this to filter out system call 
// exit events.
//
#define INFINITYHOOK_MAGIC_1 ((ULONG)0x501802)
#define INFINITYHOOK_MAGIC_2 ((USHORT)0xF33)

static bool IfhpInitialized = false;
static INFINITYHOOKCALLBACK IfhpCallback = NULL;

static const void* EtwpDebuggerData = NULL;
static PVOID CkclWmiLoggerContext = NULL;
static PVOID SystemCallEntryPage = NULL;

static constexpr ULONG_PTR counterQueryRoutine = 0x70;
static uintptr_t halpPerformanceCounter;
static PWSTR wProviderName ;
static uintptr_t OriginalGetCpuClock;
//extern C for x64.asm
extern "C" {
	
	//extern 出去的不要加static
	uintptr_t halCounterQueryRoutine;


}
/*
*	Initialize infinity hook: executes your user defined callback on 
*	each syscall. You can extend this functionality to do other things
*	like trap on page faults, context switches, and more... This demo
*	only does syscalls.
*/
NTSTATUS IfhInitialize(_In_ 
	INFINITYHOOKCALLBACK InfinityHookCallback)
{
	if (IfhpInitialized)
	{
		return STATUS_ACCESS_DENIED;
	}

	//
	// Let's assume CKCL session is already started (which is the 
	// default scenario) and try to update it for system calls only.
	//
	NTSTATUS Status = IfhpModifyTraceSettings(CKCL_TRACE_SYSCALL);
	if (!NT_SUCCESS(Status))
	{
		//
		// Failed... let's try to turn it on.
		//
		Status = IfhpModifyTraceSettings(CKCL_TRACE_START);

		//
		// Failed again... We exit here, but it's possible to setup
		// a custom logger instead and use SystemTraceProvider instead
		// of hijacking the circular kernel context logger.
		//
		if (!NT_SUCCESS(Status))
		{
			return Status;
		}

		Status = IfhpModifyTraceSettings(CKCL_TRACE_SYSCALL);
		if (!NT_SUCCESS(Status))
		{
			return Status;
		}
	}	

	//
	// We need to resolve certain unexported symbols.
	//
	if (!IfhpResolveSymbols())
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	IfhpCallback = InfinityHookCallback;
	
	//
	// We care about overwriting the GetCpuClock (+0x28) pointer in 
	// this structure.
	//
	PVOID* AddressOfEtwpGetCycleCount = (PVOID*)((uintptr_t)CkclWmiLoggerContext + OFFSET_WMI_LOGGER_CONTEXT_CPU_CYCLE_CLOCK);
#ifndef v10_19041
	//
	// Replace this function pointer with our own. Each time syscall
	// is logged by ETW, it will invoke our new timing function.
	//
	*AddressOfEtwpGetCycleCount = IfhpInternalGetCpuClock;
#else
	//win10 19041

	//GetCpuClock = 1
	//Set the GetCpuClock member of WMI_LOGGER_CONTEXT to 1 so KeQueryPerformanceCounter is called
	*AddressOfEtwpGetCycleCount = (PVOID)1;

	hookPerformanceCounterRoutine((ULONG_PTR)checkLogger,&halCounterQueryRoutine);



#endif

	IfhpInitialized = true;

	return STATUS_SUCCESS;
}

/*
*	Disables and then re-enables the circular kernel context logger,
*	clearing the system of the infinity hook pointer override.
*/
void IfhRelease()
{
	if (!IfhpInitialized)
	{
		return;
	}

	if (NT_SUCCESS(IfhpModifyTraceSettings(CKCL_TRACE_END)))
	{
		IfhpModifyTraceSettings(CKCL_TRACE_START);
	}

	IfhpInitialized = false;
}

/*
*	Resolves necessary unexported symbols.
*/
static BOOLEAN IfhpResolveSymbols()
{
	//
	// We need to resolve nt!EtwpDebuggerData to get the current ETW
	// sessions WMI_LOGGER_CONTEXTS, find the CKCL, and overwrite its
	// GetCpuClock function pointer.
	//
	PVOID NtBaseAddress = NULL;
	ULONG SizeOfNt = 0;
	NtBaseAddress = ImgGetBaseAddress(NULL, &SizeOfNt);
	if (!NtBaseAddress)
	{
		return FALSE;
	}

	ULONG SizeOfSection;
	PVOID SectionBase = ImgGetImageSection(NtBaseAddress, ".data", &SizeOfSection);
	if (!SectionBase)
	{
		return FALSE;
	}

	//
	// Look for the EtwpDebuggerData global using the signature. This 
	// should be the same for Windows 7+.
	//
	EtwpDebuggerData = MmSearchMemory(SectionBase, SizeOfSection, EtwpDebuggerDataPattern, RTL_NUMBER_OF(EtwpDebuggerDataPattern));
	if (!EtwpDebuggerData)
	{
		//
		// Check inside of .rdata too... this is true for Windows 7.
		// Thanks to @ivanpos2015 for reporting.
		//

		//有些win7没有rdata段，现在.text段搜一下

		SectionBase = ImgGetImageSection(NtBaseAddress, ".text", &SizeOfSection);
		if (!SectionBase)
		{
			return FALSE;
		}

		EtwpDebuggerData = MmSearchMemory(SectionBase, SizeOfSection, EtwpDebuggerDataPattern, RTL_NUMBER_OF(EtwpDebuggerDataPattern));
		if (!EtwpDebuggerData)
		{
			//再没有再去.rdata搜一下
			SectionBase = ImgGetImageSection(NtBaseAddress, ".rdata", &SizeOfSection);
			if (!SectionBase)
			{
				return FALSE;
			}

			EtwpDebuggerData = MmSearchMemory(SectionBase, SizeOfSection, EtwpDebuggerDataPattern, RTL_NUMBER_OF(EtwpDebuggerDataPattern));
			if (!EtwpDebuggerData)
			{
				return FALSE;
			}
		}

	}

	// 
	// This is offset by 2 bytes due to where the signature starts.
	//
	EtwpDebuggerData = (PVOID)((uintptr_t)EtwpDebuggerData - 2);
	
	//
	// Get the silos of EtwpDebuggerData.
	//
	PVOID* EtwpDebuggerDataSilo = *(PVOID**)((uintptr_t)EtwpDebuggerData + OFFSET_ETW_DEBUGGER_DATA_SILO);

	//
	// Pull out the circular kernel context logger.
	//
	CkclWmiLoggerContext = EtwpDebuggerDataSilo[INDEX_CKCL_LOGGER];

	OriginalGetCpuClock = *reinterpret_cast<uint64_t*>((ULONG_PTR)CkclWmiLoggerContext + OFFSET_WMI_LOGGER_CONTEXT_CPU_CYCLE_CLOCK);

	//
	// Grab the system call entry value.
	//
	SystemCallEntryPage = PAGE_ALIGN(ImgGetSyscallEntry());
	if (!SystemCallEntryPage)
	{
		return FALSE;
	}

	return TRUE;
}

/*
*	Modify the trace settings for the circular kernel context logger.
*/
static NTSTATUS IfhpModifyTraceSettings(
	_In_ CKCL_TRACE_OPERATION Operation)
{
#ifdef v7_7601
	if (!pZwTraceControl) {
		//init func pointer

		static UCHAR ZwTraceControlPattern[10] = {
		0xB8,0x81,0x1,0x0,0x0,
		0xe9,0x2,0xde,0x0,0x0
		};

		PVOID NtBaseAddress = NULL;
		ULONG SizeOfNt = 0;
		ULONG SizeOfSection;
		NtBaseAddress = ImgGetBaseAddress(NULL, &SizeOfNt);
		if (!NtBaseAddress)
		{
			return FALSE;
		}

		auto SectionBase = ImgGetImageSection(NtBaseAddress, ".text", &SizeOfSection);
		if (!SectionBase)
		{
			return FALSE;
		}
		pZwTraceControl = (ZWTRACECONTROL)MmSearchMemory(SectionBase, SizeOfSection, ZwTraceControlPattern, RTL_NUMBER_OF(ZwTraceControlPattern));

		if (!pZwTraceControl)
			return false;

		pZwTraceControl = (ZWTRACECONTROL)((ULONG_PTR)pZwTraceControl - 0x14);
	}



#endif // v7_7601



	PCKCL_TRACE_PROPERTIES Property = (PCKCL_TRACE_PROPERTIES)ExAllocatePool(NonPagedPool, PAGE_SIZE);
	if (!Property)
	{
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	memset(Property, 0, PAGE_SIZE);

	Property->Wnode.BufferSize = PAGE_SIZE;
	Property->Wnode.Flags = WNODE_FLAG_TRACED_GUID;

	//兼容win7
	//Property->ProviderName = RTL_CONSTANT_STRING(L"Circular Kernel Context Logger");
	wProviderName = (PWSTR)ExAllocatePool(NonPagedPool, 256 * sizeof(WCHAR));
	if(!wProviderName)
		return STATUS_MEMORY_NOT_ALLOCATED;
	memset(wProviderName,0,256);
	RtlCopyMemory(wProviderName, L"Circular Kernel Context Logger", sizeof(L"Circular Kernel Context Logger"));
	RtlInitUnicodeString(&Property->ProviderName, (PCWSTR)wProviderName);


	Property->Wnode.Guid = CkclSessionGuid;
	Property->Wnode.ClientContext = 1;
	Property->BufferSize = sizeof(ULONG);
	Property->MinimumBuffers = Property->MaximumBuffers = 2;
	Property->LogFileMode = EVENT_TRACE_BUFFERING_MODE;

	NTSTATUS Status = STATUS_ACCESS_DENIED;
	ULONG ReturnLength = 0;

	//
	// Might be wise to actually hook ZwTraceControl so folks don't 
	// disable your infinity hook ;).
	//


	switch (Operation)
	{
		case CKCL_TRACE_START:
		{

#ifdef v7_7601
			Status = pZwTraceControl(EtwpStartTrace, Property, PAGE_SIZE, Property, PAGE_SIZE, &ReturnLength);
#else
			Status = ZwTraceControl(EtwpStartTrace, Property, PAGE_SIZE, Property, PAGE_SIZE, &ReturnLength);
#endif
			break;
		}
		case CKCL_TRACE_END:
		{

#ifdef v10_19041
			//高版本的win10一定要恢复
			if (halpPerformanceCounter && halCounterQueryRoutine) {
				*reinterpret_cast<uintptr_t*>(halpPerformanceCounter + 0x70) = halCounterQueryRoutine;
				//return true;
		}
			*reinterpret_cast<uint64_t*>((ULONG_PTR)CkclWmiLoggerContext + OFFSET_WMI_LOGGER_CONTEXT_CPU_CYCLE_CLOCK) = OriginalGetCpuClock;
#endif // v10_19041


#ifdef v7_7601
			Status = pZwTraceControl(EtwpStopTrace, Property, PAGE_SIZE, Property, PAGE_SIZE, &ReturnLength);
#else
			Status = ZwTraceControl(EtwpStopTrace, Property, PAGE_SIZE, Property, PAGE_SIZE, &ReturnLength);
#endif

			break;
		}
		case CKCL_TRACE_SYSCALL:
		{
			//
			// Add more flags here to trap on more events!
			//
			Property->EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;

#ifdef v7_7601
			Status = pZwTraceControl(EtwpUpdateTrace, Property, PAGE_SIZE, Property, PAGE_SIZE, &ReturnLength);
#else
			Status = ZwTraceControl(EtwpUpdateTrace, Property, PAGE_SIZE, Property, PAGE_SIZE, &ReturnLength);
#endif

			break;
		}
	}

	ExFreePool(Property);

	return Status;
}

/*
*	We replaced the GetCpuClock pointer to this one here which 
*	implements stack walking logic. We use this to determine whether 
*	a syscall occurred. It also provides you a way to alter the 
*	address on the stack to redirect execution to your detoured
*	function.
*	
*/
static ULONG64 IfhpInternalGetCpuClock()
{
	if (ExGetPreviousMode() == KernelMode)
	{
		return __rdtsc();
	}

	//
	// Extract the system call index (if you so desire).
	//
	PKTHREAD CurrentThread = (PKTHREAD)__readgsqword(OFFSET_KPCR_CURRENT_THREAD);
	unsigned int SystemCallIndex = *(unsigned int*)((uintptr_t)CurrentThread + OFFSET_KTHREAD_SYSTEM_CALL_NUMBER);

	PVOID* StackMax = (PVOID*)__readgsqword(OFFSET_KPCR_RSP_BASE);
	PVOID* StackFrame = (PVOID*)_AddressOfReturnAddress();

	//
	// First walk backwards on the stack to find the 2 magic values.
	//
	for (PVOID* StackCurrent = StackMax; 
		StackCurrent > StackFrame;
		--StackCurrent)
	{
		// 
		// This is intentionally being read as 4-byte magic on an 8
		// byte aligned boundary.
		//
		PULONG AsUlong = (PULONG)StackCurrent;
		if (*AsUlong != INFINITYHOOK_MAGIC_1)
		{
			continue;
		}

		// 
		// If the first magic is set, check for the second magic.
		//
		--StackCurrent;

		PUSHORT AsShort = (PUSHORT)StackCurrent;
		if (*AsShort != INFINITYHOOK_MAGIC_2)
		{
			continue;
		}

		//
		// Now we reverse the direction of the stack walk.
		//
		for (;
			StackCurrent < StackMax;
			++StackCurrent)
		{
			PULONGLONG AsUlonglong = (PULONGLONG)StackCurrent;

			if (!(PAGE_ALIGN(*AsUlonglong) >= SystemCallEntryPage && 
				PAGE_ALIGN(*AsUlonglong) < (PVOID)((uintptr_t)SystemCallEntryPage + (PAGE_SIZE * 2))))
			{
				continue;
			}

			//
			// If you want to "hook" this function, replace this stack memory 
			// with a pointer to your own function.
			//
			void** SystemCallFunction = &StackCurrent[9];

			if (IfhpCallback)
			{
				IfhpCallback(SystemCallIndex, SystemCallFunction);
			}

			break;
		}

		break;
	}

	return __rdtsc();
}

NTSTATUS hookPerformanceCounterRoutine(uintptr_t hookFunction, uintptr_t* oldFunction) {



	UNICODE_STRING keQueryPerformanceCounterUnicode = RTL_CONSTANT_STRING(L"KeQueryPerformanceCounter");
	const auto keQueryPerformanceCounter = reinterpret_cast<uintptr_t>(
		MmGetSystemRoutineAddress(&keQueryPerformanceCounterUnicode));

	if (!keQueryPerformanceCounter)
		return STATUS_NOT_FOUND;



	//首先找到HalpPerformanceCounter变量
	//距离KeQueryPerformanceCounter0x12的位置mov rdi,cs:HalpPerformanceCounter
		
	//19041的几个小版本之前特征码也不一样，这里直接加0x12
	halpPerformanceCounter = keQueryPerformanceCounter + 0x12;

	auto saddr = halpPerformanceCounter;
	halpPerformanceCounter += 3;
	halpPerformanceCounter = saddr + *reinterpret_cast<int32_t*>(halpPerformanceCounter) + 7;
	halpPerformanceCounter = *reinterpret_cast<uintptr_t*>(halpPerformanceCounter);

	*oldFunction = *reinterpret_cast<uintptr_t*>(halpPerformanceCounter + 0x70);

	*reinterpret_cast<uintptr_t*>(halpPerformanceCounter + 0x70) = hookFunction;


	/*	
kd> !pte fffff803`3c994b50
										   VA fffff8033c994b50
PXE at FFFFFF7FBFDFEF80    PPE at FFFFFF7FBFDF0060    PDE at FFFFFF7FBE00CF20    PTE at FFFFFF7C019E4CA0
contains 0000000000B49063  contains 0000000000B4A063  contains 0000000000B97063  contains 0900000002389121
pfn b49       ---DA--KWEV  pfn b4a       ---DA--KWEV  pfn b97       ---DA--KWEV  pfn 2389      -G--A--KREV
	*/

	return STATUS_SUCCESS;

}


void keQueryPerformanceCounterHook(ULONG_PTR* pStack){

	if (ExGetPreviousMode() == KernelMode) {
		return;
	}


	//
	// Extract the system call index (if you so desire).
	//
	PKTHREAD CurrentThread = (PKTHREAD)__readgsqword(OFFSET_KPCR_CURRENT_THREAD);
	unsigned int SystemCallIndex = *(unsigned int*)((uintptr_t)CurrentThread + OFFSET_KTHREAD_SYSTEM_CALL_NUMBER);

	for (size_t i = 0; i < 10; i++) {
	
		if (pStack[i] == (ULONG_PTR)CkclWmiLoggerContext) {

			if (!SystemCallIndex)
				return;

			auto stack = (ULONG_PTR)pStack + 0x280;


			if (IfhpCallback)
			{
				IfhpCallback(SystemCallIndex, (void**)stack);
			}

		}

	}


	return;
}