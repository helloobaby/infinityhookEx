/*
*	Module Name:
*		infinityhook.h
*
*	Abstract:
*		The interface to the infinity hook library.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*
*	Special thanks to Nemanja (Nemi) Mulasmajic <nm@triplefault.io>
*	for his help with the POC.
*
*/

#pragma once
#include <intrin.h>

///
/// Structures and typedefs.
///

typedef unsigned __int64  uintptr_t;
typedef int                int32_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

typedef void (__fastcall* INFINITYHOOKCALLBACK)(_In_ unsigned int SystemCallIndex, _Inout_ void** SystemCallFunction);

///
/// Forward declarations.
///

NTSTATUS IfhInitialize(
	_In_ INFINITYHOOKCALLBACK InfinityHookCallback);

void IfhRelease();

NTSTATUS hookPerformanceCounterRoutine(uintptr_t hookFunction, uintptr_t* oldFunction);

extern "C"{

	void checkLogger();
	void keQueryPerformanceCounterHook(ULONG_PTR* pStack);

}

