/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 * 
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "common.h"
#include "shared.h"

void* __cdecl operator new(size_t size, POOL_TYPE pool, ULONG tag) {
	POOL_FLAGS poolflags = 0; // create from pool
	switch (pool) {
	case NonPagedPool:
		poolflags = POOL_FLAG_NON_PAGED_EXECUTE;
	case PagedPool:
		poolflags = POOL_FLAG_PAGED;
	case NonPagedPoolMustSucceed:
		poolflags = POOL_FLAG_NON_PAGED_EXECUTE | POOL_FLAG_RAISE_ON_FAILURE;
	case DontUseThisType:
		poolflags = 0;
	case NonPagedPoolCacheAligned:
		poolflags = POOL_FLAG_NON_PAGED_EXECUTE | POOL_FLAG_CACHE_ALIGNED;
	case PagedPoolCacheAligned:
		poolflags = POOL_FLAG_PAGED | POOL_FLAG_CACHE_ALIGNED;
	case NonPagedPoolCacheAlignedMustS:
		poolflags = POOL_FLAG_NON_PAGED_EXECUTE | POOL_FLAG_CACHE_ALIGNED | POOL_FLAG_RAISE_ON_FAILURE;
	case MaxPoolType:
		poolflags = 0;
	case NonPagedPoolSession:
		poolflags = POOL_FLAG_NON_PAGED_EXECUTE | POOL_FLAG_SESSION;
	case PagedPoolSession:
		poolflags = POOL_FLAG_PAGED | POOL_FLAG_SESSION;
	case NonPagedPoolMustSucceedSession:
		poolflags = POOL_FLAG_NON_PAGED_EXECUTE | POOL_FLAG_RAISE_ON_FAILURE | POOL_FLAG_SESSION;
	case DontUseThisTypeSession:
		poolflags = 0 | POOL_FLAG_SESSION;
	case NonPagedPoolCacheAlignedSession:
		poolflags = POOL_FLAG_NON_PAGED_EXECUTE | POOL_FLAG_CACHE_ALIGNED | POOL_FLAG_SESSION;
	case PagedPoolCacheAlignedSession:
		poolflags = POOL_FLAG_PAGED | POOL_FLAG_CACHE_ALIGNED | POOL_FLAG_SESSION;
	case NonPagedPoolCacheAlignedMustSSession:
		poolflags = POOL_FLAG_NON_PAGED_EXECUTE | POOL_FLAG_CACHE_ALIGNED | POOL_FLAG_RAISE_ON_FAILURE | POOL_FLAG_SESSION;
	case NonPagedPoolNx:
		poolflags = POOL_FLAG_NON_PAGED;
	case NonPagedPoolNxCacheAligned:
		poolflags = POOL_FLAG_NON_PAGED | POOL_FLAG_CACHE_ALIGNED;
	case NonPagedPoolSessionNx:
		poolflags = POOL_FLAG_NON_PAGED | POOL_FLAG_SESSION;
	}
	PVOID newAddress = ExAllocatePool2(poolflags, size, tag);
	//
	// Remove remenants from previous use.
	//
	if (newAddress)
	{
		memset(newAddress, 0, size);
	}
	return newAddress;
}

void __cdecl operator delete(void* p, unsigned __int64) {
	ExFreePool(p);
}

PPEB PsGetProcessPeb(IN PEPROCESS Process)
{
	UNICODE_STRING funcName;
	typedef PPEB(NTAPI* PsGetProcessPeb_t)(PEPROCESS Process);
	static PsGetProcessPeb_t fPsGetProcessPeb = NULL;

	if (fPsGetProcessPeb == NULL)
	{
		RtlInitUnicodeString(&funcName, L"PsGetProcessPeb");
		fPsGetProcessPeb = RCAST<PsGetProcessPeb_t>(MmGetSystemRoutineAddress(&funcName));
	}

	return fPsGetProcessPeb(Process);
}

NTSTATUS NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
	UNICODE_STRING funcName;
	typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
	static NtQueryInformationProcess_t fNtQueryInformationProcess = NULL;

	if (fNtQueryInformationProcess == NULL)
	{
		RtlInitUnicodeString(&funcName, L"ZwQueryInformationProcess");
		fNtQueryInformationProcess = RCAST<NtQueryInformationProcess_t>(MmGetSystemRoutineAddress(&funcName));
	}

	return fNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

NTSTATUS NtQueryInformationThread(_In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _Out_ PVOID ThreadInformation, _In_ ULONG ThreadInformationLength, _Out_ PULONG ReturnLength)
{
	UNICODE_STRING funcName;
	typedef NTSTATUS(NTAPI * NtQueryInformationThread_t)(_In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _Out_ PVOID ThreadInformation, _In_ ULONG ThreadInformationLength, _Out_ PULONG ReturnLength);
	static NtQueryInformationThread_t fNtQueryInformationThread = NULL;

	if (fNtQueryInformationThread == NULL)
	{
		RtlInitUnicodeString(&funcName, L"ZwQueryInformationThread");
		fNtQueryInformationThread = RCAST<NtQueryInformationThread_t>(MmGetSystemRoutineAddress(&funcName));
	}

	return fNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
}
