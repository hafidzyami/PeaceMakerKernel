/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 * 
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "StackWalker.h"

/**
	Search the current process to see if any modules contain the address.
	@param Address - The address to search for.
	@param StackReturnInfo - The structure to be populated.
*/
VOID
StackWalker::ResolveAddressModule (
	_In_ PVOID Address,
	_Inout_ PSTACK_RETURN_INFO StackReturnInfo
	)
{
	NTSTATUS status;
	MEMORY_BASIC_INFORMATION meminfo;
	SIZE_T returnLength;
	SIZE_T mappedFilenameLength;
	PUNICODE_STRING mappedFilename;

	mappedFilenameLength = sizeof(UNICODE_STRING) + MAX_PATH * 2;

	//
	// Query the virtual memory to see if it's part of an image.
	//
	status = ZwQueryVirtualMemory(NtCurrentProcess(), Address, MemoryBasicInformation, &meminfo, sizeof(meminfo), &returnLength);
	if (NT_SUCCESS(status) && meminfo.Type == MEM_IMAGE)
	{
		StackReturnInfo->MemoryInModule = TRUE;
		StackReturnInfo->BinaryOffset = RCAST<ULONG64>(Address) - RCAST<ULONG64>(meminfo.AllocationBase);

		//
		// Allocate the filename.
		//
		mappedFilename = RCAST<PUNICODE_STRING>(ExAllocatePool2(POOL_FLAG_PAGED, mappedFilenameLength, STACK_WALK_MAPPED_NAME));
		if (mappedFilename == NULL)
		{
			DBGPRINT("StackWalker!ResolveAddressModule: Failed to allocate module name.");
			return;
		}

		//
		// Query the filename.
		//
		status = ZwQueryVirtualMemory(NtCurrentProcess(), Address, SCAST<MEMORY_INFORMATION_CLASS>(MemoryMappedFilenameInformation), mappedFilename, mappedFilenameLength, &mappedFilenameLength);
		if (status == STATUS_BUFFER_OVERFLOW)
		{
			//
			// If we don't have a large enough buffer, allocate one!
			//
			ExFreePoolWithTag(mappedFilename, STACK_WALK_MAPPED_NAME);
			mappedFilename = RCAST<PUNICODE_STRING>(ExAllocatePool2(POOL_FLAG_PAGED, mappedFilenameLength, STACK_WALK_MAPPED_NAME));
			if (mappedFilename == NULL)
			{
				DBGPRINT("StackWalker!ResolveAddressModule: Failed to allocate module name.");
				return;
			}
			status = ZwQueryVirtualMemory(NtCurrentProcess(), Address, SCAST<MEMORY_INFORMATION_CLASS>(MemoryMappedFilenameInformation), mappedFilename, mappedFilenameLength, &mappedFilenameLength);
		}

		if (NT_SUCCESS(status) == FALSE)
		{
			DBGPRINT("StackWalker!ResolveAddressModule: Failed to query memory module name with status 0x%X.", status);
			return;
		}

		//
		// Copy the mapped name.
		//
		RtlStringCbCopyUnicodeString(RCAST<NTSTRSAFE_PWSTR>(&StackReturnInfo->BinaryPath), sizeof(StackReturnInfo->BinaryPath), mappedFilename);

		ExFreePoolWithTag(mappedFilename, STACK_WALK_MAPPED_NAME);
	}
}

/**
	Check if the memory pointed by address is executable.
	@param Address - The address to check.
	@return Whether or not the memory is executable.
*/
BOOLEAN
StackWalker::IsAddressExecutable (
	_In_ PVOID Address
	)
{
	NTSTATUS status;
	MEMORY_BASIC_INFORMATION memoryBasicInformation;
	BOOLEAN executable;

	executable = FALSE;
	memset(&memoryBasicInformation, 0, sizeof(memoryBasicInformation));

	//
	// Query the basic information about the memory.
	//
	status = ZwQueryVirtualMemory(NtCurrentProcess(), Address, MemoryBasicInformation, &memoryBasicInformation, sizeof(memoryBasicInformation), NULL);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("StackWalker!IsAddressExecutable: Failed to query virtual memory for address 0x%llx with status 0x%X.", RCAST<ULONG64>(Address), status);
		goto Exit;
	}

	//
	// Check if the protection flags specifies executable.
	//
	executable = FlagOn(memoryBasicInformation.AllocationProtect, PAGE_EXECUTE) ||
				 FlagOn(memoryBasicInformation.AllocationProtect, PAGE_EXECUTE_READ) ||
				 FlagOn(memoryBasicInformation.AllocationProtect, PAGE_EXECUTE_READWRITE) ||
				 FlagOn(memoryBasicInformation.AllocationProtect, PAGE_EXECUTE_WRITECOPY);
Exit:
	return NT_SUCCESS(status) && executable;
}

/**
	Walk the stack of the current thread and resolve the module associated with the return addresses.
	@param ResolvedStack - Caller-supplied array of return address information that this function populates.
	@param ResolvedStackSize - The number of return addresses to resolve.
	@param ResolvedStackTag - The tag to allocate ResolvedStack with.
*/
VOID
StackWalker::WalkAndResolveStack (
	_Inout_ PSTACK_RETURN_INFO* ResolvedStack,
	_Inout_ ULONG* ResolvedStackSize,
	_In_ ULONG ResolvedStackTag
	)
{
	PVOID* stackReturnPtrs;
	ULONG capturedReturnPtrs;
	ULONG i;
	
	capturedReturnPtrs = 0;
	*ResolvedStack = NULL;

	//
	// Allocate space for the return addresses.
	//
	stackReturnPtrs = RCAST<PVOID*>(ExAllocatePool2(POOL_FLAG_PAGED, sizeof(PVOID) * *ResolvedStackSize, STACK_WALK_ARRAY_TAG));
	if (stackReturnPtrs == NULL)
	{
		DBGPRINT("StackWalker!WalkAndResolveStack: Failed to allocate space for temporary stack array.");
		goto Exit;
	}

	memset(stackReturnPtrs, 0, sizeof(PVOID) * *ResolvedStackSize);

	//
	// Get the return addresses leading up to this call.
	//
	capturedReturnPtrs = RtlWalkFrameChain(stackReturnPtrs, *ResolvedStackSize, 1);
	if (capturedReturnPtrs == 0)
	{
		DBGPRINT("StackWalker!WalkAndResolveStack: Failed to walk the stack.");
		goto Exit;
	}

	NT_ASSERT((ULONGLONG) capturedReturnPtrs < (ULONGLONG) ResolvedStackSize);

	*ResolvedStackSize = capturedReturnPtrs;

	//
	// Allocate space for the stack return info array.
	//
	*ResolvedStack = RCAST<PSTACK_RETURN_INFO>(ExAllocatePool2(POOL_FLAG_PAGED, sizeof(STACK_RETURN_INFO) * *ResolvedStackSize, ResolvedStackTag));
	if (*ResolvedStack == NULL)
	{
		DBGPRINT("StackWalker!WalkAndResolveStack: Failed to allocate space for stack info array.");
		goto Exit;
	}
	memset(*ResolvedStack, 0, sizeof(STACK_RETURN_INFO) * *ResolvedStackSize);


	//
	// Iterate each return address and fill out the struct.
	//
	for (i = 0; i < capturedReturnPtrs; i++)
	{
		(*ResolvedStack)[i].RawAddress = stackReturnPtrs[i];

		//
		// If the memory isn't executable or is in kernel, it's not worth our time.
		//
		if (RCAST<ULONG64>(stackReturnPtrs[i]) < MmUserProbeAddress && this->IsAddressExecutable(stackReturnPtrs[i]))
		{
			(*ResolvedStack)[i].ExecutableMemory = TRUE;
			this->ResolveAddressModule(stackReturnPtrs[i], &(*ResolvedStack)[i]);
		}
	}
Exit:
	if (stackReturnPtrs)
	{
		ExFreePoolWithTag(stackReturnPtrs, STACK_WALK_ARRAY_TAG);
	}
}