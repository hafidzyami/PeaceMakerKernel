#include "ImageFilter.h"

// Initialize static member variables
StackWalker ImageFilter::walker;
PPROCESS_HISTORY_ENTRY ImageFilter::ProcessHistoryHead;
EX_PUSH_LOCK ImageFilter::ProcessHistoryLock;
BOOLEAN ImageFilter::destroying;
ULONG64 ImageFilter::ProcessHistorySize;
PDETECTION_LOGIC ImageFilter::detector;

/**
	Register the necessary notify routines.
	@param Detector - Detection instance used to analyze untrusted operations.
	@param InitializeStatus - Status of initialization.
*/
ImageFilter::ImageFilter (
	_In_ PDETECTION_LOGIC Detector,
	_Out_ NTSTATUS* InitializeStatus
	)
{
	NTSTATUS tempStatus = STATUS_SUCCESS;
	
	//
	// Initialize process history components
	//
	
	//
	// Set the create process notify routine.
	//
	tempStatus = PsSetCreateProcessNotifyRoutineEx(ImageFilter::CreateProcessNotifyRoutine, FALSE);
	if (NT_SUCCESS(tempStatus) == FALSE)
	{
		DBGPRINT("ImageFilter!ImageFilter: Failed to register create process notify routine with status 0x%X.", tempStatus);
		*InitializeStatus = tempStatus;
		return;
	}
	
	//
	// Set the load image notify routine.
	//
	tempStatus = PsSetLoadImageNotifyRoutine(ImageFilter::LoadImageNotifyRoutine);
	if (NT_SUCCESS(tempStatus) == FALSE)
	{
		DBGPRINT("ImageFilter!ImageFilter: Failed to register load image notify routine with status 0x%X.", tempStatus);
		*InitializeStatus = tempStatus;
		return;
	}

	FltInitializePushLock(&ImageFilter::ProcessHistoryLock);

	ImageFilter::ProcessHistoryHead = RCAST<PPROCESS_HISTORY_ENTRY>(ExAllocatePool2(POOL_FLAG_PAGED, sizeof(PROCESS_HISTORY_ENTRY), PROCESS_HISTORY_TAG));
	if (ImageFilter::ProcessHistoryHead == NULL)
	{
		DBGPRINT("ImageFilter!ImageFilter: Failed to allocate the process history head.");
		*InitializeStatus = STATUS_NO_MEMORY;
		return;
	}
	memset(ImageFilter::ProcessHistoryHead, 0, sizeof(PROCESS_HISTORY_ENTRY));
	InitializeListHead(RCAST<PLIST_ENTRY>(ImageFilter::ProcessHistoryHead));
	this->ProcessHistorySize = 0;

	//
	// Set the detector.
	//
	ImageFilter::detector = Detector;
	
	//
	// Initialize thread filter components
	//
	
	//
	// Create a thread notify routine.
	//
	tempStatus = PsSetCreateThreadNotifyRoutine(ImageFilter::ThreadNotifyRoutine);
	if (NT_SUCCESS(tempStatus) == FALSE)
	{
		DBGPRINT("ImageFilter!ImageFilter: Failed to create thread notify routine with status 0x%X.", tempStatus);
		*InitializeStatus = tempStatus;
		return;
	}
	
	*InitializeStatus = STATUS_SUCCESS;
}

/**
	Clean up and remove notify routines.
*/
ImageFilter::~ImageFilter (
	VOID
	)
{
	PPROCESS_HISTORY_ENTRY currentProcessHistory;
	PIMAGE_LOAD_HISTORY_ENTRY currentImageEntry;

	//
	// Set destroying to TRUE so that no other threads can get a lock.
	//
	ImageFilter::destroying = TRUE;

	//
	// Remove all notify routines.
	//
	PsSetCreateProcessNotifyRoutineEx(ImageFilter::CreateProcessNotifyRoutine, TRUE);
	PsRemoveLoadImageNotifyRoutine(ImageFilter::LoadImageNotifyRoutine);
	PsRemoveCreateThreadNotifyRoutine(ImageFilter::ThreadNotifyRoutine);

	//
	// Acquire an exclusive lock to push out other threads.
	//
	FltAcquirePushLockExclusive(&ImageFilter::ProcessHistoryLock);

	//
	// Release the lock.
	//
	FltReleasePushLock(&ImageFilter::ProcessHistoryLock);

	//
	// Delete the lock for the process history linked-list.
	//
	FltDeletePushLock(&ImageFilter::ProcessHistoryLock);

	//
	// Go through each process history and free it.
	//
	if (ImageFilter::ProcessHistoryHead)
	{
		while (IsListEmpty(RCAST<PLIST_ENTRY>(ImageFilter::ProcessHistoryHead)) == FALSE)
		{
			currentProcessHistory = RCAST<PPROCESS_HISTORY_ENTRY>(RemoveHeadList(RCAST<PLIST_ENTRY>(ImageFilter::ProcessHistoryHead)));
			//
			// Clear the images linked-list.
			//
			FltDeletePushLock(&currentProcessHistory->ImageLoadHistoryLock);
			if (currentProcessHistory->ImageLoadHistory)
			{
				while (IsListEmpty(RCAST<PLIST_ENTRY>(currentProcessHistory->ImageLoadHistory)) == FALSE)
				{
					currentImageEntry = RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(RemoveHeadList(RCAST<PLIST_ENTRY>(currentProcessHistory->ImageLoadHistory)));

					//
					// Free the image name.
					//
					if (currentImageEntry->ImageFileName.Buffer)
					{
						ExFreePoolWithTag(currentImageEntry->ImageFileName.Buffer, IMAGE_NAME_TAG);
					}

					if (currentImageEntry->CallerImageFileName)
					{
						ExFreePoolWithTag(currentImageEntry->CallerImageFileName, IMAGE_NAME_TAG);
					}

					//
					// Free the stack history.
					//
					ExFreePoolWithTag(currentImageEntry->CallerStackHistory, STACK_HISTORY_TAG);

					ExFreePoolWithTag(currentImageEntry, IMAGE_HISTORY_TAG);
				}

				//
				// Finally, free the list head.
				//
				ExFreePoolWithTag(currentProcessHistory->ImageLoadHistory, IMAGE_HISTORY_TAG);
			}

			//
			// Free the names.
			//
			if (currentProcessHistory->ProcessImageFileName)
			{
				ExFreePoolWithTag(currentProcessHistory->ProcessImageFileName, IMAGE_NAME_TAG);
			}
			if (currentProcessHistory->CallerImageFileName)
			{
				ExFreePoolWithTag(currentProcessHistory->CallerImageFileName, IMAGE_NAME_TAG);
			}
			if (currentProcessHistory->ParentImageFileName)
			{
				ExFreePoolWithTag(currentProcessHistory->ParentImageFileName, IMAGE_NAME_TAG);
			}
			if (currentProcessHistory->ProcessCommandLine)
			{
				ExFreePoolWithTag(currentProcessHistory->ProcessCommandLine, IMAGE_COMMMAND_TAG);
			}

			//
			// Free the stack history.
			//
			ExFreePoolWithTag(currentProcessHistory->CallerStackHistory, STACK_HISTORY_TAG);

			//
			// Free the process history.
			//
			ExFreePoolWithTag(currentProcessHistory, PROCESS_HISTORY_TAG);
		}

		//
		// Finally, free the list head.
		//
		ExFreePoolWithTag(ImageFilter::ProcessHistoryHead, PROCESS_HISTORY_TAG);
	}
}

/**
	Add a process to the linked-list of process history objects. This function attempts to add a history object regardless of failures.
	@param ProcessId - The process ID of the process to add.
	@param CreateInfo - Information about the process being created.
*/
VOID
ImageFilter::AddProcessToHistory (
	_In_ HANDLE ProcessId,
	_In_ PPS_CREATE_NOTIFY_INFO CreateInfo
	)
{
	NTSTATUS status;
	PPROCESS_HISTORY_ENTRY newProcessHistory;
	LARGE_INTEGER systemTime;
	LARGE_INTEGER localSystemTime;
	BOOLEAN processHistoryLockHeld;

	processHistoryLockHeld = FALSE;
	status = STATUS_SUCCESS;

	if (ImageFilter::destroying)
	{
		return;
	}

	newProcessHistory = RCAST<PPROCESS_HISTORY_ENTRY>(ExAllocatePool2(POOL_FLAG_PAGED, sizeof(PROCESS_HISTORY_ENTRY), PROCESS_HISTORY_TAG));
	if (newProcessHistory == NULL)
	{
		DBGPRINT("ImageFilter!AddProcessToHistory: Failed to allocate space for the process history.");
		status = STATUS_NO_MEMORY;
		goto Exit;
	}

	memset(newProcessHistory, 0, sizeof(PROCESS_HISTORY_ENTRY));

	//
	// Basic fields.
	//
	newProcessHistory->ProcessId = ProcessId;
	newProcessHistory->ParentId = CreateInfo->ParentProcessId;
	newProcessHistory->CallerId = PsGetCurrentProcessId();
	newProcessHistory->ProcessTerminated = FALSE;
	newProcessHistory->ImageLoadHistorySize = 0;
	KeQuerySystemTime(&systemTime);
	ExSystemTimeToLocalTime(&systemTime, &localSystemTime);
	newProcessHistory->EpochExecutionTime = localSystemTime.QuadPart / TICKSPERSEC - SECS_1601_TO_1970;
	//
	// Image file name fields.
	//
	
	//
	// Allocate the necessary space.
	//
	newProcessHistory->ProcessImageFileName = RCAST<PUNICODE_STRING>(ExAllocatePool2(POOL_FLAG_PAGED, sizeof(UNICODE_STRING) + CreateInfo->ImageFileName->Length, IMAGE_NAME_TAG));
	if (newProcessHistory->ProcessImageFileName == NULL)
	{
		DBGPRINT("ImageFilter!AddProcessToHistory: Failed to allocate space for process ImageFileName.");
		goto Exit;
	}

	newProcessHistory->ProcessImageFileName->Buffer = RCAST<PWCH>(RCAST<ULONG_PTR>(newProcessHistory->ProcessImageFileName) + sizeof(UNICODE_STRING));
	newProcessHistory->ProcessImageFileName->Length = CreateInfo->ImageFileName->Length;
	newProcessHistory->ProcessImageFileName->MaximumLength = CreateInfo->ImageFileName->Length;

	//
	// Copy the image file name string.
	//
	RtlCopyUnicodeString(newProcessHistory->ProcessImageFileName, CreateInfo->ImageFileName);

	//
	// Allocate the necessary space.
	//
	if (CreateInfo->CommandLine)
	{
		newProcessHistory->ProcessCommandLine = RCAST<PUNICODE_STRING>(ExAllocatePool2(POOL_FLAG_PAGED, sizeof(UNICODE_STRING) + CreateInfo->CommandLine->Length, IMAGE_COMMMAND_TAG));
		if (newProcessHistory->ProcessCommandLine == NULL)
		{
			DBGPRINT("ImageFilter!AddProcessToHistory: Failed to allocate space for process command line.");
			goto Exit;
		}

		newProcessHistory->ProcessCommandLine->Buffer = RCAST<PWCH>(RCAST<ULONG_PTR>(newProcessHistory->ProcessCommandLine) + sizeof(UNICODE_STRING));
		newProcessHistory->ProcessCommandLine->Length = CreateInfo->CommandLine->Length;
		newProcessHistory->ProcessCommandLine->MaximumLength = CreateInfo->CommandLine->Length;

		//
		// Copy the command line string.
		//
		RtlCopyUnicodeString(newProcessHistory->ProcessCommandLine, CreateInfo->CommandLine);
	}
	//
	// These fields are optional.
	//
	ImageFilter::GetProcessImageFileName(CreateInfo->ParentProcessId, &newProcessHistory->ParentImageFileName);

	if (PsGetCurrentProcessId() != CreateInfo->ParentProcessId)
	{
		ImageFilter::GetProcessImageFileName(PsGetCurrentProcessId(), &newProcessHistory->CallerImageFileName);
	}

	//
	// Grab the user-mode stack.
	//
	newProcessHistory->CallerStackHistorySize = MAX_STACK_RETURN_HISTORY; // Will be updated in the resolve function.
	walker.WalkAndResolveStack(&newProcessHistory->CallerStackHistory, &newProcessHistory->CallerStackHistorySize, STACK_HISTORY_TAG);
	if (newProcessHistory->CallerStackHistory == NULL)
	{
		DBGPRINT("ImageFilter!AddProcessToHistory: Failed to allocate space for the stack history.");
		status = STATUS_NO_MEMORY;
		goto Exit;
	}

	newProcessHistory->ImageLoadHistory = RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(ExAllocatePool2(POOL_FLAG_PAGED, sizeof(IMAGE_LOAD_HISTORY_ENTRY), IMAGE_HISTORY_TAG));
	if (newProcessHistory->ImageLoadHistory == NULL)
	{
		DBGPRINT("ImageFilter!AddProcessToHistory: Failed to allocate space for the image load history.");
		status = STATUS_NO_MEMORY;
		goto Exit;
	}
	memset(newProcessHistory->ImageLoadHistory, 0, sizeof(IMAGE_LOAD_HISTORY_ENTRY));

	InitializeListHead(RCAST<PLIST_ENTRY>(newProcessHistory->ImageLoadHistory));

	//
	// Initialize this last so we don't have to delete it if anything failed.
	//
	FltInitializePushLock(&newProcessHistory->ImageLoadHistoryLock);

	//
	// Grab a lock to add an entry.
	//
	FltAcquirePushLockExclusive(&ImageFilter::ProcessHistoryLock);

	InsertTailList(RCAST<PLIST_ENTRY>(ImageFilter::ProcessHistoryHead), RCAST<PLIST_ENTRY>(newProcessHistory));
	ImageFilter::ProcessHistorySize++;

	FltReleasePushLock(&ImageFilter::ProcessHistoryLock);

	//
	// Audit the stack.
	//
	ImageFilter::detector->AuditUserStackWalk(ProcessCreate,
													 newProcessHistory->ProcessId,
													 newProcessHistory->ParentImageFileName,
													 newProcessHistory->ProcessImageFileName,
													 newProcessHistory->CallerStackHistory,
													 newProcessHistory->CallerStackHistorySize);

	//
	// Check for parent process ID spoofing.
	//
	ImageFilter::detector->AuditCallerProcessId(ProcessCreate,
													   PsGetCurrentProcessId(),
													   CreateInfo->ParentProcessId,
													   newProcessHistory->ParentImageFileName,
													   newProcessHistory->ProcessImageFileName,
													   newProcessHistory->CallerStackHistory,
													   newProcessHistory->CallerStackHistorySize);
Exit:
	if (newProcessHistory && NT_SUCCESS(status) == FALSE)
	{
		ExFreePoolWithTag(newProcessHistory, PROCESS_HISTORY_TAG);
	}
}

/**
	Set a process to terminated, still maintain the history.
	@param ProcessId - The process ID of the process being terminated.
*/
VOID
ImageFilter::TerminateProcessInHistory (
	_In_ HANDLE ProcessId
	)
{
	PPROCESS_HISTORY_ENTRY currentProcessHistory;

	if (ImageFilter::destroying)
	{
		return;
	}

	//
	// Acquire a shared lock to iterate processes.
	//
	FltAcquirePushLockShared(&ImageFilter::ProcessHistoryLock);

	//
	// Iterate histories for a match.
	//
	if (ImageFilter::ProcessHistoryHead)
	{
		currentProcessHistory = ImageFilter::ProcessHistoryHead;
		do
		{
			//
			// Find the process history with the same PID and then set it to terminated.
			//
			if (currentProcessHistory->ProcessId == ProcessId)
			{
				currentProcessHistory->ProcessTerminated = TRUE;
				break;
			}
			currentProcessHistory = RCAST<PPROCESS_HISTORY_ENTRY>(currentProcessHistory->ListEntry.Blink);
		} while (currentProcessHistory && currentProcessHistory != ImageFilter::ProcessHistoryHead);
	}

	//
	// Release the lock.
	//
	FltReleasePushLock(&ImageFilter::ProcessHistoryLock);
}

/**
	Notify routine called on new process execution.
	@param Process - The EPROCESS structure of the new/terminating process.
	@param ProcessId - The new child's process ID.
	@param CreateInfo - Information about the process being created.
*/
VOID
ImageFilter::CreateProcessNotifyRoutine (
	_In_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_In_ PPS_CREATE_NOTIFY_INFO CreateInfo
	)
{
	UNREFERENCED_PARAMETER(Process);
	//
	// If a new process is being created, add it to the history of processes.
	//
	if (CreateInfo)
	{
		ImageFilter::AddProcessToHistory(ProcessId, CreateInfo);
		DBGPRINT("ImageFilter!CreateProcessNotifyRoutine: Registered process 0x%X.", ProcessId);
	}
	else
	{
		DBGPRINT("ImageFilter!CreateProcessNotifyRoutine: Terminating process 0x%X.", ProcessId);
		//
		// Set the process as "terminated".
		//
		ImageFilter::TerminateProcessInHistory(ProcessId);
	}
}

/**
	Retrieve the full image file name for a process.
	@param ProcessId - The process to get the name of.
	@param ProcessImageFileName - PUNICODE_STRING to fill with the image file name of the process.
*/
BOOLEAN
ImageFilter::GetProcessImageFileName (
	_In_ HANDLE ProcessId,
	_Inout_ PUNICODE_STRING* ImageFileName
	)
{
	NTSTATUS status;
	PEPROCESS processObject;
	HANDLE processHandle;
	ULONG returnLength;

	processHandle = NULL;
	*ImageFileName = NULL;
	returnLength = 0;

	//
	// Before we can open a handle to the process, we need its PEPROCESS object.
	//
	status = PsLookupProcessByProcessId(ProcessId, &processObject);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("ImageFilter!GetProcessImageFileName: Failed to find process object with status 0x%X.", status);
		goto Exit;
	}

	//
	// Open a handle to the process.
	//
	status = ObOpenObjectByPointer(processObject, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, GENERIC_ALL, *PsProcessType, KernelMode, &processHandle);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("ImageFilter!GetProcessImageFileName: Failed to open handle to process with status 0x%X.", status);
		goto Exit;
	}

	//
	// Query for the size of the UNICODE_STRING.
	//
	status = NtQueryInformationProcess(processHandle, ProcessImageFileName, NULL, 0, &returnLength);
	if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW)
	{
		DBGPRINT("ImageFilter!GetProcessImageFileName: Failed to query size of process ImageFileName with status 0x%X.", status);
		goto Exit;
	}

	//
	// Allocate the necessary space.
	//
	*ImageFileName = RCAST<PUNICODE_STRING>(ExAllocatePool2(POOL_FLAG_PAGED, returnLength, IMAGE_NAME_TAG));
	if (*ImageFileName == NULL)
	{
		DBGPRINT("ImageFilter!GetProcessImageFileName: Failed to allocate space for process ImageFileName.");
		goto Exit;
	}

	//
	// Query the image file name.
	//
	status = NtQueryInformationProcess(processHandle, ProcessImageFileName, *ImageFileName, returnLength, &returnLength);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("ImageFilter!GetProcessImageFileName: Failed to query process ImageFileName with status 0x%X.", status);
		goto Exit;
	}
Exit:
	if (processHandle)
	{
		ZwClose(processHandle);
	}
	if (NT_SUCCESS(status) == FALSE && *ImageFileName)
	{
		ExFreePoolWithTag(*ImageFileName, IMAGE_NAME_TAG);
		*ImageFileName = NULL;
	}
	return NT_SUCCESS(status);
}

/**
	Notify routine called when a new image is loaded into a process. Adds the image to the corresponding process history element.
	@param FullImageName - A PUNICODE_STRING that identifies the executable image file. Might be NULL.
	@param ProcessId - The process ID where this image is being mapped.
	@param ImageInfo - Structure containing a variety of properties about the image being loaded.
*/
VOID
ImageFilter::LoadImageNotifyRoutine(
	_In_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
	)
{
	NTSTATUS status;
	PPROCESS_HISTORY_ENTRY currentProcessHistory;
	PIMAGE_LOAD_HISTORY_ENTRY newImageLoadHistory;

	UNREFERENCED_PARAMETER(ImageInfo);

	currentProcessHistory = NULL;
	newImageLoadHistory = NULL;
	status = STATUS_SUCCESS;

	if (ImageFilter::destroying)
	{
		return;
	}

	//
	// Acquire a shared lock to iterate processes.
	//
	FltAcquirePushLockShared(&ImageFilter::ProcessHistoryLock);

	//
	// Iterate histories for a match.
	//
	if (ImageFilter::ProcessHistoryHead)
	{
		currentProcessHistory = ImageFilter::ProcessHistoryHead;
		do
		{
			if (currentProcessHistory->ProcessId == ProcessId && currentProcessHistory->ProcessTerminated == FALSE)
			{
				break;
			}
			currentProcessHistory = RCAST<PPROCESS_HISTORY_ENTRY>(currentProcessHistory->ListEntry.Blink);
		} while (currentProcessHistory && currentProcessHistory != ImageFilter::ProcessHistoryHead);
	}

	//
	// This might happen if we load on a running machine that already has processes.
	//
	if (currentProcessHistory == NULL || currentProcessHistory == ImageFilter::ProcessHistoryHead)
	{
		DBGPRINT("ImageFilter!LoadImageNotifyRoutine: Failed to find PID 0x%X in history.", ProcessId);
		status = STATUS_NOT_FOUND;
		goto Exit;
	}

	//
	// Allocate space for the new image history entry.
	//
	newImageLoadHistory = RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(ExAllocatePool2(POOL_FLAG_PAGED, sizeof(IMAGE_LOAD_HISTORY_ENTRY), IMAGE_HISTORY_TAG));
	if (newImageLoadHistory == NULL)
	{
		DBGPRINT("ImageFilter!LoadImageNotifyRoutine: Failed to allocate space for the image history entry.");
		status = STATUS_NO_MEMORY;
		goto Exit;
	}
	memset(newImageLoadHistory, 0, sizeof(IMAGE_LOAD_HISTORY_ENTRY));

	newImageLoadHistory->CallerProcessId = PsGetCurrentProcessId();
	if (PsGetCurrentProcessId() != ProcessId)
	{
		newImageLoadHistory->RemoteImage = TRUE;
		ImageFilter::GetProcessImageFileName(PsGetCurrentProcessId(), &newImageLoadHistory->CallerImageFileName);
	}

	//
	// Copy the image file name if it is provided.
	//
	if (FullImageName)
	{
		//
		// Allocate the copy buffer. FullImageName will not be valid forever.
		//
		newImageLoadHistory->ImageFileName.Buffer = RCAST<PWCH>(ExAllocatePool2(POOL_FLAG_PAGED, SCAST<SIZE_T>(FullImageName->Length) + 2, IMAGE_NAME_TAG));
		if (newImageLoadHistory->ImageFileName.Buffer == NULL)
		{
			DBGPRINT("ImageFilter!LoadImageNotifyRoutine: Failed to allocate space for the image file name.");
			status = STATUS_NO_MEMORY;
			goto Exit;
		}

		newImageLoadHistory->ImageFileName.Length = SCAST<SIZE_T>(FullImageName->Length) + 2;
		newImageLoadHistory->ImageFileName.MaximumLength = SCAST<SIZE_T>(FullImageName->Length) + 2;

		//
		// Copy the image name.
		//
		status = RtlStringCbCopyUnicodeString(newImageLoadHistory->ImageFileName.Buffer, SCAST<SIZE_T>(FullImageName->Length) + 2, FullImageName);
		if (NT_SUCCESS(status) == FALSE)
		{
			DBGPRINT("ImageFilter!LoadImageNotifyRoutine: Failed to copy the image file name with status 0x%X. Destination size = 0x%X, Source Size = 0x%X.", status, SCAST<SIZE_T>(FullImageName->Length) + 2, SCAST<SIZE_T>(FullImageName->Length));
			goto Exit;
		}
	}

	//
	// Grab the user-mode stack.
	//
	newImageLoadHistory->CallerStackHistorySize = MAX_STACK_RETURN_HISTORY; // Will be updated in the resolve function.
	walker.WalkAndResolveStack(&newImageLoadHistory->CallerStackHistory, &newImageLoadHistory->CallerStackHistorySize, STACK_HISTORY_TAG);
	if (newImageLoadHistory->CallerStackHistory == NULL)
	{
		DBGPRINT("ImageFilter!LoadImageNotifyRoutine: Failed to allocate space for the stack history.");
		status = STATUS_NO_MEMORY;
		goto Exit;
	}

	FltAcquirePushLockExclusive(&currentProcessHistory->ImageLoadHistoryLock);

	InsertHeadList(RCAST<PLIST_ENTRY>(currentProcessHistory->ImageLoadHistory), RCAST<PLIST_ENTRY>(newImageLoadHistory));
	currentProcessHistory->ImageLoadHistorySize++;

	FltReleasePushLock(&currentProcessHistory->ImageLoadHistoryLock);

	//
	// Audit the stack.
	//
	ImageFilter::detector->AuditUserStackWalk(ImageLoad,
													 PsGetCurrentProcessId(),
													 currentProcessHistory->ProcessImageFileName,
													 &newImageLoadHistory->ImageFileName,
													 newImageLoadHistory->CallerStackHistory,
													 newImageLoadHistory->CallerStackHistorySize);
Exit:
	//
	// Release the lock.
	//
	FltReleasePushLock(&ImageFilter::ProcessHistoryLock);

	//
	// Clean up on failure.
	//
	if (newImageLoadHistory && NT_SUCCESS(status) == FALSE)
	{
		if (newImageLoadHistory->ImageFileName.Buffer)
		{
			ExFreePoolWithTag(newImageLoadHistory->ImageFileName.Buffer, IMAGE_NAME_TAG);
			DBGPRINT("Free'd 'PmIn' at 0x%llx.", newImageLoadHistory->ImageFileName.Buffer);
		}
		if (newImageLoadHistory->CallerStackHistory)
		{
			ExFreePoolWithTag(newImageLoadHistory->CallerStackHistory, STACK_HISTORY_TAG);
			DBGPRINT("Free'd 'PmSh' at 0x%llx.", newImageLoadHistory->CallerStackHistory);
		}
		ExFreePoolWithTag(newImageLoadHistory, IMAGE_HISTORY_TAG);
		DBGPRINT("Free'd 'PmIh' at 0x%llx.", newImageLoadHistory);
	}
}

/**
	Get the summary for MaxProcessSummaries processes starting from the top of list + SkipCount.
	@param SkipCount - How many processes to skip in the list.
	@param ProcessSummaries - Caller-supplied array of process summaries that this function fills.
	@param MaxProcessSumaries - Maximum number of process summaries that the array allows for.
	@return The actual number of summaries returned.
*/
ULONG
ImageFilter::GetProcessHistorySummary (
	_In_ ULONG SkipCount,
	_Inout_ PPROCESS_SUMMARY_ENTRY ProcessSummaries,
	_In_ ULONG MaxProcessSummaries
	)
{
	PPROCESS_HISTORY_ENTRY currentProcessHistory;
	ULONG currentProcessIndex;
	ULONG actualFilledSummaries;
	NTSTATUS status;

	currentProcessIndex = 0;
	actualFilledSummaries = 0;

	if (ImageFilter::destroying)
	{
		return 0;
	}

	//
	// Acquire a shared lock to iterate processes.
	//
	FltAcquirePushLockShared(&ImageFilter::ProcessHistoryLock);

	//
	// Iterate histories for the MaxProcessSummaries processes after SkipCount processes.
	//
	if (ImageFilter::ProcessHistoryHead)
	{
		currentProcessHistory = RCAST<PPROCESS_HISTORY_ENTRY>(ImageFilter::ProcessHistoryHead->ListEntry.Flink);
		while (currentProcessHistory && currentProcessHistory != ImageFilter::ProcessHistoryHead && actualFilledSummaries < MaxProcessSummaries)
		{
			if (currentProcessIndex >= SkipCount)
			{
				//
				// Fill out the summary.
				//
				ProcessSummaries[actualFilledSummaries].EpochExecutionTime = currentProcessHistory->EpochExecutionTime;
				ProcessSummaries[actualFilledSummaries].ProcessId = currentProcessHistory->ProcessId;
				ProcessSummaries[actualFilledSummaries].ProcessTerminated = currentProcessHistory->ProcessTerminated;
				
				if (currentProcessHistory->ProcessImageFileName)
				{
					//
					// Copy the image name.
					//
					status = RtlStringCbCopyUnicodeString(RCAST<NTSTRSAFE_PWSTR>(&ProcessSummaries[actualFilledSummaries].ImageFileName), MAX_PATH * sizeof(WCHAR), currentProcessHistory->ProcessImageFileName);
					if (NT_SUCCESS(status) == FALSE)
					{
						DBGPRINT("ImageFilter!GetProcessHistorySummary: Failed to copy the image file name with status 0x%X.", status);
						break;
					}
				}
				actualFilledSummaries++;
			}
			currentProcessIndex++;
			currentProcessHistory = RCAST<PPROCESS_HISTORY_ENTRY>(currentProcessHistory->ListEntry.Flink);
		}
	}

	//
	// Release the lock.
	//
	FltReleasePushLock(&ImageFilter::ProcessHistoryLock);

	return actualFilledSummaries;
}

/**
	Populate a request for detailed information on a process.
	@param ProcessDetailedRequest - The request to populate.
*/
VOID
ImageFilter::PopulateProcessDetailedRequest (
	_Inout_ PPROCESS_DETAILED_REQUEST ProcessDetailedRequest
	)
{
	NTSTATUS status;
	PPROCESS_HISTORY_ENTRY currentProcessHistory;
	PIMAGE_LOAD_HISTORY_ENTRY currentImageEntry;
	ULONG i;

	i = 0;

	if (ImageFilter::destroying)
	{
		return;
	}

	//
	// Acquire a shared lock to iterate processes.
	//
	FltAcquirePushLockShared(&ImageFilter::ProcessHistoryLock);

	if (ImageFilter::ProcessHistoryHead)
	{
		currentProcessHistory = RCAST<PPROCESS_HISTORY_ENTRY>(ImageFilter::ProcessHistoryHead->ListEntry.Blink);
		while (currentProcessHistory && currentProcessHistory != ImageFilter::ProcessHistoryHead)
		{
			if (ProcessDetailedRequest->ProcessId == currentProcessHistory->ProcessId &&
				ProcessDetailedRequest->EpochExecutionTime == currentProcessHistory->EpochExecutionTime)
			{
				//
				// Set basic fields.
				//
				ProcessDetailedRequest->Populated = TRUE;
				ProcessDetailedRequest->CallerProcessId = currentProcessHistory->CallerId;
				ProcessDetailedRequest->ParentProcessId = currentProcessHistory->ParentId;

				//
				// Copy the stack history.
				//
				ProcessDetailedRequest->StackHistorySize = (ProcessDetailedRequest->StackHistorySize > currentProcessHistory->CallerStackHistorySize) ? currentProcessHistory->CallerStackHistorySize : ProcessDetailedRequest->StackHistorySize;
				memcpy(ProcessDetailedRequest->StackHistory, currentProcessHistory->CallerStackHistory, ProcessDetailedRequest->StackHistorySize * sizeof(STACK_RETURN_INFO));

				//
				// Copy the paths.
				//
				if (currentProcessHistory->ProcessImageFileName)
				{
					status = RtlStringCbCopyUnicodeString(RCAST<NTSTRSAFE_PWSTR>(ProcessDetailedRequest->ProcessPath), MAX_PATH * sizeof(WCHAR), currentProcessHistory->ProcessImageFileName);
					if (NT_SUCCESS(status) == FALSE)
					{
						DBGPRINT("ImageFilter!PopulateProcessDetailedRequest: Failed to copy the image file name of the process with status 0x%X.", status);
						break;
					}
				}
				if (currentProcessHistory->CallerImageFileName)
				{
					status = RtlStringCbCopyUnicodeString(RCAST<NTSTRSAFE_PWSTR>(ProcessDetailedRequest->CallerProcessPath), MAX_PATH * sizeof(WCHAR), currentProcessHistory->CallerImageFileName);
					if (NT_SUCCESS(status) == FALSE)
					{
						DBGPRINT("ImageFilter!PopulateProcessDetailedRequest: Failed to copy the image file name of the caller with status 0x%X.", status);
						break;
					}
				}
				if (currentProcessHistory->ParentImageFileName)
				{
					status = RtlStringCbCopyUnicodeString(RCAST<NTSTRSAFE_PWSTR>(ProcessDetailedRequest->ParentProcessPath), MAX_PATH * sizeof(WCHAR), currentProcessHistory->ParentImageFileName);
					if (NT_SUCCESS(status) == FALSE)
					{
						DBGPRINT("ImageFilter!PopulateProcessDetailedRequest: Failed to copy the image file name of the parent with status 0x%X.", status);
						break;
					}
				}
				if (currentProcessHistory->ProcessCommandLine)
				{
					status = RtlStringCbCopyUnicodeString(RCAST<NTSTRSAFE_PWSTR>(ProcessDetailedRequest->ProcessCommandLine), MAX_PATH * sizeof(WCHAR), currentProcessHistory->ProcessCommandLine);
					if (NT_SUCCESS(status) == FALSE)
					{
						DBGPRINT("ImageFilter!PopulateProcessDetailedRequest: Failed to copy the command line of the process with status 0x%X.", status);
						break;
					}
				}

				//
				// Iterate the images for basic information.
				//
				FltAcquirePushLockShared(&currentProcessHistory->ImageLoadHistoryLock);

				//
				// The head isn't an element so skip it.
				//
				currentImageEntry = RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(currentProcessHistory->ImageLoadHistory->ListEntry.Flink);
				while (currentImageEntry != currentProcessHistory->ImageLoadHistory && i < ProcessDetailedRequest->ImageSummarySize)
				{
					__try
					{
						if (currentImageEntry->ImageFileName.Buffer)
						{
							status = RtlStringCbCopyUnicodeString(RCAST<NTSTRSAFE_PWSTR>(ProcessDetailedRequest->ImageSummary[i].ImagePath), MAX_PATH * sizeof(WCHAR), &currentImageEntry->ImageFileName);
							if (NT_SUCCESS(status) == FALSE)
							{
								DBGPRINT("ImageFilter!PopulateProcessDetailedRequest: Failed to copy the image file name of an image with status 0x%X and source size %i.", status, currentImageEntry->ImageFileName.Length);
								break;
							}
						}
						ProcessDetailedRequest->ImageSummary[i].StackSize = currentImageEntry->CallerStackHistorySize;
					}
					__except (1)
					{
						DBGPRINT("ImageFilter!PopulateProcessDetailedRequest: Exception while processing image summaries.");
						break;
					}
					
					i++;

					currentImageEntry = RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(currentImageEntry->ListEntry.Flink);
				}

				FltReleasePushLock(&currentProcessHistory->ImageLoadHistoryLock);

				ProcessDetailedRequest->ImageSummarySize = i; // Actual number of images put into the array.
				break;
			}
			currentProcessHistory = RCAST<PPROCESS_HISTORY_ENTRY>(currentProcessHistory->ListEntry.Blink);
		}
	}

	//
	// Release the lock.
	//
	FltReleasePushLock(&ImageFilter::ProcessHistoryLock);
}

/**
	Query a thread's start address for validation.
	@param ThreadId - The target thread's ID.
	@return The start address of the target thread.
*/
PVOID
ImageFilter::GetThreadStartAddress(
	_In_ HANDLE ThreadId
	)
{
	NTSTATUS status;
	PVOID startAddress;
	PETHREAD threadObject;
	HANDLE threadHandle;
	ULONG returnLength;

	startAddress = NULL;
	threadHandle = NULL;

	//
	// First look up the PETHREAD of the thread.
	//
	status = PsLookupThreadByThreadId(ThreadId, &threadObject);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("ImageFilter!GetThreadStartAddress: Failed to lookup thread 0x%X by its ID.", ThreadId);
		goto Exit;
	}

	//
	// Open a handle to the thread.
	//
	status = ObOpenObjectByPointer(threadObject, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, GENERIC_ALL, *PsThreadType, KernelMode, &threadHandle);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("ImageFilter!GetThreadStartAddress: Failed to open handle to process with status 0x%X.", status);
		goto Exit;
	}

	//
	// Query the thread's start address.
	//
	status = NtQueryInformationThread(threadHandle, ThreadQuerySetWin32StartAddress, &startAddress, sizeof(startAddress), &returnLength);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("ImageFilter!GetThreadStartAddress: Failed to query thread start address with status 0x%X.", status);
		goto Exit;
	}
Exit:
	if (threadHandle != NULL)
	{
		ZwClose(threadHandle);
	}
	return startAddress;
}

/**
	Called when a new thread is created. Ensure the thread is legit.
	@param ProcessId - The process ID of the process receiving the new thread.
	@param ThreadId - The thread ID of the new thread.
	@param Create - Whether or not this is termination of a thread or creation.
*/
VOID
ImageFilter::ThreadNotifyRoutine(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create
	)
{
	ULONG processThreadCount;
	PVOID threadStartAddress;
	PSTACK_RETURN_INFO threadCreateStack;
	ULONG threadCreateStackSize;
	PUNICODE_STRING threadCallerName;
	PUNICODE_STRING threadTargetName;

	threadCreateStack = NULL;
	threadCreateStackSize = 20;
	threadCallerName = NULL;
	threadTargetName = NULL;

	//
	// We don't really care about thread termination or if the thread is kernel-mode.
	//
	if (Create == FALSE || ExGetPreviousMode() == KernelMode)
	{
		return;
	}

	//
	// If we can't find the process or it's the first thread of the process, skip it.
	//
	if (ImageFilter::AddProcessThreadCount(ProcessId, &processThreadCount) == FALSE ||
		processThreadCount <= 1)
	{
		return;
	}

	//
	// Walk the stack.
	//
	ImageFilter::walker.WalkAndResolveStack(&threadCreateStack, &threadCreateStackSize, STACK_HISTORY_TAG);

	//
	// Grab the name of the caller.
	//
	if (ImageFilter::GetProcessImageFileName(PsGetCurrentProcessId(), &threadCallerName) == FALSE)
	{
		goto Exit;
	}

	threadTargetName = threadCallerName;

	//
	// We only need to resolve again if the target process is a different than the caller.
	//
	if (PsGetCurrentProcessId() != ProcessId)
	{
		//
		// Grab the name of the target.
		//
		if (ImageFilter::GetProcessImageFileName(ProcessId, &threadTargetName) == FALSE)
		{
			goto Exit;
		}
	}
	
	//
	// Grab the start address of the thread.
	//
	threadStartAddress = ImageFilter::GetThreadStartAddress(ThreadId);

	//
	// Audit the target's start address.
	//
	ImageFilter::detector->AuditUserPointer(ThreadCreate, threadStartAddress, PsGetCurrentProcessId(), threadCallerName, threadTargetName, threadCreateStack, threadCreateStackSize);

	//
	// Audit the caller's stack.
	//
	ImageFilter::detector->AuditUserStackWalk(ThreadCreate, PsGetCurrentProcessId(), threadCallerName, threadTargetName, threadCreateStack, threadCreateStackSize);

	//
	// Check if this is a remote operation.
	//
	ImageFilter::detector->AuditCallerProcessId(ThreadCreate, PsGetCurrentProcessId(), ProcessId, threadCallerName, threadTargetName, threadCreateStack, threadCreateStackSize);
Exit:
	if (threadCreateStack != NULL)
	{
		ExFreePoolWithTag(threadCreateStack, STACK_HISTORY_TAG);
	}
	if (threadCallerName != NULL)
	{
		ExFreePoolWithTag(threadCallerName, IMAGE_NAME_TAG);
	}
	if (threadCallerName != threadTargetName && threadTargetName != NULL)
	{
		ExFreePoolWithTag(threadTargetName, IMAGE_NAME_TAG);
	}
}

/**
	Increment process thread count by one and retrieve the latest value.
	@param ProcessId - The process ID of the target process.
	@param ThreadCount - The resulting thread count.
	@return Whether or not the process was found.
*/
BOOLEAN
ImageFilter::AddProcessThreadCount(
	_In_ HANDLE ProcessId,
	_Inout_ ULONG* ThreadCount
	)
{
	PPROCESS_HISTORY_ENTRY currentProcessHistory;
	BOOLEAN foundProcess;

	foundProcess = FALSE;

	if (ImageFilter::destroying)
	{
		return foundProcess;
	}

	//
	// Acquire a shared lock to iterate processes.
	//
	FltAcquirePushLockShared(&ImageFilter::ProcessHistoryLock);

	if (ImageFilter::ProcessHistoryHead)
	{
		currentProcessHistory = RCAST<PPROCESS_HISTORY_ENTRY>(ImageFilter::ProcessHistoryHead->ListEntry.Blink);
		while (currentProcessHistory && currentProcessHistory != ImageFilter::ProcessHistoryHead)
		{
			if (ProcessId == currentProcessHistory->ProcessId &&
				currentProcessHistory->ProcessTerminated == FALSE)
			{
				currentProcessHistory->ProcessThreadCount++;
				*ThreadCount = currentProcessHistory->ProcessThreadCount;
				foundProcess = TRUE;
				break;
			}
			currentProcessHistory = RCAST<PPROCESS_HISTORY_ENTRY>(currentProcessHistory->ListEntry.Blink);
		}
	}

	//
	// Release the lock.
	//
	FltReleasePushLock(&ImageFilter::ProcessHistoryLock);

	return foundProcess;
}

/**
	Populate a process sizes request.
	@param ProcessSizesRequest - The request to populate.
*/
VOID
ImageFilter::PopulateProcessSizes (
	_Inout_ PPROCESS_SIZES_REQUEST ProcessSizesRequest
	)
{
	PPROCESS_HISTORY_ENTRY currentProcessHistory;

	if (ImageFilter::destroying)
	{
		return;
	}

	//
	// Acquire a shared lock to iterate processes.
	//
	FltAcquirePushLockShared(&ImageFilter::ProcessHistoryLock);

	if (ImageFilter::ProcessHistoryHead)
	{
		currentProcessHistory = RCAST<PPROCESS_HISTORY_ENTRY>(ImageFilter::ProcessHistoryHead->ListEntry.Blink);
		while (currentProcessHistory && currentProcessHistory != ImageFilter::ProcessHistoryHead)
		{
			if (ProcessSizesRequest->ProcessId == currentProcessHistory->ProcessId &&
				ProcessSizesRequest->EpochExecutionTime == currentProcessHistory->EpochExecutionTime)
			{
				ProcessSizesRequest->StackSize = currentProcessHistory->CallerStackHistorySize;
				ProcessSizesRequest->ImageSize = currentProcessHistory->ImageLoadHistorySize;
				break;
			}
			currentProcessHistory = RCAST<PPROCESS_HISTORY_ENTRY>(currentProcessHistory->ListEntry.Blink);
		}
	}

	//
	// Release the lock.
	//
	FltReleasePushLock(&ImageFilter::ProcessHistoryLock);
}

/**
	Populate an image detailed request.
	@param ImageDetailedRequest - The request to populate.
*/
VOID
ImageFilter::PopulateImageDetailedRequest(
	_Inout_ PIMAGE_DETAILED_REQUEST ImageDetailedRequest
	)
{
	NTSTATUS status;
	PPROCESS_HISTORY_ENTRY currentProcessHistory;
	PIMAGE_LOAD_HISTORY_ENTRY currentImageEntry;
	ULONG i;

	i = 0;

	if (ImageFilter::destroying)
	{
		return;
	}

	//
	// Acquire a shared lock to iterate processes.
	//
	FltAcquirePushLockShared(&ImageFilter::ProcessHistoryLock);

	if (ImageFilter::ProcessHistoryHead)
	{
		currentProcessHistory = RCAST<PPROCESS_HISTORY_ENTRY>(ImageFilter::ProcessHistoryHead->ListEntry.Blink);
		while (currentProcessHistory && currentProcessHistory != ImageFilter::ProcessHistoryHead)
		{
			if (ImageDetailedRequest->ProcessId == currentProcessHistory->ProcessId &&
				ImageDetailedRequest->EpochExecutionTime == currentProcessHistory->EpochExecutionTime)
			{
				//
				// Iterate the images for basic information.
				//
				FltAcquirePushLockShared(&currentProcessHistory->ImageLoadHistoryLock);

				//
				// The head isn't an element so skip it.
				//
				currentImageEntry = RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(currentProcessHistory->ImageLoadHistory->ListEntry.Flink);
				while (currentImageEntry != currentProcessHistory->ImageLoadHistory)
				{
					if (i == ImageDetailedRequest->ImageIndex)
					{
						if (currentImageEntry->ImageFileName.Buffer)
						{
							status = RtlStringCbCopyUnicodeString(RCAST<NTSTRSAFE_PWSTR>(ImageDetailedRequest->ImagePath), MAX_PATH * sizeof(WCHAR), &currentImageEntry->ImageFileName);
							if (NT_SUCCESS(status) == FALSE)
							{
								DBGPRINT("ImageFilter!PopulateImageDetailedRequest: Failed to copy the image file name of an image with status 0x%X and source size %i.", status, currentImageEntry->ImageFileName.Length);
								break;
							}
						}

						//
						// Copy the stack history.
						//
						ImageDetailedRequest->StackHistorySize = (ImageDetailedRequest->StackHistorySize > currentImageEntry->CallerStackHistorySize) ? currentImageEntry->CallerStackHistorySize : ImageDetailedRequest->StackHistorySize;
						memcpy(ImageDetailedRequest->StackHistory, currentImageEntry->CallerStackHistory, ImageDetailedRequest->StackHistorySize * sizeof(STACK_RETURN_INFO));

						ImageDetailedRequest->Populated = TRUE;
					}
					i++;
					currentImageEntry = RCAST<PIMAGE_LOAD_HISTORY_ENTRY>(currentImageEntry->ListEntry.Flink);
				}

				FltReleasePushLock(&currentProcessHistory->ImageLoadHistoryLock);
				break;
			}
			currentProcessHistory = RCAST<PPROCESS_HISTORY_ENTRY>(currentProcessHistory->ListEntry.Blink);
		}
	}

	//
	// Release the lock.
	//
	FltReleasePushLock(&ImageFilter::ProcessHistoryLock);
}