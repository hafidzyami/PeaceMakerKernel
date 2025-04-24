/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 * 
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "StringFilters.h"

/**
	Initialize the CUSTOM_FILTERS class by initializing the linked list's lock.
	@param Type - The type of filter to add (registry).
	@param RegistryPath - The registry path of the driver.
	@param FilterStoreName - Name of the filter store.
*/
StringFilters::StringFilters (
	_In_ STRING_FILTER_TYPE FilterType,
	_In_ PUNICODE_STRING RegistryPath,
	_In_ CONST WCHAR* FilterStoreName
	)
{
	//
	// Initialize the lock for the filters.
	//
	FltInitializePushLock(&this->filtersLock);

	this->filtersHead = RCAST<PFILTER_INFO_LINKED>(ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, sizeof(FILTER_INFO_LINKED), FILTER_INFO_TAG));
	InitializeListHead(RCAST<PLIST_ENTRY>(this->filtersHead));
	this->destroying = FALSE;

	this->filtersCount = 0;
	this->filterType = FilterType;

	//
	// Initialize space for the driver registry key.
	//
	this->driverRegistryPath.Buffer = RCAST<PWCH>(ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, RegistryPath->MaximumLength, FILTER_INFO_TAG));
	this->driverRegistryPath.MaximumLength = RegistryPath->MaximumLength;
	RtlCopyUnicodeString(&this->driverRegistryPath, RegistryPath);

	RtlInitUnicodeString(&this->filterStoreValueName, FilterStoreName);
}

/**
	Destroy the CustomFilters class by clearing the filters linked list and deleting the associated lock.
*/
StringFilters::~StringFilters()
{
	PLIST_ENTRY currentFilter;

	//
	// Set destroying to TRUE so that no other threads can get a lock.
	//
	this->destroying = TRUE;

	//
	// Acquire an exclusive lock to push out other threads.
	//
	FltAcquirePushLockExclusive(&this->filtersLock);

	//
	// Release the lock.
	//
	FltReleasePushLock(&this->filtersLock);

	//
	// Delete the lock for the filters.
	//
	FltDeletePushLock(&this->filtersLock);

	//
	// Go through each filter and free it.
	//
	if (this->filtersHead)
	{
		while (IsListEmpty(RCAST<PLIST_ENTRY>(this->filtersHead)) == FALSE)
		{
			currentFilter = RemoveHeadList(RCAST<PLIST_ENTRY>(this->filtersHead));
			//
			// Free the filter.
			//
			ExFreePoolWithTag(SCAST<PVOID>(currentFilter), FILTER_INFO_TAG);
		}

		//
		// Finally, free the list head.
		//
		ExFreePoolWithTag(SCAST<PVOID>(this->filtersHead), FILTER_INFO_TAG);
	}

	//
	// Free the driver registy path.
	//
	ExFreePoolWithTag(this->driverRegistryPath.Buffer, FILTER_INFO_TAG);
}

/**
	Add a filter to the linked list of filters.
	@param MatchString - The string to filter with.
	@param OperationFlag - Specifies what operations this filter should be used for.
	@param SaveFilters - Whether or not to save filters.
	@return A random identifier required for future operations with the new filter.
*/
ULONG
StringFilters::AddFilter (
	_In_ WCHAR* MatchString,
	_In_ ULONG OperationFlag,
	_In_ BOOLEAN SaveFilters
	)
{
	PFILTER_INFO_LINKED newFilter;
	LARGE_INTEGER currentTime;
	ULONG epochSeconds;

	if (this == NULL || this->destroying)
	{
		return NULL;
	}

	//
	// Get an exclusive lock because we're modifying the filters linked list.
	//
	FltAcquirePushLockExclusive(&this->filtersLock);

	//
	// Allocate space for the new filter.
	//
	newFilter = RCAST<PFILTER_INFO_LINKED>(ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, sizeof(FILTER_INFO_LINKED), FILTER_INFO_TAG));
	if (newFilter == NULL)
	{
		DBGPRINT("Failed to allocate space for filter info.");
		goto Exit;
	}

	memset(RCAST<PVOID>(newFilter), 0, sizeof(FILTER_INFO_LINKED));

	InsertTailList(RCAST<PLIST_ENTRY>(this->filtersHead), RCAST<PLIST_ENTRY>(newFilter));

	this->filtersCount++;

	//
	// Generate a pseudo-random ID for the filter using the system time.
	//
	KeQuerySystemTime(&currentTime);
	RtlTimeToSecondsSince1970(&currentTime, &epochSeconds);
	newFilter->Filter.Id = RtlRandomEx(&epochSeconds);
	newFilter->Filter.Type = this->filterType;

	//
	// Copy the filter string to the new filter.
	//
	wcsncpy_s(newFilter->Filter.MatchString, MatchString, MAX_PATH);

	//
	// Set the operation flags for this filter.
	//
	newFilter->Filter.Flags = OperationFlag;
Exit:
	//
	// New filter has been initialized, release the lock.
	//
	FltReleasePushLock(&this->filtersLock);
	if (SaveFilters)
	{
		this->SaveFilters();
	}

	if (newFilter)
	{
		return newFilter->Filter.Id;
	}

	//
	// The ID cannot be 0 because we add 1.
	//
	return NULL;
}

/**
	Remove a filter from the linked list of filters.
	@param FilterId - The unique filter ID of the filter to delete.
	@return Whether or not deletion was successful.
*/
BOOLEAN
StringFilters::RemoveFilter (
	_In_ ULONG FilterId
	)
{
	BOOLEAN filterDeleted;
	PFILTER_INFO_LINKED currentFilter;

	currentFilter = NULL;
	filterDeleted = FALSE;

	if (this == NULL || this->destroying)
	{
		return FALSE;
	}

	//
	// Get an exclusive lock because we're modifying the filters linked list.
	//
	FltAcquirePushLockExclusive(&this->filtersLock);

	//
	// Check if we have a single filter already.
	//
	if (this->filtersHead)
	{
		currentFilter = RCAST<PFILTER_INFO_LINKED>(this->filtersHead->ListEntry.Flink);

		while (currentFilter && currentFilter != this->filtersHead)
		{
			if (currentFilter->Filter.Id == FilterId)
			{
				break;
			}
			currentFilter = RCAST<PFILTER_INFO_LINKED>(currentFilter->ListEntry.Flink);
		}
		
		//
		// Remove the entry from the list.
		//
		if (currentFilter && currentFilter != this->filtersHead)
		{
			RemoveEntryList(RCAST<PLIST_ENTRY>(currentFilter));
			filterDeleted = TRUE;
			this->filtersCount--;
			//
			// Free the filter.
			//
			ExFreePoolWithTag(SCAST<PVOID>(currentFilter), FILTER_INFO_TAG);
		}
	}

	//
	// Release the lock.
	//
	FltReleasePushLock(&this->filtersLock);

	if (filterDeleted)
	{
		this->SaveFilters();
	}

	return filterDeleted;
}

/**
	Check if a string contains any filtered phrases.
	@param StrToCmp - The string to search.
	@param OperationFlag - Specify FILTER_FLAG_X's to match certain filters for a variety of operations.
	@return Whether or not there was a filter that matched.
*/
BOOLEAN
StringFilters::MatchesFilter (
	_In_ WCHAR* StrToCmp,
	_In_ ULONG OperationFlag
	)
{
	BOOLEAN filterMatched;
	PFILTER_INFO_LINKED currentFilter;
	WCHAR tempStrToCmp[MAX_PATH];
	INT i;

	if (this == NULL || this->destroying)
	{
		return FALSE;
	}

	filterMatched = FALSE;

	//
	// Copy the string to compare so we don't modify the original string.
	//
	wcsncpy_s(tempStrToCmp, StrToCmp, MAX_PATH);

	//
	// Make the input string lowercase.
	//
	i = 0;
	while (tempStrToCmp[i])
	{
		tempStrToCmp[i] = towlower(tempStrToCmp[i]);
		i++;
	}

	//
	// Acquire a shared lock to iterate filters.
	//
	FltAcquirePushLockShared(&this->filtersLock);

	//
	// Iterate filters for a match.
	//
	if (this->filtersHead)
	{
		currentFilter = RCAST<PFILTER_INFO_LINKED>(this->filtersHead->ListEntry.Flink);
		while (currentFilter && currentFilter != this->filtersHead)
		{
			//
			// Check if the string to compare contains the filter.
			//
			if ((currentFilter->Filter.Flags & OperationFlag) &&
				(wcsstr(RCAST<CONST WCHAR*>(&tempStrToCmp), RCAST<CONST WCHAR*>(&currentFilter->Filter.MatchString)) != NULL))
			{
				filterMatched = TRUE;
				goto Exit;
			}
			currentFilter = RCAST<PFILTER_INFO_LINKED>(currentFilter->ListEntry.Flink);
		}
	}
Exit:
	FltReleasePushLock(&this->filtersLock);
	return filterMatched;
}

/**
	Get the filters present in the linked-list.
	@param SkipFilters - The number of filters to skip.
	@param Filters - The output array.
	@param FilterSize - Maximum number of filters.
	@return The number of filters copied.
*/
ULONG
StringFilters::GetFilters (
	_In_ ULONG SkipFilters,
	_Inout_ PFILTER_INFO Filters,
	_In_ ULONG FiltersSize
	)
{
	PFILTER_INFO_LINKED currentFilter;
	ULONG skipCount;
	ULONG copyCount;

	skipCount = 0;
	copyCount = 0;

	//
	// Acquire a shared lock to iterate filters.
	//
	FltAcquirePushLockShared(&this->filtersLock);

	//
	// Iterate filters for a match.
	//
	if (this->filtersHead)
	{
		currentFilter = RCAST<PFILTER_INFO_LINKED>(this->filtersHead->ListEntry.Flink);
		while (currentFilter && currentFilter != this->filtersHead && copyCount < FiltersSize)
		{
			if (skipCount >= SkipFilters)
			{
				memcpy_s(&Filters[copyCount], sizeof(FILTER_INFO), &currentFilter->Filter, sizeof(FILTER_INFO));
				DBGPRINT("StringFilters!GetFilters: Copying filter ID 0x%X.", currentFilter->Filter.Id);
				copyCount++;
			}
			skipCount++;
			currentFilter = RCAST<PFILTER_INFO_LINKED>(currentFilter->ListEntry.Flink);
		}
	}

	FltReleasePushLock(&this->filtersLock);

	return copyCount;
}

/**
	Save the current filters to the registry for persistence.
	@return Whether or not the save was successful.
*/
BOOLEAN
StringFilters::SaveFilters (
	VOID
	)
{
	PFILTER_STORE filterStore;
	PFILTER_INFO_LINKED currentFilter;
	ULONG i;
	OBJECT_ATTRIBUTES driverRegistryAttributes;
	NTSTATUS status;
	HANDLE driverRegistryKey;
	BOOLEAN result;

	result = FALSE;
	driverRegistryKey = NULL;
	i = 0;

	//
	// Allocate space for the filter store.
	//
	filterStore = RCAST<PFILTER_STORE>(ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, FILTER_STORE_SIZE(this->filtersCount), FILTER_INFO_TAG));
	if (filterStore == NULL)
	{
		DBGPRINT("StringFilters!SaveFilters: Failed to allocate space for the filter store with size %i.", this->filtersCount);
		goto Exit;
	}
	memset(filterStore, 0, sizeof(filterStore));

	//
	// Initialize basic members.
	//
	filterStore->FilterCount = this->filtersCount;

	//
	// Acquire a shared lock to iterate filters.
	//
	FltAcquirePushLockShared(&this->filtersLock);

	//
	// Iterate filters for a match.
	//
	if (this->filtersHead)
	{
		currentFilter = RCAST<PFILTER_INFO_LINKED>(this->filtersHead->ListEntry.Flink);
		while (currentFilter && currentFilter != this->filtersHead)
		{
			memcpy_s(&filterStore->Filters[i], sizeof(FILTER_INFO), &currentFilter->Filter, sizeof(FILTER_INFO));
			i++;
			currentFilter = RCAST<PFILTER_INFO_LINKED>(currentFilter->ListEntry.Flink);
		}
	}

	FltReleasePushLock(&this->filtersLock);

	//
	// Open the driver's registry key.
	//
	InitializeObjectAttributes(&driverRegistryAttributes, &this->driverRegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenKey(&driverRegistryKey, KEY_ALL_ACCESS, &driverRegistryAttributes);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("StringFilters!SaveFilters: Failed to open driver registry key with status 0x%X.", status);
		goto Exit;
	}

	//
	// Write the current filters.
	//
	status = ZwSetValueKey(driverRegistryKey, &this->filterStoreValueName, 0, REG_BINARY, filterStore, FILTER_STORE_SIZE(this->filtersCount));
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("StringFilters!SaveFilters: Failed to write filter store to driver registry key with status 0x%X.", status);
		goto Exit;
	}
	result = TRUE;
Exit:
	if (filterStore)
	{
		ExFreePoolWithTag(filterStore, FILTER_INFO_TAG);
	}
	if (driverRegistryKey)
	{
		ZwClose(driverRegistryKey);
	}
	return result;
}

/**
	Restore filters from the registry.
	@return Whether or not the restoration was successful.
*/
BOOLEAN
StringFilters::RestoreFilters (
	VOID
	)
{
	OBJECT_ATTRIBUTES driverRegistryAttributes;
	NTSTATUS status;
	HANDLE driverRegistryKey;
	ULONG filterStorePartialSize;
	PFILTER_STORE filterStore;
	PKEY_VALUE_PARTIAL_INFORMATION filterStorePartial;
	ULONG i;
	BOOLEAN result;

	result = FALSE;
	i = 0;
	filterStorePartial = NULL;
	filterStore = NULL;

	//
	// Open the driver's registry key.
	//
	InitializeObjectAttributes(&driverRegistryAttributes, &this->driverRegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenKey(&driverRegistryKey, KEY_ALL_ACCESS, &driverRegistryAttributes);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("StringFilters!RestoreFilters: Failed to open driver registry key with status 0x%X.", status);
		goto Exit;
	}
	
	//
	// Read the size of the FilterStore.
	//
	status = ZwQueryValueKey(driverRegistryKey, &this->filterStoreValueName, KeyValuePartialInformation, NULL, 0, &filterStorePartialSize);
	if (status != STATUS_BUFFER_TOO_SMALL)
	{
		DBGPRINT("StringFilters!RestoreFilters: Failed to query filter store size with status 0x%X.", status);
		goto Exit;
	}
	
	//
	// Allocate space for the FilterStore partial struct and query the actual value.
	//
	filterStorePartial = RCAST<PKEY_VALUE_PARTIAL_INFORMATION>(ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, filterStorePartialSize, FILTER_INFO_TAG));
	status = ZwQueryValueKey(driverRegistryKey, &this->filterStoreValueName, KeyValuePartialInformation, filterStorePartial, filterStorePartialSize, &filterStorePartialSize);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT("StringFilters!RestoreFilters: Failed to query filter store with status 0x%X.", status);
		goto Exit;
	}
	
	//
	// Grab the filter store from the data member of the partial struct.
	//
	filterStore = RCAST<PFILTER_STORE>(filterStorePartial->Data);

	//
	// Add the filters.
	//
	for (i = 0; i < filterStore->FilterCount; i++)
	{
		this->AddFilter(filterStore->Filters[i].MatchString, filterStore->Filters[i].Flags, FALSE);
	}
	result = TRUE;
Exit:
	if (driverRegistryKey)
	{
		ZwClose(driverRegistryKey);
	}
	if (filterStorePartial)
	{
		ExFreePoolWithTag(filterStorePartial, FILTER_INFO_TAG);
	}
	return result;
}