/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 * 
 * COPYRIGHT Bill Demirkapi 2020
 */
#include "ObjectFilter.h"

// Initialize static member variables
// Registry Filter components
LARGE_INTEGER ObjectFilter::RegistryFilterCookie;
PDETECTION_LOGIC ObjectFilter::detector;
STACK_WALKER ObjectFilter::walker;
PSTRING_FILTERS ObjectFilter::RegistryStringFilters;

// Tamper Guard components
HANDLE ObjectFilter::ProtectedProcessId;

/**
    Initialize object filtering mechanisms including registry filtering and tamper protection.
    @param DriverObject - The object of the driver necessary for filter initialization.
    @param RegistryPath - The registry path of the driver.
    @param Detector - Detection instance used to analyze untrusted operations.
    @param InitializeStatus - Status of initialization.
*/
ObjectFilter::ObjectFilter(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PDETECTION_LOGIC Detector,
    _Out_ NTSTATUS* InitializeStatus
    )
{
    UNICODE_STRING filterAltitude;
    NTSTATUS tempStatus = STATUS_SUCCESS;

    //
    // Initialize Registry Filter components
    //
    
    ObjectFilter::RegistryStringFilters = new (NonPagedPool, STRING_REGISTRY_FILTERS_TAG) StringFilters(RegistryFilter, RegistryPath, L"RegistryFilterStore");
    if (ObjectFilter::RegistryStringFilters == NULL)
    {
        DBGPRINT("ObjectFilter!ObjectFilter: Failed to allocate memory for string filters.");
        *InitializeStatus = STATUS_NO_MEMORY;
        return;
    }
    //
    // Restore existing filters.
    //
    ObjectFilter::RegistryStringFilters->RestoreFilters();

    //
    // Put our altitude into a UNICODE_STRING.
    //
    RtlInitUnicodeString(&filterAltitude, FILTER_ALTITUDE);

    //
    // Register our registry callback.
    //
    tempStatus = CmRegisterCallbackEx(RCAST<PEX_CALLBACK_FUNCTION>(ObjectFilter::RegistryCallback), &filterAltitude, DriverObject, NULL, &RegistryFilterCookie, NULL);
    if (NT_SUCCESS(tempStatus) == FALSE)
    {
        DBGPRINT("ObjectFilter!ObjectFilter: Failed to register registry callback with status 0x%X.", tempStatus);
        *InitializeStatus = tempStatus;
        return;
    }

    //
    // Set the detector.
    //
    ObjectFilter::detector = Detector;
    
    //
    // Initialize Tamper Guard components
    //
    
    ObRegistrationInformation.Version = OB_FLT_REGISTRATION_VERSION;
    ObRegistrationInformation.OperationRegistrationCount = 2;
    ObRegistrationInformation.Altitude = filterAltitude;
    ObRegistrationInformation.RegistrationContext = NULL;
    ObRegistrationInformation.OperationRegistration = ObOperationRegistration;

    //
    // We want to protect both the process and the threads of the protected process.
    //
    ObOperationRegistration[0].ObjectType = PsProcessType;
    ObOperationRegistration[0].Operations |= OB_OPERATION_HANDLE_CREATE;
    ObOperationRegistration[0].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
    ObOperationRegistration[0].PreOperation = PreOperationCallback;

    ObOperationRegistration[1].ObjectType = PsThreadType;
    ObOperationRegistration[1].Operations |= OB_OPERATION_HANDLE_CREATE;
    ObOperationRegistration[1].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
    ObOperationRegistration[1].PreOperation = PreOperationCallback;

    //
    // Actually register the callbacks.
    //
    tempStatus = ObRegisterCallbacks(&ObRegistrationInformation, &RegistrationHandle);
    if (NT_SUCCESS(tempStatus) == FALSE)
    {
        DBGPRINT("ObjectFilter!ObjectFilter: Failed to register object callbacks with status 0x%X.", tempStatus);
        *InitializeStatus = tempStatus;
        return;
    }
    
    *InitializeStatus = STATUS_SUCCESS;
}

/**
    Cleanup registry filter and tamper guard resources.
*/
ObjectFilter::~ObjectFilter()
{
    // Clean up Registry Filter components
    CmUnRegisterCallback(this->RegistryFilterCookie);
    
    ObjectFilter::RegistryStringFilters->~StringFilters();
    ExFreePoolWithTag(ObjectFilter::RegistryStringFilters, STRING_REGISTRY_FILTERS_TAG);
    
    // Clean up Tamper Guard components
    ObUnRegisterCallbacks(RegistrationHandle);
}

/**
    Return the string filters used in the registry filter.
    @return String filters for registry operations.
*/
PSTRING_FILTERS 
ObjectFilter::GetRegistryStringFilters()
{
    return ObjectFilter::RegistryStringFilters;
}

/**
    Update the process to protect.
    @param NewProcessId - The new process to protect from tampering.
*/
VOID
ObjectFilter::UpdateProtectedProcess(
    _In_ HANDLE NewProcessId
    )
{
    ObjectFilter::ProtectedProcessId = NewProcessId;
}

/**
    Function that decides whether or not to block a registry operation.
    @param KeyObject - The registry key of the operation.
    @param ValueName - The name of the registry value specified by the operation.
    @param OperationFlag - The flags of the operation (i.e WRITE/DELETE).
    @return Whether or not to block the operation.
*/
BOOLEAN
ObjectFilter::BlockRegistryOperation(
    _In_ PVOID KeyObject,
    _In_ PUNICODE_STRING ValueName,
    _In_ ULONG OperationFlag
    )
{
    BOOLEAN blockOperation;
    NTSTATUS internalStatus;
    HANDLE keyHandle;
    PKEY_NAME_INFORMATION pKeyNameInformation;
    ULONG returnLength;
    ULONG fullKeyValueLength;
    PWCHAR tempValueName;
    PWCHAR fullKeyValueName;

    UNICODE_STRING registryOperationPath;
    PUNICODE_STRING callerProcessPath;
    PSTACK_RETURN_INFO registryOperationStack;
    ULONG registryOperationStackSize;

    blockOperation = FALSE;
    registryOperationStackSize = MAX_STACK_RETURN_HISTORY;
    keyHandle = NULL;
    returnLength = NULL;
    pKeyNameInformation = NULL;
    tempValueName = NULL;
    fullKeyValueName = NULL;

    if (ValueName == NULL || ValueName->Length == 0 || ValueName->Buffer == NULL || ValueName->Length > (NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR)))
    {
        DBGPRINT("ObjectFilter!BlockRegistryOperation: ValueName is NULL.");
        goto Exit;
    }

    tempValueName = RCAST<PWCHAR>(ExAllocatePool2(POOL_FLAG_NON_PAGED, ValueName->Length, REGISTRY_KEY_NAME_TAG));
    if (tempValueName == NULL)
    {
        DBGPRINT("ObjectFilter!BlockRegistryOperation: Failed to allocate memory for value name with size 0x%X.", ValueName->Length);
        goto Exit;
    }

    //
    // There can be some wonky exceptions with weird input,
    // just in case we don't handle something is a simple
    // catch all.
    //
    __try {
        //
        // Open the registry key.
        //
        internalStatus = ObOpenObjectByPointer(KeyObject, OBJ_KERNEL_HANDLE, NULL, GENERIC_ALL, *CmKeyObjectType, KernelMode, &keyHandle);
        if (NT_SUCCESS(internalStatus) == FALSE)
        {
            DBGPRINT("ObjectFilter!BlockRegistryOperation: Failed to open a handle to a key object with status 0x%X.", internalStatus);
            goto Exit;
        }

        ZwQueryKey(keyHandle, KeyNameInformation, NULL, 0, &returnLength);
        if (returnLength == 0)
        {
            DBGPRINT("ObjectFilter!BlockRegistryOperation: Failed to determine size of key name.");
            goto Exit;
        }

        returnLength += 1; // For null terminator.
        pKeyNameInformation = RCAST<PKEY_NAME_INFORMATION>(ExAllocatePool2(POOL_FLAG_PAGED, returnLength, REGISTRY_KEY_NAME_TAG));
        if (pKeyNameInformation == NULL)
        {
            DBGPRINT("ObjectFilter!BlockRegistryOperation: Failed to allocate memory for key name with size 0x%X.", returnLength);
            goto Exit;
        }

        //
        // Query the name information of the key to retrieve its name.
        //
        internalStatus = ZwQueryKey(keyHandle, KeyNameInformation, pKeyNameInformation, returnLength, &returnLength);
        if (NT_SUCCESS(internalStatus) == FALSE)
        {
            DBGPRINT("ObjectFilter!BlockRegistryOperation: Failed to query name of key object with status 0x%X.", internalStatus);
            goto Exit;
        }

        //
        // Allocate space for key name, a backslash, the value name, and the null-terminator.
        //
        fullKeyValueLength = pKeyNameInformation->NameLength + 2 + ValueName->Length + 1000;
        fullKeyValueName = RCAST<PWCHAR>(ExAllocatePool2(POOL_FLAG_NON_PAGED, fullKeyValueLength, REGISTRY_KEY_NAME_TAG));
        if (fullKeyValueName == NULL)
        {
            DBGPRINT("ObjectFilter!BlockRegistryOperation: Failed to allocate memory for full key/value name with size 0x%X.", fullKeyValueLength);
            goto Exit;
        }

        //
        // Copy the key name.
        //
        internalStatus = RtlStringCbCopyNW(fullKeyValueName, fullKeyValueLength, RCAST<PCWSTR>(&pKeyNameInformation->Name), pKeyNameInformation->NameLength);
        if (NT_SUCCESS(internalStatus) == FALSE)
        {
            DBGPRINT("ObjectFilter!BlockRegistryOperation: Failed to copy key name with status 0x%X.", internalStatus);
            goto Exit;
        }

        //
        // Concatenate the backslash.
        //
        internalStatus = RtlStringCbCatW(fullKeyValueName, fullKeyValueLength, L"\\");
        if (NT_SUCCESS(internalStatus) == FALSE)
        {
            DBGPRINT("ObjectFilter!BlockRegistryOperation: Failed to concatenate backslash with status 0x%X.", internalStatus);
            goto Exit;
        }

        //
        // Concatenate the value name.
        //
        internalStatus = RtlStringCbCatNW(fullKeyValueName, fullKeyValueLength, ValueName->Buffer, ValueName->Length);
        if (NT_SUCCESS(internalStatus) == FALSE)
        {
            DBGPRINT("ObjectFilter!BlockRegistryOperation: Failed to concatenate value name with status 0x%X.", internalStatus);
            goto Exit;
        }

        blockOperation = ObjectFilter::RegistryStringFilters->MatchesFilter(fullKeyValueName, OperationFlag);

        //DBGPRINT("ObjectFilter!BlockRegistryOperation: Full name: %S.", fullKeyValueName);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {}

    if (blockOperation)
    {
        //
        // Grab the caller's path.
        //
        ImageFilter::GetProcessImageFileName(PsGetCurrentProcessId(), &callerProcessPath);

        //
        // Walk the stack.
        //
        ObjectFilter::walker.WalkAndResolveStack(&registryOperationStack, &registryOperationStackSize, STACK_HISTORY_TAG);

        NT_ASSERT(registryOperationStack);

        //
        // Only if we successfully walked the stack, report the violation.
        //
        if (registryOperationStack != NULL && registryOperationStackSize != 0)
        {
            //
            // Convert the registry path to a unicode string.
            //
            RtlInitUnicodeString(&registryOperationPath, fullKeyValueName);

            //
            // Report the violation.
            //
            ObjectFilter::detector->ReportFilterViolation(RegistryFilterMatch, PsGetCurrentProcessId(), callerProcessPath, &registryOperationPath, registryOperationStack, registryOperationStackSize);

            //
            // Clean up.
            //
            ExFreePoolWithTag(registryOperationStack, STACK_HISTORY_TAG);
        }

        ExFreePoolWithTag(callerProcessPath, IMAGE_NAME_TAG);
    }
Exit:
    if (tempValueName)
    {
        ExFreePoolWithTag(tempValueName, REGISTRY_KEY_NAME_TAG);
    }
    if (fullKeyValueName)
    {
        ExFreePoolWithTag(fullKeyValueName, REGISTRY_KEY_NAME_TAG);
    }
    if (pKeyNameInformation)
    {
        ExFreePoolWithTag(pKeyNameInformation, REGISTRY_KEY_NAME_TAG);
    }
    if (keyHandle)
    {
        ZwClose(keyHandle);
    }
    return blockOperation;
}

/**
    The callback for registry operations. If necessary, blocks certain operations on protected keys/values.
    @param CallbackContext - Unreferenced parameter.
    @param OperationClass - The type of registry operation.
    @param Argument2 - A pointer to the structure associated with the operation.
    @return The status of the registry operation.
*/
NTSTATUS 
ObjectFilter::RegistryCallback(
    _In_ PVOID CallbackContext,
    _In_ REG_NOTIFY_CLASS OperationClass, 
    _In_ PVOID Argument2
    )
{
    UNREFERENCED_PARAMETER(CallbackContext);
    NTSTATUS returnStatus;
    PREG_SET_VALUE_KEY_INFORMATION setValueInformation;
    PREG_DELETE_VALUE_KEY_INFORMATION deleteValueInformation;

    returnStatus = STATUS_SUCCESS;

    //
    // PeaceMaker is not designed to block kernel operations.
    //
    if (ExGetPreviousMode() != KernelMode)
    {
        switch (OperationClass)
        {
        case RegNtPreSetValueKey:
            setValueInformation = RCAST<PREG_SET_VALUE_KEY_INFORMATION>(Argument2);
            if (BlockRegistryOperation(setValueInformation->Object, setValueInformation->ValueName, FILTER_FLAG_WRITE))
            {
                DBGPRINT("ObjectFilter!RegistryCallback: Detected RegNtPreSetValueKey of %wZ. Prevented set!", setValueInformation->ValueName);
                returnStatus = STATUS_ACCESS_DENIED;
            }
            break;
        case RegNtPreDeleteValueKey:
            deleteValueInformation = RCAST<PREG_DELETE_VALUE_KEY_INFORMATION>(Argument2);
            if (BlockRegistryOperation(deleteValueInformation->Object, deleteValueInformation->ValueName, FILTER_FLAG_DELETE))
            {
                DBGPRINT("ObjectFilter!RegistryCallback: Detected RegNtPreDeleteValueKey of %wZ. Prevented deletion!", deleteValueInformation->ValueName);
                returnStatus = STATUS_ACCESS_DENIED;
            }
            break;
        }
    }

    return returnStatus;
}

/**
    Filter for certain operations on a protected process.
    @param RegistrationContext - Always NULL.
    @param OperationInformation - Information about the current operation.
*/
OB_PREOP_CALLBACK_STATUS
ObjectFilter::PreOperationCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    HANDLE callerProcessId;
    HANDLE targetProcessId;
    ACCESS_MASK targetAccessMask;

    UNREFERENCED_PARAMETER(RegistrationContext);

    callerProcessId = NULL;
    targetProcessId = NULL;
    targetAccessMask = NULL;
    callerProcessId = PsGetCurrentProcessId();

    //
    // Grab the appropriate process IDs based on the operation object type.
    //
    if (OperationInformation->ObjectType == *PsProcessType)
    {
        targetProcessId = PsGetProcessId(RCAST<PEPROCESS>(OperationInformation->Object));
        targetAccessMask = PROCESS_TERMINATE;
    }
    else if (OperationInformation->ObjectType == *PsThreadType)
    {
        targetProcessId = PsGetThreadProcessId(RCAST<PETHREAD>(OperationInformation->Object));
        targetAccessMask = THREAD_TERMINATE;
    }

    //
    // If this is an operation on your own process, ignore it.
    //
    if (callerProcessId == targetProcessId)
    {
        return OB_PREOP_SUCCESS;
    }

    //
    // If the target process isn't the process we're protecting, no issue.
    //
    if (targetProcessId != ObjectFilter::ProtectedProcessId)
    {
        return OB_PREOP_SUCCESS;
    }

    //
    // Strip the proper desired access ACCESS_MASK.
    //
    switch (OperationInformation->Operation)
    {
    case OB_OPERATION_HANDLE_CREATE:
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~targetAccessMask;
        break;
    case OB_OPERATION_HANDLE_DUPLICATE:
        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~targetAccessMask;
        break;
    }

    DBGPRINT("ObjectFilter!PreOperationCallback: Stripped process 0x%X terminate handle on protected process.", callerProcessId);

    return OB_PREOP_SUCCESS;
}
