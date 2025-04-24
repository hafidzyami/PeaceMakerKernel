/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 * 
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include "StackWalker.h"
#include "shared.h"
#include "DetectionLogic.h"

#define IMAGE_NAME_TAG 'nImP'
#define IMAGE_COMMMAND_TAG 'cImP'
#define PROCESS_HISTORY_TAG 'hPmP'
#define STACK_HISTORY_TAG 'hSmP'
#define IMAGE_HISTORY_TAG 'hImP'

typedef struct ImageLoadHistoryEntry
{
	LIST_ENTRY ListEntry;					// The list entry to iterate multiple images in a process.
	UNICODE_STRING ImageFileName;			// The full image file name of loaded image.
	HANDLE CallerProcessId;					// The real caller of the load image routine.
	BOOLEAN RemoteImage;					// Whether or not the image was loaded remotely.
	PUNICODE_STRING CallerImageFileName;		// The full image file name of the caller. Only specified if RemoteImage == TRUE.
	PSTACK_RETURN_INFO CallerStackHistory;	// A variable-length array of the stack that loaded the image.
	ULONG CallerStackHistorySize;			// The size of the variable-length stack history array.
} IMAGE_LOAD_HISTORY_ENTRY, *PIMAGE_LOAD_HISTORY_ENTRY;

typedef struct ProcessHistoryEntry
{
	LIST_ENTRY ListEntry;						// The list entry to iterate multiple process histories.

	HANDLE CallerId;							// The process id of the caller process.
	PUNICODE_STRING CallerImageFileName;		// OPTIONAL: The image file name of the caller process.

	HANDLE ParentId;							// The process id of the alleged parent process.
	PUNICODE_STRING ParentImageFileName;		// OPTIONAL: The image file name of the alleged parent process.

	HANDLE ProcessId;							// The process id of the executed process.
	PUNICODE_STRING ProcessImageFileName;		// The image file name of the executed process.

	PUNICODE_STRING ProcessCommandLine;			// The command-line string for the executed process.

	ULONG ProcessThreadCount;					// The number of threads the process has.
	
	ULONGLONG EpochExecutionTime;				// Process execution time in seconds since 1970.
	BOOLEAN ProcessTerminated;					// Whether or not the process has terminated.

	PSTACK_RETURN_INFO CallerStackHistory;		// A variable-length array of the stack that started the process.
	ULONG CallerStackHistorySize;				// The size of the variable-length stack history array.

	PIMAGE_LOAD_HISTORY_ENTRY ImageLoadHistory;	// A linked-list of loaded images and their respective stack histories.
	EX_PUSH_LOCK ImageLoadHistoryLock;			// The lock protecting the linked-list of loaded images.
	ULONG ImageLoadHistorySize;					// The size of the image load history linked-list.
} PROCESS_HISTORY_ENTRY, *PPROCESS_HISTORY_ENTRY;

typedef class ImageHistoryFilter
{

	static VOID CreateProcessNotifyRoutine (
		_In_ PEPROCESS Process,
		_In_ HANDLE ProcessId,
		_In_ PPS_CREATE_NOTIFY_INFO CreateInfo
		);

	static VOID LoadImageNotifyRoutine (
		_In_ PUNICODE_STRING FullImageName,
		_In_ HANDLE ProcessId,
		_In_ PIMAGE_INFO ImageInfo
		);

	static StackWalker walker;							// Stack walking utility.
	static PPROCESS_HISTORY_ENTRY ProcessHistoryHead;	// Linked-list of process history objects.
	static EX_PUSH_LOCK ProcessHistoryLock;				// Lock protecting the ProcessHistory linked-list.
	static BOOLEAN destroying;							// This boolean indicates to functions that a lock should not be held as we are in the process of destruction.
	static PDETECTION_LOGIC detector;

	static VOID AddProcessToHistory(
		_In_ HANDLE ProcessId,
		_In_ PPS_CREATE_NOTIFY_INFO CreateInfo
		);

	static VOID TerminateProcessInHistory(
		_In_ HANDLE ProcessId
		);

public:
	ImageHistoryFilter(
		_In_ PDETECTION_LOGIC Detector,
		_Out_ NTSTATUS* InitializeStatus
		);
	~ImageHistoryFilter(VOID);

	static BOOLEAN GetProcessImageFileName(
		_In_ HANDLE ProcessId,
		_Inout_ PUNICODE_STRING* ImageFileName
		);

	ULONG GetProcessHistorySummary(
		_In_ ULONG SkipCount,
		_Inout_ PPROCESS_SUMMARY_ENTRY ProcessSummaries,
		_In_ ULONG MaxProcessSummaries
		);

	VOID PopulateProcessDetailedRequest(
		_Inout_ PPROCESS_DETAILED_REQUEST ProcessDetailedRequest
		);

	VOID PopulateProcessSizes(
		_Inout_ PPROCESS_SIZES_REQUEST ProcessSizesRequest
		);

	VOID PopulateImageDetailedRequest(
		_Inout_ PIMAGE_DETAILED_REQUEST ImageDetailedRequest
		);

	static BOOLEAN AddProcessThreadCount(
		_In_ HANDLE ProcessId,
		_Inout_ ULONG* ThreadCount
		);
	static ULONG64 ProcessHistorySize;					// Number of entries in the ProcessHistory linked-list.
} IMAGE_HISTORY_FILTER, *PIMAGE_HISTORY_FILTER;