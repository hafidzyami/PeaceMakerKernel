/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE', which is part of this source code package.
 * 
 * COPYRIGHT Bill Demirkapi 2020
 */
#pragma once
#include "common.h"
#include "DetectionLogic.h"
#include "ImageHistoryFilter.h"
#include "StackWalker.h"

typedef class ThreadFilter
{
	static PDETECTION_LOGIC Detector;	// Detection utility.
	static STACK_WALKER Walker;			// Stack walking utility.

	static PVOID GetThreadStartAddress(
		_In_ HANDLE ThreadId
		);

	static VOID ThreadNotifyRoutine(
		HANDLE ProcessId,
		HANDLE ThreadId,
		BOOLEAN Create
		);
public:
	ThreadFilter(
		_In_ PDETECTION_LOGIC DetectionLogic,
		_Inout_ NTSTATUS* InitializeStatus
		);
	~ThreadFilter(VOID);


} THREAD_FILTER, *PTHREAD_FILTER;