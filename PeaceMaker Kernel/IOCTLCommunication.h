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
#include "ThreadFilter.h"
#include "RegistryFilter.h"
#include "TamperGuard.h"

typedef class IOCTLCommunication
{
	static PDRIVER_OBJECT DriverObject;
	static PDETECTION_LOGIC Detector;
	static PIMAGE_HISTORY_FILTER ImageProcessFilter;
	static PREGISTRY_BLOCKING_FILTER RegistryMonitor;
	static PTHREAD_FILTER ThreadOperationFilter;
	static PTAMPER_GUARD TamperGuardFilter;

	NTSTATUS InitializeDriverIOCTL(VOID);
	VOID UninitializeDriverIOCTL(VOID);

	static NTSTATUS IOCTLCreateClose(
		_In_ PDEVICE_OBJECT DeviceObject,
		_In_ PIRP Irp
		);
	static NTSTATUS IOCTLDeviceControl(
		_In_ PDEVICE_OBJECT DeviceObject,
		_In_ PIRP Irp
		);

public:
	IOCTLCommunication(
		_In_ PDRIVER_OBJECT Driver,
		_In_ PUNICODE_STRING RegistryPath,
		_In_ PFLT_FILTER_UNLOAD_CALLBACK UnloadRoutine OPTIONAL,
		_Inout_ NTSTATUS* InitializeStatus
		);
	~IOCTLCommunication(VOID);
} IOCTL_COMMUNICATION, *PIOCTL_COMMUNICATION;

#define DETECTION_LOGIC_TAG 'lDmP'
#define IMAGE_HISTORY_FILTER_TAG 'fImP'
#define REGISTRY_MONITOR_TAG 'mRmP'
#define THREAD_FILTER_TAG 'fTmP'
#define TAMPER_GUARD_TAG 'gTmP'