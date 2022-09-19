#pragma once
#include <Windows.h>
#include "ntstructs.h"

typedef NTSTATUS(NTAPI* sNtWaitForSingleObject)(

	IN HANDLE               ObjectHandle,
	IN BOOLEAN              Alertable,
	IN PLARGE_INTEGER       TimeOut OPTIONAL);

typedef NTSTATUS(NTAPI* sNtAllocateVirtualMemory)(

	IN HANDLE               ProcessHandle,
	IN OUT PVOID*			BaseAddress,
	IN ULONG                ZeroBits,
	IN OUT PULONG           RegionSize,
	IN ULONG                AllocationType,
	IN ULONG                Protect);

typedef NTSTATUS(NTAPI* sNtFreeVirtualMemory)(

	IN HANDLE               ProcessHandle,
	IN PVOID*				BaseAddress,
	IN OUT PULONG           RegionSize,
	IN ULONG                FreeType);

typedef NTSTATUS(NTAPI* sNtProtectVirtualMemory)(

	IN HANDLE               ProcessHandle,
	IN OUT PVOID*			BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection);

typedef NTSTATUS(NTAPI* sNtWriteVirtualMemory)(

	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL);

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE)(
	_In_ PVOID ApcContext,
	_In_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ ULONG Reserved);

typedef NTSTATUS(NTAPI* sNtQueueApcThread)(

	IN HANDLE               ThreadHandle,
	IN PIO_APC_ROUTINE      ApcRoutine,
	IN PVOID                ApcRoutineContext OPTIONAL,
	IN PIO_STATUS_BLOCK     ApcStatusBlock OPTIONAL,
	IN ULONG                ApcReserved OPTIONAL);

typedef NTSTATUS (NTAPI* sNtContinue)(

	IN PCONTEXT             ThreadContext,
	IN BOOLEAN              RaiseAlert);

typedef NTSTATUS(NTAPI* sRtlCreateUserThread)(
	IN HANDLE               ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN              CreateSuspended,
	IN ULONG                StackZeroBits,
	IN OUT PULONG           StackReserved,
	IN OUT PULONG           StackCommit,
	IN PVOID                StartAddress,
	IN PVOID                StartParameter OPTIONAL,
	OUT PHANDLE             ThreadHandle,
	OUT PCLIENT_ID          ClientID);


typedef NTSTATUS(NTAPI* sNtWaitForSingleObject)(
	IN HANDLE               ObjectHandle,
	IN BOOLEAN              Alertable,
	IN PLARGE_INTEGER       TimeOut OPTIONAL);