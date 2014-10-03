/**********************************************************************
 * MODULE NAME :  procstat.h             AUTHOR:  Rick Fishman        *
 * DATE WRITTEN:   2-10-92                                            *
 *                                                                    *
 * DESCRIPTION:                                                       *
 *                                                                    *
 *  This header file contains the function prototype for the asofyet  *
 *  undocumented DosQProcStatus API.  It also contains the structure  *
 *  definitions that are used in the buffer that is returned by the   *
 *  API call.                                                         *
 *                                                                    *
 *  In order to invoke DosQProcStatus, your .DEF file must contain    *
 *  this entry:                                                       *
 *                                                                    *
 *           IMPORTS DOSQPROCSTATUS=DOSCALLS.154                      *
 *                                                                    *
 **********************************************************************/

#pragma linkage( DosQProcStatus, far16 pascal )
USHORT DosQProcStatus( PVOID pvBuf, USHORT cbBuf );

#define PROCESS_END_INDICATOR   3       // Indicates end of process structs

#pragma pack(1)

typedef struct _SUMMARY
{
    ULONG   ulThreadCount;              // Number of threads in system
    ULONG   ulProcessCount;             // Number of processes in system
    ULONG   ulModuleCount;              // Number of modules in system

} SUMMARY, *PSUMMARY;


typedef struct _THREADINFO
{
    UCHAR   uchDontKnow1;               //
    UCHAR   uchDontKnow2;               //
    USHORT  usDontKnow3;                //
    USHORT  tidWithinProcess;           // TID within process (TID is 4 bytes!!)
    USHORT  tidWithinSystem;            // TID within system
    ULONG   ulBlockId;                  // Block ID (?)
    USHORT  usPriority;                 // Priority
    USHORT  usDontKnow4;                //
    USHORT  usDontKnow5;                //
    USHORT  usDontKnow6;                //
    USHORT  usDontKnow7;                //
    USHORT  usDontKnow8;                //
    USHORT  usThreadStatus;             // 2=blocked or ready, 5=running
    USHORT  usDontKnow9;                //

} THREADINFO, *PTHREADINFO;


typedef struct _PROCESSINFO
{
    ULONG       ulEndIndicator;         // 1 means not end, 3 means last entry
    PTHREADINFO ptiFirst;               // Address of the 1st Thread Control Blk
    USHORT      pid;                    // Process ID (2 bytes - PID is 4 bytes)
    USHORT      pidParent;              // Parent's process ID
    USHORT      usDontKnow2;            //
    USHORT      usDontKnow3;            //
    USHORT      usDontKnow4;            //
    USHORT      usDontKnow5;            //
    USHORT      idSession;              // Session ID
    USHORT      usDontKnow6;            //
    USHORT      hModRef;                // Module handle of EXE
    USHORT      usThreadCount;          // Number of threads in this process
    USHORT      usSessionType;          // Session type (SSF_TYPE_xx)
    CHAR        achDontKnow7[ 6 ];      //
    USHORT      usThreadIdCount;        // Number of USHORTs in Thread id table?
    USHORT      usModCount;             // Number of USHORTs in ModHandle table?
    USHORT      usUshortCount;          // Number of USHORTs in Ushort table?
    USHORT      usDontKnow8;            //
    ULONG       ulThreadIdTableAddr;    // Maybe the address of a TID table
    PUSHORT	pModHandleTable;	// Address of a ModHandle table (DLLS?)
    ULONG       ulUshortTableAddr;      // Address of a table of USHORTs (?)

} PROCESSINFO, *PPROCESSINFO;


typedef struct _SEMHEADER
{
    USHORT   ownPid;			// 0 Owner PID
    USHORT   achDontKnow1;		// 2
    ULONG    achDontKnow2[2];		// 4
    USHORT   usIndex;			// C Semaphore Index
    USHORT   achDontKnow3;		// E
					// 10
} SEMHEADER, *PSEMHEADER;

typedef struct _SEMINFO
{
    struct _SEMINFO *pNext;		// 0 Pointer to next block
    USHORT   fsFlags;			// 4 (MSB-LSB)
    UCHAR    achDontKnow1[1];		// 6
    UCHAR    uchReferenceCount; 	// 7 Number of references
    UCHAR    uchRequestCount;		// 8 Number of requests
    CHAR     achDontKnow2[3];		// 9
    USHORT   usIndex;			// c Semaphore Index
    CHAR     szSemName[ 1 ];		// e ASCIIZ semaphore name
					// ?
} SEMINFO, *PSEMINFO;

typedef struct _SHRMEMINFO
{
    struct _SHRMEMINFO *pNext;           // Pointer to next block
    USHORT      usMemHandle;             // Shared memory handle (?)
    SEL         selMem;                  // Selector
    USHORT      usReferenceCount;        // Number of references
    CHAR        szMemName[ 1 ];          // ASCIIZ shared memory name

} SHRMEMINFO, *PSHRMEMINFO;


typedef struct _MODINFO
{
    struct _MODINFO *pNext;              // Pointer to next block
    USHORT   hMod;                       // Module handle
    USHORT   usModType;                  // Module type (0=16bit,1=32bit)
    ULONG    ulModRefCount;              // Count of module references
    ULONG    ulSegmentCount;             // Number of segments in module
    ULONG    ulDontKnow1;                //
    PSZ      szModName;                  // Addr of fully qualified module name
    USHORT   usModRef[ 1 ];              // Handles of module references

} MODINFO, *PMODINFO;


typedef struct _BUFFHEADER
{
    PSUMMARY	    psumm;		// Pointer to SUMMARY section
    PPROCESSINFO    ppi;		// Pointer to PROCESS section
    PSEMINFO	    psi;		// Pointer to SEMAPHORE section
    PVOID	    pDontKnow1; 	// Unknown
    PSHRMEMINFO     psmi;		// Pointer to SHARED MEMORY section
    PMODINFO	    pmi;		// Pointer to MODULE section
    PVOID	    pDontKnow2; 	//
    PVOID	    pDontKnow3; 	//

} BUFFHEADER, *PBUFFHEADER;

#pragma pack()
