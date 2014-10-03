/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
#define INCL_DOSERRORS
#define INCL_DOSPROCESS
#include <os2.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "debug.h"
#include "debugger.h"
#include "procstat.h"

/*
** Local buffer for the process status.
*/
static PBUFFHEADER  buff;
#define BUFF_SIZE   0x8000

/*
** Display the name associated with a module handle.
*/
static void DisplayName(USHORT hMod)
{
PMODINFO    pmi = buff->pmi;
int	    i;

    /*
    ** Find the module requested.
    */
    while(pmi && (hMod != pmi->hMod)) {
	pmi = pmi->pNext;
    }

    /*
    ** Sanity check
    */
    if((pmi == NULL) || (hMod != pmi->hMod)) {
	fprintf(logFile, "Error finding module %04x.\n", hMod);
	return;
    }

    /*
    ** Dump the information.
    */
    fprintf(logFile, " %04x  %s\n", pmi->hMod, pmi->szModName);
}

/*
** List the status of a thread.
*/
static void DisplayThread(PTHREADINFO pThread)
{
    fprintf(logFile, "  %04x",	 pThread->tidWithinProcess);
    fprintf(logFile, "   %04x",  pThread->usPriority);
    fprintf(logFile, "   %08x", pThread->ulBlockId);
    switch(pThread->usThreadStatus) {
	case 2:     fprintf(logFile, "   blocked");
		    break;
	case 5:     fprintf(logFile, "   running");
		    break;
	default:    fprintf(logFile, "   %04x", pThread->usThreadStatus);
		    break;
    }
    fprintf(logFile, "  %04x\n", pThread->tidWithinSystem);
}

/*
** List the tasks in the system.
*/
static void DisplayTask(PID pid)
{
PPROCESSINFO ppiLocal = buff->ppi;
PTHREADINFO  pThread;
int	     i;

    while((ppiLocal->ulEndIndicator != PROCESS_END_INDICATOR) &&
	  (pid != ppiLocal->pid)) {

	/*
	** Next PROCESSINFO struct found by taking the address of the first
	** thread control block of the current PROCESSINFO structure and
	** adding the size of a THREADINFO structure times the number of
	** threads
	*/
	ppiLocal = (PPROCESSINFO) (ppiLocal->ptiFirst+ppiLocal->usThreadCount);
    }

    /*
    ** Make sure we found the PID
    */
    if(ppiLocal->ulEndIndicator == PROCESS_END_INDICATOR) {
	fprintf(logFile, "Unable to find PID\n");
	return;
    }

    /*
    ** Dump the ProcessInfo struct.
    */
    DisplayName(ppiLocal->hModRef);

    /*
    ** Dump the thread status information.
    */
    pThread = ppiLocal->ptiFirst;
    fprintf(logFile, " TID  Priority  Block ID     State  System TID\n");
    for(i=0; i<ppiLocal->usThreadCount; i++)
	DisplayThread(&pThread[i]);

    /*
    ** Dump the modules used.
    */
    fprintf(logFile, "  Modules Referenced\n");
    fprintf(logFile, "     ID    Name\n");
    for(i=0; i<ppiLocal->usModCount; i++) {
	fprintf(logFile, "    ");
	DisplayName(ppiLocal->pModHandleTable[i]);
    }
    fprintf(logFile, "\n");
}

/*
** List the tasks in the system.
*/
static void ListTasks()
{
PPROCESSINFO ppiLocal = buff->ppi;

    fprintf(logFile, "\nTasks\n");
    while(ppiLocal->ulEndIndicator != PROCESS_END_INDICATOR) {
	DisplayTask(ppiLocal->pid);

	/*
	** Next PROCESSINFO struct found by taking the address of the first
	** thread control block of the current PROCESS
	*/
	ppiLocal = (PPROCESSINFO) (ppiLocal->ptiFirst+ppiLocal->usThreadCount);
    }
}

/*
** Display the state of a system semaphore.
*/
static DisplaySemaphore(PSEMINFO psi)
{
    fprintf(logFile, "   %04x",      psi->usIndex);
    fprintf(logFile, "  %10d",	     psi->uchReferenceCount);
    fprintf(logFile, "  %8d",	     psi->uchRequestCount);
    fprintf(logFile, "  %04x",	     psi->fsFlags);
    fprintf(logFile, "     \\S%s\n", psi->szSemName);
}

/*
** List the semaphores in the system.
*/
static void ListSemaphores()
{
PSEMINFO ppiSem = (PSEMINFO) (((char *) buff->psi) + sizeof(SEMHEADER));

    fprintf(logFile, "\nSemaphores\n");
    fprintf(logFile, "  Index  References  Requests  Flag     Name\n");
    while(ppiSem->pNext) {
	DisplaySemaphore(ppiSem);
	ppiSem = ppiSem->pNext;
    }
}

/*
** Display the shared memory
*/
static void DisplaySharedMemory(PSHRMEMINFO psmi)
{
    fprintf(logFile, "   %04x ",     psmi->usMemHandle);
    fprintf(logFile, "    %04x  ",   psmi->selMem);
    fprintf(logFile, "     %04x   ", psmi->usReferenceCount);
    fprintf(logFile, "  %s\n",	     psmi->szMemName);
}

/*
** List the shared memory in the system.
*/
static void ListSharedMemory()
{
PSHRMEMINFO psmi = buff->psmi;

    fprintf(logFile, "\nShared Memory\n");
    fprintf(logFile, "  Handle  Selector  References  Shared Memory Name\n");
    while(psmi->pNext) {
	DisplaySharedMemory(psmi);
	psmi = psmi->pNext;
    }
}

/*
** Display the module list
*/
static void DisplayModule(PMODINFO pmi)
{
int i;

    fprintf(logFile, "  %04x",	 pmi->hMod);
    fprintf(logFile, "  %04x",	 pmi->usModType);
    fprintf(logFile, "  %8d",	 pmi->ulSegmentCount);
    fprintf(logFile, "  %08x",	 pmi->ulDontKnow1);
    fprintf(logFile, "  '%s'\n", pmi->szModName);
    fprintf(logFile, "  References:\n");
    fprintf(logFile, "     ID    Name\n");
    for(i=0; i<pmi->ulModRefCount; i++) {
	fprintf(logFile, "    ");
	DisplayName(pmi->usModRef[i]);
    }
    fprintf(logFile, "\n");
}

/*
** List the modules
*/
static void ListModules()
{
PMODINFO pmi = buff->pmi;

    fprintf(logFile, "\nModules\n");
    fprintf(logFile, " Module Type  SegCnt    Unknown   Name\n");
    fprintf(logFile, "\n");
    while(pmi) {
	DisplayModule(pmi);
	pmi = pmi->pNext;
    }
}

/*
** Dump pstat info
*/
void dumpPStat()
{
return;
    buff = malloc(BUFF_SIZE);
    if(DosQProcStatus(buff, BUFF_SIZE) == 0) {
	fprintf(logFile, "==================================================================\n");
	ListTasks();
	ListSemaphores();
	ListSharedMemory();
	ListModules();
	fprintf(logFile, "==================================================================\n");
    }
    free(buff);
}
