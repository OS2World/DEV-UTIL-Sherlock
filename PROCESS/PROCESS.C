/*********************************************************************/
/*------- Include relevant sections of the OS/2 header files --------*/
/*********************************************************************/

#define INCL_DOSERRORS
#define INCL_DOSPROCESS

/**********************************************************************/
/*----------------------------- INCLUDES -----------------------------*/
/**********************************************************************/

#include <os2.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "procstat.h"


/*
** Local buffer for the process status.
*/
static PBUFFHEADER  buff;

void myhexdump(unsigned char *data, int count);
void hexdump(unsigned char *data, int count, char *buff);
#define BUFF_SIZE   0x8000

/*
** Display the name associated with a module handle.
*/
void DisplayName(USHORT hMod)
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
	printf("Error finding module %04x.\n", hMod);
	return;
    }

    /*
    ** Dump the information.
    */
    printf(" %s(%04x)\n", pmi->szModName, pmi->hMod);
}

/*
** List the status of a thread.
*/
void DisplayThread(PTHREADINFO pThread)
{
    printf("  %04x",   pThread->tidWithinProcess);
    printf("   %04x",  pThread->usPriority);
    printf("    %08x", pThread->ulBlockId);
    printf("  %04x",   pThread->usThreadStatus);
    printf("  %04x\n", pThread->tidWithinSystem);


#if 0
    printf("C1 C2 S3   S4   S5   S6   S7   S8   S9\n");
    printf(" %02x", pThread->uchDontKnow1);
    printf(" %02x", pThread->uchDontKnow2);
    printf(" %04x", pThread->usDontKnow3);
    printf(" %04x", pThread->usDontKnow4);
    printf(" %04x", pThread->usDontKnow5);
    printf(" %04x", pThread->usDontKnow6);
    printf(" %04x", pThread->usDontKnow7);
    printf(" %04x", pThread->usDontKnow8);
    printf(" %04x\n", pThread->usDontKnow9);
#endif
}

/*
** List the tasks in the system.
*/
void DisplayTask(PID pid)
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
	printf("Unable to find PID\n");
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
    printf(" TID  Priority  Block ID  State  System TID\n");
    for(i=0; i<ppiLocal->usThreadCount; i++)
	DisplayThread(&pThread[i]);

    /*
    ** Dump the modules used.
    */
    for(i=0; i<ppiLocal->usModCount; i++) {
	printf("    ");
	DisplayName(ppiLocal->pModHandleTable[i]);
    }
    printf("\n");
}

/*
** List the tasks in the system.
*/
void ListTasks()
{
PPROCESSINFO ppiLocal = buff->ppi;

    printf("\nTasks\n");
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
DisplaySemaphore(PSEMINFO psi)
{
    printf("   %04x",	   psi->usIndex);
    printf("  %10d",	   psi->uchReferenceCount);
    printf("  %8d",	   psi->uchRequestCount);
    printf("  %04x",	   psi->fsFlags);
    printf("     \\S%s\n", psi->szSemName);
}

/*
** List the semaphores in the system.
*/
void ListSemaphores()
{
PSEMINFO ppiSem = (PSEMINFO) (((char *) buff->psi) + sizeof(SEMHEADER));

    printf("\nSemaphores\n");
    printf("  Index  References  Requests  Flag     Name\n");
    while(ppiSem->pNext) {
	DisplaySemaphore(ppiSem);
	ppiSem = ppiSem->pNext;
    }
}

/*
** Display the shared memory
*/
void DisplaySharedMemory(PSHRMEMINFO psmi)
{
    printf("   %04x ",	   psmi->usMemHandle);
    printf("    %04x  ",   psmi->selMem);
    printf("     %04x   ", psmi->usReferenceCount);
    printf("  %s\n",	   psmi->szMemName);
}

/*
** List the shared memory in the system.
*/
void ListSharedMemory()
{
PSHRMEMINFO psmi = buff->psmi;

    printf("\nShared Memory\n");
    printf("  Handle  Selector  References  Shared Memory Name\n");
    while(psmi->pNext) {
	DisplaySharedMemory(psmi);
	psmi = psmi->pNext;
    }
}

/*
** Display the module list
*/
DisplayModule(PMODINFO pmi)
{
int i;

    printf("  %04x",   pmi->hMod);
    printf("  %04x",   pmi->usModType);
    printf("  %8d",    pmi->ulSegmentCount);
    printf("  %08x",   pmi->ulDontKnow1);
    printf("  '%s'\n", pmi->szModName);
    printf("  References:\n");
    for(i=0; i<pmi->ulModRefCount; i++) {
	printf("    ");
	DisplayName(pmi->usModRef[i]);
    }
    printf("\n");
}

/*
** List the modules
*/
void ListModules()
{
PMODINFO pmi = buff->pmi;

    printf("\nModules\n");
    printf(" Module Type  SegCnt    Unknown   Name\n");
    printf("\n");
    while(pmi) {
	DisplayModule(pmi);
	pmi = pmi->pNext;
    }
}

/*
** Main entrance
*/
int main(int argc, char **argv)
{
    buff = malloc(BUFF_SIZE);
    DosQProcStatus(buff, BUFF_SIZE);
    ListTasks();
    ListSemaphores();
    ListSharedMemory();
    ListModules();
    free(buff);
    return 0;
}
