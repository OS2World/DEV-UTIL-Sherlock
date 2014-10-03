/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
**  Dispatch a command.  If we have a module loaded, get the
*/
#include    <stdlib.h>
#include    <stdio.h>
#include    <sys/stat.h>
#define     INCL_DOSSESMGR
#define     INCL_DOSPROCESS
#include    <os2.h>
#include    "debug.h"

#include    "Debugger.h"
#include    "SrcInter.h"
#include    "Source.h"

/*
** Global variables.
*/
int FlipScreen = 1;

/*
** Static variables.
*/
static int nest = 0;

/*
** Dispatch a command and handle it properly.
*/
int _System DispatchCommand(int command)
{
int keepGoing = 1;
int status;
int tmp, active;

    if(command == DBG_C_Go ||
       command == DBG_C_SStep ||
       command == DBG_C_RangeStep ||
       command == DBG_C_XchgOpcode)
	active = 1;
    else
	active = 0;

    debugBuffer.Cmd = command;
    if(FlipScreen && active)
	DosSelectSession(debugInfo.session);
    while(keepGoing) {
	fflush(logFile);
	if((status = DosDebug(&debugBuffer)) != 0) {
	    fprintf(logFile, "COMMAND %d ERROR!: %d\n", command, status);
	    exit(1);
	}
	switch(debugBuffer.Cmd) {
            case DBG_N_ModuleLoad:  /* Module loaded    */
		tmp = FlipScreen;
		FlipScreen = 0;
		LoadDebuggeeModule(debugBuffer.Value);
		DispatchCommand(DBG_C_Stop);
		debugBuffer.Cmd = command;
		FlipScreen = tmp;
		break;

            case DBG_N_ModuleFree:  /* Module freed     */
		tmp = FlipScreen;
		FlipScreen = 0;
		FreeDebuggeeModule(debugBuffer.Value);
		DispatchCommand(DBG_C_Stop);
		debugBuffer.Cmd = command;
		FlipScreen = tmp;
		break;

            case DBG_N_Success:     /* Successful command completion    */
		keepGoing = 0;
                break;

            case DBG_N_Error:       /* Error detected during command    */
                keepGoing = 0;
                break;

            case DBG_N_ProcTerm:    /* Process termination - DosExitList done   */
                keepGoing = 0;
                break;

            case DBG_N_Exception:   /* Exception detected               */
                keepGoing = 0;
		break;

            case DBG_N_CoError:     /* Coprocessor not in use error     */
                keepGoing = 0;
                break;

            case DBG_N_ThreadTerm:  /* Thread termination - not in DosExitList  */
                keepGoing = 0;
                break;

            case DBG_N_AsyncStop:   /* Async Stop detected              */
                keepGoing = 0;
                break;

            case DBG_N_NewProc:     /* New Process started      */
                keepGoing = 0;
                break;

            case DBG_N_AliasFree:   /* Alias needs to be freed  */
                keepGoing = 0;
                break;

            case DBG_N_Watchpoint:  /* Watchpoint hit           */
                keepGoing = 0;
                break;

            case DBG_N_ThreadCreate:    /* Thread creation      */
                keepGoing = 0;
                break;

            case DBG_N_RangeStep:   /* Range Step detected      */
                keepGoing = 0;
                break;
        }
    }

    /*
    ** Restore the screen if needed.
    */
#ifndef SHERLOCK
    if(FlipScreen && active)
	DosSelectSession(0);
#endif
    nest--;
    return debugBuffer.Cmd;
}
