/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
**  Handle an exeption from the debuggee.
*/
#include    <stdlib.h>
#include    <stdio.h>
#define     INCL_DOSSESMGR
#define     INCL_DOSPROCESS
#define     INCL_DOSEXCEPTIONS
#include    <os2.h>
#include    <sys\stat.h>
#include    "debug.h"

#include    "Debugger.h"
#include    "SrcInter.h"
#include    "Source.h"
#include    "Except.h"
#include    "BrkPoint.h"

ULONG   ExecptionNumber;

/*
** Get an ASCII equivalent of the exection's name.
*/
static char *findExceptionName(ULONG exceptionNum)
{
    switch(exceptionNum) {

        /*
        ** Portable Non-Fatal Software-Generated Exceptions
        */
        case XCPT_GUARD_PAGE_VIOLATION:
            return "Guard Page violation";

        /*
        ** Portable Fatal Hardware-Generated Exceptions
        */
        case XCPT_ACCESS_VIOLATION:
            return "Access violation";
        case XCPT_INTEGER_DIVIDE_BY_ZERO:
            return "Integer divide by zero";
        case XCPT_FLOAT_DIVIDE_BY_ZERO:
            return "Float divide by zero";
        case XCPT_FLOAT_INVALID_OPERATION:
            return "Float invalid operation";
        case XCPT_ILLEGAL_INSTRUCTION:
            return "Illegal instruction";
        case XCPT_PRIVILEGED_INSTRUCTION:
            return "Privileged instruction";
        case XCPT_INTEGER_OVERFLOW:
            return "Integer overflow";
        case XCPT_FLOAT_OVERFLOW:
            return "Float overflow";
        case XCPT_FLOAT_UNDERFLOW:
            return "Float underflow";
        case XCPT_FLOAT_DENORMAL_OPERAND:
            return "Float denormal operand";
        case XCPT_FLOAT_INEXACT_RESULT:
            return "Float inexact result";
        case XCPT_FLOAT_STACK_CHECK:
            return "Float stack check";
        case XCPT_DATATYPE_MISALIGNMENT:
            return "Datatype misalignment";
        case XCPT_BREAKPOINT:
            return "Breakpoint";
        case XCPT_SINGLE_STEP:
            return "Single step";

        /*
        ** Portable Fatal Software-Generated Exceptions
        */
        case XCPT_IN_PAGE_ERROR:
            return "In page error";
        case XCPT_PROCESS_TERMINATE:
            return "Process terminate";
        case XCPT_NONCONTINUABLE_EXCEPTION:
            return "Noncontinuable exception";
        case XCPT_INVALID_DISPOSITION:
            return "Invalid disposition";

        /*
        ** Non-portable Fatal exceptions
        */
        case XCPT_INVALID_LOCK_SEQUENCE:
            return "Invalid lock sequence";
        case XCPT_ARRAY_BOUNDS_EXCEEDED:
            return "Array bounds exceeded";

        /*
        ** Unwind operation exceptions.
        */
        case XCPT_UNWIND:
            return "Unwind";
        case XCPT_BAD_STACK:
            return "Bad stack";
        case XCPT_INVALID_UNWIND_TARGET:
            return "Invalid unwind target";

        /*
        ** Fatal signal exceptions.
        */
        case XCPT_SIGNAL:
            return "Signal";
    }
    return "UNKNOWN";
}

/*
** Handle an exception.  Return whether the execption was expected
** or whether it was unexpected.
*/
int HandleException(int command)
{
DebugModule *module;

    /*
    ** Pre-first change for debugger help.
    */
    fprintf(logFile, "Execption type %d at %08x\n",
	    debugBuffer.Value, debugBuffer.Addr);
    if(debugBuffer.Value == 0) {

	/*
        ** Single step is always expected if the command was
        ** single step!
        */
        if((command == DBG_C_SStep) &&
           (debugBuffer.Buffer == XCPT_SINGLE_STEP)) {
                debugBuffer.Value = XCPT_CONTINUE_STOP;
		DispatchCommand(DBG_C_Continue);
                return 0;
        }

        /*
        ** Breakpoints are expected only if a breakpoint was
        ** set at the address.
        */
        if(debugBuffer.Buffer == XCPT_BREAKPOINT) {
            if(isValidBreakpoint(debugBuffer.Addr)) {
                debugBuffer.Value = XCPT_CONTINUE_STOP;
		DispatchCommand(DBG_C_Continue);
                return 0;
            } else {
                debugBuffer.Value = XCPT_CONTINUE_SEARCH;
		DispatchCommand(DBG_C_Continue);
		fprintf(logFile, "ERROR! Unexpected breakpoint!\n");
                return 0;
            }
        }

        /*
        ** Unknown exection!
        */
	fprintf(logFile, "ERROR! Unexpected exception: %s (%08x) for pre-first!\n",
                findExceptionName(debugBuffer.Buffer), debugBuffer.Buffer);
	debugBuffer.Value = XCPT_CONTINUE_STOP;
	DispatchCommand(DBG_C_Continue);
	return 0;
    }

    /*
    ** First or second notification.
    */
    if((debugBuffer.Value == 1) || (debugBuffer.Value == 2)) {
	EXCEPTIONREPORTRECORD	stats;
	int			i;

	debugBuffer.Len    = sizeof(stats);
	debugBuffer.Addr   = debugBuffer.Buffer;
	debugBuffer.Buffer = (ULONG) &stats;
	if(DispatchCommand(DBG_C_ReadMemBuf) != DBG_N_Success) {
	    fprintf(logFile, "Unable to get exception record\n");
	}

	fprintf(logFile, "  Except #: %08x  %s\n",
		stats.ExceptionNum,
		findExceptionName(stats.ExceptionNum));
	fprintf(logFile, "  Flags:    %08x\n",
		stats.fHandlerFlags);
	fprintf(logFile, "  Next Rec: %08x\n",
		stats.NestedExceptionReportRecord);
	fprintf(logFile, "  Except Addr: %08x\n",
		stats.ExceptionAddress);
	fprintf(logFile, "  Num Parms: %d\n",
		stats.cParameters);
	for(i=0; i<stats.cParameters; i++) {
	    fprintf(logFile, "  Except %d: %08x\n",
		    i, stats.ExceptionInfo[i]);
	}

	/*
	** Find where this address is.
	*/
	module = FindModule(debugBuffer.MTE, NULL);
	if(module != NULL) {
	    char    funcName[MAX_FUNCNAME];
	    char    sourceName[CCHMAXPATH];
	    ULONG   lineNum;

	    FindSource(module, (ULONG) stats.ExceptionAddress,
	       funcName, sourceName, &lineNum);
	    if(lineNum != 0)
		fprintf(logFile, "\n"
				"  Module:   %s\n"
				"  Size:     %u\n"
				"  Timestamp:%s\n"
				"  Function: %s\n"
				"  Source:   %s\n"
				"  Line:     %d\n\n",
			module->name, module->fileSize,
			ctime(&module->fTimestamp),
			funcName, sourceName, lineNum);
	    else
		fprintf(logFile, "  Module:   %s\n"
				"  Size:     %u\n"
				"  Timestamp:%s\n"
				"  Lo Function: %s\n"
				"  Hi Function: %s\n\n",
			module->name, module->fileSize,
			ctime(&module->fTimestamp),
			funcName, sourceName);
	}

	/*
	** Tell the system to continue with the exception handling.
	*/
	debugBuffer.Value = XCPT_CONTINUE_STOP;
	DispatchCommand(DBG_C_Continue);
	return 0;
    }

    /*
    ** Invalid stack notification.
    */
    if(debugBuffer.Value == 3) {
	fprintf(logFile, "INVALID STACK EXECTION %08x AT: %08x\n",
                debugBuffer.Buffer, debugBuffer.Addr);
    }

    debugBuffer.Value = XCPT_CONTINUE_STOP;
    DispatchCommand(DBG_C_Continue);
    return 0;
}
