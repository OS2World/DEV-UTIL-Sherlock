/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
** Define how to set/clear/list breakpoints.
*/
#include    <stdio.h>
#include    <stdlib.h>
#include    <ctype.h>
#include    <string.h>
#include    <sys\stat.h>
#define     INCL_DOSSESMGR
#define     INCL_DOSEXCEPTIONS

#define     INCL_DOSPROCESS
#include    <os2.h>
#include    "debug.h"

#include    "Debugger.h"
#include    "SrcInter.h"
#include    "Source.h"
#include    "BrkPoint.h"

/*
** Typedefs & structures
*/
typedef struct _Breakpoint {
    struct _Breakpoint *next;
    ULONG   id;                 /* Watchpoint ID from DosDebug      */
    ULONG   addr;               /* Address of the breakpoint        */
    char   *desc;               /* Description of the breakpoint    */
    int     oneTimeFlag;        /* true if go, false if breakpoint  */
} Breakpoint;

static Breakpoint *Breakpoints = NULL;

/*
** Take a string which is supposed to be an executable address,
** and find out what that address is.
*/
ULONG FindExecAddr(char *label, char **brkDesc)
{
ULONG	addr = 0;
char   *desc;
char   *dummy;
ULONG lineNum;
DebugModule *module;
char	funcName[MAX_FUNCNAME];
char	sourceName[CCHMAXPATH];

    /*
    ** If there is no label, give up the ghost!
    */
    if(label == NULL)
	return 0;

    /*
    ** Find the address of the line given a line number.
    */
    if(label[0] == '.') {
        module = FindModule(debugBuffer.MTE, NULL);
	FindSource(module, Linearize(debugBuffer.EIP, debugBuffer.CS),
		   funcName, sourceName, &lineNum);

	/* Cannot find source module. */
	if(strcmp(sourceName, "UNKNOWN") == 0) {
	    return 0;
	}
	lineNum = strtol(&label[1], &dummy, 0);
	addr = FindSourceLine(module, lineNum, sourceName);

	/*
	** Build a string which describes the breakpoint.
	*/
	desc = malloc(strlen(label) + strlen(sourceName) + 1);
	strcpy(desc, sourceName);
	strcat(desc, ":");
	strcat(desc, &label[1]);
	*brkDesc = desc;
	return addr;
    }

    /*
    ** If we have a '!' in the string, then it is a compound
    ** filename/line number
    */
    if(strchr(label, '!') != NULL) {
	char	    *line;

        line = strchr(label, '!');
        *line = '\0';
        module = FindModule(debugBuffer.MTE, NULL);
	FindSource(module, Linearize(debugBuffer.EIP, debugBuffer.CS),
		   funcName, sourceName, &lineNum);
	/* Cannot find source module. */
	if(strcmp(sourceName, "UNKNOWN") == 0) {
	    return 0;
	}
	lineNum = strtol(&label[1], &dummy, 0);
	addr = FindSourceLine(module, lineNum, sourceName);

	/*
	** Build a string which describes the breakpoint.
	*/
	desc = malloc(strlen(label) + strlen(sourceName) + 1);
	strcpy(desc, sourceName);
	strcat(desc, ":");
	strcat(desc, &label[1]);
	*brkDesc = desc;
	return addr;
    }

    /*
    ** Try finding the name as a function
    */
    if((addr = FindFuncAddr(NULL, label)) != 0) {
	desc = malloc(strlen(label) + 1);
	strcpy(desc, label);
	*brkDesc = desc;
	return addr;
    }

    /*
    ** If we could not find a function, try using the label as
    ** a hex offset to break at.
    */
    addr = StrToAddr(label, TOADDR_CODE);
    desc = malloc(strlen(label) + 1);
    strcpy(desc, label);
    *brkDesc = desc;
    return addr;
}

/*
** Take the command pointers and set up the commands.
*/
int CommandGo(char **ptrs)
{
int	i;
ULONG	addr;
char   *desc;
Breakpoint *bp;

    /*
    ** If no parameter, then just go.
    */
    if(ptrs[2] == NULL)
	return DBG_C_Go;

    /*
    ** Find the address of the breakpoint.
    */
    addr = FindExecAddr(ptrs[2], &desc);
    if(addr == 0) {
	fprintf(logFile, "FUNCTION NOT FOUND!\n");
	return -1;
    }

    /*
    ** Set the breakpoint to the address specified.
    */
    debugBuffer.Addr  = addr;
    debugBuffer.Len   = 1;
    debugBuffer.Index = 0;
    debugBuffer.Value = DBG_W_Local | DBG_W_Execute;
    DispatchCommand(DBG_C_SetWatch);

    /*
    ** Add the breakpoint to the list, and tag it as a 'go'
    ** breakpoint which will unconditionally be cleared the
    ** next time we get back from the debuggee.
    */
    if(Breakpoints) {
	for(i=0, bp=Breakpoints; bp->next; i++, bp=bp->next) ;
	bp->next = malloc(sizeof(Breakpoint));
	bp = bp->next;
    } else {
	i = 0;
	Breakpoints = bp = malloc(sizeof(Breakpoint));
    }
    bp->id = debugBuffer.Index;
    bp->addr = addr;
    bp->next = NULL;
    bp->desc = desc;
    bp->oneTimeFlag = 1;
    return DBG_C_Go;
}

/*
** Do a single step to the next source instruction.
*/
int CommandStep(char **ptrs)
{
int	    i;
ULONG	    addr;
ULONG	    lineNum;
Breakpoint *bp;
DebugModule *module;
char	    funcName[MAX_FUNCNAME];
char	    funcName2[MAX_FUNCNAME];
char	    sourceName[CCHMAXPATH];

    /*
    ** Provide a reference to keep from getting a compile warning.
    */
    ptrs;

    /*
    ** Find the address specified.
    */
    module = FindModule(debugBuffer.MTE, NULL);
    FindSource(module, Linearize(debugBuffer.EIP, debugBuffer.CS),
	       funcName, sourceName, &lineNum);
    for(i=0; i<100; i++) {
	lineNum++;
	addr = FindSourceLine(module, lineNum, sourceName);
	if(addr != 0) {
	    FindSource(module, addr, funcName2, sourceName, &lineNum);
	    if(strcmp(funcName2, funcName) == 0)
		break;
	    fprintf(logFile, "Unable to find next line.  Next function found!\n");
	    return -1;
	}
    }

    /*
    ** Did we find a line
    */
    if(addr == 0) {
	fprintf(logFile, "Unable to find next line.\n");
	return -1;
    }

    /*
    ** Set the breakpoint at the address specified.
    */
    debugBuffer.Addr  = addr;
    debugBuffer.Len   = 1;
    debugBuffer.Index = 0;
    debugBuffer.Value = DBG_W_Local | DBG_W_Execute;
    DispatchCommand(DBG_C_SetWatch);

    /*
    ** Add the breakpoint to the list, and tag it as a 'go'
    ** breakpoint which will unconditionally be cleared the
    ** next time we get back from the debuggee.
    */
    if(Breakpoints) {
	for(i=0, bp=Breakpoints; bp->next; i++, bp=bp->next) ;
	bp->next = malloc(sizeof(Breakpoint));
	bp = bp->next;
    } else {
	i = 0;
	Breakpoints = bp = malloc(sizeof(Breakpoint));
    }
    bp->id = debugBuffer.Index;
    bp->addr = addr;
    bp->next = NULL;
    bp->desc = NULL;
    bp->oneTimeFlag = 1;
    return DBG_C_Go;
}

/*
** Take the command pointers and set up the commands.
*/
int CommandBreakpoint(char **ptrs)
{
int	i;
ULONG	addr;
char   *dummy;
char   *desc;
Breakpoint *bp;

    /*
    ** Something to do with breakpoints.  Find out what and do it.
    */
    switch(tolower(ptrs[1][1])) {
	/*
	** Set a breakpoint.
	*/
	case 'p': {
	    int err;

	    /*
	    ** Get the address of the breakpoint.
	    */
	    addr = FindExecAddr(ptrs[2], &desc);
	    if(addr == 0) {
		fprintf(logFile, "FUNCTION NOT FOUND!\n");
		free(desc);
		return -1;
	    }

	    /*
	    ** Set the breakpoint
	    */
	    debugBuffer.Addr  = addr;
	    debugBuffer.Len   = 1;
	    debugBuffer.Index = 0;
	    debugBuffer.Value = DBG_W_Local | DBG_W_Execute;
	    err = DispatchCommand(DBG_C_SetWatch);
	    if(debugBuffer.Cmd != DBG_N_Success) {
		fprintf(logFile, "ERROR CREATING BREAKPOINT %d!\n", err);
		free(desc);
		return -1;
	    }

	    /*
	    ** Connect it to the list.
	    */
	    if(Breakpoints) {
		for(i=0, bp=Breakpoints; bp->next; i++, bp=bp->next) ;
		bp->next = malloc(sizeof(Breakpoint));
		bp = bp->next;
	    } else {
		i = 0;
		Breakpoints = bp = malloc(sizeof(Breakpoint));
	    }
	    bp->id = debugBuffer.Index;
	    bp->addr = addr;
	    bp->next = NULL;
	    bp->desc = desc;
	    bp->oneTimeFlag = 0;
	    break;
	}

	/*
	** Clear a breakpoint.
	*/
	case 'c': {
	    Breakpoint *prior;
	    int num;

	    /*
	    ** Find the watch number, and then the watchpoint id.
	    */
	    if(ptrs[2][0] == '*') {
		FreeAllBreakpoints();
		break;
	    } else {
		i = strtol(ptrs[2], &dummy, 0);
		prior = bp = Breakpoints;
		for(i=0; bp && i<num; i++) {
		    prior = bp;
		    bp = bp->next;
		}
	    }

	    /*
	    ** Make sure the breakpoint exists.
	    */
	    if(bp == NULL) {
		fprintf(logFile, "ILLEGAL BREAKPOINT NUMBER!\n");
		return -1;
	    }

	    /*
	    ** Remove the breakpoint from the list and from the debuggee.
	    */
	    if(bp == Breakpoints) {
		Breakpoints = bp->next;
	    }
	    debugBuffer.Index = bp->id;
	    if(bp->desc)
		free(bp->desc);
	    free(bp);
	    DispatchCommand(DBG_C_ClearWatch);
	    break;
	}

	/*
	** List all of the breakpoints.
	*/
	case 'l': {
	    for(i=0, bp=Breakpoints; bp; i++, bp=bp->next) {
		fprintf(logFile, "Breakpoint [%d]:%08x\n\t%s\n",
			i, bp->addr, bp->desc);
	    }
	    break;
	}
    }
    return -1;
}

/*
** Free all breakpoints.
*/
void FreeAllBreakpoints()
{
Breakpoint *bp, *next;

    for(bp=Breakpoints; bp; ) {
        debugBuffer.Index = bp->id;
	DispatchCommand(DBG_C_ClearWatch);
	next = bp->next;
	if(bp->desc)
	    free(bp->desc);
        free(bp);
        bp = next;
    }
    Breakpoints = NULL;
}

/*
** Answer whether a breakpoint is actually set at the given address.
*/
int isValidBreakpoint(ULONG addr)
{
Breakpoint *bp;
Breakpoint *tmp;
int	    isValid = 0;
int	    firstDead = 1;

    /*
    ** First, see if this is an expected breakpoint.
    */
    for(bp=Breakpoints; bp; bp=bp->next) {
        if(bp->addr == addr) {
	    isValid = 1;
            debugBuffer.Addr  = addr;
            debugBuffer.Len   = 1;
            debugBuffer.Index = 0;
            debugBuffer.Value = DBG_W_Local | DBG_W_Execute;
	    DispatchCommand(DBG_C_SetWatch);
	    break;
        }
    }

    /*
    ** Now, remove all breakpoints.
    */
    for(bp=Breakpoints; bp;bp=bp->next) {
        debugBuffer.Index = bp->id;
	DispatchCommand(DBG_C_ClearWatch);
    }

    /*
    ** Now, go through the list again, setting only the 'permanent' breakpoints.
    */
    tmp = NULL;
    for(bp=Breakpoints; bp;) {
        if(!bp->oneTimeFlag) {
            debugBuffer.Addr  = bp->addr;
            debugBuffer.Len   = 1;
            debugBuffer.Index = 0;
            debugBuffer.Value = DBG_W_Local | DBG_W_Execute;
	    DispatchCommand(DBG_C_SetWatch);
            if(tmp)
                tmp->next = bp;
            else
                tmp = bp;
            bp = bp->next;
        } else {
            Breakpoint *tmp2;

            tmp2 = bp;
	    bp = bp->next;
	    if(tmp2->desc)
		free(tmp2->desc);
            free(tmp2);
        }
    }
    Breakpoints = tmp;
    return isValid;
}
