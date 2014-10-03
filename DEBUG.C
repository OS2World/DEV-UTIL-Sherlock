/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
**  Beginning of a debugger.
*/
#include    <signal.h>
#include    <stdio.h>
#include    <stdlib.h>
#include    <setjmp.h>
#include    <ctype.h>
#include    <string.h>
#include    <sys\stat.h>
#define     INCL_DOSSESMGR
#define     INCL_DOSPROCESS
#define     INCL_DOSEXCEPTIONS
#include    <os2.h>
#include    "debug.h"

#include    "Debugger.h"
#include    "BrkPoint.h"
#include    "Watch.h"
#include    "Register.h"
#include    "Except.h"
#include    "SrcInter.h"
#include    "Source.h"
#include    "SrcDisp.h"
#ifndef SHERLOCK
#include    "ProcStat.h"
#endif

#define MAX_ARGS 10

struct ThreadList {
    struct ThreadList  *next;
    TID 		tid;
} threadList = { NULL, 1};

static char *ptrs[MAX_ARGS];	    /* Pointers to command arguments.	*/
#define MAX_COMMAND 256
static char buff[MAX_COMMAND];	    /* Command buffer.			*/
static char dupBuff[MAX_COMMAND];   /* Command buffer copy.		*/
static jmp_buf	JumpBuff;	    /* Break jump buffer.		*/
static char logFileName[260] = "SHERLOCK.LOG";	/* Default log file.	*/

/*
** Function prototypes for the files static functions.
*/
static void APIENTRY Cleanup(void);
static void GetCommand(char *buff, int sizeBuff, char **ptrs, int sizePtrs);
static int DoCommand(char **ptrs);

/*
** Terminate the debugger.
*/
static void APIENTRY Cleanup()
{
    FreeAllBreakpoints();
    FreeAllWatchpoints();
    FreeAllModules();
    DosExitList(EXLST_EXIT, (PFNEXITLIST) Cleanup);
    return;
}

/*
** Function to dump the exception data.
*/
static void dumpExceptionData(void);
static void dumpExceptionData()
{
ULONG curTID;
struct ThreadList *link;

    curTID = debugBuffer.Tid;
    fprintf(logFile, "Exception in thread: %d\n\n", curTID);
    for(link=&threadList; link; link=link->next) {
        debugBuffer.Tid = link->tid;
        if(DispatchCommand(DBG_C_ReadReg) != DBG_N_Success)
            continue;
        DumpRegs(&debugBuffer);
        DumpStack(link->tid);
    }
    debugBuffer.Tid = curTID;
}

/*
** If we get a ^Break or ^C:
**   1) then stop program execution
**   2) Prompt for kill debuggee
**   3) Either continue or stop
**
*/
static void breakHandler(int event);
static void breakHandler(int event)
{
int	stop;

    /*
    ** Reset the break handler.
    */
    signal(event, breakHandler);

    /*
    ** Stop the debuggee for now.
    */
    debugBuffer.Tid = 0;
    DispatchCommand(DBG_C_Stop);

    /*
    ** Ask whether to stop the debuggee if in the debugger.
    ** If in Sherlock, stop the debuggee.
    */
#ifdef SHERLOCK
    stop = 1;
#else
    fprintf(stderr, "Stop debug process? (Y/n)");
    fflush(stderr);
    while(1) {
	char	ans;

	ans = getchar();
	if((ans == 'Y') || (ans == 'y') || (ans == '\n') || (ans == '\r')) {
	    stop = 1;
	    break;
	}

	if((ans = 'N') || (ans == 'n')) {
	    stop = 0;
	    break;
	}
    }
#endif

    /*
    ** If we wish to stop, jump to debug loop and continue.
    */
    if(stop)
	longjmp(JumpBuff, 0);

    /*
    ** If response is not to stop, then continue.
    */
    DispatchCommand(DBG_C_Go);
    return;
}

/*
** Get a command from the user and parse it into pieces.
*/
static void GetCommand(char *buff, int sizeBuff, char **ptrs, int sizePtrs)
{
char *p;
int  i;

    fflush(logFile);
    for(i=0; i<sizePtrs; i++)
	ptrs[i]=NULL;

restart:
    fprintf(logFile, "\nCommand>");
    fflush(logFile);
    fgets(buff, sizeBuff, stdin);

    p = buff;
    ptrs[0] = dupBuff;
    for(i=0; i<(int)strlen(buff); i++) {
	if(isspace(buff[i]))
	    buff[i] = ' ';
    }
    for(i=strlen(buff)-1; i>=0 && isspace(buff[i]); i--) {
	if(isspace(buff[i]))
	    buff[i] = 0;
    }

    /*
    ** Set up the full argument list parameter as index 0
    */
    while( isspace(*p) && *p) p++;
    while(!isspace(*p) && *p) p++;
    while( isspace(*p) && *p) p++;
    if(*p) {
	strcpy(dupBuff, p);
	ptrs[0] = dupBuff;
    } else {
	ptrs[0] = NULL;
    }

    /*
    ** For convienience, break the space separated parameters.
    */
    p = buff;
    for(i=1; i<sizePtrs; i++) {
	if(*p == 0)
	    break;

	/*
        ** Strip off the leading white space.
	*/
        for(;isspace(*p) && *p; p++)
            ;

        /*
        ** Skip over parameter?
        */
        if(*p == ',') {
            continue;
        }

        /*
	** No more on line?
	*/
	if(*p == 0)
	    break;
        ptrs[i] = p;

        /*
        ** Quote delimited strings are allowed.
        */
        if(*p == '\'') {
            p++;
            ptrs[i] = p;
            for(; *p && *p != '\''; p++)
                ;
            if(*p != '\'') {
		fprintf(logFile, "ILLEGAL STRING!\n");
                goto restart;
            }

        /*
        ** Double quote string.
        */
        } else if(*p == '"') {
            p++;
            ptrs[i] = p;
            for(; *p && *p != '"'; p++) ;
            if(*p != '"') {
		fprintf(logFile, "ILLEGAL STRING!\n");
                goto restart;
            }

        /*
        ** Normal parameter.
        */
        } else {
            for(;!((*p == ',') || isspace(*p)) && *p; p++)
                ;
        }

	/*
	** If we are at the end of the line, drop it.
	*/
	if(*p == 0)
	    break;

        /*
	** Null terminate the parameter and then continue;
	*/
        *p = '\0';
	p++;

        /*
        ** Drop a trailing , if it exists.
        */
        if(*p == ',')
            p++;
    }

    /*
    ** If we don't have any commands, try again!
    */
    if(ptrs[1] == NULL)
        goto restart;

    return;
}

/*
** Dispatch a command.
*/
static int DoCommand(char **ptrs)
{
char	cmd;

    cmd = (char) tolower(ptrs[1][0]);

    /*
    ** Quit?
    */
    if(cmd == 'q')
	return 666;

    /*
    ** Redisplay where we currently are.
    */
    if(cmd == '.') {
	DebugModule *module;
	char	    funcName[MAX_FUNCNAME];
	char	    sourceName[CCHMAXPATH];
	ULONG	    lineNum;

	debugBuffer.Addr = Linearize(debugBuffer.EIP, debugBuffer.CS);
	DispatchCommand(DBG_C_AddrToObject);
	if((debugBuffer.Cmd == DBG_N_Success) && (debugBuffer.Value & 0x10000000)) {
	    module = FindModule(debugBuffer.MTE, NULL);
	    FindSource(module, Linearize(debugBuffer.EIP, debugBuffer.CS),
		       funcName, sourceName, &lineNum);
	    DisplaySource(module, sourceName, lineNum);
	}
	return -1;
    }

    /*
    ** Stack dump.
    */
    if(cmd == 'k') {
	int threadID;
	char *dummy;

	threadID = debugBuffer.Tid;
	if(ptrs[2] != NULL)
	    threadID = strtoul(ptrs[2], &dummy, 0);
	DumpStack(threadID);
        return -1;
    }

    /*
    ** Talk to the watchpoint module to do the watchpoints.
    */
    if(cmd == 'w') {
	WatchCommand(ptrs);
	return -1;
    }

    /*
    ** Display an expression.
    */
    if(cmd == '?') {
        ViewVariableCommand(ptrs);
        return -1;
    }

    /*
    ** Display an expression.
    */
    if(cmd == 'd') {
	ULONG	startAddr;
	ULONG	endAddr;
	char	buff[80];
	UCHAR	data[16];
	char   *dummy;

	if(ptrs[2] != NULL)
	    startAddr = strtoul(ptrs[2], &dummy, 16);
	else
	    startAddr = 0;

	if(ptrs[3] != NULL)
	    endAddr= strtoul(ptrs[2], &dummy, 16);
	else
	    endAddr = startAddr + 0x80;

	if(startAddr == 0)
	    return -1;

	for( ; startAddr < endAddr; startAddr += 16) {
	    int len;

	    len = (startAddr - endAddr) > 16 ? 16 : startAddr - endAddr;
	    debugBuffer.Len    = len;
	    debugBuffer.Addr   = startAddr;
	    debugBuffer.Buffer = (ULONG) data;
	    if(DispatchCommand(DBG_C_ReadMemBuf) != DBG_N_Success)
		return -1;

	    hexdump(data, len, buff);
	    fprintf(logFile, "%08x %s\n", startAddr, buff);
	}
        return -1;
    }

    /*
    ** Dump/Display registers.
    */
    if(cmd == 'r') {
	return CommandRegister(ptrs);
    }

    /*
    ** Talk to the breakpoint module to do the breakpoints.
    */
    if(cmd == 't')
	return DBG_C_SStep;

    if(cmd == 'b')
	return CommandBreakpoint(ptrs);

    if(cmd == 'g')
	return CommandGo(ptrs);

    if(cmd == 'p')
	return CommandStep(ptrs);

    /*
    ** Source/Assembler view options.
    */
    if(cmd == 'v')
	return CommandView(ptrs);

    if(cmd == 'u')
	return CommandUnassemble(ptrs);

    if(cmd == 's')
	return CommandSource(ptrs);

    return -1;
}

/*
** Parse the command line
*/
int parseCommandLine(int argc, char **argv)
{
int i;

    for(i=1; i<argc; i++) {
	if(argv[i][0] != '-')
	    return i;
	switch(tolower(argv[i][1])) {
	    case 'l':	if(argv[i][2] == 0)
			    return -i;
			strcpy(logFileName, &argv[i][2]);
			break;
	}
    }
    return argc;
}

/*
** Main entrance routine.
*/
int main(int argc, char **argv);
int main(int argc, char **argv)
{
static char sourceName[CCHMAXPATH];
static char funcName[MAX_FUNCNAME];
int nextState;                  /* Desired next state.                  */
int live = 1;                   /* Whether the debugger is still alive  */
int lastState = DBG_N_Success;
ULONG lineNum;

    /*
    ** Put up the banner.
    */
    fprintf(stderr, "SHERLOCK - Copyright 1992, 1993, 1994, 1994\n");
    fprintf(stderr, " Version 1.1\n");
    fprintf(stderr, " Harfmann Software\n");
    fprintf(stderr, " All rights reserved.\n");

    /*
    ** Parse the command line.
    */
    nextState = parseCommandLine(argc, argv);
    if(nextState < 0) {
	fprintf(stderr, "Command line error: '%s'\n", argv[-nextState]);
	exit(1);
    }
    if(argc == nextState) {
	fprintf(stderr, "Usage: %s [-l] test.exe <parm1 parm2 ...>\n", argv[0]);
	exit(0);
    }

    /*
    ** Either assign stderr to the output log file or open a log file.
    */
#ifdef SHERLOCK
    logFile = fopen(logFileName, "w");
    if(logFile == NULL) {
	fprintf(stderr, "Unable to open log file\n");
	exit(1);
    }
#else
    logFile = stderr;
#endif

    /*
    ** Set up an exit list processor to make sure that everything gets
    ** cleaned up.
    */
    DosExitList(EXLST_ADD, (PFNEXITLIST) Cleanup);
    signal(SIGBREAK, breakHandler);
    signal(SIGINT,   breakHandler);

    /*
    ** Start and connect to the debuggee.
    */
    StartProgram(argc, argv, nextState);
    debugBuffer.Pid = debugInfo.pid;
    debugBuffer.Tid = 0;
    debugBuffer.Value = DBG_L_386;
    if(DispatchCommand(DBG_C_Connect) != DBG_N_Success) {
	fprintf(logFile, "Unable to connect!\n");
        exit(1);
    }
    debugBuffer.Tid = 0;
    if(DispatchCommand(DBG_C_SStep) != DBG_N_Exception) {
	fprintf(logFile, "Unable to single step to force DLL load!\n");
        exit(1);
    }
    debugBuffer.Value = XCPT_CONTINUE_STOP;
    if(DispatchCommand(DBG_C_Continue) != DBG_N_Success) {
	fprintf(logFile, "Unable to continue after single step!\n");
        exit(1);
    }
#ifndef SHERLOCK
    DosSelectSession(0);
#endif

    /*
    ** Starting with the connect command, dispatch a command and then
    ** get the next command.
    */
    setjmp(JumpBuff);
    while(live) {

        /*
        ** Get the next command.
	*/
	do {
#ifdef SHERLOCK
	    if(lastState == DBG_N_ProcTerm)
		goto ExitDebugger;

	    strcpy(buff, "g");
	    ptrs[0] = buff;
	    ptrs[1] = ptrs[0];
#else
	    GetCommand(buff, sizeof(buff), ptrs, MAX_ARGS);
#endif
            nextState = DoCommand(ptrs);

            /*
            ** If the next state is 666, die.
            */
	    if(nextState == 666)
		goto ExitDebugger;

        } while(nextState <= 0);

        /*
        ** Dispatch the command and then dump the stack and registers.
        **
        ** Depending upon the state of the dispatched message, print
        ** the appropriate message.
        */
commandRestart:
	switch(lastState = DispatchCommand(nextState)) {
            case DBG_N_Success:     /* Successful command completion    */
		fprintf(logFile, "Success\n");
                break;

            case DBG_N_Error:       /* Error detected during command    */
		fprintf(logFile, "Command ERROR\n");
		fprintf(logFile, "Command: %d ILLEGAL\n", nextState);
                live = 0;
		break;

	    case DBG_N_Exception:   /* Exception detected   */
		if(HandleException(nextState))
                    goto commandRestart;
#ifdef SHERLOCK
		dumpExceptionData();
#endif
		break;

            case DBG_N_CoError:     /* Coprocessor not in use error */
		fprintf(logFile, "Coprocess Error\n");
                live = 0;
		break;

	    case DBG_N_ThreadCreate: {	/* Thread creation  */
		    struct ThreadList  *link, *next;

		    next = malloc(sizeof(struct ThreadList));
		    next->next = NULL;
		    next->tid  = debugBuffer.Tid;
		    for(link = &threadList;
			link && link->next;
			link = link->next)
			    ;
		    link->next = next;
		    fprintf(logFile, "Thread Created\n");
		    break;
		}

	    case DBG_N_ThreadTerm: {	/* Thread termination - not in DosExitList  */
		    struct ThreadList *link, *prior;

		    prior = NULL;
		    for(link=&threadList; link; link=link->next) {
			if(link->tid == debugBuffer.Tid) {
			    if(prior) {
				prior->next = link->next;
				free(link);
			    }
			    break;
			}
			prior = link;
		    }
		    fprintf(logFile, "Thread %d Terminated\n", debugBuffer.Tid);
		    break;
		}

            case DBG_N_AsyncStop:   /* Async Stop detected  */
		fprintf(logFile, "ASync Stop\n");
                live = 0;
		break;

	    case DBG_N_ProcTerm:    /* Process termination - DosExitList done	*/
		fprintf(logFile, "Process Terminated\n");
		break;

	    case DBG_N_NewProc:     /* New Process started  */
		fprintf(logFile, "New Process Stated\n");
                break;

	    case DBG_N_AliasFree:   /* Alias needs to be freed	*/
		fprintf(logFile, "Alias needs to be freed\n");
                live = 0;
		break;

            case DBG_N_Watchpoint:  /* Watchpoint hit   */
		fprintf(logFile, "Watch point hit\n");
		if(!isValidBreakpoint(Linearize(debugBuffer.EIP, debugBuffer.CS)))
		    fprintf(logFile, "UNKNOWN WATCHPOINT HIT!\n");
                break;

	    case DBG_N_ModuleFree:  /* Module freed	    */
		fprintf(logFile, "Module Freed\n");
		break;

            case DBG_N_RangeStep:   /* Range Step detected  */
		fprintf(logFile, "Range Step\n");
                break;
	}

#ifndef SHERLOCK
        {
            DebugModule *module;
            char *mod;

	    DispatchCommand(DBG_C_ReadReg);
	    debugBuffer.Addr = Linearize(debugBuffer.EIP, debugBuffer.CS);
	    DispatchCommand(DBG_C_AddrToObject);
            if((debugBuffer.Cmd == DBG_N_Success) && (debugBuffer.Value & 0x10000000)) {
                module = FindModule(debugBuffer.MTE, NULL);
                if(module == NULL)
                    mod = "UNKNOWN";
                else
                    mod = module->name;
		FindSource(module, Linearize(debugBuffer.EIP, debugBuffer.CS),
			   funcName, sourceName, &lineNum);
		fprintf(logFile, "EIP: %08x, DLL: %s Func: %s\n",
			Linearize(debugBuffer.EIP, debugBuffer.CS), mod, funcName);
		DisplaySource(module, sourceName, lineNum);
	    }
	}
#endif
	DumpWatchpoints();
    }
#ifndef SHERLOCK
    dumpPStat();
#endif
ExitDebugger:
    return 0;
}
