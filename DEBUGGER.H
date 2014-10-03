/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
** Define the structures used.
*/
struct _debugInfo {
    PID         pid;
    ULONG       type;
    ULONG       session;
};

/*
** Define the globals used by the debugger.
*/
int		    FlipScreen;     /* Whether to flip the screen   */
struct _debugInfo   debugInfo;	    /* Global debugger buffer	    */
DebugBuffer	    debugBuffer;    /* Buffer for executions	    */
FILE		   *logFile;	    /* Log file for output	    */

/*
** Define the functions used by the debugger.
*/
void StartProgram(int argc,                 /* Argument count           */
                  char *argv[],             /* Argument values          */
                  int iarg);                /* Index to program name    */

/*
** Dispatch a command.
*/
int _System DispatchCommand(int command);

/*
** General purpose dump routines.
*/
#define TOADDR_CODE  1
#define TOADDR_DATA  2
#define TOADDR_STACK 3
ULONG StrToAddr(char *str, int type);
ULONG Linearize(ULONG offset, USHORT segment);
void hexdump(unsigned char *data, int count, char *buff);
void DumpStack(int threadID);

#define MAX_FUNCNAME	256
