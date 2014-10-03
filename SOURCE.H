/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
** Functions to access the source code.
*/
int     FindSource(DebugModule *module, ULONG eipOffset,
		   char *funcName, char *sourceName, ULONG *lineNum);
ULONG	FindSourceLine(DebugModule *module, int line, char *fileName);
ULONG   FindFuncAddr(DebugModule *module, char *name);

/*
** Variable access.
*/
int   GetName(DebugModule *module, State *state, State *state2);
int   GetArray(DebugModule *module, State *state, State *state2);
int   GetNumMembers(DebugModule *module, State *state);
int   GetMemberIndex(DebugModule *module, State *state, int MemberIndex, char *name);


/*
** Load/free a module.
*/
void LoadDebuggeeModule(ULONG MTE);
void FreeDebuggeeModule(ULONG MTE);
void FreeAllModules(void);

/*
** Find a module given it's module handle.
*/
DebugModule *FindModule(ULONG MTE, DebugModule **prior);

/*
** Function prototypes for the expression analyser.
*/
int   evaluate(char *expr, DebugModule *module, ULONG eip, ULONG ebp, Value *value);

/*
** Connect to a module without debugging information.
*/
int DefConnectModule(DebugModule *module);
