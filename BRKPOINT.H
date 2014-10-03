/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
** Public access routines for breakpoints.
*/
int  CommandGo(char **ptrs);
int  CommandStep(char **ptrs);
int  CommandBreakpoint(char **ptrs);
void FreeAllBreakpoints(void);
int  isValidBreakpoint(ULONG addr);
