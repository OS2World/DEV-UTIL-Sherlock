/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
** Display the source
*/
int	CommandSource(char **ptrs);
int	CommandView(char **ptrs);
int	CommandUnassemble(char **ptrs);
int	DisplaySource(DebugModule *module, char *sourceName, int lineNum);
int	GetLastLine(DebugModule *module);
void	DumpAsm(ULONG addr, ULONG length, int is32Bit);
