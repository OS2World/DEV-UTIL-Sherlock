/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
** Display the source for the given source file and line number.
*/
#include    <stdio.h>
#include    <stdlib.h>
#include    <ctype.h>
#include    <string.h>
#include    <sys\stat.h>

#define     INCL_DOSPROCESS
#include    <os2.h>
#include    "debug.h"

#include    "Debugger.h"
#include    "SrcInter.h"
#include    "Source.h"
#include    "SrcDisp.h"

typedef struct {
    char   *basePath;
    char   *lastSource;
    int     lastLine;
    ULONG   lastAddr;
} View;

static char    drive[_MAX_DRIVE];
static char    dir[_MAX_DIR];
static char    fname[_MAX_FNAME];
static char    ext[_MAX_EXT];
static int     ShouldDumpSource = 1;
static int     ShouldDumpAsm = 0;

/*
** Set the view into the source.
*/
int CommandSource(char **ptrs)
{
    if(ptrs[1][1] == '+') {
	ShouldDumpSource = 1;
	ShouldDumpAsm	 = 0;
	return -1;
    }

    if(ptrs[1][1] == '&') {
	ShouldDumpSource = 1;
	ShouldDumpAsm	 = 1;
	return -1;
    }

    if(ptrs[1][1] == '-') {
	ShouldDumpSource = 0;
	ShouldDumpAsm	 = 1;
	return -1;
    }

    fprintf(logFile, "Source command error\n");
    return -1;
}

/*
** View the source for the lines specified.
*/
int CommandView(char **ptrs)
{
DebugModule    *module;
char	       *srcEnd;
ULONG		addr;
ULONG		lineNum;
char		funcName[MAX_FUNCNAME];
char		sourceName[CCHMAXPATH];

    /*
    ** Get the common data.
    */
    module = FindModule(debugBuffer.MTE, NULL);
    FindSource(module, Linearize(debugBuffer.EIP, debugBuffer.CS),
	       funcName, sourceName, &lineNum);

    /*
    ** View the next lines to be displayed.
    */
    if(ptrs[2] == NULL) {
	DisplaySource(module, sourceName, GetLastLine(module) + 5);
	return -1;
    }

    /*
    ** View a line.
    */
    if(ptrs[2][0] == '.') {

	/*
	** Find the line number or the file name/line number
	*/
	if(isdigit(ptrs[2][1])) {
	    lineNum = atol(&ptrs[2][1]);
	} else {
	    strcpy(sourceName, &ptrs[2][1]);
	    *strrchr(sourceName, ':') = 0;
	    lineNum = atol(strrchr(ptrs[2], ':') + 1);
	}
	DisplaySource(module, sourceName, lineNum);
	return -1;
    }

    /*
    ** Get a view at a given offset.
    */
    if(isxdigit(ptrs[2][0])) {
	/*
	** Find the module associated with the address specified.
	*/
	debugBuffer.Addr = addr = StrToAddr(ptrs[2], TOADDR_CODE);
	DispatchCommand(DBG_C_AddrToObject);

	/*
	** Find the module/source associated with the information given.
	*/
	module = FindModule(debugBuffer.MTE, NULL);
	FindSource(NULL, addr, funcName, sourceName, &lineNum);
	DisplaySource(module, sourceName, lineNum);
	return -1;
    }

    /*
    ** ERROR!
    */
    fprintf(logFile, "Invalid syntax\n");
    return -1;
}

/*
** View the assembler for the address/line specified.
*/
int CommandUnassemble(char **ptrs)
{
DebugModule    *module;
View	       *viewData;
char	       *srcEnd;
ULONG		addr;
int		lineNum;
int		is32Bit;
char		sourceName[CCHMAXPATH];

    /*
    ** Get the common data.
    */
    module   = FindModule(debugBuffer.MTE, NULL);
    viewData = (View *) module->ViewData;
    if(viewData == NULL) {
	viewData = module->ViewData = calloc(sizeof(View), 1);
	viewData->lastSource = strdup("");
	viewData->basePath   = strdup("");
    }
    is32Bit  = (debugBuffer.CSAtr & 0x80) != 0;
    addr     = Linearize(debugBuffer.EIP, debugBuffer.CS);

    /*
    ** View the next lines to be displayed.
    */
    if(ptrs[2] == NULL) {
        DumpAsm(viewData->lastAddr, 0x20, is32Bit);
	viewData->lastAddr = addr + 0x20;
	return -1;
    }

    /*
    ** View a source line.
    */
    if(ptrs[2][0] == '.') {

	/*
	** Find the line number or the file name/line number
	*/
	if(isdigit(ptrs[2][1])) {
	    lineNum = atol(&ptrs[2][1]);
	    if(viewData->lastSource == NULL) {
		fprintf(logFile, "No source yet displayed\n");
		return -1;
	    }
	    strcpy(sourceName, viewData->lastSource);
	} else {
	    strcpy(sourceName, &ptrs[2][1]);
	    *strrchr(sourceName, ':') = 0;
	    lineNum = atol(strrchr(ptrs[2], ':') + 1);
	}
	addr = FindSourceLine(module, lineNum, sourceName);
	DumpAsm(addr, 0x20, is32Bit);
	viewData->lastAddr = addr + 0x20;
	return -1;
    }

    /*
    ** Get a view at a given offset.
    */
    if(isxdigit(ptrs[2][0])) {
	addr = StrToAddr(ptrs[2], TOADDR_CODE);
	DumpAsm(addr, 0x20, is32Bit);
	viewData->lastAddr = addr + 0x20;
	return -1;
    }

    /*
    ** ERROR!
    */
    fprintf(logFile, "Invalid syntax\n");
    return -1;
}

/*
** Display the source file and line number.
*/
int DisplaySource(DebugModule *module, char *sourceName, int lineNum)
{
int	i, lastChar, is32Bit;
int	curLine;
FILE   *file = NULL;
View   *viewData = (View *) module->ViewData;
ULONG	addr, addr2;
char	buff[CCHMAXPATH];
char	dummy[CCHMAXPATH];

    /*
    ** Find out whether this is a 32 bit segment.
    */
    DispatchCommand(DBG_C_ReadReg);
    is32Bit = (debugBuffer.CSAtr & 0x80) != 0;

    /*
    ** If the view data does not exist, create and initialize it.
    */
    if(viewData == NULL) {
	viewData = module->ViewData = calloc(sizeof(View), 1);
	viewData->lastSource = strdup("");
	viewData->basePath   = strdup("");
    }

    /*
    ** Find and open the source file.
    */
    if(strlen(sourceName) > 0) {
	strcpy(buff, sourceName);
	_splitpath(sourceName, drive, dir, fname, ext);
	_splitpath(viewData->basePath, drive, dir, dummy, dummy);
	_makepath(buff, drive, dir, fname, ext);
	while((file = fopen(buff, "r")) == NULL) {
#ifdef SHERLOCK
	    buff[0] = 0;
#else
	    fprintf(logFile, "Please enter path for %s\n", sourceName);
	    fgets(buff, sizeof(buff), stdin);
#endif
	    while((strlen(buff) > 0) && isspace(*buff))
		buff[strlen(buff) - 1] = 0;
	    if(strlen(buff) == 0)
		return 0;

	    lastChar = strlen(buff) - 1;
	    while(isspace(buff[lastChar])) {
		buff[lastChar] = 0;
		lastChar--;
	    }
	    if((buff[lastChar] != '\\') && (buff[lastChar] != '/'))
		strcat(buff, "/");
	    _splitpath(buff, drive, dir, dummy, dummy);
	    _makepath(buff, drive, dir, fname, ext);
	}
    }

    /*
    ** Free/show the last source viewed.
    */
    if(viewData->lastSource)
	free(viewData->lastSource);
    viewData->lastSource = strdup(buff);

    /*
    ** Free the previous path spec.
    */
    if(viewData->basePath)
	free(viewData->basePath);
    _splitpath(buff, drive, dir, fname, ext);
    _makepath(buff, drive, dir, "", "");
    viewData->basePath = strdup(buff);

    /*
    ** Go to just before the line specific.
    */
    if(file) {
	curLine = 0;
	for(curLine=1; curLine < lineNum - 5; curLine++) {
	    fgets(buff, sizeof(buff), file);
	}
    }

    /*
    ** Now, display the source.
    */
    if(file) {
	for(i=0; i<10; i++, curLine++) {
	    if(file)
		if(fgets(buff, sizeof(buff), file) == NULL)
		    break;
	    if(ShouldDumpSource) {
		if(curLine == lineNum)
		    fprintf(logFile, "*%5d: %s", curLine, buff);
		else
		    fprintf(logFile, " %5d: %s", curLine, buff);
	    }
	    if((addr = FindSourceLine(module, curLine, sourceName)) != 0) {
		int	j;

		/*
		** Find the next line.
		*/
		for(j=1; j < 10; j++) {
		    if((addr2=FindSourceLine(module,curLine+j,sourceName))!=0)
			break;
		}
	    }
	    if(addr2 == 0)
		addr2 = addr + 0x10;
	    if(ShouldDumpAsm)
		DumpAsm(addr, addr2-addr, is32Bit);
	}
    } else {
	addr = Linearize(debugBuffer.EIP, debugBuffer.CS);
	DumpAsm(addr, 0x20, is32Bit);
	addr2 = addr + 0x20;
    }
    viewData->lastLine = curLine - 1;
    viewData->lastAddr = addr2;
    if(file)
	fclose(file);
    return 1;
}

/*
** Answer the last line displayed for the module.
*/
int GetLastLine(DebugModule *module)
{
View   *viewData = (View *) module->ViewData;

    if(viewData == NULL)
	return -1;
    return viewData->lastLine;
}
