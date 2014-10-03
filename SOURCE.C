/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
** Find the requested source information based on certain information.
*/
#include    <stdio.h>
#include    <string.h>
#include    <stdlib.h>
#include    <sys\stat.h>
#define     INCL_DOSFILEMGR
#define     INCL_DOSMODULEMGR
#define     INCL_DOSPROCESS
#define     INCL_DOSSESMGR
#include    <os2.h>
#include    "debug.h"

typedef unsigned long DWORD;
typedef unsigned short WORD;
#include    "NewExe.h"
#include    "Exe386.h"
#include    "Debugger.h"
#include    "SrcInter.h"
#include    "Source.h"

DebugModule aModule;
typedef struct _SupportList {
    int (* _System isKnownModule)(DebugModule *module,
		 int (* _System DispatchCommand)(int command),
		 DebugBuffer *buffer);
    HMODULE	handle;
    struct _SupportList *next;
} SupportList;

static SupportList *supportDllList = NULL;

static ULONG findProgramType(char *pszPgm)
{
FILE           *mod;
struct exe_hdr	dosHdr;
union	{
    struct new_exe  os21x;
    struct e32_exe  os22x;
} header;
unsigned char numChars;
char	      name[CCHMAXPATH];

    DosQueryAppType(pszPgm, &aModule.typeFlags);
    if((aModule.typeFlags & 0x07) != FAPPTYP_NOTSPEC)
	return aModule.typeFlags;

    /*
    ** Open the file.
    */
    if((mod = fopen(pszPgm, "rb")) == NULL) {
	fprintf(logFile, "Unable to open module %s.\n", pszPgm);
	return 0;
    }

    /*
    ** Get the DOS exe header.
    */
    fread(&dosHdr, sizeof(struct exe_hdr), 1, mod);
    fseek(mod, dosHdr.e_lfanew, SEEK_SET);

    /*
    ** Read the os2 header.
    */
    fread(&header, sizeof(header), 1, mod);
    if(header.os21x.ne_magic == NEMAGIC) {
	WORD	i;

	fseek(mod, dosHdr.e_lfanew + header.os21x.ne_imptab, SEEK_SET);
	for(i=0; i<header.os21x.ne_cmod; i++) {
	    fread(&numChars, 1, 1, mod);
	    fread(name, numChars, 1, mod);
	    name[numChars] = 0;
	    if(stricmp(name, "PMWIN") == 0) {
		aModule.typeFlags |= FAPPTYP_WINDOWAPI;
		fclose(mod);
		return aModule.typeFlags;
	    }
	}
    } else {
	DWORD	i;

	fseek(mod, dosHdr.e_lfanew + header.os22x.e32_impmod, SEEK_SET);
	for(i=0; i<header.os22x.e32_impmodcnt; i++) {
	    fread(&numChars, 1, 1, mod);
	    fread(name, numChars, 1, mod);
	    name[numChars] = 0;
	    if(stricmp(name, "PMWIN") == 0) {
		aModule.typeFlags |= FAPPTYP_WINDOWAPI;
		fclose(mod);
		return aModule.typeFlags;
	    }
	}
    }

    /*
    ** Let the system decide.
    */
    fclose(mod);
    return aModule.typeFlags;
}

/*
** Start the program.
*/
void StartProgram(int argc,         /* Argument count               */
                  char *argv[],     /* Argument values              */
                  int iarg)         /* Index to program name        */
{
ULONG	idErr;			    /* Error code		    */
CHAR   *p1, *p2;
CHAR	pszPgm[CCHMAXPATH];	    /* Name of program to profile   */
CHAR	szArgs[CCHMAXPATH];	    /* Program arguments	    */
CHAR	szFail[CCHMAXPATH];	    /* Program Failure		    */
CHAR	name[CCHMAXPATH];	    /* Debugging session name	    */
STARTDATA stdata;		    /* DosStartSession data	    */

   /* Extract program name from arguments   */

    strcpy(pszPgm, argv[iarg]);
    strupr(pszPgm);
    if(strstr(pszPgm, ".EXE") == NULL)
        strcat(pszPgm, ".EXE");

   /* Build argument string for program to be profiled  */

    szArgs[0] = 0;
    for (iarg++; iarg < argc; iarg++) {
        if ((strlen(szArgs) + strlen(argv[iarg]) + 1) >= sizeof(szArgs))
            break;
        strcat (szArgs, argv[iarg]);
        strcat (szArgs, " ");
    }

    /*
    ** Start the session used by the debuggee.
    */
    stdata.Length = sizeof (stdata);
    stdata.Related = SSF_RELATED_CHILD;
    stdata.FgBg = SSF_FGBG_BACK;
    stdata.TraceOpt = SSF_TRACEOPT_TRACE;
    strcpy(name, "Debug session - ");
    p1 = strrchr(pszPgm, '\\');
    p2 = strrchr(pszPgm, '/');
    if(p1 || p2)
	strcat(name, p1 > p2 ? p1 : p2);
    else
        strcat(name, pszPgm);

    stdata.PgmTitle = name;
    stdata.PgmName = pszPgm;
    stdata.PgmInputs = szArgs;
    stdata.TermQ = NULL;
    stdata.Environment = NULL;
    stdata.InheritOpt = SSF_INHERTOPT_PARENT;
    aModule.typeFlags = findProgramType(pszPgm);
    stdata.SessionType = aModule.typeFlags & 0x07;
    stdata.IconFile = NULL;
    stdata.PgmHandle = (ULONG) NULL;
    stdata.PgmControl = SSF_CONTROL_VISIBLE;
    stdata.InitXPos = stdata.InitYPos = 0;
    stdata.InitXSize = stdata.InitYSize = 0;
    stdata.ObjectBuffer = szFail;
    if(idErr = DosStartSession(&stdata, &debugInfo.session, &debugInfo.pid)) {
	fprintf(logFile, "\n%s could not be started\nError %u - %s)\n",
		   pszPgm, idErr, szFail);
	exit(idErr);
    }
    return;
}


/*
** Find a debug module for a given MTE.
*/
DebugModule *FindModule(ULONG MTE, DebugModule **prior)
{
DebugModule *ptr;

    if(prior)
	prior[0] = &aModule;

    /*
    ** See if the module is already in the module list.
    */
    for(ptr = &aModule; ptr->MTE != MTE;) {
	if(prior)
            prior[0] = ptr;

	ptr = ptr->nextModule;
	if(ptr == NULL)
	    return NULL;
    }

    /*
    ** Make sure we save the data.
    */
    if(MTE != ptr->MTE) {
	prior[0] = ptr;
	return NULL;
    }
    return ptr;
}

/*
** Return a pointer to the file name of the source if it is known
** for the given linear offset of the instruction pointer.
*/
int FindSource(DebugModule *module, ULONG eipOffset,
	       char *funcName, char *sourceName, ULONG *lineNum)
{
    if(module)
        if(module->FindSource)
            return module->FindSource(module, eipOffset,
                                      funcName, sourceName, lineNum);

    return 0;
}

/*
** Find the offset for a given line number in a given file.
*/
ULONG	FindSourceLine(DebugModule *module, int line, char *fileName)
{
    if(module)
        if(module->FindSourceLine)
            return module->FindSourceLine(module, line, fileName);

    return 0;
}

/*
** Return the linear address of the object given the name of the
**  variable to find and the linear address of the instruction
**  pointer.
*/
ULONG FindFuncAddr(DebugModule *module, char *name)
{
ULONG       addr;

    if(module == NULL) {
	for(module = &aModule; module != NULL; module = module->nextModule) {
	    if(module->FindFuncAddr) {
                if(addr = module->FindFuncAddr(module, name)) {
                    return addr;
                }
	    }
	}
    } else {
        if(module->FindFuncAddr) {
            if(addr = module->FindFuncAddr(module, name)) {
                return addr;
            }
        }
    }
    return 0;
}

/*
** Return the linear address of the object given the name of the
**  variable to find and the linear address of the instruction
**  pointer.
*/
int GetName(DebugModule *module, State *state, State *state2)
{
int rVal;

    if(module == NULL) {
	debugBuffer.Addr = state->baseEIP;
	DispatchCommand(DBG_C_AddrToObject);
	module = FindModule(debugBuffer.MTE, NULL);
	if(module) {
	    if(module->GetName(module, state, state2))
		return 1;
	    for(module = &aModule; module != NULL;
		module = module->nextModule) {
		rVal = module->GetName(module, state, state2);
		if(rVal == SUCCESS) {
		    return SUCCESS;
		}
	    }
	}
    } else {
	if(module->GetName) {
	    return module->GetName(module, state, state2);
        }
    }
    return INVALID_NAME;
}

/*
** Find the information about a member in a structure.
*/
int GetArray(DebugModule *module, State *state, State *state2)
{
    if(module)
	if(module->GetArray)
	    return module->GetArray(module, state, state2);

    return INVALID_INDEX;
}

/*
** Get the number of members in a structure.
*/
int GetNumMembers(DebugModule *module, State *state)
{
    if(module) {
	if(module->GetNumMembers) {
	    return module->GetNumMembers(module, state);
	}
    }

    return 0;
}

/*
** Get the name of the index'th member in a structure.
*/
int GetMemberIndex(DebugModule *module, State *state, int MemberIndex, char *name)
{
    if(module) {
	if(module->GetMemberIndex) {
	    return module->GetMemberIndex(module, state, MemberIndex, name);
        }
    }

    return INVALID_NAME;
}

/*
** Find all of the DLLs in the Debuggers root dir and try to load them.
*/
void loadSupportDlls(void)
{
HMODULE 	mte;
int		err;
HDIR		hDir;
ULONG		count;
HMODULE 	module;
TIB	       *tib;
PIB	       *pib;
char	       *ptr;
SupportList    *list;
int	      (* _System proc)(DebugModule *module,
		    int (* _System DispatchCommand)(int command),
		    DebugBuffer *buff);
int	      (* _System priorityProc)();
FILEFINDBUF3	findBuffer;
char		debugName[CCHMAXPATH];
char		errBuff[CCHMAXPATH];

    /*
    ** Find the debugger's path.
    */
    DosGetInfoBlocks(&tib, &pib);
    mte = pib->pib_hmte;
    DosQueryModuleName(mte, sizeof(debugName), debugName);
    ptr = strrchr(debugName, '\\');
    *(ptr+1) = '\0';

    /*
    ** Now use the base path as a search path.
    */
    count = 1;
    hDir  = 1;
    strcat(debugName, "*.dll");
    err = DosFindFirst(debugName,	    /* Search Path.		*/
		       &hDir,		    /* Handle to use.		*/
		       0,		    /* Normal files.		*/
		       &findBuffer,	    /* Find file buffer.	*/
		       sizeof(findBuffer),  /* Find file buffer size.	*/
		       &count,		    /* Count of files found.	*/
		       FIL_STANDARD);	    /* Standard file find.	*/
    while(err == 0) {

	/*
	** Build the path to the name.
	*/
	*(ptr+1) = '\0';
	strcat(debugName, findBuffer.achName);

	/*
	** Try to load the module.
	*/
	if(err = DosLoadModule(errBuff, sizeof(errBuff), debugName, &module)) {
	    fprintf(logFile, "Error loading '%s' %d\n",
		    findBuffer.achName, err);
	    goto getNext;
	}

	/*
	** Load the known procedure function.
	*/
	if(err = DosQueryProcAddr(module, 0, "isKnownModule", (PFN *) &proc)) {
	    fprintf(logFile, "Error loading procedure: %d\n", err);
	    proc = NULL;
	    DosFreeModule(module);
	    goto getNext;
	}

	/*
	** Load the known procedure function.
	*/
	if(err = DosQueryProcAddr(module, 0, "linkPriority", (PFN *) &priorityProc)) {
	    fprintf(logFile, "Error loading procedure: %d\n", err);
	    DosFreeModule(module);
	    goto getNext;
	}

	/*
	** Build the link for the list.
	*/
	list = calloc(sizeof(SupportList), 1);
	list->next = NULL;
	list->handle = module;
	list->isKnownModule = proc;

	/*
	** If priority linkage, put at the front of the list.
	** else, put at the end of the list.
	*/
	if(supportDllList == NULL) {
	    supportDllList = list;
	} else {
	    if((*priorityProc)()) {
		list->next = supportDllList;
		supportDllList = list;
	    } else {
		SupportList *t;
		for(t=supportDllList;t->next;t=t->next)
		    ;
		t->next = list;
	    }
	}

	/*
	** Make sure to put link to list if necessary.
	*/

	/*
	** Get the next name of the DLL.
	*/
getNext:err = DosFindNext(hDir, &findBuffer, sizeof(findBuffer), &count);

    }
    DosFindClose(hDir);
}

/*
** Load the module and find out if there is any debugging information.
*/
void LoadDebuggeeModule(ULONG MTE)
{
DebugModule *prior, *ptr;
SupportList *list;
int	    i;
static char modName[CCHMAXPATH];

    /*
    ** See if the module is already in the module list.
    */
    if(ptr = FindModule(MTE, &prior))
        return;

    /*
    ** If it is not listed, add it onto the end.
    */
    prior->nextModule = ptr = calloc(sizeof(DebugModule), 1);
    ptr->MTE = MTE;

    /*
    ** Get the module name.
    */
    DosQueryModuleName(MTE, sizeof(modName), modName);
    ptr->name = malloc(strlen(modName) + 1);
    strcpy(ptr->name, modName);

    /*
    ** Determine the type of dll.
    */
    DosQueryAppType(modName, &ptr->typeFlags);

    /*
    ** Load the support DLLs.
    */
    if(supportDllList == NULL)
	loadSupportDlls();

    /*
    ** Find out what system supports the source.
    */
    for(list = supportDllList; list; list=list->next) {
	if(list->isKnownModule) {
	    if(list->isKnownModule(ptr, DispatchCommand, &debugBuffer)) {
		return;
	    }
	}
    }

    /*
    ** No one else wants it, use the default handler.
    */
    if(!DefConnectModule(ptr)) {
	fprintf(logFile, "ERROR LOADING MODULE FOR DEBUGGING: '%s'.\n", modName);
    }
    return;
}

/*
** Free the debuggee module from the list.
*/
void FreeDebuggeeModule(ULONG MTE)
{
DebugModule *ptr;

    /*
    ** See if the module is already in the module list.
    */
    ptr = FindModule(MTE, NULL);

    /*
    ** If it is not listed, add it onto the end.
    */
    if(ptr == NULL) {
	fprintf(logFile, "ERROR - Module not in our list!\n");
	exit(1);
    }
}

/*
** Free all library information which has been loaded.
*/
void FreeAllModules()
{
DebugModule *module;

    for(module = &aModule; module != NULL; module = module->nextModule) {
        if(module->FreeModule) {
            module->FreeModule(module);
	}
    }
    return;
}
