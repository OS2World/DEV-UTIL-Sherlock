/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
** SYM file interface functions to extract symbolic information
** given a state to extract information from.
*/
#include    <stdio.h>
#include    <string.h>
#include    <malloc.h>
#include    <memory.h>
#include    <sys\stat.h>

#define     INCL_DOSPROCESS
#include    <os2.h>
#include    "..\Debug.h"

#include    "..\SrcInter.h"
#include    "MapSym.h"

/*
** Global variables.
*/
static int (* _System Dispatch)(int command);
DebugBuffer *debugBuffer;

/*
** Answer the linkage priority.
** Return 1 for insert in front of list - (first crack at linking)
** Return 0 for add to end of list.	- (last crack at linking)
*/
int _System linkPriority(void)
{
    return 0;
}

/*
** Load the symbols.
*/
SymData32 *load32Symbols(FILE *symFile,
	    long base, long pConstDef, WORD cConsts)
{
SYMDEF32    sym32;
WORD	    i;
SymData32  *symHead=NULL;
SymData32  *symData=NULL;
WORD	   *ptrs;

    fseek(symFile, base + pConstDef, SEEK_SET);
    ptrs = (WORD *) malloc(cConsts * sizeof(WORD));
    fread(ptrs, cConsts, sizeof(WORD), symFile);
    for(i=0; i<cConsts; i++) {
	fseek(symFile, base + ((DWORD) ptrs[i]), SEEK_SET);
	fread(&sym32, sizeof(SYMDEF32), 1, symFile);
	if(symHead == NULL) {
	    symData = (SymData32 *) malloc(sizeof(SymData32) + sym32.dbSymName);
	    symHead = symData;
	    symData->next = NULL;
	} else {
	    symData->next = (SymData32 *) malloc(sizeof(SymData32) + sym32.dbSymName);
	    symData = symData->next;
	    symData->next = NULL;
	}
	symData->lSymVal = sym32.lSymVal;
	fread(symData->SymName, sym32.dbSymName, 1, symFile);
	symData->SymName[sym32.dbSymName] = '\0';
    }
    return symHead;
}

/*
** Load the symbols.
*/
SymData16 *load16Symbols(FILE *symFile,
	    long base, long pConstDef, WORD cConsts)
{
SYMDEF16    sym16;
WORD	    i;
SymData16  *symHead=NULL;
SymData16  *symData=NULL;
WORD	   *ptrs;

    fseek(symFile, base + pConstDef, SEEK_SET);
    ptrs = (WORD *) malloc(cConsts * sizeof(WORD));
    fread(ptrs, cConsts, sizeof(WORD), symFile);
    for(i=0; i<cConsts; i++) {
	fseek(symFile, base + ((DWORD) ptrs[i]), SEEK_SET);
	fread(&sym16, sizeof(SYMDEF16), 1, symFile);
	if(symHead == NULL) {
	    symData = (SymData16 *) malloc(sizeof(SymData16) + sym16.dbSymName);
	    symHead = symData;
	    symData->next = NULL;
	} else {
	    symData->next = (SymData16 *) malloc(sizeof(SymData16) + sym16.dbSymName);
	    symData = symData->next;
	    symData->next = NULL;
	}
	symData->wSymVal = sym16.wSymVal;
	fread(symData->SymName, sym16.dbSymName, 1, symFile);
	symData->SymName[sym16.dbSymName] = '\0';
    }
    return symHead;
}

/*
** Answer whether the module named is a MapSym module.
** If so, set the function pointers and return true.
*/
int _System isKnownModule(DebugModule *module,
			   int (* _System DispatchCommand)(int command),
			   DebugBuffer *buffer)
{
FILE	   *symFile;
char	   *chPtr;
WORD	    i;
char	    symName[CCHMAXPATH];
MAPDEF	    mapDef;
SEGDEF	    segDef;
SymSegmentData *auxData;
ULONG	    base;

    debugBuffer = buffer;
    Dispatch = DispatchCommand;

    /*
    ** Open the file.
    */
    strcpy(symName, module->name);
    chPtr = strrchr(symName, '.');
    if(chPtr == NULL)
	return 0;
    strcpy(chPtr, ".SYM");
    if((symFile = fopen(symName, "rb")) == NULL)
	return 0;

    /*
    ** Read the map definition header.
    */
    fread(&mapDef, sizeof(mapDef), 1, symFile);

    /*
    ** Read the segment definitions.
    */
    base = ((ULONG) mapDef.ppSegDef) << 4;
    for(i=0; i<mapDef.cSegs; i++) {

	/*
	** Get the segment definition
	*/
	fseek(symFile, base, SEEK_SET);
	fread(&segDef, sizeof(segDef), 1, symFile);

	/*
	** If not the first time through, get a new block.
	*/
	if(i == 0) {
	    module->AuxData = (void *)
		calloc(sizeof(SymSegmentData) + segDef.cbSegName, 1);
	    auxData = (SymSegmentData *) module->AuxData;
	    auxData->next = NULL;
	} else {
	    auxData->next = (SymSegmentData *)
		calloc(sizeof(SymSegmentData) + segDef.cbSegName, 1);
	    auxData = auxData->next;
	    auxData->next = NULL;
	}
	fread(auxData->name, segDef.cbSegName, 1, symFile);
	auxData->name[segDef.cbSegName] = 0;

	/*
	** Now, get the symbols.
	*/
	if(segDef.bFlags & 0x01) {
	    auxData->first16Symbol = NULL;
	    auxData->first32Symbol =
		load32Symbols(symFile,
			      base,
			      segDef.pSymDef,
			      segDef.cSymbols);
	} else {
	    auxData->first32Symbol = NULL;
	    auxData->first16Symbol =
		load16Symbols(symFile,
			      base,
			      segDef.pSymDef,
			      segDef.cSymbols);
	}
	base = ((ULONG) segDef.ppNextSeg) << 4;
    }
    fclose(symFile);

    /*
    ** Set up the links to access the data.
    */
    module->FindSource	   = SymFindSource;
    module->FindSourceLine = SymFindSourceLine;
    module->FindFuncAddr   = SymFindFuncAddr;

#if 0
    module->GetName	   = SymGetName;
    module->GetArray	   = SymGetArray;
    module->GetNumMembers  = SymGetNumMembers;
    module->GetMemberIndex = SymGetMemberIndex;
#endif
    return 1;
}

/*
** Define the stub for connecting to the system.
*/
int DispatchCommand(int command)
{
    if(Dispatch)
	return Dispatch(command);
    return DBG_N_Error;
}
