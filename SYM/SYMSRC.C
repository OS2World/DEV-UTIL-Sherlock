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
#include    <sys\stat.h>

#define     INCL_DOSPROCESS
#include    <os2.h>
#include    "..\Debug.h"

#include    "..\SrcInter.h"
#include    "MapSym.h"

/*
** Find the offset of a line given a file name.
*/
ULONG SymFindSourceLine(DebugModule *module, int line, char *fileName)
{
    return 0;
}

/*
** Find the source file associated with a given EIP for the module.
*/
int SymFindSource(DebugModule *module, ULONG eipOffset,
			char *funcName, char *sourceName, ULONG *lineNum)
{
SymSegmentData *symData = (SymSegmentData *) module->AuxData;
SymData16  *sym16;
SymData32  *sym32;
ULONG	    relOffset;
ULONG	    baseOffset;
USHORT	    objectNum;

    *sourceName = '\0';
    *funcName = '\0';
    *lineNum = 0;

    /*
    ** Find out which object and relative offset the EIP is assocated with.
    */
    debugBuffer->Addr = eipOffset;
    debugBuffer->MTE  = module->MTE;
    if(DispatchCommand(DBG_C_AddrToObject))
	return 0;
    baseOffset = debugBuffer->Buffer;
    relOffset  = eipOffset - baseOffset;

    /*
    ** Find the object number associated with the address.
    */
    for(objectNum=1;;objectNum++) {
	debugBuffer->Value = (ULONG) objectNum;
	debugBuffer->MTE   = module->MTE;
	if(DispatchCommand(DBG_C_NumToAddr) != DBG_N_Success)
	    break;
	if(debugBuffer->Addr == baseOffset)
	    break;
	symData = symData->next;
    }

    /*
    ** Set the Source file name to the segment name.
    */
    *lineNum = relOffset;

    /*
    ** Try to load the 16 byte symbols.
    */
    sym16 = symData->first16Symbol;
    if(sym16) {
	while(sym16->next) {
	    if(sym16->next->wSymVal > relOffset) {
		break;
	    }
	    sym16 = sym16->next;
	}
	if(sym16 == NULL)
	    return 0;
	*lineNum = relOffset - ((ULONG) sym16->wSymVal);
	strcpy(funcName, sym16->SymName);
	return 1;
    }

    /*
    ** Try the 32 bit symbols.
    */
    sym32 = symData->first32Symbol;
    while(sym32->next) {
	if(sym32->next->lSymVal > relOffset) {
	    break;
	}
	sym32 = sym32->next;
    }
    if(sym32 == NULL)
	return 0;

    *lineNum = relOffset - ((ULONG) sym32->lSymVal);
    strcpy(funcName, sym32->SymName);
    return 1;
}

/*
** Find the address of a function given the name.
*/
ULONG SymFindFuncAddr(DebugModule *module, char *funcName)
{
SymSegmentData *symData = (SymSegmentData *) module->AuxData;
SymData16      *sym16;
SymData32      *sym32;
int		objectNum = 1;
int		flag = 0;
ULONG		relOffset;

    /*
    ** Iterate through all segments.
    */
    while(symData) {

	/*
	** Iterate through all symbols for the segment
	*/
	sym16 = symData->first16Symbol;
	sym32 = symData->first32Symbol;
	if(sym16) {
	    while(sym16) {
		if((strcmp(funcName,  sym16->SymName)	 == 0) ||
		   (strcmp(funcName, &sym16->SymName[1]) == 0)) {
		    relOffset = (ULONG) sym16->wSymVal;
		    flag      = 1;
		    break;
		}
		sym16 = sym16->next;
	    }
	}

	if(sym32) {
	    while(sym32) {
		if((strcmp(funcName,  sym32->SymName)	 == 0) ||
		   (strcmp(funcName, &sym32->SymName[1]) == 0)) {
		    relOffset = (ULONG) sym32->lSymVal;
		    flag      = 1;
		    break;
		}
		sym32 = sym32->next;
	    }
	}

	/*
	** If we found the function, return
	*/
	if(flag) {
	    debugBuffer->MTE = module->MTE;
	    debugBuffer->Value = objectNum;
	    if(DispatchCommand(DBG_C_NumToAddr))
			return 0;
	    return debugBuffer->Addr + relOffset;
	}

	/*
	** NEXT!
	*/
	symData = symData->next;
	objectNum++;
    }
    return 0;
}
