/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
** HLL interface functions to extract symbolic information
** given a state to extract information from.
*/
#include    <stdio.h>
#include    <string.h>
#include    <sys/stat.h>

#define     INCL_DOSPROCESS
#include    <os2.h>
#include    "..\Debug.h"

#include    "..\SrcInter.h"
#include    "HLL.h"

/*
** Find the offset of a line given a file name.
*/
ULONG HLLFindSourceLine(DebugModule *module, int line, char *fileName)
{
HLLModule  *hllMod = ((HLLAuxData *) module->AuxData)->moduleData;
USHORT	    i;
SrcLine    *lineData;

    /*
    ** Find the source module.
    */
    for(; hllMod; hllMod=hllMod->next) {

	if(hllMod->newLineData == NULL)
	    continue;
	if(hllMod->newLineData->entryData.srcLines == NULL)
            continue;

        /*
        ** Check for the correct file name.
        */
	if(stricmp(hllMod->newLineData->fileNames[0], fileName) != 0)
            continue;

        /*
        ** Read the line/offset pairs.
	*/
	lineData = hllMod->newLineData->entryData.srcLines;
	for(i=0; i<hllMod->newLineData->numEntries; i++) {
	    USHORT  lineNum;
	    ULONG   offset;

	    lineNum = lineData[i].lineNum;
	    if(line == (int) lineNum) {

		offset	= lineData[i].offset;

		/*
                ** Find the adjustment for the object.
                */
		debugBuffer->Value = hllMod->module->segment;
		debugBuffer->MTE   = module->MTE;
		if(DispatchCommand(DBG_C_NumToAddr))
		    return 0;
		return offset + debugBuffer->Addr;
            }
	    if(line < (int) lineNum) {
                return 0;
            }
        }
    }

    return 0;
}

/*
** Find the source file associated with a given EIP for the module.
*/
int HLLFindSource(DebugModule *module, ULONG eipOffset,
			char *funcName, char *sourceName, ULONG *lineNum)
{
HLLModule  *hllMod = ((HLLAuxData *) module->AuxData)->moduleData;
SrcLine    *lineData;
ULONG	    relOffset;
ULONG	    baseOffset;
USHORT	    i;
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
    }

    /*
    ** Find the source module.
    */
    for(; hllMod; hllMod=hllMod->next) {
	USHORT	 totalBytes;

	/*
        ** Is this module a possiblity
        */
	if((hllMod->module->offset > relOffset) ||
	   ((hllMod->module->offset+hllMod->module->cbSeg) < relOffset))
            continue;

	/*
	** Search the symbol records until we find the function we are looking for.
	*/
	totalBytes = hllMod->symbolSize;
	if(hllMod->symbols != NULL) {
	    unsigned char    *tmp;

	    tmp = hllMod->symbols;
	    while(totalBytes > 0) {
                totalBytes -= tmp[0] + 1;
		if(tmp[1] == 0x01 || tmp[1] == 0x0f) {
		    BeginBlock *tp;

		    tp = (BeginBlock *) &tmp[2];
		    if((relOffset >= tp->offset) &&
		       (relOffset < tp->offset + tp->procLength)) {
			if(tp->name[0] == '_') {
			    strncpy(funcName, &tp->name[1], tp->cbName-1);
			    funcName[tp->cbName-1] = '\0';
			} else {
			    strncpy(funcName, tp->name, tp->cbName);
			    funcName[tp->cbName] = '\0';
			}
		    }
		}
                tmp += tmp[0] + 1;
            }
	}

	/*
	** If there are no symbol records, then check the publics.
	*/
	if(hllMod->public != NULL) {
	    HLLPublic *public, *best;

	    best = NULL;
	    for(public = hllMod->public; public; public=public->next) {
		if(public->data.segment != objectNum)
		    continue;

		if(best == NULL)
		    best = public;
		if((relOffset >= public->data.offset) &&
		    (public->data.offset < best->data.offset)) {
		    best = public;
		}
	    }
	    strcpy(sourceName, "UNKNOWN");
	    if(best == NULL) {
		strcpy(funcName, "UNKNOWN");
	    } else {
		if(best->data.name[0] == '_')
		    strcpy(funcName, &best->data.name[1]);
		else
		    strcpy(funcName, best->data.name);
	    }
	}

	/*
	** Find the line for the offset.
	*/
	if(hllMod->newLineData) {
	    lineData = hllMod->newLineData->entryData.srcLines;
	    if(lineData && (hllMod->newLineData->entryType == 0)) {
		for(i=1; i<hllMod->newLineData->numEntries; i++) {
		    if(relOffset < lineData[i].offset) {
			break;
		    }
		}
		*lineNum = lineData[i-1].lineNum;
		strcpy(sourceName, hllMod->newLineData->
			fileNames[lineData[i-1].srcFileIndex-1]);
	    } else {
		sourceName[0] = 0;
	    }
	}
	return 0;
    }
    return 1;
}

/*
** Find the address of a function given the name.
*/
ULONG HLLFindFuncAddr(DebugModule *module, char *funcName)
{
HLLModule  *hllMod = ((HLLAuxData *) module->AuxData)->moduleData;
UCHAR       cbName = (unsigned char) strlen(funcName);

    /*
    ** Find the source module.
    */
    for(;hllMod; hllMod=hllMod->next) {
	USHORT		totalBytes;
	unsigned char  *tmp;

	if(hllMod->symbols != NULL) {
	    tmp = hllMod->symbols;
	    totalBytes = hllMod->symbolSize;
	    while(totalBytes > 0) {
		totalBytes -= tmp[0] + 1;

		/*
		** 32 Bit procedure.
		*/
		if(tmp[1] == 0x01 || tmp[1] == 0x0f) {
		    BeginBlock *tp;

		    tp = (BeginBlock *) &tmp[2];
		    if((UCHAR) (cbName+1) == tp->cbName) {
			if(strncmp(funcName, &tp->name[1], cbName-1) == 0) {
			    debugBuffer->MTE = module->MTE;
			    debugBuffer->Value = hllMod->module->segment;
			    if(DispatchCommand(DBG_C_NumToAddr))
				return 0;
			    return debugBuffer->Addr + tp->offset;
			}
		    }
		    if(cbName = tp->cbName) {
			if(strncmp(funcName, tp->name, cbName) == 0) {
			    debugBuffer->MTE = module->MTE;
			    debugBuffer->Value = hllMod->module->segment;
			    if(DispatchCommand(DBG_C_NumToAddr))
				return 0;
			    return debugBuffer->Addr + tp->offset;
			}
		    }
		}

		/*
		** 32 Bit code label.
		*/
		if(tmp[1] == 0x0b) {
		    CodeLabel *cl;

		    cl = (CodeLabel *) &tmp[2];
		    if((UCHAR) (cbName+1) == cl->cbName) {
			if(strncmp(funcName, &cl->name[1], cbName-1) == 0) {
			    debugBuffer->MTE = module->MTE;
			    debugBuffer->Value = hllMod->module->segment;
			    if(DispatchCommand(DBG_C_NumToAddr))
				return 0;
			    return debugBuffer->Addr + cl->offset;
			}
		    }
		    if(cbName == cl->cbName) {
			if(strncmp(funcName, cl->name, cbName) == 0) {
			    debugBuffer->MTE = module->MTE;
			    debugBuffer->Value = hllMod->module->segment;
			    if(DispatchCommand(DBG_C_NumToAddr))
				return 0;
			    return debugBuffer->Addr + cl->offset;
			}
		    }
		}
		tmp += tmp[0] + 1;
	    }
	}

	/*
	** If there are no symbol records, then check the publics.
	*/
	if(hllMod->public != NULL) {
	    HLLPublic *public;

	    for(public = hllMod->public; public; public=public->next) {
		if((strcmp(funcName,  public->data.name) == 0) ||
		   (strcmp(funcName, &public->data.name[1]) == 0)) {
		    debugBuffer->MTE = module->MTE;
		    debugBuffer->Value = public->data.segment;
		    if(DispatchCommand(DBG_C_NumToAddr))
			return 0;
		    return debugBuffer->Addr + public->data.offset;
		}
	    }
	}
    }
    return 0;
}
