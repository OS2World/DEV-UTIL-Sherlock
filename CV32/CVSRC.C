/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
** Code view interface functions to extract symbolic information
** given a state to extract information from.
*/
#include    <string.h>
#include    <sys\stat.h>

#define     INCL_DOSPROCESS
#include    <os2.h>
#include    "..\Debug.h"

#include    "..\SrcInter.h"
#include    "CV.h"
#include    "CV32.h"

/*
** Find the offset of a line given a file name.
*/
ULONG _System CVFindSourceLine(DebugModule *module, int line, char *fileName)
{
CVModule   *cvMod   = ((CVAuxData *) module->AuxData)->moduleData;
USHORT      i;
LineOffsetEntry32   *lineData;

    /*
    ** Find the source module.
    */
    for(; cvMod; cvMod=cvMod->next) {

        if(cvMod->lineData == NULL)
            continue;

        /*
        ** Check for the correct file name.
        */
        if(stricmp(cvMod->lineData->fileName, fileName) != 0)
            continue;

        /*
        ** Read the line/offset pairs.
        */
        lineData = cvMod->lineData->lineData;
        for(i=0; i<cvMod->lineData->count; i++) {
	    if(line == (int) lineData[i].line) {
                ULONG offset;

                offset = lineData[i].offset;

                /*
                ** Find the adjustment for the object.
                */
		debugBuffer->Value = cvMod->module->segment;
		debugBuffer->MTE   = module->MTE;
		if(DispatchCommand(DBG_C_NumToAddr))
		    return 0;
		return offset + debugBuffer->Addr;
            }
	    if(line < (int) lineData[i].line) {
                return 0;
            }
        }
    }

    return 0;
}

/*
** Find the source file associated with a given EIP for the module.
*/
int _System CVFindSource(DebugModule *module, ULONG eipOffset,
			char *funcName, char *sourceName, ULONG *lineNum)
{
CVModule   *cvMod   = ((CVAuxData *) module->AuxData)->moduleData;
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
    for(; cvMod; cvMod=cvMod->next) {
        LineOffsetEntry32  *lineData;
	USHORT	 totalBytes;

	/*
        ** Is this module a possiblity
        */
        if((cvMod->module->offset > relOffset) ||
           ((cvMod->module->offset+cvMod->module->cbSeg) < relOffset))
            continue;

	/*
	** Search the symbol records until we find the function we are looking for.
	*/
	totalBytes = cvMod->symbolSize;
	if(cvMod->symbols != NULL) {
	    unsigned char    *tmp;

	    tmp = cvMod->symbols;
	    while(totalBytes > 0) {
                totalBytes -= tmp[0] + 1;
		if(tmp[1] == 0x81 || tmp[1] == 0x8f) {
		    ProcedureStart32 *tp;

		    tp = (ProcedureStart32 *) &tmp[2];
		    if((relOffset >= tp->offset) &&
		       (relOffset < tp->offset + tp->procLength)) {
			if(tp->name[0] == '_') {
			    strncpy(funcName, &tp->name[1], tp->cbName-1);
			    funcName[tp->cbName-1] = '\0';
			} else {
			    strncpy(funcName, tp->name, tp->cbName);
			    funcName[tp->cbName] = '\0';
			}
			break;
		    }
		} else if(tmp[1] == 0x01 || tmp[1] == 0x0f) {
		    ProcedureStart *tp;

		    tp = (ProcedureStart *) &tmp[2];
		    if((relOffset >= tp->offset) &&
		       (relOffset < tp->offset + tp->procLength)) {
			if(tp->name[0] == '_') {
			    strncpy(funcName, &tp->name[1], tp->cbName-1);
			    funcName[tp->cbName-1] = '\0';
			} else {
			    strncpy(funcName, tp->name, tp->cbName);
			    funcName[tp->cbName] = '\0';
			}
			break;
		    }
		}
                tmp += tmp[0] + 1;
            }

	/*
	** If there are no symbol records, then check the publics.
	*/
	} else if(cvMod->public != NULL) {
	    CVPublic32 *public, *best;

	    best = NULL;
	    for(public = cvMod->public; public; public=public->next) {
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
	if(cvMod->lineData) {
	    lineData = cvMod->lineData->lineData;
	    for(i=1; i<cvMod->lineData->count; i++) {
		if(relOffset < lineData[i].offset)
		    break;
	    }
	    *lineNum = (ULONG) lineData[i-1].line;
	    strcpy(sourceName, cvMod->lineData->fileName);
	} else {
	    sourceName[0] = 0;
	}
	return 1;
    }
    return 0;
}

/*
** Find the address of a function given the name.
*/
ULONG _System CVFindFuncAddr(DebugModule *module, char *funcName)
{
CVModule   *cvMod = ((CVAuxData *) module->AuxData)->moduleData;
UCHAR       cbName = (unsigned char) strlen(funcName);

    /*
    ** Find the source module.
    */
    for(;cvMod; cvMod=cvMod->next) {
        USHORT  totalBytes;
	unsigned char	*tmp;

	/*
	** Try the symbol records first.
	*/
	if(cvMod->symbols != NULL) {

	    tmp = cvMod->symbols;
	    totalBytes = cvMod->symbolSize;
	    while(totalBytes > 0) {

		totalBytes -= tmp[0] + 1;

		/*
		** 32 Bit procedure.
                */
		if(tmp[1] == 0x81 || tmp[1] == 0x8f) {
		    ProcedureStart32 *tp;

		    tp = (ProcedureStart32 *) &tmp[2];
                    if((UCHAR) (cbName+1) == tp->cbName) {
			if(strncmp(funcName, &tp->name[1], cbName-1) == 0) {
			    debugBuffer->MTE = module->MTE;
			    debugBuffer->Value = cvMod->module->segment;
			    if(DispatchCommand(DBG_C_NumToAddr))
				return 0;
			    return debugBuffer->Addr + tp->offset;
			}
		    }
		    if(cbName = tp->cbName) {
			if(strncmp(funcName, tp->name, cbName) == 0) {
			    debugBuffer->MTE = module->MTE;
			    debugBuffer->Value = cvMod->module->segment;
			    if(DispatchCommand(DBG_C_NumToAddr))
				return 0;
			    return debugBuffer->Addr + tp->offset;
			}
		    }
		}

		/*
		** 32 Bit code label.
		*/
		if(tmp[1] == 0x8b) {
		    CodeLabel32 *cl;

		    cl = (CodeLabel32 *) &tmp[2];
                    if((UCHAR) (cbName+1) == cl->cbName) {
			if(strncmp(funcName, &cl->name[1], cbName-1) == 0) {
			    debugBuffer->MTE = module->MTE;
			    debugBuffer->Value = cvMod->module->segment;
			    if(DispatchCommand(DBG_C_NumToAddr))
				return 0;
			    return debugBuffer->Addr + cl->offset;
			}
		    }
		    if(cbName == cl->cbName) {
			if(strncmp(funcName, cl->name, cbName) == 0) {
			    debugBuffer->MTE = module->MTE;
			    debugBuffer->Value = cvMod->module->segment;
			    if(DispatchCommand(DBG_C_NumToAddr))
				return 0;
			    return debugBuffer->Addr + cl->offset;
			}
		    }
		}

		/*
		** 16 Bit procedure.
		*/
		if(tmp[1] == 0x01 || tmp[1] == 0x0f) {
		    ProcedureStart *tp;

		    tp = (ProcedureStart *) &tmp[2];
                    if((UCHAR) (cbName+1) == tp->cbName) {
			if(strncmp(funcName, &tp->name[1], cbName-1) == 0) {
			    debugBuffer->MTE = module->MTE;
			    debugBuffer->Value = cvMod->module->segment;
			    if(DispatchCommand(DBG_C_NumToAddr))
				return 0;
			    return debugBuffer->Addr + tp->offset;
			}
		    }
		    if(cbName = tp->cbName) {
			if(strncmp(funcName, tp->name, cbName) == 0) {
			    debugBuffer->MTE = module->MTE;
			    debugBuffer->Value = cvMod->module->segment;
			    if(DispatchCommand(DBG_C_NumToAddr))
				return 0;
			    return debugBuffer->Addr + tp->offset;
			}
		    }
		}

		/*
		** 16 Bit code label.
		*/
		if(tmp[1] == 0x0b) {
		    CodeLabel *cl;

		    cl = (CodeLabel *) &tmp[2];
                    if((UCHAR) (cbName+1) == cl->cbName) {
			if(strncmp(funcName, &cl->name[1], cbName-1) == 0) {
			    debugBuffer->MTE = module->MTE;
			    debugBuffer->Value = cvMod->module->segment;
			    if(DispatchCommand(DBG_C_NumToAddr))
				return 0;
			    return debugBuffer->Addr + cl->offset;
			}
		    }
		    if(cbName == cl->cbName) {
			if(strncmp(funcName, cl->name, cbName) == 0) {
			    debugBuffer->MTE = module->MTE;
			    debugBuffer->Value = cvMod->module->segment;
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
	** Try the public records last.
	*/
	if(cvMod->public != NULL) {
	    CVPublic32 *public;

	    for(public = cvMod->public; public; public=public->next) {
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
