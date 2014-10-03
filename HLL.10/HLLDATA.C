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
#include    <malloc.h>
#include    <sys/stat.h>

#define     INCL_DOSPROCESS
#include    <os2.h>
#include    "..\Debug.h"

#include    "..\SrcInter.h"
#include    "HLL.h"

/*
** Find the offset of a variable given  the name.  Find Globals,
** then statics then locals.
*/
int HLLGetName(DebugModule *module, State *state, State *state2)
{
HLLModule   *hllMod = ((HLLAuxData *) module->AuxData)->moduleData;
ULONG	    eip     = state->baseEIP;
USHORT	    cbName;

    /*
    ** If state2 is non-null, then it must be a member of a structure.
    */
    if(state2 != NULL)
	return HLLGetMember(module, state, state2);

    /*
    ** Make sure we have a name in state.
    */
    cbName = (USHORT) strlen(state->value.val.sVal);
    if(state->value.typeValue != NAME_VAL)
	return INVALID_NAME;

    /*
    ** Find out which object and relative offset the EIP is assocated with.
    */
    debugBuffer->Addr = eip;
    debugBuffer->MTE  = module->MTE;
    if(DispatchCommand(DBG_C_AddrToObject))
	return INTERNAL_ERROR;
    eip -= debugBuffer->Buffer;

    /*
    ** Find the source module.
    */
    for(; hllMod; hllMod=hllMod->next) {

        /*
        ** See if this is the correct module to look in for locals and
        ** file statics.
        */
	if(hllMod->module != NULL) {
	    if((eip >= hllMod->module->offset) &&
	       (eip <  hllMod->module->offset + hllMod->module->cbSeg))
               break;
        }
    }
    if(hllMod == NULL)
	return INVALID_NAME;

    /*
    ** Try the local symbols first.
    */
    if(hllMod->symbols != NULL) {
	unsigned char  *tmp = hllMod->symbols;
	unsigned short	totalBytes;
	unsigned int	foundProc=0;

	totalBytes = hllMod->symbolSize;
        while(totalBytes > 0) {
            totalBytes -= tmp[0] + 1;

	    /*
	    ** Try to match a block to the function.
	    */
	    if(tmp[1] == 0x00) {
		BlockStart *base;

		/*
                ** Read the record and null terminate the string.
                */
		base = (BlockStart *) &tmp[2];

		/*
		** Find if the procedure is ok.
		*/
		if((eip >= base->offset) &&
		   (eip < base->offset + base->length))
		    foundProc++;
	    }

	    /*
	    ** Try to match a procedure to the function.
	    */
	    if((tmp[1] == 0x01) || (tmp[1] == 0x0f)) {
		BeginBlock *base;

		/*
                ** Read the record and null terminate the string.
                */
		base = (BeginBlock *) &tmp[2];

		/*
		** Find if the procedure is ok.
		*/
		if((eip >= base->offset) &&
		   (eip < base->offset + base->procLength))
		    foundProc++;
	    }

	    /*
	    ** If we found an end record, make sure it is ok.
	    */
	    if(tmp[1] == 0x02) {
		if(foundProc) {
		    foundProc--;
		    if(foundProc == 0)
			break;
		}
	    }

	    /*
            ** BP-Relative symbol.
            */
	    if((tmp[1] == 0x04) && foundProc) {
		BPRelativeSymbol *base;

                /*
                ** Read the record and null terminate the string.
                */
		base = (BPRelativeSymbol *) &tmp[2];

                /*
                ** Is the length correct?
		*/
		if(cbName == base->cbName) {

                    /*
                    ** Is the name correct.
                    */
		    if(strncmp(state->value.val.sVal, base->name, cbName) == 0) {
			HLLTypeData *td;

                        /*
                        ** Set the state/type information.
			*/
			td = (HLLTypeData *) malloc(sizeof(HLLTypeData));
			state->typeData     = td;
			state->typeDataSize = sizeof(HLLTypeData);
			td->module	    = hllMod;
			td->registerNum     = -1;
			td->typeIndex	    = base->type;
			state->elementSize  = elementSize(state);
			state->addr = state->baseEBP + base->offset;
			return HLLGetValue(module, state);
                    }
                }
            }

            /*
            ** Local symbol.
            */
	    if((tmp[1] == 0x05) && foundProc) {
		LocalSymbol *base;

                /*
                ** Read the record and null terminate the string.
                */
		base = (LocalSymbol *) &tmp[2];

                /*
                ** Is the length correct?
                */
                if(cbName == base->cbName) {

                    /*
                    ** Is the name correct.
                    */
		    if(strncmp(state->value.val.sVal, base->name, cbName) == 0) {
			HLLTypeData *td;

			td = (HLLTypeData *)malloc(sizeof(HLLTypeData));
			state->typeData     = td;
			state->typeDataSize = sizeof(HLLTypeData);
			td->module	    = hllMod;
			td->typeIndex	    = base->type;
			td->registerNum     = -1;
			state->elementSize  = elementSize(state);

                        /*
                        ** Get the base of the object.
                        */
			debugBuffer->Value = base->segment;
			debugBuffer->MTE = module->MTE;
			if(DispatchCommand(DBG_C_NumToAddr))
			    return INTERNAL_ERROR;
			state->addr = debugBuffer->Addr + base->offset;
			state->value.val.lVal  = 0;
			state->value.typeValue = UNKNOWN_VAL;
			return HLLGetValue(module, state);
                    }
                }
            }

	    /*
            ** Register variable.
            */
	    if((tmp[1] == 0x0d) && foundProc) {
                RegisterSymbol *base;

                base = (RegisterSymbol *) &tmp[2];

                /*
                ** Is the length correct?
                */
                if(cbName == base->cbName) {
                    /*
                    ** Is this the correct variable?
                    */
		    if(strncmp(state->value.val.sVal, base->name, cbName) == 0) {
			HLLTypeData *td;

			td = (HLLTypeData *)malloc(sizeof(HLLTypeData));
			state->typeData     = td;
			state->typeDataSize = sizeof(HLLTypeData);
			td->module	    = hllMod;
			td->typeIndex	    = base->type;
			td->registerNum     = base->registerNum;
			state->elementSize  = elementSize(state);
			state->addr = 0;
			if(base->type < 0x200) {
			    if((base->type & 0x60) == 0) {
				switch((base->type & 0x1c) >> 2) {
				    case 0:
				    case 1:
				    case 4: state->value.typeValue = LONG_VAL; break;
				    case 2: state->value.typeValue = DOUBLE_VAL; break;
				    case 3: state->value.typeValue = CHAR_VAL; break;
				    case 5: state->value.typeValue = CHAR_VAL; break;
				    case 6: state->value.typeValue = UNKNOWN_VAL; break;
				    case 7: state->value.typeValue = UNKNOWN_VAL; break;
				}
			    } else {
				state->value.typeValue = PTR_VAL;
			    }
			} else {
			    state->value.typeValue = PTR_VAL;
			}
			return HLLGetRegisterValue(module, state);
                    }
                }
            }
            tmp += tmp[0] + 1;
        }
    }

    /*
    ** We did not find a local variable, try a public variable.
    */
    hllMod = ((HLLAuxData *) module->AuxData)->moduleData;
    for(; hllMod; hllMod=hllMod->next) {

	if(hllMod->public != NULL) {
	    HLLPublic  *hllPub = hllMod->public;

	    for(;hllPub; hllPub=hllPub->next) {
                /*
                ** Is this the correct variable?
		*/
		if(strncmp(state->value.val.sVal, hllPub->data.name, cbName) == 0) {
		    HLLTypeData *td;

		    td = (HLLTypeData *)malloc(sizeof(HLLTypeData));
		    state->typeData	= td;
		    state->typeDataSize = sizeof(HLLTypeData);
		    td->module		= hllMod;
		    td->typeIndex	= hllPub->data.type;
		    td->registerNum	= -1;
		    state->elementSize	= elementSize(state);

                    /*
                    ** Get the base of the object.
                    */
		    debugBuffer->Value = hllPub->data.segment;
		    debugBuffer->MTE = module->MTE;
		    if(DispatchCommand(DBG_C_NumToAddr))
			return INTERNAL_ERROR;
		    state->addr = debugBuffer->Addr + hllPub->data.offset;
		    state->value.val.lVal  = 0;
		    state->value.typeValue = UNKNOWN_VAL;
		    return HLLGetValue(module, state);
                }
            }
        }
    }
    return INVALID_NAME;
}

/*
** Get the member of a structure.
*/
int HLLGetMember(DebugModule *module, State *state, State *state2)
{
HLLTypeData *hllType = hllType = state->typeData;
UCHAR	   *types;
UCHAR	   *tList;
UCHAR	   *nList;
ULONG	    nameLen;
ULONG	    index;
ULONG	    i;
ULONG	    num, numFields;

    module;
    /*
    ** Make sure we have an address in state.
    */
    if(state->value.typeValue != PTR_VAL)
	return INVALID_VALUE;

    /*
    ** Make sure we have a name in state2.
    */
    if(state2->value.typeValue != NAME_VAL)
	return INVALID_NAME;

    /*
    ** Get the type data for the structure.
    */
    types = FindType(hllType, hllType->typeIndex);
    if(types == NULL)
	return INTERNAL_ERROR;
    if(types[3] != 0x79)
	return INTERNAL_ERROR;

    /*
    ** Get the type list for the name.
    */
    tList = FindType(hllType, *((USHORT *) &types[12]));
    nList = FindType(hllType, *((USHORT *) &types[15]));
    if((nList == NULL) || (tList == NULL)) {
	return INTERNAL_ERROR;
    }
    if((nList[3] != 0x7f) || (tList[3] != 0x7f)) {
	return INTERNAL_ERROR;
    }

    /*
    ** Find the name in the name list.
    */
    nameLen = strlen(state2->value.val.sVal);
    numFields = *((USHORT *) &types[9]);
    for(i=5, index = 0; numFields; numFields--, index++) {
	if(nameLen == nList[i+1]) {
	    if(strncmp(&nList[i+2], state2->value.val.sVal, nameLen) == 0) {
		break;
	    }
	}

	i += nList[i+1] + 2;
	switch(nList[i]) {
	    case 0x85:	i+=3; break;
	    case 0x86:	i+=5; break;
	    case 0x88:	i+=2; break;
	    case 0x89:	i+=3; break;
	    case 0x8A:	i+=5; break;
	    case 0x8B:	i+=2; break;
	}
    }
    if(nameLen != nList[i+1])
	return INVALID_NAME;
    if(strncmp(&nList[i+2], state2->value.val.sVal, nameLen) != 0)
	return INVALID_NAME;

    /*
    ** Find the actual offset of the value and then put it
    ** into the address field of the state.
    */
    i += nList[i+1] + 2;
    switch(nList[i]) {
	case 0x85:  num = *((USHORT *) &nList[i+1]); break;
	case 0x86:  num = *((ULONG  *) &nList[i+1]); break;
	case 0x88:  num = *((UCHAR  *) &nList[i+1]); break;
	case 0x89:  num = *((USHORT *) &nList[i+1]); break;
	case 0x8A:  num = *((ULONG  *) &nList[i+1]); break;
	case 0x8B:  num = *((UCHAR  *) &nList[i+1]); break;
    }
    state->addr = state->value.val.lVal + num;

    /*
    ** Find the type information.
    */
    hllType->registerNum = -1;
    hllType->typeIndex = *((USHORT *) &tList[index * 3 + 6]);
    return HLLGetValue(module, state);
}

/*
** Find the number of members in a structure.
*/
int HLLGetNumMembers(DebugModule *module, State *state)
{
HLLTypeData *hllType = state->typeData;
UCHAR      *types;

    module; /* Reference to keep from getting a warning! */

    /*
    ** Get a pointer to the type string.
    */
    types = FindType(hllType, hllType->typeIndex);
    if(types == NULL)
        return 0;

    /*
    ** We are now pointing at the type string for the structure,
    ** now, return the number of elements in the structure.
    */
    if(types[3] == 0x79) {
	/*
	** Return the number of fields in the structure.
	*/
	return *((USHORT *) &types[9]);
    }
    return 0;
}

/*
** Get the value at the element specified in state2.
*/
int HLLGetArray(DebugModule *module, State *state, State *state2)
{
HLLTypeData *hllType = state->typeData;
int	    offset;
UCHAR	   *types;

    module;

    /*
    ** Verify the offset parameter.
    */
    if(state2->value.typeValue != LONG_VAL)
	return INVALID_VALUE;
    offset = state2->value.val.lVal;

    /*
    ** Verify the address parameter.
    */
    if(state->value.typeValue != PTR_VAL)
	return INVALID_VALUE;

    /*
    ** Check the type of the data.
    */
    if(hllType->typeIndex < 0x200) {
	if((hllType->typeIndex & 0x60) == 0)
	    return INVALID_VALUE;

	state->value.val.lVal  = offset * state->elementSize;
	state->value.typeValue = BYTE_INDEX_IN_LVAL;
	return HLLGetValue(module, state);
    }

    /*
    ** Complex data type.
    */
    types = FindType(hllType, hllType->typeIndex);
    if(types == NULL)
	return INTERNAL_ERROR;

    /*
    ** Pointers.
    */
    if(types[3] == 0x7A) {
	hllType->typeIndex = *((USHORT *) &types[6]);
	hllType->registerNum	= 0;
	state->value.val.lVal  = offset * state->elementSize;
	state->value.typeValue = BYTE_INDEX_IN_LVAL;
	return HLLGetValue(module, state);
    }

    /*
    ** Structures.
    */
    if(types[3] == 0x79) {
	hllType->registerNum	= 0;
	state->value.val.lVal  = offset * *((ULONG *) &types[5]);
	state->value.typeValue = BYTE_INDEX_IN_LVAL;
	return HLLGetValue(module, state);
    }

{
char buff[80];
hexdump(types, 16, buff);
fprintf(stderr, "Unknown type in GetArray\n");
fprintf(stderr, "%s\n", buff);
}
    return INVALID_VALUE;
}

/*
** Get the name of the index'th structure name.
*/
int HLLGetMemberIndex(DebugModule *module,
	State *state, int memberIndex, char *name)
{
HLLTypeData *hllType = state->typeData;
UCHAR	   *types, *nList;
int	    i;
ULONG	    num;

    module;
    /*
    ** Get a pointer to the type string.
    */
    types = FindType(hllType, hllType->typeIndex);
    if(types == NULL) {
	*name = '\0';
	return INTERNAL_ERROR;
    }

    /*
    ** Verify that this is a structure.
    */
    if(types[3] != 0x79) {
	*name = '\0';
	return INVALID_NAME;
    }

    /*
    ** Need to skip over the length string.
    */
    num = *((USHORT *) &types[9]);
    if((num <= memberIndex) || (memberIndex < 0))
	return INVALID_INDEX;

    /*
    ** Get the index of the name/offset data.
    */
    nList = FindType(hllType, *((USHORT *) &types[15]));
    if(nList == NULL) {
	return INTERNAL_ERROR;
    }
    if((nList[3] != 0x7f) || (nList[4] != 0x02)) {
	return INTERNAL_ERROR;
    }

    /*
    ** Find the name in the name list.
    */
    for(i=5; memberIndex; memberIndex--) {
	i += nList[i+1] + 2;
	i += HLLGetNumber(&nList[i], &num);
	switch(nList[i]) {
	    case 0x85:	i+=2; break;
	    case 0x86:	i+=4; break;
	    case 0x88:	i+=1; break;
	    case 0x89:	i+=2; break;
	    case 0x8A:	i+=4; break;
	    case 0x8B:	i+=1; break;
	}
    }
    strncpy(name, &nList[i+2], nList[i+1]);
    name[nList[i+1]] = 0;
    return SUCCESS;
}
