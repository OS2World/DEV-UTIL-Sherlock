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
#include    <stdio.h>
#include    <string.h>
#include    <malloc.h>
#include    <sys\stat.h>

#define     INCL_DOSPROCESS
#include    <os2.h>
#include    "..\Debug.h"

#include    "..\SrcInter.h"
#include    "CV.h"
#include    "CV32.h"

/*
** Get the member of a structure.
*/
int CVGetMember(DebugModule *module, State *state, State *state2)
{
CVTypeData *cvType = cvType = state->typeData;
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
    types = FindType(cvType, cvType->typeIndex);
    if(types == NULL)
	return INTERNAL_ERROR;
    if(types[3] != 0x79)
	return INTERNAL_ERROR;

    /*
    ** Need to skip over the length string.
    */
    i  = CVGetNumber(&types[4], &num) + 4;
    i += CVGetNumber(&types[i], &numFields);

    /*
    ** Get the type list for the name.
    */
    tList = FindType(cvType, GetType(&types[i  ]));
    nList = FindType(cvType, GetType(&types[i+3]));
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
    for(i=4, index=0; index<numFields; index++) {
	if(nameLen == nList[i+1])
	    if(strncmp(&nList[i+2], state2->value.val.sVal, nameLen) == 0)
		break;
	i += nList[i+1] + 2;
	i += CVGetNumber(&nList[i], &num);
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
    i += CVGetNumber(&nList[i], &num);
    state->addr = state->value.val.lVal + num;

    /*
    ** Find the type information.
    */
    cvType->registerNum = -1;
    cvType->typeIndex = GetType(&tList[index * 3 + 4]);
    return CVGetValue(module, state);
}

/*
** Find the offset of a variable given  the name.  Find Globals,
** then statics then locals.
*/
int CVGetName(DebugModule *module, State *state, State *state2)
{
CVModule   *cvMod   = ((CVAuxData *) module->AuxData)->moduleData;
USHORT	    cbName  = (USHORT) strlen(state->value.val.sVal);
ULONG       eip     = state->baseEIP;

    /*
    ** If state2 is non-null, then it must be a member of a structure.
    */
    if(state2 != NULL)
	return CVGetMember(module, state, state2);

    /*
    ** Make sure we have a name in state.
    */
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
    for(; cvMod; cvMod=cvMod->next) {

        /*
        ** See if this is the correct module to look in for locals and
        ** file statics.
        */
        if(cvMod->module != NULL) {
            if((eip >= cvMod->module->offset) &&
               (eip <  cvMod->module->offset + cvMod->module->cbSeg))
               break;
        }
    }
    if(cvMod == NULL)
	return INVALID_NAME;

    /*
    ** Try the local symbols first.
    */
    if(cvMod->symbols != NULL) {
        unsigned char  *tmp = cvMod->symbols;
        unsigned short  totalBytes;

        totalBytes = cvMod->symbolSize;
        while(totalBytes > 0) {
            totalBytes -= tmp[0] + 1;

            /*
            ** BP-Relative symbol.
            */
            if(tmp[1] == 0x84) {
                BPRelativeSymbol32 *base;

                /*
                ** Read the record and null terminate the string.
                */
                base = (BPRelativeSymbol32 *) &tmp[2];

                /*
                ** Is the length correct?
                */
                if(cbName == base->cbName) {

                    /*
                    ** Is the name correct.
                    */
		    if(strncmp(state->value.val.sVal, base->name, cbName) == 0) {
			CVTypeData *td;

                        /*
                        ** Set the state/type information.
			*/
			td = (CVTypeData *) malloc(sizeof(CVTypeData));
			state->typeData     = td;
			state->typeDataSize = sizeof(CVTypeData);
			td->module	    = cvMod;
			td->registerNum     = -1;
			td->typeIndex	    = base->type;
			state->elementSize  = elementSize(state);
			state->addr = state->baseEBP + base->offset;
			return CVGetValue(module, state);
                    }
                }
            }

            /*
            ** Local symbol.
            */
            if(tmp[1] == 0x85) {
                LocalSymbol32 *base;

                /*
                ** Read the record and null terminate the string.
                */
                base = (LocalSymbol32 *) &tmp[2];

                /*
                ** Is the length correct?
                */
                if(cbName == base->cbName) {

                    /*
                    ** Is the name correct.
                    */
		    if(strncmp(state->value.val.sVal, base->name, cbName) == 0) {
			CVTypeData *td;

			td = (CVTypeData *)malloc(sizeof(CVTypeData));
			state->typeData     = td;
			state->typeDataSize = sizeof(CVTypeData);
			td->module	    = cvMod;
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
			return CVGetValue(module, state);
                    }
                }
            }

            /*
            ** Register variable.
            */
            if((tmp[1] == 0x8d) || (tmp[1] == 0x0d)) {
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
			CVTypeData *td;

			td = (CVTypeData *)malloc(sizeof(CVTypeData));
			state->typeData     = td;
			state->typeDataSize = sizeof(CVTypeData);
			td->module	    = cvMod;
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
			return CVGetRegisterValue(module, state);
                    }
                }
            }
            tmp += tmp[0] + 1;
        }
    }

    /*
    ** We did not find a local variable, try a public variable.
    */
    cvMod = ((CVAuxData *) module->AuxData)->moduleData;
    for(; cvMod; cvMod=cvMod->next) {

        if(cvMod->public != NULL) {
            CVPublic32  *cvPub = cvMod->public;

            for(;cvPub; cvPub=cvPub->next) {
                /*
                ** Is this the correct variable?
		*/
		if(strncmp(state->value.val.sVal, cvPub->data.name, cbName) == 0) {
		    CVTypeData *td;

		    td = (CVTypeData *)malloc(sizeof(CVTypeData));
		    state->typeData	= td;
		    state->typeDataSize = sizeof(CVTypeData);
		    td->module		= cvMod;
		    td->typeIndex	= cvPub->data.type;
		    td->registerNum	= -1;
		    state->elementSize	= elementSize(state);

                    /*
                    ** Get the base of the object.
                    */
		    debugBuffer->Value = cvPub->data.segment;
		    debugBuffer->MTE = module->MTE;
		    if(DispatchCommand(DBG_C_NumToAddr))
			return INTERNAL_ERROR;
		    state->addr = debugBuffer->Addr + cvPub->data.offset;
		    state->value.val.lVal  = 0;
		    state->value.typeValue = UNKNOWN_VAL;
		    return CVGetValue(module, state);
                }
            }
        }
    }
    return INVALID_NAME;
}

/*
** Find the number of members in a structure.
*/
int CVGetNumMembers(DebugModule *module, State *state)
{
CVTypeData *cvType = state->typeData;
UCHAR      *types;
int	    i;
ULONG	    num;

    module; /* Reference to keep from getting a warning! */

    /*
    ** Get a pointer to the type string.
    */
    types = FindType(cvType, cvType->typeIndex);
    if(types == NULL)
        return 0;

    /*
    ** We are now pointing at the type string for the structure,
    ** now, return the number of elements in the structure.
    */
    if(types[3] == 0x79) {
	/*
	** Need to skip over the length string.
	*/
	i  = CVGetNumber(&types[4], &num) + 4;
	i += CVGetNumber(&types[i], &num);
	return num;
    }
    return 0;
}

/*
** Get the value at the element specified in state2.
*/
int CVGetArray(DebugModule *module, State *state, State *state2)
{
CVTypeData *cvType = state->typeData;
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
    if(cvType->typeIndex < 0x200) {
	if((cvType->typeIndex & 0x60) == 0)
	    return INVALID_VALUE;

	state->value.val.lVal  = offset * state->elementSize;
	state->value.typeValue = BYTE_INDEX_IN_LVAL;
	return CVGetValue(module, state);
    }

    /*
    ** Complex data type.
    */
    types = FindType(cvType, cvType->typeIndex);
    if(types == NULL)
	return INTERNAL_ERROR;

    /*
    ** Pointers.
    */
    if(types[3] == 0x7A) {
	cvType->typeIndex = GetType(&types[5]);
	cvType->registerNum    = 0;
	state->value.val.lVal  = offset * state->elementSize;
	state->value.typeValue = BYTE_INDEX_IN_LVAL;
	return CVGetValue(module, state);
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
int CVGetMemberIndex(DebugModule *module,
	State *state, int memberIndex, char *name)
{
CVTypeData *cvType = state->typeData;
UCHAR	   *types, *nList;
int	    i;
ULONG	    num;

    module;
    /*
    ** Get a pointer to the type string.
    */
    types = FindType(cvType, cvType->typeIndex);
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
    i  = CVGetNumber(&types[4], &num) + 4;
    i += CVGetNumber(&types[i], &num);
    if((num <= memberIndex) || (memberIndex < 0))
	return INVALID_INDEX;

    /*
    ** Get the index of the name/offset data.
    */
    nList = FindType(cvType, GetType(&types[i+3]));
    if(nList == NULL) {
	return INTERNAL_ERROR;
    }
    if(nList[3] != 0x7f) {
	return INTERNAL_ERROR;
    }

    /*
    ** Find the name in the name list.
    */
    for(i=4; memberIndex; memberIndex--) {
	i += nList[i+1] + 2;
	i += CVGetNumber(&nList[i], &num);
    }
    strncpy(name, &nList[i+2], nList[i+1]);
    name[nList[i+1]] = 0;
    return SUCCESS;
}
