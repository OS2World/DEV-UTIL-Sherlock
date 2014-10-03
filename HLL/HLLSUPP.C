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
#include    <stdlib.h>
#include    <ctype.h>
#include    <malloc.h>
#include    <memory.h>
#include    <sys/stat.h>

#define     INCL_DOSPROCESS
#include    <os2.h>
#include    "..\Debug.h"

#include    "..\SrcInter.h"
#include    "HLL.h"

void hexdump(unsigned char *data, int count, char *buff);

/*
** Get the value of a number leave.
*/
int HLLGetNumber(UCHAR *types, ULONG *num)
{

    /*
    ** Unsigned numeric leaves
    */
    if(types[0] < 0x80) {
	*num = types[0];
	return 1;
    } else if(types[0] == 0x85) {
	*num = types[1] + (types[2]<<8);
	return 3;
    } else if(types[0] == 0x86) {
	*num = types[1]     + types[2]<<8 +
	       types[3]<<16 + types[4]<<24;
	return 5;

    /*
    ** Signed numeric leaves
    */
    } else if(types[0] == 0x88) {
	*num = (ULONG) ((int) types[1]);
	return 2;
    } else if(types[0] == 0x89) {
	*num = (ULONG) ((int) (types[1] + types[2]<<8));
	return 3;
    } else if(types[0] == 0x8a) {
	*num = types[1]     + types[2]<<8 +
	       types[3]<<16 + types[4]<<24;
	return 5;
    }
    return 0;
}

/*
** Get a type index.
*/
USHORT GetType(UCHAR *types)
{
USHORT *ptr;

    if(types[0] != 0x83)
	return 0xffff;

    ptr = (USHORT *) &types[1];
    return *ptr;
}

/*
** Given a target type index, return a pointer to the start of the type string.
*/
UCHAR *FindType(HLLTypeData *hllType, USHORT targetIndex)
{
HLLModule   *hllMod;
UCHAR      *types;
USHORT      currentIndex = 0x200;
USHORT      i;

    hllMod	 = hllType->module;
    types	= hllMod->type;
    if(targetIndex < 0x200)
        return NULL;

    /*
    ** Search for the type.
    */
    for(i=0; i<hllMod->typeSize;) {
        if(targetIndex == currentIndex)
            break;

        i += types[i+1] + types[i+2] * 256 + 3;
        currentIndex++;
    }
    return &types[i];
}

/*
** Answer the size of a base type size.
*/
int HLLGetBaseTypeSize(USHORT targetIndex)
{
    if(targetIndex >= 0x200)
	return 4;

    switch((targetIndex & 0x01c) >> 2) {
        /* Real */
        case 2: switch(targetIndex & 0x03) {
                    case 0: /* Single */
                        return 4;
                    case 1: /* Double */
                        return 8;
                    case 2: /* Long double */
                        return 10;
                    case 3: /* Reserved */
                        return 4;
                    } break;

        /* Complex */
        case 3: switch(targetIndex & 0x03) {
                    case 0: /* Single */
                        return 8;
                    case 1: /* Double */
                        return 16;
                    case 2: /* Long double */
                        return 20;
                    case 3: /* Reserved */
                        return 4;
                } break;

        /* Currency */
        case 6: switch(targetIndex & 0x03) {
                    case 1:
                        return 8;   /* Normal   */
                    case 0: /* Reserved */
                    case 2:
                    case 3: return 4;
                } break;

        /* Other base c types. */
        case 0:
        case 1:
        case 4:
        case 5:
        case 7: switch(targetIndex & 0x03) {
                    case 0: /* Byte */
                        return 1;   /* Byte     */
                    case 1: /* Word */
                        return 2;   /* Word     */
                    case 2: /* Long     */
                        return 4;
                    case 3: /* Reserved */
                        return 4;
                } break;
    }
    return 4;
}

/*
** Answer the size of the structure.
*/
int elementSize(State *state)
{
HLLTypeData *hllType = state->typeData;
UCHAR	   *types;
USHORT	    targetIndex;
ULONG	    num;


    /*
    ** Get the pointer to the type string.
    */
    types = FindType(hllType, hllType->typeIndex);
    if(types != NULL) {
        /*
        ** Verify that this is a structure.
        */
	if(types[3] == 0x79) {
	    /*
	    ** Get the length of the structure.
	    */
	    return *((ULONG *) &types[4]);
	}

	/*
	** See if this is a pointers structure.
	*/
	if(types[3] == 0x7a) {
	    return 4;
	}

	/*
	** Try for an array.
	*/
	if(types[3] == 0x78) {
	    int i;

	    i = HLLGetNumber(&types[4], &num) + 4;
	    targetIndex = GetType(&types[i]);
	    if(targetIndex < 0x200)
		return HLLGetBaseTypeSize(targetIndex);
	    types = FindType(hllType, targetIndex);
	    if(types[3] == 0x7a)
		return 4;
	    if(types[3] == 0x79)
		return 4;
	    if(types[3] == 0x78) {
		i = HLLGetNumber(&types[4], &num) + 4;
		return HLLGetBaseTypeSize(GetType(&types[i]));
	    }
	    return 4;
	}

	/*
	** Dump the unknown data type.
	*/
	{
{
char buff[80];
hexdump(types, 16, buff);
fprintf(stderr, "Unknown type encountered:\n");
fprintf(stderr, "%s\n", buff);
}
	    return 4;

	}
    }

    targetIndex = hllType->typeIndex;
    return HLLGetBaseTypeSize(targetIndex);
}

/*
** Get the data from the debuggee, format it and then put it in a buffer.
*/
int HLLGetValue(DebugModule *module, State *state)
{
UCHAR	   *data;
HLLTypeData *hllType = state->typeData;
USHORT	    targetIndex;


    module;
    /*
    ** Get the data from the debuggee
    */
    data = calloc(state->elementSize + 4, 1);
    debugBuffer->Len	= state->elementSize;
    debugBuffer->Addr	= state->addr;
    debugBuffer->Buffer = (ULONG) data;
    if(DispatchCommand(DBG_C_ReadMemBuf) != DBG_N_Success) {
	fprintf(stderr, "OUT OF CONTEXT!\n");
	free(data);
	return OUT_OF_CONTEXT;
    }
    if(state->value.typeValue == BYTE_INDEX_IN_LVAL)
	*(ULONG *) data = *(ULONG *)data + state->value.val.lVal;

    /*
    ** Check the type of the data.
    */
    targetIndex = hllType->typeIndex;
    if(targetIndex > 0x0200) {
	char *types;

	types = FindType(hllType, hllType->typeIndex);
	if(types == NULL) {
	    free(data);
	    return INTERNAL_ERROR;
	}

	/*
	** Pointers
	*/
	if(types[3] == 0x7a) {
	    USHORT  typeIndex;

	    state->value.typeValue = PTR_VAL;
	    state->value.val.lVal = *(ULONG *) data;
	    typeIndex = *((USHORT *) &types[6]);
	    state->isStruct = 0;
	    if(typeIndex >= 0x200) {
		types = FindType(hllType, typeIndex);
		if(types[3] == 0x79) {
		    state->isStruct = 1;
		    hllType->typeIndex = typeIndex;
		}
	    }
	    free(data);
	    return SUCCESS;
	}

	/*
	** Structures
	*/
	if(types[3] == 0x79) {
	    state->value.typeValue = PTR_VAL;
	    state->value.val.lVal  = state->addr;
	    state->isStruct	   = 1;
	    return SUCCESS;
	}

	/*
	** Arrays
	*/
	if(types[3] == 0x78) {
	    ULONG   i;
	    ULONG   size;
	    USHORT  typeIndex;

	    state->value.typeValue = PTR_VAL;
	    state->value.val.lVal  = state->addr;
	    size = *((ULONG *) &types[5]);
	    typeIndex = *((USHORT *) &types[13]);
	    hllType->typeIndex = typeIndex;
	    if((typeIndex == 0x80) || (typeIndex == 0x84)) {
		char   *ptr;

		size /= 8;
		ptr = malloc(size+1);
		ptr[size] = 0;
		state->value.typeValue = STR_VAL;
		state->value.val.sVal  = ptr;
		debugBuffer->Len       = size;
		debugBuffer->Addr      = state->addr;
		debugBuffer->Buffer    = (ULONG) ptr;
		if((i = DispatchCommand(DBG_C_ReadMemBuf)) == DBG_N_Success)
		    return SUCCESS;

		free(ptr);
		state->value.typeValue = PTR_VAL;
		state->value.val.lVal  = *(ULONG *) data;
		return OUT_OF_CONTEXT;
	    }
	    return SUCCESS;
	}
	free(data);
	return INVALID_NAME;
    }

    /*
    ** For predefined types, break it down.
    */
    switch((targetIndex & 0x01c) >> 2) {
	/* Real */
	case 2: switch(targetIndex & 0x03) {
		    case 0: /* Single */
			    state->value.val.dVal  = *(float *) data;
			    state->value.typeValue = DOUBLE_VAL;
                            free(data);
			    return SUCCESS;
		    case 1: /* Double */
			    state->value.val.dVal  = *(double *) data;
			    state->value.typeValue = DOUBLE_VAL;
                            free(data);
			    return SUCCESS;
		    case 2: /* Long double */
			    free(data);
			    return INVALID_VALUE;
		    case 3: /* Reserved */
			    free(data);
			    return INTERNAL_ERROR;
		} break;

	/* Complex */
	case 3: free(data);
		return INVALID_VALUE;

	/* Currency */
	case 6: free(data);
		return INVALID_VALUE;

	/* Other base c types. */
	case 0: /* SIGNED   */
	case 1: /* UNSIGNED */
	case 4: /* BOOLEAN  */
	case 5: /* ASCII    */
		if((targetIndex & 0x60) == 0) {
		    switch(targetIndex & 0x03) {
			case 0: /* Byte */
				state->value.val.lVal  = data[0];
				state->value.typeValue = CHAR_VAL;
                                free(data);
				return SUCCESS;;
			case 1: /* Word */
				state->value.val.lVal  = *(short *) data;
				state->value.typeValue = LONG_VAL;
                                free(data);
				return SUCCESS;;
			case 2: /* Long     */
				state->value.val.lVal  = *(long *) data;
				state->value.typeValue = LONG_VAL;
				free(data);
				return SUCCESS;;
			case 3: /* Reserved */
				free(data);
				return INTERNAL_ERROR;
		    }
		} else {
		    debugBuffer->Addr	= *(ULONG *) data;
		    debugBuffer->Buffer = (ULONG) data;
		    debugBuffer->Len	= 4;
		    if(DispatchCommand(DBG_C_ReadMemBuf) != 0) {
			free(data);
			return OUT_OF_CONTEXT;
		    }
		    switch(targetIndex & 0x03) {
			case 0: /* Byte */
			    {
				ULONG	base, tmp;
				int	numBytes;

				tmp = base = *(ULONG *) data;
				numBytes = 0;
				do {
				    debugBuffer->Addr	= tmp;
				    debugBuffer->Buffer = (ULONG) data;
				    debugBuffer->Len	= 1;
				    if(DispatchCommand(DBG_C_ReadMemBuf) != 0) {
					free(data);
					return OUT_OF_CONTEXT;
				    }
				    numBytes++;
				    tmp++;
				} while(data[0] != 0);
				state->value.val.sVal  = malloc(numBytes);
				state->value.typeValue = STR_VAL;
				debugBuffer->Addr   = base;
				debugBuffer->Buffer = (ULONG) state->value.val.sVal;
				debugBuffer->Len    = numBytes;
				if(DispatchCommand(DBG_C_ReadMemBuf) != 0) {
				    free(data);
				    return OUT_OF_CONTEXT;
				}
				state->value.val.sVal[numBytes] = 0;
				free(data);
				return SUCCESS;
			    }
			case 1: /* Word */
				state->value.val.lVal  = *(short *) data;
				state->value.typeValue = LONG_VAL;
                                free(data);
				return SUCCESS;
			case 2: /* Long     */
				state->value.val.lVal  = *(long *) data;
				state->value.typeValue = LONG_VAL;
                                free(data);
				return SUCCESS;
			case 3: /* Reserved */
				free(data);
				return INTERNAL_ERROR;
		    }
		    return INVALID_VALUE;
		} break;
    }
    free(data);
    return INVALID_VALUE;
}

/*
** Assuming the address is a pointer to a pointer, return the value
** at the pointer.
*/
int HLLGetRegisterValue(DebugModule *module, State *state)
{
HLLTypeData *hllType = state->typeData;

    module;
    if(hllType->registerNum != -1) {
	if(DispatchCommand(DBG_C_ReadReg))
	    return INTERNAL_ERROR;
	switch(hllType->registerNum) {
	    case 0x10: state->value.val.lVal = debugBuffer->EAX; return SUCCESS;
	    case 0x11: state->value.val.lVal = debugBuffer->ECX; return SUCCESS;
	    case 0x12: state->value.val.lVal = debugBuffer->EDX; return SUCCESS;
	    case 0x13: state->value.val.lVal = debugBuffer->EBX; return SUCCESS;
	    case 0x14: state->value.val.lVal = debugBuffer->ESP; return SUCCESS;
	    case 0x15: state->value.val.lVal = debugBuffer->EBP; return SUCCESS;
	    case 0x16: state->value.val.lVal = debugBuffer->ESI; return SUCCESS;
	    case 0x17: state->value.val.lVal = debugBuffer->EDI; return SUCCESS;
	    default: state->value.typeValue = UNKNOWN_VAL; return INVALID_NAME;
	}
    }
    return INVALID_NAME;
}

/*
**  Dump a buffer of length to the buffer given.  Assume that length is
**  less than 16 and that the buffer is large enough to hold the result.
*/
void hexdump(unsigned char *data, int count, char *buff)
{
int i;
static char digits[] = "0123456789ABCDEF";

    count = min(count, 16);
    for(i=0; i<count; i++) {
        if(i == 8) {
            *buff++ = ' ';
            *buff++ = ' ';
        }
        *buff++ = digits[data[i]/16];
        *buff++ = digits[data[i]%16];
        *buff++ = ' ';
    }
    *buff++ = ' ';
    *buff++ = ' ';
    *buff++ = ' ';

    memcpy(buff, data, 16);
    for(i=0; i<count; i++)
	buff[i] = isgraph(buff[i]) ? buff[i] : (char) '.';
    buff[16] = '\0';
    return;
}
