/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
**  Analyize an expression to find a variable in memory.
*/
#include    <stdio.h>
#include    <stdlib.h>
#include    <limits.h>
#include    <string.h>
#include    <malloc.h>
#include    <ctype.h>
#include    <math.h>
#include    <sys\stat.h>

#define     INCL_DOSPROCESS
#include    <os2.h>
#include    "debug.h"

#include    "Debugger.h"
#include    "SrcInter.h"
#include    "Source.h"

/*
** Manifest constants.
*/
#define TRUE	1
#define FALSE	0

/*
** Macros for common operations.
*/
#define freeData(state) 			\
    {	if(state.value.typeValue == STR_VAL)	\
	    free(state.value.val.sVal); 	    \
	if(state.value.typeValue == NAME_VAL)	\
	    free(state.value.val.sVal); 	    \
	state.value.val.sVal = NULL;		    \
	if(state.typeData != NULL)		\
	    free(state.typeData);		\
	state.typeData = NULL;			\
    }

#define copyState(state, state2)		 \
    {	memcpy(&state2, state, sizeof(State));	 \
	memset(&state2.value, 0, sizeof(Value)); \
	state2.isStruct = FALSE;		 \
	state2.typeData = NULL; 		 \
    }



static char *curPtr;

static int match(char *matchString);
static char *isName(void);
static int isNumber(State *state);
static int isLiteral(State *state);

static int exp1(State *state);
static int exp2(State *state);
static int exp3(State *state);
static int exp4(State *state);
static int exp5(State *state);
static int exp6(State *state);
static int primary(State *state);
static int member(State *state);

/*
** Concatinate the rest of the strings since they will become
** the expression.
*/
int evaluate(char *expr, DebugModule *module, ULONG eip, ULONG ebp, Value *value)
{
int	rVal;
State	state;

    /*
    ** Initialize the state block.
    */
    memset(&state, 0, sizeof(state));
    state.baseEIP = eip;
    state.baseEBP = ebp;
    debugBuffer.Addr = eip;
    if(module == NULL) {
	DispatchCommand(DBG_C_AddrToObject);
	state.module = FindModule(debugBuffer.MTE, NULL);
    } else {
	state.module = module;
    }
    curPtr = expr;

    /*
    ** Evaluate the expression.
    */
    if((rVal = exp1(&state)) != SUCCESS) {
	freeData(state);
	return rVal;
    }

    /*
    ** If this is a structure, build a structure value array.
    */
    if((state.value.typeValue == PTR_VAL) && state.isStruct) {
	int	     i, numMembers;
	State	     state2, state3;
	StructValue *valueData;
	void	    *newTD;

	/*
	** Make a copy of the state and the type data for later
	** use.  GetName destroys the type data, so we need to
	** make a copy of it for reuse later.
	*/
	value->typeValue = STRUCT_VAL;
	value->val.strVal = valueData = calloc(sizeof(StructValue), 1);
	valueData->str = malloc(strlen(expr) + 20);
	sprintf(valueData->str, "%s: (0x%08x)", expr, state.value.val.lVal);
	numMembers = GetNumMembers(state.module, &state);
	newTD = malloc(state.typeDataSize);

	/*
	** Iterate through each member of the array.
	*/
	for(i=0; i<numMembers; i++) {
	    int     size;
	    char    name[MAX_FUNCNAME];

	    /*
	    ** Copy the state so we can traverse the list of members.
	    */
	    memcpy(&state2, &state, sizeof(State));
	    state2.typeData = newTD;
	    memcpy(state2.typeData, state.typeData, state.typeDataSize);
	    memcpy(&state3, &state, sizeof(State));
	    state3.value.typeValue = NAME_VAL;
	    state3.value.val.sVal  = name;
	    state3.typeData	   = NULL;

	    /*
	    ** Find out what variable is at the current index.
	    */
	    if((rVal = GetMemberIndex(state.module, &state2, i, name)) != SUCCESS) {
		valueData->next = calloc(sizeof(StructValue), 1);
		valueData = valueData->next;
		valueData->str = malloc(strlen(name) + 40);
		sprintf(valueData->str, "%s: Member error! %d", name, rVal);
		continue;
	    }

	    /*
	    ** Get the data for the name specified
	    */
	    if((rVal = GetName(state.module, &state2, &state3)) != SUCCESS) {
		valueData->next = calloc(sizeof(StructValue), 1);
		valueData = valueData->next;
		valueData->str	= malloc(strlen(name) + 40);
		sprintf(valueData->str, "%s: ERROR! %d 0x%08x",
			name, state2.value.typeValue, state2.value.val.lVal);
		continue;
	    }

	    /*
	    ** Put the data into the return linked list.
	    */
	    size = strlen(name) +
		   ((state2.value.typeValue == STR_VAL) ?
			(strlen(state2.value.val.sVal) + 20): 20);
	    valueData->next = calloc(sizeof(StructValue), 1);
	    valueData = valueData->next;
	    valueData->str  = malloc(size);
	    switch(state2.value.typeValue) {
		case UNKNOWN_VAL:
		    sprintf(valueData->str, "%s: UNKNOWN!", name);
		    break;
		case LONG_VAL:
		    sprintf(valueData->str, "%s: %d (0x%08x)", name,
			    state2.value.val.lVal, state2.value.val.lVal);
		    break;
		case DOUBLE_VAL:
		    sprintf(valueData->str, "%s: %lf", name,
			    state2.value.val.dVal);
		    break;
		case CHAR_VAL:
		    sprintf(valueData->str, "%s: '%c' (0x%02x)", name,
			    state2.value.val.cVal, state2.value.val.cVal);
		    break;
		case STR_VAL:
		    sprintf(valueData->str, "%s: (0x%08x) - \"%s\"", name,
			    state2.value.val.sVal, state2.value.val.sVal);
		    break;
		case NAME_VAL:
		    sprintf(valueData->str, "%s: NAME: \"%s\"", name,
			    state2.value.val.sVal);
		    break;
		case PTR_VAL:
		    sprintf(valueData->str, "%s: PTR 0x%08x", name,
			    state2.value.val.lVal);
		    break;
		default:
		    sprintf(valueData->str, "%s: INTERNAL ERROR!  Type: %d", name,
			    state2.value.typeValue);
		    break;
	    }
	}
	return SUCCESS;
    }

    /*
    ** Copy the value to whoever wanted the evaluation.
    */
    memcpy(value, &state.value, sizeof(Value));
    return SUCCESS;
}

/*
** Is the current token a literal?
** If so, return true, else return false;
*/
static int isLiteral(State *state)
{
    /*
    ** Skip over white space.
    */
    while(isspace(*curPtr))
	curPtr++;

    /*
    ** Initialize the structure.
    */
    memset(&state->value, 0, sizeof(Value));

    if(isNumber(state))
	return TRUE;

    /*
    ** Is this a quote delimited string?
    */
    if(match("\"")) {
        int i;
        char *buff;
	buff = malloc(strlen(curPtr) + 1);
        for(i=0; *curPtr != '"' && *curPtr; i++, curPtr++) {
            buff[i] = *curPtr;
	}
	curPtr++;
        buff[i] = 0;
	state->value.typeValue = STR_VAL;
	state->value.val.sVal = strdup(buff);
	return TRUE;
    }

    /*
    ** No escape sequences yet!
    */
    if(match("'")) {
	state->value.val.cVal	   = *curPtr++;
	state->value.typeValue = CHAR_VAL;
	if(state->value.val.cVal == '\\') {
            switch(*curPtr) {
		case '\\':  state->value.val.cVal = '\\'; ++curPtr; break;
		case 'n':   state->value.val.cVal = '\n'; ++curPtr; break;
		case 't':   state->value.val.cVal = '\t'; ++curPtr; break;
		case 'v':   state->value.val.cVal = '\v'; ++curPtr; break;
		case 'b':   state->value.val.cVal = '\b'; ++curPtr; break;
		case 'r':   state->value.val.cVal = '\r'; ++curPtr; break;
		case 'f':   state->value.val.cVal = '\f'; ++curPtr; break;
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
		case '7':   state->value.val.cVal = (char) strtol(curPtr, &curPtr, 8);
                            break;
                case 'x':
		case 'X':   state->value.val.cVal = (char) strtol(curPtr + 1, &curPtr, 16);
                            break;
		default:    return FALSE;
            }
        }
	curPtr++;
	return TRUE;
    }
    return FALSE;
}

/*
** Is the current token a number?
** Return true if it is, false if not.
*/
static int isNumber(State *state)
{
int	isFloat = 0;
int	i;
char   *dummy;
char	buffer[30];

    if(!isdigit(*curPtr))
	return FALSE;

    buffer[0] = 0;
    for(i=0; i<sizeof(buffer); i++, curPtr++) {
        if(isdigit(*curPtr)) {
	    buffer[i] = *curPtr;
	    continue;
	}
	if((*curPtr == '.') || (*curPtr == 'e') || (*curPtr == 'E')) {
	    buffer[i] = *curPtr;
	    isFloat = 1;
	    continue;
	}
	buffer[i] = 0;
	break;
    }
    if(isFloat) {
	state->value.val.dVal	   = strtod(buffer, &dummy);
	state->value.typeValue = DOUBLE_VAL;
    } else {
	state->value.val.lVal = strtol(buffer, &dummy, 0);
	if(state->value.val.lVal == LONG_MAX || state->value.val.lVal == LONG_MIN)
	    state->value.val.lVal = strtoul(buffer, &dummy, 0);
	state->value.typeValue = LONG_VAL;
    }
    return TRUE;
}

/*
** Is this a register?
*/
static int isRegister(State *state)
{
ULONG  *offset = NULL;
int	shift  = 0;
int	length;

    /*
    ** 32 Bit registers.
    */
    if(stricmp(curPtr, "EAX") == 0) {
	offset = &debugBuffer.EAX;
	length = 4;
    } else if(stricmp(curPtr, "EBX") == 0) {
	offset = &debugBuffer.EBX;
	length = 4;
    } else if(stricmp(curPtr, "ECX") == 0) {
	offset = &debugBuffer.ECX;
	length = 4;
    } else if(stricmp(curPtr, "EDX") == 0) {
	offset = &debugBuffer.EDX;
	length = 4;
    } else if(stricmp(curPtr, "ESP") == 0) {
	offset = &debugBuffer.ESP;
	length = 4;
    } else if(stricmp(curPtr, "EBP") == 0) {
	offset = &debugBuffer.EBP;
	length = 4;
    } else if(stricmp(curPtr, "ESI") == 0) {
	offset = &debugBuffer.ESI;
	length = 4;
    } else if(stricmp(curPtr, "EDI") == 0) {
	offset = &debugBuffer.EDI;
	length = 4;
    } else if(stricmp(curPtr, "EIP") == 0) {
	offset = &debugBuffer.EIP;
	length = 4;
    } else

    /*
    ** 16 Bit registers.
    */
    if(stricmp(curPtr, "AX") == 0) {
	offset = &debugBuffer.EAX;
	length = 2;
    } else if(stricmp(curPtr, "BX") == 0) {
	offset = &debugBuffer.EBX;
	length = 2;
    } else if(stricmp(curPtr, "CX") == 0) {
	offset = &debugBuffer.ECX;
	length = 2;
    } else if(stricmp(curPtr, "DX") == 0) {
	offset = &debugBuffer.EDX;
	length = 2;
    } else if(stricmp(curPtr, "SP") == 0) {
	offset = &debugBuffer.ESP;
	length = 2;
    } else if(stricmp(curPtr, "BP") == 0) {
	offset = &debugBuffer.EBP;
	length = 2;
    } else if(stricmp(curPtr, "SI") == 0) {
	offset = &debugBuffer.ESI;
	length = 2;
    } else if(stricmp(curPtr, "DI") == 0) {
	offset = &debugBuffer.EDI;
	length = 2;
    } else if(stricmp(curPtr, "IP") == 0) {
	offset = &debugBuffer.EIP;
	length = 2;
    } else

    /*
    ** 8 Bit registers.
    */
    if(stricmp(curPtr, "AL") == 0) {
	offset = &debugBuffer.EAX;
	length = 1;
    } else if(stricmp(curPtr, "AH") == 0) {
	offset = &debugBuffer.EAX;
	length = 1;
	shift  = 8;
    } else if(stricmp(curPtr, "BL") == 0) {
	offset = &debugBuffer.EBX;
	length = 1;
    } else if(stricmp(curPtr, "BH") == 0) {
	offset = &debugBuffer.EBX;
	length = 1;
	shift  = 8;
    } else if(stricmp(curPtr, "CL") == 0) {
	offset = &debugBuffer.ECX;
	length = 1;
    } else if(stricmp(curPtr, "CH") == 0) {
	offset = &debugBuffer.ECX;
	length = 1;
	shift  = 8;
    } else if(stricmp(curPtr, "DL") == 0) {
	offset = &debugBuffer.EDX;
	length = 1;
    } else if(stricmp(curPtr, "DH") == 0) {
	offset = &debugBuffer.EDX;
	length = 1;
	shift  = 8;
    } else

    /*
    ** Segment registers.
    */
    if(stricmp(curPtr, "CS") == 0) {
	offset = (ULONG *) &debugBuffer.CS;
	length = 2;
    } else if(stricmp(curPtr, "DS") == 0) {
	offset = (ULONG *) &debugBuffer.DS;
	length = 2;
    } else if(stricmp(curPtr, "ES") == 0) {
	offset = (ULONG *) &debugBuffer.ES;
	length = 2;
    } else if(stricmp(curPtr, "SS") == 0) {
	offset = (ULONG *) &debugBuffer.SS;
	length = 2;
    } else if(stricmp(curPtr, "FS") == 0) {
	offset = (ULONG *) &debugBuffer.FS;
	length = 2;
    } else if(stricmp(curPtr, "GS") == 0) {
	offset = (ULONG *) &debugBuffer.GS;
	length = 2;
    }

    /*
    ** See if we matched a register.
    */
    if(offset == NULL)
	return FALSE;

    /*
    ** Get the registers
    */
    DispatchCommand(DBG_C_ReadReg);
    if(length == 1) {
	state->value.val.lVal = (*offset >> shift) & 0xff;
    } else if(length == 2) {
	state->value.val.lVal = *offset & 0xffff;
    } else {
	state->value.val.lVal = *offset;
    }
    state->value.typeValue = LONG_VAL;
    return TRUE;
}

/*
** Is the current token a name?
** Return NULL if not, else a duplicate if so.
*/
static char *isName(void)
{
int	i;
char	buffer[MAX_FUNCNAME];

    if((*curPtr != '_') && !isalpha(*curPtr))
	return NULL;

    for(i=0; i<sizeof(buffer); i++, curPtr++) {
	if((*curPtr == '_') || isalnum(*curPtr)) {
	    buffer[i] = *curPtr;
	    continue;
	}
	buffer[i] = 0;
	break;
    }
    return strdup(buffer);
}

/*
** Answer whether the specified string matches the next token.
** If it does, return true.  If not, return false.
*/
static int match(char *matchString)
{
    /*
    ** Skip over white space.
    */
    while(isspace(*curPtr))
	curPtr++;

    /*
    ** Compare the match string to the current text.
    */
    if(strncmp(curPtr, matchString, strlen(matchString)) == 0) {
	curPtr += strlen(matchString);
	return TRUE;
    }
    return FALSE;
}

/*
** Handle logical operations.
*/
static int exp1(State *state)
{
int	rVal;
State	state2;

    if((rVal = exp2(state)) != SUCCESS)
	return rVal;

    /*
    ** Initialize the state variable.
    */
    copyState(state, state2);

    while(TRUE) {

	/*
	** Logical or.
	*/
	if(match("|")) {
	    if(state->value.typeValue != LONG_VAL)
		return INVALID_VALUE;

	    if((rVal = exp2(&state2)) != SUCCESS) {
		freeData(state2);
		return rVal;
	    }
	    if(state2.value.typeValue != LONG_VAL) {
		freeData(state2);
		return INVALID_VALUE;
	    }

	    state->value.val.lVal = state->value.val.lVal | state2.value.val.lVal;
	    freeData(state2);
	    continue;
	}

	/*
	** Logical xor.
	*/
	if(match("^")) {
	    if(state->value.typeValue != LONG_VAL)
		return INVALID_VALUE;

	    if((rVal = exp2(&state2)) != SUCCESS) {
		freeData(state2);
		return rVal;
	    }
	    if(state2.value.typeValue != LONG_VAL) {
		freeData(state2);
		return INVALID_VALUE;
	    }

	    state->value.val.lVal = state->value.val.lVal ^ state2.value.val.lVal;
	    freeData(state2);
	    continue;
	}

	/*
	** Logical and.
	*/
	if(match("&")) {
	    if(state->value.typeValue != LONG_VAL)
		return INVALID_VALUE;

	    if((rVal = exp2(&state2)) != SUCCESS) {
		freeData(state2);
		return rVal;
	    }
	    if(state2.value.typeValue != LONG_VAL) {
		freeData(state2);
		return INVALID_VALUE;
	    }

	    state->value.val.lVal = state->value.val.lVal & state2.value.val.lVal;
	    freeData(state2);
	    continue;
	}
	return SUCCESS;
    }
}

/*
** Handle the shift operations.
*/
static int exp2(State *state)
{
int	rVal;
State	state2;

    if((rVal = exp3(state)) != SUCCESS)
	return rVal;

    /*
    ** Initialize the state variable.
    */
    copyState(state, state2);

    while(TRUE) {
	/*
	** Shift left.
	*/
	if(match("<<")) {
	    if(state->value.typeValue != LONG_VAL)
		return INVALID_VALUE;

	    if((rVal = exp3(&state2)) != SUCCESS) {
		freeData(state2);
		return rVal;
	    }
	    if(state2.value.typeValue != LONG_VAL) {
		freeData(state2);
		return INVALID_VALUE;
	    }

	    state->value.val.lVal = state->value.val.lVal << state2.value.val.lVal;
	    freeData(state2);
	    continue;
	}

	/*
	** Shift right.
	*/
	if(match(">>")) {
	    if(state->value.typeValue != LONG_VAL)
		return INVALID_VALUE;

	    if((rVal = exp3(&state2)) != SUCCESS) {
		freeData(state2);
		return rVal;
	    }
	    if(state2.value.typeValue != LONG_VAL) {
		freeData(state2);
		return INVALID_VALUE;
	    }

	    state->value.val.lVal = state->value.val.lVal >> state2.value.val.lVal;
	    continue;
	}
	return SUCCESS;
    }
}

/*
** Add/Subtract
*/
static int exp3(State *state)
{
int	rVal;
State	state2;

    if((rVal = exp4(state)) != SUCCESS)
	return rVal;

    /*
    ** Initialize the state variable.
    */
    copyState(state, state2);

    while(TRUE) {
	/*
	** Addition.
	*/
	if(match("+")) {
	    if((rVal = exp4(&state2)) != SUCCESS) {
		freeData(state2);
		return rVal;
	    }

	    if(state->value.typeValue == LONG_VAL) {
		if(state2.value.typeValue == LONG_VAL) {
		    state->value.val.lVal = state->value.val.lVal + state2.value.val.lVal;
		    state->value.typeValue = LONG_VAL;
		} else {
		    state->value.val.dVal = state->value.val.lVal + state2.value.val.dVal;
		    state->value.typeValue = DOUBLE_VAL;
		}
	    } else {
		if(state2.value.typeValue == LONG_VAL) {
		    state->value.val.dVal = state->value.val.dVal + state2.value.val.lVal;
		    state->value.typeValue = DOUBLE_VAL;
		} else {
		    state->value.val.dVal = state->value.val.dVal + state2.value.val.dVal;
		    state->value.typeValue = DOUBLE_VAL;
		}
	    }
	    freeData(state2);
	    continue;
	}

	/*
	** Subtraction.
	*/
	if(match("-")) {
	    if((rVal = exp4(&state2)) != SUCCESS) {
		freeData(state2);
		return rVal;
	    }

	    if(state->value.typeValue == LONG_VAL) {
		if(state2.value.typeValue == LONG_VAL) {
		    state->value.val.lVal = state->value.val.lVal - state2.value.val.lVal;
		    state->value.typeValue = LONG_VAL;
		} else {
		    state->value.val.dVal = state->value.val.lVal - state2.value.val.dVal;
		    state->value.typeValue = DOUBLE_VAL;
		}
	    } else {
		if(state2.value.typeValue == LONG_VAL) {
		    state->value.val.dVal = state->value.val.dVal - state2.value.val.lVal;
		    state->value.typeValue = DOUBLE_VAL;
		} else {
		    state->value.val.dVal = state->value.val.dVal - state2.value.val.dVal;
		    state->value.typeValue = DOUBLE_VAL;
		}
	    }
	    freeData(state2);
	    continue;
	}
	return SUCCESS;
    }
}

/*
** Multiply/Divide
*/
static int exp4(State *state)
{
int	rVal;
State	state2;

    if((rVal = exp5(state)) != SUCCESS)
	return rVal;

    /*
    ** Initialize the state variable.
    */
    copyState(state, state2);

    while(TRUE) {
	/*
	** Multiplication.
	*/
	if(match("*")) {
	    if((rVal = exp5(&state2)) != SUCCESS) {
		freeData(state2);
		return rVal;
	    }

	    if(state->value.typeValue == LONG_VAL) {
		if(state2.value.typeValue == LONG_VAL) {
		    state->value.val.lVal = state->value.val.lVal * state2.value.val.lVal;
		    state->value.typeValue = LONG_VAL;
		} else {
		    state->value.val.dVal = state->value.val.lVal * state2.value.val.dVal;
		    state->value.typeValue = DOUBLE_VAL;
		}
	    } else {
		if(state2.value.typeValue == LONG_VAL) {
		    state->value.val.dVal = state->value.val.dVal * state2.value.val.lVal;
		    state->value.typeValue = DOUBLE_VAL;
		} else {
		    state->value.val.dVal = state->value.val.dVal * state2.value.val.dVal;
		    state->value.typeValue = DOUBLE_VAL;
		}
	    }
	    freeData(state2);
	    continue;
	}

	/*
	** Division
	*/
	if(match("/")) {
	    if((rVal = exp5(&state2)) != SUCCESS) {
		freeData(state2);
		return rVal;
	    }

	    if(state->value.typeValue == LONG_VAL) {
		if(state2.value.typeValue == LONG_VAL) {
		    state->value.val.lVal = state->value.val.lVal / state2.value.val.lVal;
		    state->value.typeValue = LONG_VAL;
		} else {
		    state->value.val.dVal = state->value.val.lVal / state2.value.val.dVal;
		    state->value.typeValue = DOUBLE_VAL;
		}
	    } else {
		if(state2.value.typeValue == LONG_VAL) {
		    state->value.val.dVal = state->value.val.dVal / state2.value.val.lVal;
		    state->value.typeValue = DOUBLE_VAL;
		} else {
		    state->value.val.dVal = state->value.val.dVal / state2.value.val.dVal;
		    state->value.typeValue = DOUBLE_VAL;
		}
	    }
	    freeData(state2);
	    continue;
	}

	/*
	** Modulues
	*/
	if(match("%")) {
	    if((rVal = exp5(&state2)) != SUCCESS) {
		freeData(state2);
		return rVal;
	    }

	    if(state->value.typeValue == LONG_VAL) {
		if(state2.value.typeValue == LONG_VAL) {
		    state->value.val.lVal = state->value.val.lVal % state2.value.val.lVal;
		    state->value.typeValue = LONG_VAL;
		} else {
		    state->value.typeValue = DOUBLE_VAL;
		    state->value.val.dVal = fmod(state->value.val.dVal, state2.value.val.dVal);
		}
	    } else {
		if(state2.value.typeValue == LONG_VAL) {
		    state->value.typeValue = DOUBLE_VAL;
		    state->value.val.dVal = fmod(state->value.val.dVal, state2.value.val.lVal);
		} else {
		    state->value.typeValue = DOUBLE_VAL;
		    state->value.val.dVal = fmod(state->value.val.dVal, state2.value.val.dVal);
		}
	    }
	    freeData(state2);
	    continue;
	}

	/*
	** No more matches at this level, then must be done.
	*/
	return SUCCESS;
    }
}

/*
** Unary ops
*/
static int exp5(State *state)
{
int rVal;

    /*
    ** Complement
    */
    if(match("~")) {
	if((rVal = exp6(state)) != SUCCESS)
	    return rVal;

	if(state->value.typeValue != LONG_VAL)
	    return INVALID_VALUE;

	state->value.val.lVal = ~state->value.val.lVal;
	return SUCCESS;
    }

    /*
    ** Not
    */
    if(match("!")) {
	if((rVal = exp6(state)) != SUCCESS)
	    return rVal;

	if(state->value.typeValue != LONG_VAL)
	    return INVALID_VALUE;

	state->value.val.lVal = !state->value.val.lVal;
	return SUCCESS;
    }

    /*
    ** Negate
    */
    if(match("-")) {
	if((rVal = exp6(state)) != SUCCESS)
	    return rVal;

	if(state->value.typeValue == LONG_VAL)
	    state->value.val.lVal = -state->value.val.lVal;
	else
	    state->value.val.dVal = -state->value.val.dVal;

	return SUCCESS;
    }

    /*
    ** Address of expression.
    */
    if(match("&")) {
	if((rVal = exp6(state)) != SUCCESS)
	    return rVal;

	state->value.val.lVal = state->addr;
	state->value.typeValue = LONG_VAL;
    }

    /*
    ** Dereference the expresssion.
    */
    if(match("*")) {
	if((rVal = exp5(state)) != SUCCESS)
	    return rVal;

fprintf(logFile, "Address Dereference Not yet implemented\n");
    }

    /*
    ** Allow nested parens.
    */
    if(match("(")) {
	if((rVal = exp1(state)) != SUCCESS)
	    return rVal;
	if(!match(")"))
	    return SYNTAX_ERROR;
	return SUCCESS;
    }

    return exp6(state);
}

/*
** Nesting
*/
static int exp6(State *state)
{
int	rVal;
State	state2;

    /*
    ** Initialize the state variable.
    */
    copyState(state, state2);

    /*
    ** Is the next token a literal?
    */
    if(isLiteral(state)) {
	rVal = SUCCESS;
    } else {
	rVal = primary(state);
    }

    while(TRUE) {

	/*
	** See if we have an array.
	*/
	if(match("[")) {
	    if((rVal = exp1(&state2)) != SUCCESS) {
		freeData(state2);
		return rVal;
	    }

	    if(state2.value.typeValue != LONG_VAL) {
		freeData(state2);
		return INVALID_VALUE;
	    }
	    if(!match("]")) {
		freeData(state2);
		return SYNTAX_ERROR;
	    }

	    /*
	    ** See if this is a string.
	    */
	    if(state->value.typeValue != PTR_VAL) {
		if(state->value.typeValue == STR_VAL) {
		    char   *data;

		    data = state->value.val.sVal;
		    state->value.typeValue = CHAR_VAL;
		    if(((int) state2.value.val.lVal < 0) ||
		      (state2.value.val.lVal >= strlen(data)))
			return INVALID_INDEX;

		    state->value.val.cVal = data[state2.value.val.lVal];
		    freeData(state2);
		    free(data);
		    return SUCCESS;
		}
		return SYNTAX_ERROR;
	    }

	    /*
	    ** Must be for a more complex array.
	    */
	    if((rVal = GetArray(state->module, state, &state2)) != SUCCESS) {
		freeData(state2);
		return rVal;
	    }
	    freeData(state2);
	    continue;
	}

	/*
	** While we find members of a name, keep getting them.
	*/
	if(match("->") || match(".")) {
	    char   *ptr;
	    if((ptr = isName()) == NULL) {
		return INVALID_NAME;
	    }
	    state2.value.typeValue = NAME_VAL;
	    state2.value.val.sVal = ptr;
	    if((rVal = GetName(state->module, state, &state2)) != SUCCESS) {
		freeData(state2);
		return rVal;
	    }
	    freeData(state2);
	    continue;
	}
	return SUCCESS;
    }
}

/*
** Primary name.
*/
static int primary(State *state)
{
int	rVal;
char   *ptr;

    /*
    ** If we do not match a name, we are in trouble.
    */
    if((ptr = isName()) == NULL) {
	if(isRegister(state))
	    return SUCCESS;
	return INVALID_NAME;
    }

    /*
    ** Find the primary name.
    */
    state->value.val.sVal = ptr;
    state->value.typeValue = NAME_VAL;
    if((rVal = GetName(state->module, state, NULL)) != SUCCESS) {
	return rVal;
    }

    return rVal;
}
