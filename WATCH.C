/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
**  Watch variables.
*/
#include    <stdio.h>
#include    <stdlib.h>
#include    <ctype.h>
#include    <string.h>
#include    <sys\stat.h>
#define     INCL_DOSSESMGR
#define     INCL_DOSEXCEPTIONS
#define     INCL_DOSPROCESS
#include    <os2.h>
#include    "debug.h"

#include    "Debugger.h"
#include    "SrcInter.h"
#include    "Source.h"
#include    "Watch.h"

/*
** Typedefs & structures
*/
typedef struct _Watchpoint {
    struct _Watchpoint *next;
    DebugModule        *module;
    char	       *expr;
} Watchpoint;

static Watchpoint *Watchpoints = NULL;

/*
** Evaluate an expression and display the result
*/
static void DisplayVariable(char *expr, DebugModule *module, ULONG eip, ULONG ebp)
{
int	rVal;
Value	value;

    switch(rVal = evaluate(expr, module, eip, ebp, &value)) {
	case SUCCESS:
	    fprintf(logFile, "%s = ", expr);
	    switch(value.typeValue) {
		case UNKNOWN_VAL:
		    fprintf(logFile, "UNKNOWN!\n");
		    break;
		case LONG_VAL:
		    fprintf(logFile, "%d (0x%08x)\n", value.val.lVal, value.val.lVal);
		    break;
		case DOUBLE_VAL:
		    fprintf(logFile, "%lf\n", value.val.dVal);
		    break;
		case CHAR_VAL:
		    fprintf(logFile, "'%c' (0x%02x)\n", value.val.cVal, value.val.cVal);
		    break;
		case STR_VAL:
		    fprintf(logFile, "(0x%08x) - \"%s\"\n", value.val.sVal, value.val.sVal);
		    break;
		case NAME_VAL:
		    fprintf(logFile, "NAME: \"%s\"", value.val.sVal);
		    break;
		case PTR_VAL:
		    fprintf(logFile, "PTR 0x%08x\n", value.val.lVal);
		    break;
		case STRUCT_VAL: {
		    StructValue *valueData;

		    for(valueData = value.val.strVal; valueData;
			valueData = valueData->next) {
			fprintf(logFile, "%s\n", valueData->str);
		    }
		    for(valueData = value.val.strVal; valueData;) {
			StructValue *killer;

			killer = valueData;
			valueData = valueData->next;
			free(killer->str);
			free(killer);
		    }
		    break;
		}
		default:
		    fprintf(logFile, "INTERNAL ERROR!  Type: %d\n", value.typeValue);
		    break;
	    }
	    break;
	case INVALID_VALUE:
	    fprintf(logFile, "INVALID VALUE\n");
	    break;
	case SYNTAX_ERROR:
	    fprintf(logFile, "SYNTAX ERROR\n");
	    break;
	case INVALID_NAME:
	    fprintf(logFile, "INVALID NAME\n");
	    break;
	case NO_MORE_MEMBERS:
	    fprintf(logFile, "NO MORE MEMBERS\n");
	    break;
	case OUT_OF_CONTEXT:
	    fprintf(logFile, "OUT OF CONTEXT\n");
	    break;
	case INVALID_INDEX:
	    fprintf(logFile, "INVALID INDEX\n");
	    break;
	case INTERNAL_ERROR:
	    fprintf(logFile, "INTERNAL ERROR\n");
	    break;
	default:
	    fprintf(logFile, "UNKNOWN ERROR! (%d)\n", rVal);
	    break;
    }
    return;
}

/*
** View a variable
*/
void ViewVariableCommand(char **ptrs)
{
    /*
    ** Make sure there is a second parameter.
    */
    if(ptrs[0] == NULL) {
	fprintf(logFile, "Please specify a parameter!\n");
        return;
    }

    DispatchCommand(DBG_C_ReadReg);
    DisplayVariable(ptrs[0], NULL,
		    Linearize(debugBuffer.EIP, debugBuffer.CS),
		    Linearize(debugBuffer.EBP, debugBuffer.SS));
    return;
}

/*
** Add a watchpoint to the list of watchpoints.
*/
void WatchCommand(char **ptrs)
{
int	i;
Watchpoint *wp;

    switch(tolower(ptrs[1][1])) {

	/*
	** Set a watchpoint.
	*/
	case 'p':   {
	    DebugModule *module;

	    /*
            ** Find the address of the variable.
            */
	    DispatchCommand(DBG_C_ReadReg);
	    module = FindModule(debugBuffer.MTE, NULL);

            /*
	    ** Connect it to the list.
	    */
	    if(Watchpoints) {
		for(i=0, wp=Watchpoints; wp->next; i++, wp=wp->next) ;
		wp->next = malloc(sizeof(Watchpoint));
		wp = wp->next;
	    } else {
		Watchpoints = wp = malloc(sizeof(Watchpoint));
	    }
	    wp->expr   = strdup(ptrs[0]);
	    wp->module = module;
	    wp->next   = NULL;
	    break;
	}

	/*
	** Clear a watchpoint.
	*/
	case 'c': {
	    Watchpoint *prior;
	    char *dummy;
	    int num;

            /*
            ** If we want to free all watch points, do it.
            */
            if(strcmp(ptrs[2], "*") == 0) {
                FreeAllWatchpoints();
                return;
            }

	    /*
	    ** Find the watch number, and then the watchpoint id.
            */
            i = strtol(ptrs[2], &dummy, 0);
	    prior = wp = Watchpoints;
	    for(i=0; wp && i<num; i++) {
		prior = wp;
		wp = wp->next;
	    }

	    /*
	    ** Make sure the watchpoint exists.
	    */
	    if(wp == NULL) {
		fprintf(logFile, "ILLEGAL WATCHPOINT NUMBER!\n");
		return;
	    }

	    /*
	    ** Remove the watchpoint from the list and from the debuggee.
	    */
	    if(wp == Watchpoints) {
		Watchpoints = wp->next;
            } else {
                prior->next = wp->next;
            }
	    free(wp->expr);
	    free(wp);
	    break;
	}

	/*
	** List all of the watchpoints.
	*/
	case 'l': {
	    for(i=0, wp=Watchpoints; wp; i++, wp=wp->next) {
		fprintf(logFile, "Watchpoint [%d]:(%s)\n",
			i, wp->expr);
	    }
	    break;
	}
    }
}

/*
** Print the value of all watchpoints.
*/
void DumpWatchpoints(void)
{
Watchpoint *wp;
int	    i;
ULONG	    eip, ebp;


    /*
    ** Make sure that there are variable to display.
    */
    if(wp == NULL)
	return;

    /*
    ** Get the current eip/ebp for the evaluation routine.
    */
    DispatchCommand(DBG_C_ReadReg);
    eip = Linearize(debugBuffer.EIP, debugBuffer.CS);
    ebp = Linearize(debugBuffer.EBP, debugBuffer.SS);

    /*
    ** Get the variables and display the values.
    */
    if(Watchpoints)
	fprintf(logFile, "Watched variables\n");
    for(wp = Watchpoints,i=0; wp; wp=wp->next, i++) {
	fprintf(logFile, "[%2d] ", i);
	DisplayVariable(wp->expr, wp->module, eip, ebp);
    }
}

/*
** Free all watchpoints.
*/
void FreeAllWatchpoints(void)
{
Watchpoint *wp, *next;

    for(wp=Watchpoints; wp; ) {
        next = wp->next;
	free(wp->expr);
        free(wp);
        wp = next;
    }
    Watchpoints = NULL;
}
