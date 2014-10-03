/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
** Structures and manifest constants for the expression analyiser.
*/

/*
** State return values.
*/
#define SUCCESS 	0   /* Success in requested function	*/
#define INVALID_VALUE	1   /* Invalid value given for state.	*/
#define SYNTAX_ERROR	2   /* Syntax error from parser 	*/
#define INVALID_NAME	3   /* Invalid name given		*/
#define NO_MORE_MEMBERS 4   /* No more elements in structure	*/
#define OUT_OF_CONTEXT	5   /* Request for information out of
			    ** retrievable context		*/
#define INVALID_INDEX	6   /* Index given too large		*/
#define INTERNAL_ERROR	7   /* Internal error			*/

/*
** State of the interpreter for finding how to get from a name to
** a variable.
*/
typedef struct _StructValue {
    struct _StructValue *next;	/* Pointer to next element  */
    char		*str;	/* Element name 	    */
} StructValue;

typedef struct {
    int     typeValue;	    /* Type of data				*/
    union {		    /* Data for item				*/
	ULONG	lVal;
        double  dVal;
        char    cVal;
	char   *sVal;
	StructValue *strVal;
    } val;
} Value;
/*
** Value of a variable to display.
*/
#define UNKNOWN_VAL 0
#define LONG_VAL    1	/* Use lVal */
#define DOUBLE_VAL  2	/* Use dVal */
#define CHAR_VAL    3	/* Use cVal */
#define STR_VAL     4	/* Use sVal */
#define PTR_VAL     5	/* Use sVal */
#define NAME_VAL    6	/* Use sVal - Name of some type. */
#define STRUCT_VAL  7	/* Not expected in support DLL */


typedef struct {
    struct _DebugModule *module; /* Handle of the debug module of the source.*/
    ULONG   baseEIP;        /* EIP for context of evaluating locals     */
    ULONG   baseEBP;        /* EBP for context of evaluating locals     */
    ULONG   addr;           /* Address of the variable                  */
    ULONG   elementSize;    /* Size of the member specified.		*/
    int     isStruct;	    /* Is the value a ptr to a structure?	*/
    Value   value;	    /* Data for item.				*/
    int     typeDataSize;   /* Size of the type data information.	*/
    void   *typeData;	    /* Aux data for use by the source module	*/
} State;

/*
** Find the requested source information based on certain information.
*/
typedef struct _DebugModule {
    void   *nextModule; /* Pointer to the next debug module.	    */
    char   *name;	/* Name as given by DosQueryModuleName	    */
    void   *AuxData;	/* Pointer for use by the support DLL	    */
    void   *ViewData;	/* Pointer used by the source code control  */
    time_t  fTimestamp; /* Time stamp of the module		    */
    ULONG   fileSize;	/* File size of the module		    */
    ULONG   MTE;	/* Module handle			    */
    ULONG   typeFlags;	/* Flags returned by DosQueryAppType	    */

    /*
    ** Module cleanup.	Free any support structures.
    */
    void    (* _System FreeModule)(
		       struct _DebugModule *module);	/* Module handle */

    /*
    ** Source functions.
    */
    int     (* _System FindSource)(	    /* 1 found / 0 - not found	 */
			struct _DebugModule *module,	/* Module handle */
			ULONG eipOffset,    /* EIP for function to find  */
			char *funcName,     /* Buffer for function name  */
			char *sourceName,   /* Buffer for source code	 */
			ULONG *lineNum);    /* Pointer to line number	 */

    ULONG   (* _System FindSourceLine)(     /* Return offset of file/line*/
			struct _DebugModule *module,	/* Module handle */
			int line,	    /* Line to find		 */
			char *fileName);    /* File name		 */

    ULONG   (* _System FindFuncAddr)(	    /* Return offset of function */
			struct _DebugModule *module,	/* Module handle */
			char *name);	    /* Function name.		 */

    /*
    ** Variable functions.
    */
    int     (* _System GetName)(    /* State return value from above	*/
			struct _DebugModule *module,	/* Module handle */
			State *state,	/* State information to retrieve.
					** Contains name of variable.
					*/
			State *state2); /* If !NULL: state2 is element of
					** structure given in state.
					*/


    int     (* _System GetArray)(	/* State return value from above */
			struct _DebugModule *module,	/* Module handle */
			State *state,	/* Name of array		*/
			State *state2); /* Index of element to retrieve */

    int     (* _System GetNumMembers)(	/* Return # of elements 0 if not
					** a structure
					*/
			struct _DebugModule *module,	/* Module handle */
			State *state);	/* Variable to query and program
					** state
					*/

    /*
    ** Get the name of the index'th structure element
    */
    int     (* _System GetMemberIndex)( /* State return value from above */
			struct _DebugModule *module,	/* Module handle */
			State *state,	/* Program state		 */
			int MemberIndex,/* Index of element to retrieve  */
			char *name);	/* Buffer to return name into	 */

    /*
    ** Get the address of a variable and it's type.
    */
} DebugModule;

/*
** Public access to debugger support specific routines.
*/
int _System isKnownModule(DebugModule *module,
			   int (* _System DispatchCommand)(int command),
			   DebugBuffer *buffer);
int _System DispatchCommand(int command);
int _System linkPriority(void);
