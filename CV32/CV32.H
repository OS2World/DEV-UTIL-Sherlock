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
#pragma pack(1)
typedef struct _CVObject {
    struct _CVObject   *next;
    ULONG               base;
    ULONG               length;
} CVObject;

typedef struct {
    USHORT  segment;
    USHORT  count;
    char    *fileName;
    LineOffsetEntry32 *lineData;
} CVLineData;

typedef struct _CVPublic32 {
    struct _CVPublic32 *next;
    PublicsDataEntry32  data;
} CVPublic32;

typedef struct _CVModule {
    struct _CVModule   *next;
    ModulesDataEntry32 *module;
    CVPublic32         *public;
    char               *type;
    char               *symbols;
    USHORT              typeSize;
    USHORT              symbolSize;
    CVLineData         *lineData;
    CVLineData         *lineSegData;
} CVModule;

typedef struct {
    char        tag[4];
    ULONG       dirOffset;
    char       *compactedData;
    USHORT      compactedSize;
    char      **libraries;
    CVModule   *moduleData;
} CVAuxData;

typedef struct {
    CVModule   *module;
    USHORT	typeIndex;
    SHORT	registerNum;
} CVTypeData;
#pragma pack()

UCHAR *FindType(CVTypeData *cvType, USHORT targetIndex);
int CVGetBaseTypeSize(USHORT targetIndex);
int elementSize(State *state);
USHORT GetType(UCHAR *types);
int CVGetValue(DebugModule *module, State *state);
int CVGetRegisterValue(DebugModule *module, State *state);
int CVGetNumber(UCHAR *types, ULONG *num);

int _System CVFindSource(DebugModule *module, ULONG eipOffset,
			char *funcName, char *sourceName, ULONG *lineNum);
ULONG _System CVFindSourceLine(DebugModule *module, int line, char *fileName);
ULONG _System CVFindFuncAddr(DebugModule *module, char *funcName);
int _System CVGetName(DebugModule *module, State *state, State *state2);
int _System CVGetArray(DebugModule *module, State *state, State *state2);
int _System CVGetNumMembers(DebugModule *module, State *state);
int _System CVGetMemberIndex(DebugModule *module,
	State *state, int memberIndex, char *name);
int _System CVGetMember(DebugModule *module, State *state, State *state2);

/*
** Manifest constants.
*/
#define BYTE_INDEX_IN_LVAL 0x100

/*
** Global variables.
*/
DebugBuffer *debugBuffer;
