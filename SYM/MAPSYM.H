/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
#ifndef DWORD
    typedef unsigned long DWORD;
#endif
#ifndef WORD
    typedef unsigned short WORD;
#endif

#pragma pack(1)
typedef struct	tag_mapdef {

    WORD    ppNextMap;
    BYTE    bFlags;
    BYTE    bReserved1;
    WORD    pSegEntry;
    WORD    cConsts;
    WORD    pConstDef;
    WORD    cSegs;
    WORD    ppSegDef;
    BYTE    cbMaxSym;
    BYTE    cbModName;
} MAPDEF;

typedef struct tag_endmapdef {
    WORD    ppNextMap;
    BYTE    release;
    BYTE    version;
} END_MAPDEF;

typedef struct tag_segdef {
    WORD    ppNextSeg;
    WORD    cSymbols;
    WORD    pSymDef;
    WORD    wReserved1;
    WORD    wReserved2;
    WORD    wReserved3;
    WORD    wReserved4;
    BYTE    bFlags;
    BYTE    bReserved1;
    WORD    ppLineDef;
    BYTE    bReserved2;
    BYTE    bReserved3;
    BYTE    cbSegName;
} SEGDEF;

typedef struct tag_symdef16 {
    WORD    wSymVal;
    BYTE    dbSymName;
} SYMDEF16;

typedef struct tag_symdef32 {
    DWORD   lSymVal;
    BYTE    dbSymName;
} SYMDEF32;

typedef struct tag_linedef {
    WORD    ppNextLine;
    WORD    wReserved1;
    WORD    pLines;
    WORD    wReserved2;
    WORD    cLines;
    BYTE    cbFileName;
} LINEDEF;

typedef struct tag_lineinf16 {
    WORD    wCodeOffset;
    WORD    dwFileOffset;
} LINEINF16;

typedef struct tag_lineinf32 {
    DWORD   lCodeOffset;
    WORD    dwFileOffset;
} LINEINF32;

/*
** Structures used by the DLL.
*/
typedef struct mysymdef16 {
    struct mysymdef16 *next;
    WORD    wSymVal;
    char    SymName[1];
} SymData16;

typedef struct mysymdef32 {
    struct mysymdef32 *next;
    DWORD   lSymVal;
    char    SymName[1];
} SymData32;

typedef struct tag_SegData {
    struct tag_SegData *next;		/* Pointer to next segment */
    SymData16	       *first16Symbol;	/* Pointer to first symbol */
    SymData32	       *first32Symbol;	/* Pointer to first symbol */
    char		name[1];	/* Name of the segment	   */
} SymSegmentData;

int _System SymFindSource(DebugModule *module, ULONG eipOffset,
			char *funcName, char *sourceName, ULONG *lineNum);
ULONG _System SymFindSourceLine(DebugModule *module, int line, char *fileName);
ULONG _System SymFindFuncAddr(DebugModule *module, char *funcName);

/*
** Global variables.
*/
DebugBuffer *debugBuffer;
#pragma pack()
