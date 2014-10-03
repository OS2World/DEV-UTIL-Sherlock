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

#pragma pack()
