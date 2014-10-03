/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
**  Header file to read the IBM HLL debug information from an EXE file.
*/
#pragma pack(1)

/**********************************************
**					     **
** These structures are uses to describe the **
** structure of the debugging information    **
** within the executable file		     **
**					     **
**********************************************/
    /*
    ** This is the header linkage structure.
    */
    typedef struct {
	char	signature[4];
	long	offset;
    } HLLHeader;

    /*
    ** This structure preceeds the DNT structures.
    */
    typedef struct {
	unsigned short	res1;
	unsigned short	res2;
	unsigned long	numEntries;
    } SubSectionDictHeader;

    /*
    ** This is the DNT structure.
    */
    typedef struct {
	unsigned short	sectionType;
	unsigned short	moduleIndex;
	unsigned long	offsetStart;
	unsigned long	sectionSize;
    } SubSectionDictionary;

/**************************************
**				     **
** sstModules - 0x0101		     **
**				     **
**************************************/
#define sstModules	0x101
    typedef struct {
	unsigned short	segment;
	unsigned long	offset;
	unsigned long	cbSeg;
	unsigned short	ovlNbr;
	unsigned short	iLibraries;
	unsigned short	cSeg;
	unsigned short	res1;
	unsigned short	res2;
	char		cbName;
	char		name[1];
    } ModulesDataEntry;


/**************************************
**				     **
** sstPublics - 0x0102		     **
**				     **
**************************************/
#define sstPublic	0x102
    typedef struct {
	unsigned long	offset;
	unsigned short	segment;
	unsigned short	type;
	unsigned char	cbName;
	char		name[1];
    } PublicsDataEntry;


/**************************************
**				      *
** sstTypes	- 0x0103	      *
**				      *
**************************************/
#define sstTypes	0x103
#define sstCompacted	0x108

/**************************************
**				     **
** sstSymbols - 0x0104		     **
**				     **
**************************************/
#define sstSymbols	0x104

    /*
    ** Begin Block - 0x00
    */
    typedef struct {
	unsigned long	offset;
	unsigned short	length;
	unsigned char	cbName;
	unsigned char	name[1];
    } BlockStart;

    /*
    ** Procedure Start - 0x01
    */
    typedef struct {
	unsigned long	offset;
	unsigned short	type;
	unsigned long	procLength;
	unsigned short	prologueLength;
	unsigned long	prologueAndBody;
	unsigned short	reserved;
	unsigned char	nearFar;
	unsigned char	cbName;
	unsigned char	name[1];
    } BeginBlock;

    /*
    ** End - 0x02
    */
    /* typedef struct { } End; */

    /*
    ** BP-Relative symbol - 0x04
    */
    typedef struct {
	unsigned long	offset;
	unsigned short	type;
	unsigned char	cbName;
	unsigned char	name[1];
    } BPRelativeSymbol;

    /*
    **	Local (Data) Symbols - 0x05
    */
    typedef struct {
	unsigned long	offset;
	unsigned short	segment;
	unsigned short	type;
	unsigned char	cbName;
	unsigned char	name[1];
    } LocalSymbol;

    /*
    ** Code Label - 0x0B
    */
    typedef struct {
	unsigned long	offset;
	unsigned char	distance;
	unsigned char	cbName;
	unsigned char	name[1];
    } CodeLabel;

    /*
    ** Register Symbol - 0x0D
    */
    typedef struct {
	unsigned short	type;
	unsigned char	registerNum;
	unsigned char	cbName;
	unsigned char	name[1];
    } RegisterSymbol;

    /*
    ** Constant Symbol - 0x0E
    */
    typedef struct {
	unsigned short	type;
	unsigned char	lenValue;
    } ConstantSymbol;

    /*
    ** Secondary Entry - 0x0F
    */
    typedef struct {
	unsigned long	offset;
	unsigned short	typeIndex;
	unsigned long	procLength;
	unsigned short	prologueStart;
	unsigned long	prologuePlusBody;
	unsigned short	reserved;
	unsigned char	distance;
	unsigned char	cbName;
	unsigned char	name[1];
    } SecondaryEntry;

    /*
    ** Skip - 0x10
    */
    /* typedef struct { unsigned char data[1]; } Skip; */

    /*
    ** Change Default Segment - 0x11
    */
    typedef struct {
	unsigned short	segment;
	unsigned short	reserved;
    } ChangeDefaultSegment;

    /*
    ** User Defined Symbol - 0x12
    */
    typedef struct {
	unsigned short	type;
	unsigned char	cbName;
	unsigned char	name[1];
    } UserDefinedSymbol;

    /*
    ** Public Symbol - 0x13
    */
    typedef struct {
	unsigned long	offset;
	unsigned short	segment;
	unsigned short	type;
	unsigned char	cbName;
	unsigned char	name[1];
    } PublicSymbol;

    /*
    ** Member - 0x14
    */
    typedef struct {
	unsigned short	offset;
	unsigned char	cbName;
	unsigned char	name[1];
    } Member;

    /*
    ** Based - 0x15
    */
    typedef struct {
	unsigned short	offset;
	unsigned short	type;
	unsigned char	cbName;
	unsigned char	name[1];
    } Based;

    /*
    ** Tag - 0x16
    */
    typedef struct {
	unsigned short	type;
	unsigned char	cbName;
	unsigned char	name[1];
    } Tag;

    /*
    ** Table - 0x17
    */
    typedef struct {
	unsigned long	offset;
	unsigned short	segment;
	unsigned short	type;
	unsigned long	indexOffset;
	unsigned char	cbName;
	unsigned char	name[1];
    } Table;

    /*
    ** Map - 0x18
    */
    typedef struct {
	unsigned char	cbName;
	unsigned char	name[1];
    } Map;

    /*
    ** Compilable Unit Information - 0x40
    */
    typedef struct {
	unsigned char	compilerID;
	unsigned char	lenOpts;
	unsigned long	compilerOptions;
	DATETIME	timeStamp;
    } CompilableInfo;


/**************************************
**				      *
** sstLibraries - 0x0106	      *
**				      *
**************************************/
#define sstLibraries	0x106

    typedef struct {
	unsigned char	cbLibs;
	char		Libs[1];
    } LIB;

/**************************************
**				      *
** sstNewLineData - 0x010B	      *
**				      *
**************************************/
#define sstNewLineData	0x10b

typedef struct _tag_SourceLines {
    USHORT  lineNum;
    UCHAR   srcFileIndex;
    UCHAR   flags;
    ULONG   offset;
} SrcLine;

typedef struct _tag_StatementLines {
    ULONG   lineNum;
    ULONG   statementNum;
    ULONG   offset;
} Statement;

typedef struct _tag_SourceListLines {
    USHORT  lineNum;
    UCHAR   srcFileIndex;
    UCHAR   flags;
    ULONG   listLineNum;
    ULONG   listStatementNum;
    ULONG   offset;
} SrcState;

typedef union EntryData {
	SrcLine     *srcLines;
	Statement   *statementLines;
	SrcState    *srcStateLines;
} EntryData;

typedef struct {
    UCHAR   entryType;
    USHORT  numEntries;
    EntryData entryData;
    USHORT  numPathEntries;
    struct _tag_PathEntries {
	ULONG	offset;
	USHORT	pathCode;
    } *pathEntries;

    ULONG   startRecNum;
    ULONG   numPrimaries;
    ULONG   numSrcFiles;
    char   *fileNames[1];
} HLLLineData;

/*
** Define the structures use to hold the HLL data internally.
*/
typedef struct _HLLPublic {
    struct _HLLPublic *next;
    PublicsDataEntry  data;
} HLLPublic;

typedef struct _HLLModule {
    struct _HLLModule	*next;
    ModulesDataEntry	*module;
    HLLPublic		*public;
    char		*type;
    char		*symbols;
    USHORT              typeSize;
    USHORT              symbolSize;
    HLLLineData 	*newLineData;
} HLLModule;

typedef struct {
    char        tag[4];
    ULONG       dirOffset;
    char       *compactedData;
    USHORT      compactedSize;
    char      **libraries;
    HLLModule	*moduleData;
    char	*other;
} HLLAuxData;

typedef struct {
    HLLModule	*module;
    USHORT	typeIndex;
    SHORT	registerNum;
} HLLTypeData;

UCHAR *FindType(HLLTypeData *hllType, USHORT targetIndex);
int HLLGetBaseTypeSize(USHORT targetIndex);
int elementSize(State *state);
USHORT GetType(UCHAR *types);
int HLLGetValue(DebugModule *module, State *state);
int HLLGetRegisterValue(DebugModule *module, State *state);
int HLLGetNumber(UCHAR *types, ULONG *num);

int _System HLLFindSource(DebugModule *module, ULONG eipOffset,
			char *funcName, char *sourceName, ULONG *lineNum);
ULONG _System HLLFindSourceLine(DebugModule *module, int line, char *fileName);
ULONG _System HLLFindFuncAddr(DebugModule *module, char *funcName);
int _System HLLGetName(DebugModule *module, State *state, State *state2);
int _System HLLGetArray(DebugModule *module, State *state, State *state2);
int _System HLLGetNumMembers(DebugModule *module, State *state);
int _System HLLGetMemberIndex(DebugModule *module,
	State *state, int memberIndex, char *name);
int HLLGetMember(DebugModule *module, State *state, State *state2);

/*
** Manifest constants.
*/
#define BYTE_INDEX_IN_LVAL 0x100

/*
** Global variables.
*/
DebugBuffer *debugBuffer;
#pragma pack()
