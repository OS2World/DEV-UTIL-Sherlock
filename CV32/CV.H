/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
**  Header file to read the Codeview information from an EXE file.
*/
#pragma pack(1)

#define sstModules	0x101
#define sstPublic	0x102
#define sstTypes	0x103
#define sstSymbols	0x104
#define sstSrcLines	0x105
#define sstLibraries	0x106
#define sstCompacted	0x108
#define sstSrcLnSeg	0x109

/*
** This is the header linkage structure.
*/
typedef struct {
    char    signature[4];
    long    offset;
} Header;


/*
** This is the DNT structure.
*/
typedef struct {
    unsigned short  sectionType;
    unsigned short  moduleIndex;
    signed long     offsetStart;
    unsigned short  sectionSize;
} SubSectionDictionary;


typedef struct {
    char	cbName;
    char	name[1];
} NAME;

/**************************************
**				      *
** Make up of the sstModules - 0x0101 *
**				      *
**************************************/
typedef struct {
    unsigned short  segment;
    unsigned short  offset;
    unsigned short  cbSeg;
    unsigned short  ovlNbr;	 /* this represents the first segment. */
    unsigned short  iLibraries;
    char	    cSeg;
    char	    reserved;
    char	    cbName;
    char	    name[1];
} ModulesDataEntry;

typedef struct {
    unsigned short  segment;
    unsigned long   offset;
    unsigned long   cbSeg;
    unsigned short  ovlNbr;	 /* this represents the first segment. */
    unsigned short  iLibraries;
    char	    cSeg;
    char	    reserved;
    char	    cbName;
    char	    name[1];
} ModulesDataEntry32;


/**************************************
**				      *
** sstPublics - 0x0102		      *
**				      *
**************************************/
typedef struct {
    unsigned short  offset;
    unsigned short  segment;
    unsigned short  type;
    unsigned char   cbName;
    char	    name[1];
} PublicsDataEntry;

typedef struct {
    unsigned long   offset;
    unsigned short  segment;
    unsigned short  type;
    unsigned char   cbName;
    char	    name[1];
} PublicsDataEntry32;


/**************************************
**				      *
** sstSrcLines - 0x0105 	      *
**  UCHAR  - Name Length	      *
**  UCHAR* - Name		      *
**  USHORT - count		      *
**				      *
** sstSrcLnSeg - 0x0109 	      *
**  UCHAR  - Name Length	      *
**  UCHAR* - Name		      *
**  USHORT - segment		      *
**  USHORT - count		      *
**				      *
**				      *
** Line offset pair information.      *
**************************************/
typedef struct {
    unsigned short  line;
    unsigned short  offset;
} LineOffsetEntry;

typedef struct {
    unsigned short  line;
    unsigned long   offset;
} LineOffsetEntry32;


/**************************************
**				      *
** sstLibraries - 0x0106	      *
**				      *
**************************************/
typedef struct {
    unsigned char   cbLibs;
    char	    Libs[1];
} LIB;

/**************************************
**				      *
** sstSymbols - 0x0104		      *
**				      *
**				      *
** Define the symbol types.	      *
**				      *
**				      *
** Block Start - 0x00 & 0x80	      *
**				      *
**************************************/
typedef struct {
    unsigned short  offset;
    unsigned short  length;
    unsigned char   cbName;
    unsigned char   name[1];
} BlockStart;

typedef struct {
    unsigned long   offset;
    unsigned short  length;
    unsigned char   cbName;
    unsigned char   name[1];
} BlockStart32;

/*
** BP-Relative symbol - 0x04 & 0x84
*/
typedef struct {
    unsigned short  offset;
    unsigned short  type;
    unsigned char   cbName;
    unsigned char   name[1];
} BPRelativeSymbol;

typedef struct {
    unsigned long   offset;
    unsigned short  type;
    unsigned char   cbName;
    unsigned char   name[1];
} BPRelativeSymbol32;

/*
**  Local (Data) Symbols - 0x05 & 0x85
*/
typedef struct {
    unsigned short  offset;
    unsigned short  segment;
    unsigned short  type;
    unsigned char   cbName;
    unsigned char   name[1];
} LocalSymbol;

typedef struct {
    unsigned long   offset;
    unsigned short  segment;
    unsigned short  type;
    unsigned char   cbName;
    unsigned char   name[1];
} LocalSymbol32;

/*
** Code Label - 0x0B & 0x8B
*/
typedef struct {
    unsigned short  offset;
    unsigned char   distance;
    unsigned char   cbName;
    unsigned char   name[1];
} CodeLabel;

typedef struct {
    unsigned long   offset;
    unsigned char   distance;
    unsigned char   cbName;
    unsigned char   name[1];
} CodeLabel32;

/*
** Register Symbol - 0x0D & 0x8D
*/
typedef struct {
    unsigned short  type;
    unsigned char   registerNum;
    unsigned char   cbName;
    unsigned char   name[1];
} RegisterSymbol;

/*
** Procedure Start - 0x01 & 0x81
*/
typedef struct {
    unsigned short  offset;
    unsigned short  type;
    unsigned short  procLength;
    unsigned short  debugStart;
    unsigned short  debugEnd;
    unsigned short  reserved;
    unsigned char   distance;
    unsigned char   cbName;
    unsigned char   name[1];
} ProcedureStart;

typedef struct {
    unsigned long   offset;
    unsigned short  typeIndex;
    unsigned short  procLength;
    unsigned short  debugStart;
    unsigned short  debugEnd;
    unsigned short  reserved;
    unsigned char   distance;
    unsigned char   cbName;
    unsigned char   name[1];
} ProcedureStart32;

/*
** Change Default Segment - 0x11
*/
typedef struct {
    unsigned short  segment;
    unsigned short  reserved;
} ChangeDefaultSegment;


/**************************************
**				      *
** sstTypes	- 0x0103	      *
** sstCompacted - 0x0108	      *
**				      *
**************************************/
#pragma pack()
