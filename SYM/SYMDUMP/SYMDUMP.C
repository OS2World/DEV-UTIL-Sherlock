/*
** Dump a .SYM
*/
#include    <os2.h>
#include    <stdio.h>
#include    <stdlib.h>
#include    <memory.h>
#include    "mapsym.h"

FILE *symFile;

void dumpSymbols(FILE *symFile,
	    long base, long pConstDef, WORD cConsts,
	    int is32Bit);
void dumpMap(FILE *symFile, MAPDEF *map);
void dumpLineDefs(FILE *symFile, WORD ppLineDef, int is32Bit);

int main(int argc, char **argv)
{
MAPDEF	map;
long	base;

    /*
    ** Make sure the number of parameters is correct.
    */
    if(argc != 2) {
	fprintf(stderr, "Usage: SYMDUMP file.sym\n");
	exit(1);
    }

    /*
    ** Try to open the file.
    */
    if((symFile = fopen(argv[1], "rb")) == NULL) {
	fprintf(stderr, "Unable to open %s\n", argv[1]);
	exit(1);
    }

    /*
    ** Dump the first record
    */
    memset(&map, 0, sizeof(map));
    do {
	dumpMap(symFile, &map);
	fseek(symFile, ((long) map.ppNextMap) << 4, SEEK_SET);
    } while(map.ppNextMap != 0);

    /*
    ** Close the file
    */
    fclose(symFile);
    return 0;
}

void dumpMap(FILE *symFile, MAPDEF *map)
{
WORD	i;
long	base;
SEGDEF	segdef;
char	buff[255];

    /*
    ** Dump the map header.
    */
    base = map->ppNextMap << 4;
    fread(map, sizeof(MAPDEF), 1, symFile);
    if(map->ppNextMap == 0)
	return;
    fprintf(stderr, "ppNextMap  : %04x\n", map->ppNextMap);
    fprintf(stderr, "bFlags     : %02x\n", map->bFlags);
    fprintf(stderr, "bReserved1 : %02x\n", map->bReserved1);
    fprintf(stderr, "pSegEntry  : %04x\n", map->pSegEntry);
    fprintf(stderr, "cConsts    : %04x\n", map->cConsts);
    fprintf(stderr, "pConstDef  : %04x\n", map->pConstDef);
    fprintf(stderr, "cSegs      : %04x\n", map->cSegs);
    fprintf(stderr, "ppSegDef   : %04x\n", map->ppSegDef);
    fprintf(stderr, "cbMaxSym   : %02x\n", map->cbMaxSym);
    fprintf(stderr, "cbModName  : %02x\n", map->cbModName);
    fread(buff, map->cbModName, 1, symFile);
    buff[map->cbModName] = '\0';
    fprintf(stderr, "ModName    : %s\n", buff);

    /*
    ** Dump the constant symbols
    */
    fprintf(stderr, "\n\nCONSTANTS\n");
    dumpSymbols(symFile, base,
		(long) map->pConstDef, (WORD) map->cConsts,
		map->bFlags & 0x01);

    /*
    ** Dump each segment.
    */
    base = ((DWORD) (map->ppSegDef)) << 4;
    fprintf(stderr, "SYMBOLS\n");
    for(i=0; i<map->cSegs; i++) {
	fseek(symFile, base, SEEK_SET);
	fread(&segdef, sizeof(SEGDEF), 1, symFile);

	fprintf(stderr, "\n\nSegment\n");
	fprintf(stderr, "ppNextSeg  : %04x\n", segdef.ppNextSeg);
	fprintf(stderr, "cSymbols   : %04x\n", segdef.cSymbols);
	fprintf(stderr, "pSymDef    : %04x\n", segdef.pSymDef);
	fprintf(stderr, "wReserved1 : %04x\n", segdef.wReserved1);
	fprintf(stderr, "wReserved2 : %04x\n", segdef.wReserved2);
	fprintf(stderr, "wReserved3 : %04x\n", segdef.wReserved3);
	fprintf(stderr, "wReserved4 : %04x\n", segdef.wReserved4);
	fprintf(stderr, "bFlags     : %02x\n", segdef.bFlags);
	fprintf(stderr, "bReserved1 : %02x\n", segdef.bReserved1);
	fprintf(stderr, "ppLineDef  : %04x\n", segdef.ppLineDef);
	fprintf(stderr, "bReserved2 : %02x\n", segdef.bReserved2);
	fprintf(stderr, "bReserved3 : %02x\n", segdef.bReserved3);
	fprintf(stderr, "cbSegName  : %02x\n", segdef.cbSegName);
	fread(buff, segdef.cbSegName, 1, symFile);
	buff[segdef.cbSegName] = '\0';
	fprintf(stderr, "SegName    : %s\n", buff);

	dumpSymbols(symFile,
		    base, segdef.pSymDef, segdef.cSymbols,
		    segdef.bFlags & 0x01);
	dumpLineDefs(symFile, segdef.ppLineDef, segdef.bFlags & 0x01);
	base = ((DWORD) (segdef.ppNextSeg)) << 4;
    }
}

void dumpSymbols(FILE *symFile,
	    long base, long pConstDef, WORD cConsts,
	    int is32Bit)
{
SYMDEF16    sym16;
SYMDEF32    sym32;
char	    buff[255];
WORD	    i;
BYTE	    cbName;
DWORD	    val;
WORD	   *ptrs;

fprintf(stderr, "cConsts = %d\n", cConsts);
    fseek(symFile, base + pConstDef, SEEK_SET);
    ptrs = malloc(cConsts * sizeof(WORD));
    fread(ptrs, cConsts, sizeof(WORD), symFile);
    fprintf(stderr, "%30s\t%s\n", "Name", "Value");
    for(i=0; i<cConsts; i++) {
	fseek(symFile, base + ((DWORD) ptrs[i]), SEEK_SET);
	if(is32Bit) {
	    fread(&sym32, sizeof(SYMDEF32), 1, symFile);
	    cbName = sym32.dbSymName;
	    val    = sym32.lSymVal;
	} else {
	    fread(&sym16, sizeof(SYMDEF16), 1, symFile);
	    cbName = sym16.dbSymName;
	    val    = (DWORD) sym16.wSymVal;
	}
	fread(buff, cbName, 1, symFile);
	buff[cbName] = '\0';
	fprintf(stderr, "%4d %30s\t%08lx\n", i+1, buff, val);
    }
}

void dumpLineDefs(FILE *symFile, WORD ppLineDef, int is32Bit)
{
WORD	    i;
long	    base;
LINEINF32  *line32;
LINEINF16  *line16;
LINEDEF     line;
char	    buff[255];

    if(ppLineDef == 0)
	return;
    base = ftell(symFile);
    fseek(symFile, ppLineDef << 4, SEEK_SET);
    fread(&line, sizeof(LINEDEF), 1, symFile);
    fprintf(stderr, "ppNextLine : %04x\n", line.ppNextLine);
    fprintf(stderr, "wReserved1 : %04x\n", line.wReserved1);
    fprintf(stderr, "pLines     : %04x\n", line.pLines);
    fprintf(stderr, "wReserved2 : %04x\n", line.wReserved2);
    fprintf(stderr, "cLines     : %02x\n", line.cLines);
    fprintf(stderr, "cbFileName : %02x\n", line.cbFileName);
    fread(buff, 1, line.cbFileName, symFile);
    buff[line.cbFileName] = '\0';
    fprintf(stderr, "FileName   : %s\n", buff);

    fseek(symFile, base + line.pLines, SEEK_SET);
    if(is32Bit) {
	line32 = malloc(line.cLines * sizeof(LINEINF32));
	fread(line32, line.cLines, sizeof(LINEINF32), symFile);
    } else {
	line16 = malloc(line.cLines * sizeof(LINEINF16));
	fread(line16, line.cLines, sizeof(LINEINF16), symFile);
    }

fprintf(stderr, "is32Bit = %d\n", is32Bit);
    for(i=0; i<line.cLines; i++) {
	if(is32Bit)
	    fprintf(stderr, "%08x\t%4d\n",
		    line32[i].lCodeOffset, line32[i].dwFileOffset);
	else
	    fprintf(stderr, "%04x\t%4d\n",
		    line16[i].wCodeOffset, line16[i].dwFileOffset);
    }
}
