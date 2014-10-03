/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
** Display the source for the given source file and line number.
*/
#include    <stdio.h>
#include    <stdlib.h>
#include    <ctype.h>
#include    <string.h>
#include    <sys\stat.h>

#define     INCL_DOSPROCESS
#include    <os2.h>
#include    "debug.h"

#include    "Debugger.h"
#include    "SrcInter.h"
#include    "Source.h"
#include    "SrcDisp.h"

typedef struct {
    ULONG   addr;
    int     is32BitSegment:1;
    int     is32BitOperands:1;
    int     is32BitAddress:1;
    char   *ptr;
    ULONG   ptr_offset;
    char    reg[32];
    char    rm[32];
    char    temp[32];
} DumpState;

/*
** Data for disassembly.
*/
static char *dword_reg[] = { "EAX","ECX","EDX","EBX","ESP","EBP","ESI","EDI"};
static char *word_reg[]  = {  "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"};
static char *byte_reg[]  = {  "AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"};
static char *drm_reg[]	 = { "EAX","ECX","EDX","EBX","ESP","EBP","ESI","EDI"};
static char *rm_reg[]	 = { "BX+SI", "BX+DI", "BP+SI", "BP+DI",
			     "SI",    "DI",    "BP",	"BX"};
static char *seg_reg[]	 = {  "ES", "CS", "SS", "DS"};
static char *bw_ptr[]	 = { "BYTE PTR", "WORD PTR" };
static char *dbw_ptr[]	 = { "BYTE PTR", "DWORD PTR" };

/*
** Function prototypes for the local functions.
*/
static int  DispatchByte(UCHAR *ptr, DumpState *state);
static int  reg_mod(int is8BitOp, UCHAR *pData, DumpState *state);
static int  byte_reg_mod(UCHAR *pData, DumpState *state);
static int  word_reg_mod(UCHAR *pData, DumpState *state);
static int  type00(UCHAR *ptr, DumpState *state);
static int  type0F(UCHAR *ptr, DumpState *state);
static int  type40(UCHAR *ptr, DumpState *state);
static int  type60(UCHAR *ptr, DumpState *state);
static int  type70(UCHAR *ptr, DumpState *state);
static int  type80(UCHAR *ptr, DumpState *state);
static int  type90(UCHAR *ptr, DumpState *state);
static int  typeA0(UCHAR *ptr, DumpState *state);
static int  typeB0(UCHAR *ptr, DumpState *state);
static int  typeC0(UCHAR *ptr, DumpState *state);
static int  typeD0(UCHAR *ptr, DumpState *state);
static int  typeE0(UCHAR *ptr, DumpState *state);
static int  typeF0(UCHAR *ptr, DumpState *state);
static int  coprosseser(UCHAR *ptr, DumpState *state);
static int  cotypeD8(UCHAR *ptr, DumpState *state);
static int  cotypeD9(UCHAR *ptr, DumpState *state);
static int  cotypeDA(UCHAR *ptr, DumpState *state);
static int  cotypeDB(UCHAR *ptr, DumpState *state);
static int  cotypeDC(UCHAR *ptr, DumpState *state);
static int  cotypeDD(UCHAR *ptr, DumpState *state);
static int  cotypeDE(UCHAR *ptr, DumpState *state);
static int  cotypeDF(UCHAR *ptr, DumpState *state);

/*
** Disassemable the code starting at addr for the length specified.
*/
void DumpAsm(ULONG addr, ULONG length, int is32Bit)
{
int	    i;
DumpState   state;

    /*
    ** Fill a buffer with the code from the program.
    */
    state.ptr = calloc(length, 1);
    debugBuffer.Addr   = addr;
    debugBuffer.Len    = length;
    debugBuffer.Buffer = (ULONG) state.ptr;
    if((i=DispatchCommand(DBG_C_ReadMemBuf)) != DBG_N_Success) {
	return;
    }
    state.ptr = (UCHAR *) debugBuffer.Buffer;
    state.is32BitSegment  = is32Bit;
    state.is32BitOperands = is32Bit;
    state.is32BitAddress  = is32Bit;
    state.addr	  = addr;
    state.ptr_offset = 0;

    /*
    ** Dump the code.
    */
    for(state.ptr_offset=0; state.ptr_offset<length;) {
	DispatchByte(&state.ptr[state.ptr_offset], &state);
    }

    /*
    ** Clean up.
    */
    free(state.ptr);
    return;
}

/*
** Dispatch the current byte for decode.
*/
static int DispatchByte(UCHAR *ptr, DumpState *state)
{
ULONG	length;

    switch(ptr[0] & 0xf0) {
	case 0x00:
	case 0x10:
	case 0x20:
	case 0x30:
	    length = type00(ptr, state);
	    break;
	case 0x40:
	case 0x50:
	    length = type40(ptr, state);
	    break;
	case 0x60:
	    length = type60(ptr, state);
	    break;
	case 0x70:
	    length = type70(ptr, state);
	    break;
	case 0x80:
	    length = type80(ptr, state);
	    break;
	case 0x90:
	    length = type90(ptr, state);
	    break;
	case 0xa0:
	    length = typeA0(ptr, state);
	    break;
	case 0xb0:
	    length = typeB0(ptr, state);
	    break;
	case 0xc0:
	    length = typeC0(ptr, state);
	    break;
	case 0xd0:
	    length = typeD0(ptr, state);
	    break;
	case 0xe0:
	    length = typeE0(ptr, state);
	    break;
	case 0xf0:
	    length = typeF0(ptr, state);
	    break;
    }
    state->ptr_offset += length;
    return length;
}

/************************************************
**					       **
**  print out the opcode with no/1/2 arguments **
**					       **
************************************************/
static void opcode0(DumpState *state, char *opcode)
{
ULONG	addr, hiWord, loWord;

    addr = state->addr + state->ptr_offset;
    if(state->is32BitSegment) {
	fprintf(logFile, "%08x  %s\n", addr, opcode);
	return;
    }
    loWord = addr & 0xffff;
    hiWord = addr >> 16;
    hiWord = (hiWord << 3) | 0x0007;
    fprintf(logFile, "%04x:%04x %s\n", hiWord, loWord, opcode);
}
static void opcode1(DumpState *state, char *opcode, char *op1)
{
ULONG	addr, hiWord, loWord;

    addr = state->addr + state->ptr_offset;
    if(state->is32BitSegment) {
	fprintf(logFile, "%08x  %s\t%s\n", addr, opcode, op1);
	return;
    }
    loWord = addr & 0xffff;
    hiWord = addr >> 16;
    hiWord = (hiWord << 3) | 0x0007;
    fprintf(logFile, "%04x:%04x %s\t%s\n", hiWord, loWord, opcode, op1);
}
static void opcode2(DumpState *state, char *opcode, char *op1, char *op2)
{
ULONG	addr, hiWord, loWord;

    addr = state->addr + state->ptr_offset;
    if(state->is32BitSegment) {
	fprintf(logFile, "%08x  %s\t%s,%s\n", addr, opcode, op1, op2);
	return;
    }
    loWord = addr & 0xffff;
    hiWord = addr >> 16;
    hiWord = (hiWord << 3) | 0x0007;
    fprintf(logFile, "%04x:%04x %s\t%s,%s\n", hiWord, loWord, opcode, op1, op2);
}
static void opcode3(DumpState *state, char *opcode, char *op1, char *op2, char *op3)
{
ULONG	addr, hiWord, loWord;

    addr = state->addr + state->ptr_offset;
    if(state->is32BitSegment) {
	fprintf(logFile, "%08x  %s\t%s,%s,%s\n", addr, opcode, op1, op2, op3);
	return;
    }
    loWord = addr & 0xffff;
    hiWord = addr >> 16;
    hiWord = (hiWord << 3) | 0x0007;
    fprintf(logFile, "%04x:%04x %s\t%s,%s,%s\n", hiWord, loWord, opcode, op1, op2, op3);
}

static ULONG get_immediate(UCHAR *ptr, int *length, int isByte, int is32Bit)
{
    if(isByte) {
	*length = 1;
	return (int) ((char) ptr[0]);
    }
    if(is32Bit) {
	*length = 4;
	return ptr[0]	  | ptr[1] << 8|
	       ptr[2]<<16 | ptr[3] <<24;
    }
    *length = 2;
    return (int) ((short) ptr[0] | ptr[1] << 8);
}

static ULONG get_address(UCHAR *ptr, ULONG *offset, DumpState *state)
{
    if(state->is32BitAddress) {
	*offset = ptr[0]     | ptr[1]<<8 |
		  ptr[2]<<16 | ptr[3]<<24;
	return 4;
    }
    *offset = ptr[0] | ptr[1]<<8;
    return 2;
}

/************************************************
**					       **
** Support routine to decode the rm/reg field. **
**					       **
************************************************/
static int reg_mod(int is8BitOp, UCHAR *pData, DumpState *state)
{
    if(!is8BitOp)
	return byte_reg_mod(pData, state);

    return word_reg_mod(pData, state);
}

static int word_reg_mod(UCHAR *pData, DumpState *state)
{
int offset,reg_mem,reg,mod;
int length = 1;

    reg_mem =  pData[0] & 0x07;
    reg     = (pData[0] & 0x38) >> 3;
    mod     = (pData[0] & 0xC0) >> 6;
    if(state->is32BitOperands)
	sprintf(state->reg, "%s", dword_reg[reg]);
    else
	sprintf(state->reg, "%s", word_reg[reg]);
    if((reg_mem == 0x04) && (mod != 3) && state->is32BitAddress) {
	int ss, index, base;

	/*
	** Get the base, index and scalling factor.
	*/
	length++;
	base  =  pData[1] & 0x07;
	index = (pData[1] & 0x38) >> 3;
	switch((pData[1] & 0xC0) >> 6) {
	    case 0: ss = 1; break;
	    case 1: ss = 2; break;
	    case 2: ss = 4; break;
	    case 3: ss = 8; break;
	}
	if((mod == 0) && (base == 5)) {
	    int offset;

	    offset = pData[2]	  | pData[3]<<8 |
		     pData[4]<<16 | pData[5]<<24;

	    if(state->is32BitAddress)
		sprintf(state->rm, "%s [(%s) * %d + 0x%08x]", state->is32BitOperands ?
			dbw_ptr[1] : bw_ptr[1],
			dword_reg[index], ss, offset);
	    else
		sprintf(state->rm, "%s [(%s) * %d + 0x%08x]", state->is32BitOperands ?
			dbw_ptr[1] : bw_ptr[1],
			dword_reg[index], ss, offset);
	    return length + 4;
	}
	switch(mod) {
	    case 0: offset = 0;
		    break;
	    case 1: offset = pData[2];
		    length += 1;
		    break;
	    case 2: if(state->is32BitAddress) {
			offset = pData[2]     | pData[3]<<8 |
				 pData[4]<<16 | pData[5]<<24;
			length += 4;
		    } else {
			offset = pData[2] | pData[3]<<8;
			length += 2;
		    }
		    break;
	}
	if(state->is32BitAddress)
	    sprintf(state->rm, "%s [%s + %d*(%s) + 0x%08x]", state->is32BitOperands ?
			dbw_ptr[1] : bw_ptr[1],
		    dword_reg[base], ss, dword_reg[index], offset);
	else
	    sprintf(state->rm, "%s [%s + %d*(%s) + 0x%08x]", state->is32BitOperands ?
			dbw_ptr[1] : bw_ptr[1],
		    dword_reg[base], ss, dword_reg[index], offset);
	return length;
    }
    switch(mod) {
        case 0: {
	    if(reg_mem == 5)	{
		if(state->is32BitAddress) {
		    offset = pData[1]	  | pData[2]<< 8 |
			     pData[3]<<16 | pData[4]<<24;
		    length += 4;
		    sprintf(state->rm, "%s [0x%08x]", state->is32BitOperands ?
			    dbw_ptr[1] : bw_ptr[1], offset);
		} else {
		    offset = pData[1] | pData[2] << 8;
		    if(offset & 0x8000)
			offset |= 0xffff0000;
		    length += 2;
		    sprintf(state->rm, "%s [0x%04x]", state->is32BitOperands ?
			    dbw_ptr[1] : bw_ptr[1], offset);
		}
		break;
	    }
	    if(state->is32BitAddress) {
		sprintf(state->rm, "%s [%s]", state->is32BitOperands ?
			dbw_ptr[1] : bw_ptr[1], drm_reg[reg_mem]);
	    } else {
		sprintf(state->rm, "%s [%s]", state->is32BitOperands ?
			dbw_ptr[1] : bw_ptr[1], rm_reg[reg_mem]);
	    }
            break;
        }
        case 1: {
	    offset = (int) ((char) pData[1]);
	    if(state->is32BitAddress)
		sprintf(state->rm, "%s [%s %+#x]", state->is32BitOperands ?
			dbw_ptr[1] : bw_ptr[1], drm_reg[reg_mem], offset);
	    else
		sprintf(state->rm, "%s [%s %+#x]", state->is32BitOperands ?
			dbw_ptr[1] : bw_ptr[1], rm_reg[reg_mem], offset);
            length++;
            break;
        }
	case 2: {
	    if(state->is32BitAddress) {
		offset = pData[1]     | pData[2]<< 8 |
			 pData[3]<<16 | pData[4]<<24;
		length += 4;
		sprintf(state->rm, "%s [%s %+#x]", state->is32BitOperands ?
			dbw_ptr[1] : bw_ptr[1], drm_reg[reg_mem], offset);
	    } else {
		offset = pData[1] | pData[2] << 8;
		if(offset & 0x8000)
		    offset |= 0xffff0000;
		length += 2;
		sprintf(state->rm, "%s [%s %+#x]", state->is32BitOperands ?
			dbw_ptr[1] : bw_ptr[1], rm_reg[reg_mem], offset);
	    }
            break;
        }
	case 3: {
	    if(state->is32BitOperands)
		sprintf(state->rm,"%s", dword_reg[reg_mem]);
	    else
		sprintf(state->rm,"%s", word_reg[reg_mem]);
            break;
        }
    }
    return length;
}

static int byte_reg_mod(UCHAR *pData, DumpState *state)
{
int offset,reg_mem,reg,mod;
int length = 1;

    reg_mem =  pData[0] & 0x07;
    reg     = (pData[0] & 0x38) >> 3;
    mod     = (pData[0] & 0xC0) >> 6;

    sprintf(state->reg, "%s", byte_reg[reg]);
    if((reg_mem == 0x04) && (mod != 3) && state->is32BitAddress) {
	int ss, index, base;

	/*
	** Get the base, index and scalling factor.
	*/
	length++;
	base  =  pData[1] & 0x07;
	index = (pData[1] & 0x38) >> 3;
	switch((pData[1] & 0xC0) >> 6) {
	    case 0: ss = 1; break;
	    case 1: ss = 2; break;
	    case 2: ss = 4; break;
	    case 3: ss = 8; break;
	}
	if((mod == 0) && (base == 5)) {
	    int offset;

	    offset = pData[2]	  | pData[3]<<8 |
		     pData[4]<<16 | pData[5]<<24;

	    if(state->is32BitAddress)
		sprintf(state->rm, "%s [(%s) * %d + 0x%08x]",
			bw_ptr[0], drm_reg[index], ss, offset);
	    else
		sprintf(state->rm, "%s [(%s) * %d + 0x%08x]",
			bw_ptr[0], rm_reg[index], ss, offset);
	    return length + 4;
	}
	switch(mod) {
	    case 0: offset = 0;
		    break;
	    case 1: offset = pData[2];
		    length += 1;
		    break;
	    case 2: if(state->is32BitAddress) {
			offset = pData[2]     | pData[3]<<8 |
				 pData[4]<<16 | pData[5]<<24;
			length += 4;
		    } else {
			offset = pData[2] | pData[3]<<8;
			length += 2;
		    }
		    break;
	}
	if(state->is32BitAddress)
	    sprintf(state->rm, "%s [%s + %d*(%s) + 0x%08x]",
			bw_ptr[0], drm_reg[base], ss, drm_reg[index], offset);
	else
	    sprintf(state->rm, "%s [%s + %d*(%s) + 0x%08x]",
			bw_ptr[0], rm_reg[base], ss, rm_reg[index], offset);
	return length;
    }
    switch(mod) {
        case 0: {
	    if(reg_mem == 5)	{
		if(state->is32BitAddress) {
		    offset = pData[1]	  | pData[2]<< 8 |
			     pData[3]<<16 | pData[4]<<24;
		    length += 4;
		    sprintf(state->rm, "%s [0x%08x]",
			    bw_ptr[0], offset);
		} else {
		    offset = pData[1] | pData[2] << 8;
		    if(offset & 0x8000)
			offset |= 0xffff0000;
		    length += 2;
		    sprintf(state->rm, "%s [0x%04x]",
			    bw_ptr[0], offset);
		}
		break;
	    }
	    if(state->is32BitAddress) {
		sprintf(state->rm, "%s [%s]",
			bw_ptr[0], drm_reg[reg_mem]);
	    } else {
		sprintf(state->rm, "%s [%s]",
			bw_ptr[0], rm_reg[reg_mem]);
	    }
            break;
        }
        case 1: {
	    offset = (int) ((char) pData[1]);
	    if(state->is32BitAddress)
		sprintf(state->rm, "%s [%s %+#x]",
			bw_ptr[0], drm_reg[reg_mem], offset);
	    else
		sprintf(state->rm, "%s [%s %+#x]",
			bw_ptr[0], rm_reg[reg_mem], offset);
	    length++;
	    break;
        }
	case 2: {
	    if(state->is32BitAddress) {
		offset = pData[1]     | pData[2]<< 8 |
			 pData[3]<<16 | pData[4]<<24;
		length += 4;
		sprintf(state->rm, "%s [%s %+#x]",
			bw_ptr[0], drm_reg[reg_mem], offset);
	    } else {
		offset = pData[1] | pData[2] << 8;
		if(offset & 0x8000)
		    offset |= 0xffff0000;
		length += 2;
		sprintf(state->rm, "%s [%s %+#x]",
			bw_ptr[0], rm_reg[reg_mem], offset);
	    }
            break;
        }
	case 3: {
	    sprintf(state->rm,"%s", byte_reg[reg_mem]);
            break;
        }
    }
    return length;
}

/**************************************
**				     **
** Routines to disassemble the code. **
**				     **
**************************************/

static int type00(UCHAR *ptr, DumpState *state)
{
char   *opcode,
       *op1,
       *op2;

int byte,
    index,
    length,
    operation,
    type;

    operation = *ptr;
    byte = (operation & 1) == 0;
    type = operation & 0x07;
    if(type >= 6)   {
        index = (operation >> 3) & 0x03;
        switch (operation)   {
            case    0x06:
            case    0x0E:
            case    0x16:
            case    0x1E:   {
		opcode1(state, "PUSH", seg_reg[index]);
                break;
            }
            case    0x07:
	    case    0x17:
            case    0x1F:   {
		opcode1(state, "POP", seg_reg[index]);
                break;
            }
	    case    0x0F:
		return type0F(ptr, state);
	    case    0x26:
            case    0x2E:
            case    0x36:
            case    0x3E:   {
		opcode1(state, "SEG", seg_reg[index]);
                break;
            }
            case    0x27:   {
		opcode0(state, "DAA");
                break;
            }
            case    0x2F:   {
		opcode0(state, "DAS");
                break;
            }
            case    0x37:   {
		opcode0(state, "AAA");
                break;
            }
            case    0x3F:   {
		opcode0(state, "AAS");
                break;
            }
        }
	return 1;
    }
    type = operation / 0x08;
    switch(type) {
	case 0x00:  opcode = "ADD"; break;
	case 0x01:  opcode =  "OR"; break;
	case 0x02:  opcode = "ADC"; break;
	case 0x03:  opcode = "SBB"; break;
	case 0x04:  opcode = "AND"; break;
	case 0x05:  opcode = "SUB"; break;
	case 0x06:  opcode = "XOR"; break;
	case 0x07:  opcode = "CMP"; break;
    }

    if((operation & 0x04) == 4)  {
	index = get_immediate(ptr+1, &length, byte, state->is32BitOperands);
	length++;
	if(byte)    {
	    op1 = "AL";
	} else {
	    if(state->is32BitOperands) {
		op1 = "EAX";
	    } else {
		op1 = "AX";
	    }
        }
	sprintf(state->reg, "0x%08x", index);
	op2 = state->reg;
    } else {
	length = 1 + reg_mod(ptr[0]&1, ptr+1, state);
	op1    = ((operation &	2) == 0) ? state->rm  : state->reg;
	op2    = ((operation &	2) == 0) ? state->reg : state->rm;
    }
    opcode2(state, opcode, op1, op2);
    return length;
}

static int type0F(UCHAR *ptr, DumpState *state)
{
ULONG	offset;
int	index;
int	length;
int	tmp;
char   *opcode,
       *op1,
       *op2;


    index = (ptr[2] & 0x38) >> 3;
    switch(ptr[1]) {
	case 0x00:  tmp = state->is32BitOperands;
		    state->is32BitOperands = 0;
		    length = 2 + word_reg_mod(ptr+2, state);
		    state->is32BitOperands = tmp;
		    switch(index) {
			case 0: opcode = "SLDT"; break;
			case 1: opcode = "STR";  break;
			case 2: opcode = "LLDT"; break;
			case 3: opcode = "LTR";  break;
			case 4: opcode = "VERR"; break;
			case 5: opcode = "VERW"; break;
		    }
		    opcode1(state, opcode, state->rm);
		    break;

	case 0x01:  tmp = state->is32BitOperands;
		    state->is32BitOperands = 0;
		    length = 2 + word_reg_mod(ptr+2, state);
		    state->is32BitOperands = tmp;
		    switch(index) {
			case 0: opcode = "SGDT"; break;
			case 1: opcode = "SIDT"; break;
			case 2: opcode = "LGDT"; break;
			case 3: opcode = "LIDT"; break;
			case 4: opcode = "SMSW"; break;
			case 6: opcode = "LMSW"; break;
		    }
		    opcode1(state, opcode, state->rm);
		    break;

	case 0x02:
	case 0x03:  length = 2 + word_reg_mod(ptr+2, state);
		    if(ptr[1] == 0x02)
			opcode = "LAR";
		    else
			opcode = "LSL";
		    opcode2(state, opcode, state->reg, state->rm);
		    break;

	case 0x06:  length = 2;
		    opcode0(state, "CLTS");
		    break;

	case 0x08:  length = 2;
		    opcode0(state, "INVD");
		    break;

	case 0x09:  length = 2;
		    opcode0(state, "WBINVD");
		    break;

	case 0x20:
	case 0x22:  length = 2 + word_reg_mod(ptr+2, state);
		    sprintf(state->reg, "CR%d", index);
		    if(ptr[1] == 0x20) {
			op1 = state->rm;
			op2 = state->reg;
		    } else {
			op1 = state->reg;
			op2 = state->rm;
		    }
		    opcode2(state, "MOV", op1, op2);
		    break;

	case 0x21:
	case 0x23:  length = 2 + word_reg_mod(ptr+2, state);
		    sprintf(state->reg, "DR%d", index);
		    if(ptr[1] == 0x21) {
			op1 = state->rm;
			op2 = state->reg;
		    } else {
			op1 = state->reg;
			op2 = state->rm;
		    }
		    opcode2(state, "MOV", op1, op2);
		    break;

	case 0x24:
	case 0x26:  length = 2 + word_reg_mod(ptr+2, state);
		    opcode = "MOV";
		    sprintf(state->reg, "TR%d", index);
		    if(ptr[1] == 0x24) {
			op1 = state->rm;
			op2 = state->reg;
		    } else {
			op1 = state->reg;
			op2 = state->rm;
		    }
		    opcode2(state, opcode, op1, op2);
		    break;

	case 0x80: case 0x81: case 0x82: case 0x83:
	case 0x84: case 0x85: case 0x86: case 0x87:
	case 0x88: case 0x89: case 0x8A: case 0x8B:
	case 0x8C: case 0x8D: case 0x8E: case 0x8F:
		    switch(ptr[1] & 0x0f) {
			case 0x00:  opcode = "JO";   break;
			case 0x01:  opcode = "JNO";  break;
			case 0x02:  opcode = "JB";   break;
			case 0x03:  opcode = "JAE";  break;
			case 0x04:  opcode = "JE";   break;
			case 0x05:  opcode = "JNE";  break;
			case 0x06:  opcode = "JBE";  break;
			case 0x07:  opcode = "JA";;  break;
			case 0x08:  opcode = "JS";   break;
			case 0x09:  opcode = "JNS";  break;
			case 0x0A:  opcode = "JP";   break;
			case 0x0B:  opcode = "JNP";  break;
			case 0x0C:  opcode = "JL";   break;
			case 0x0D:  opcode = "JGE";  break;
			case 0x0E:  opcode = "JLE";  break;
			case 0x0F:  opcode = "JG";   break;
		    }
		    if(state->is32BitAddress) {
			offset = ptr[2]     | ptr[3]<<8 |
				 ptr[4]<<16 | ptr[5]<<24;
			sprintf(state->reg, "$ + 0x%08x", offset);
			length = 6;
		    } else {
			offset = ptr[2] | ptr[3]<<8;
			sprintf(state->reg, "$ + 0x%04x", offset);
			length = 4;
		    }
		    opcode1(state, opcode, state->reg);
		    break;

	case 0x90: case 0x91: case 0x92: case 0x93:
	case 0x94: case 0x95: case 0x96: case 0x97:
	case 0x98: case 0x99: case 0x9A: case 0x9B:
	case 0x9C: case 0x9D: case 0x9E: case 0x9F:
		    switch(ptr[1]) {
			case 0x90:  opcode = "SETO";   break;
			case 0x91:  opcode = "SETNO";  break;
			case 0x92:  opcode = "SETB";   break;
			case 0x93:  opcode = "SETAE";  break;
			case 0x94:  opcode = "SETE";   break;
			case 0x95:  opcode = "SETNE";  break;
			case 0x96:  opcode = "SETBE";  break;
			case 0x97:  opcode = "SETA";   break;
			case 0x98:  opcode = "SETS";   break;
			case 0x99:  opcode = "SETNS";  break;
			case 0x9A:  opcode = "SETP";   break;
			case 0x9B:  opcode = "SETNP";  break;
			case 0x9C:  opcode = "SETL";   break;
			case 0x9D:  opcode = "SETGE";  break;
			case 0x9E:  opcode = "SETLE";  break;
			case 0x9F:  opcode = "SETG";   break;
		    }
		    length = 2 + byte_reg_mod(ptr+2, state);
		    opcode1(state, opcode, state->rm);
		    break;

	case 0xA0: case 0xA1: case 0xA8: case 0xA9:
		    if(ptr[1] & 0x01)
			opcode = "POP";
		    else
			opcode = "PUSH";
		    if(ptr[1] & 0x08)
			op1 = "GS";
		    else
			op1 = "FS";
		    opcode1(state, opcode, op1);
		    length = 2;
		    break;

	case 0xA3:  // BT
	case 0xAB:  // BTS
	case 0xB3:  // BTR
	case 0xBB:  // BTC
		    switch((ptr[1] & 0x38) >> 3) {
			case 0x04:  opcode = "BT"; break;
			case 0x05:  opcode = "BTS"; break;
			case 0x06:  opcode = "BTR"; break;
			case 0x07:  opcode = "BTC"; break;
		    }
		    length = 2 + reg_mod(1, ptr+2, state);
		    opcode2(state, opcode, state->rm, state->reg);
		    break;

	case 0xA4:  // SHLD    Ed, reg32, data8
	case 0xAC:  // SHRD    Ed, reg32, data8
		    length = 2 + reg_mod(1, ptr+2, state);
		    if(ptr[1] == 0xA4)
			opcode = "SHLD";
		    else
			opcode = "SHRD";
		    sprintf(state->temp, "%d", ptr[length]);
		    length++;
		    opcode3(state, opcode, state->rm, state->reg, state->temp);
		    break;


	case 0xA5:  // SHLD    Ed, reg32, CL
	case 0xAD:  // SHRD    Ed, reg32, CL
		    length = 2 + reg_mod(1, ptr+2, state);
		    if(ptr[1] == 0xA5)
			opcode = "SHLD";
		    else
			opcode = "SHRD";
		    opcode3(state, opcode, state->rm, state->reg, "CL");
		    break;

	case 0xAF:  // IMUL    reg32, Ed
		    length = 2 + reg_mod(1, ptr+2, state);
		    opcode2(state, "IMUL", state->reg, state->rm);
		    break;

	case 0xB0:  // CMPXCHG
	case 0xB1:  length = 2 + reg_mod(ptr[1] & 0x01, ptr+2, state);
		    opcode2(state, "CMPXCHG", state->rm, state->reg);
		    break;

	case 0xB2:  // LSS  reg32, Ea
	case 0xB4:  // LFS  reg32, Ea
	case 0xB5:  // LGS  reg32, Ea
		    length = 2 + reg_mod(1, ptr+2, state);
		    switch(ptr[1]) {
			case 0xB2: opcode = "LSS"; break;
			case 0xB4: opcode = "LFS"; break;
			case 0xB5: opcode = "LGS"; break;
		    }
		    opcode2(state, opcode, state->reg, state->rm);
		    break;

	case 0xBA:  /* BT, BTS, BTR, BTC */
		    switch(index) {
			case 0x04:  opcode = "BT"; break;
			case 0x05:  opcode = "BTS"; break;
			case 0x06:  opcode = "BTR"; break;
			case 0x07:  opcode = "BTC"; break;
		    }
		    length = 2 + reg_mod(1, ptr+2, state);
		    sprintf(state->reg, "%d", ptr[length]);
		    length++;
		    opcode2(state, opcode, state->rm, state->reg);
		    break;

	case 0xB6:  // MOVZX
	case 0xB7:  // MOVZX
	case 0xBE:  // MOVSX
	case 0xBF:  // MOVSX
		    if((ptr[1] == 0xB6) || (ptr[1] == 0xB7))
			opcode = "MOVZX";
		    else
			opcode = "MOVSX";
		    length = 2 + reg_mod(1, ptr+2, state);
		    strcpy(state->temp, state->reg);
		    if(ptr[1] & 0x01) {
			tmp = state->is32BitOperands;
			state->is32BitOperands = 0;
			reg_mod(1, ptr+2, state);
			state->is32BitOperands = tmp;
		    } else {
			reg_mod(0, ptr+2, state);
		    }
		    opcode2(state, opcode, state->temp, state->rm);
		    break;

	case 0xBC:  // BSF
	case 0xBD:  // BSR
		    if(ptr[1] == 0xBC)
			opcode = "BSF";
		    else
			opcode = "BSR";
		    length = 2 + reg_mod(1, ptr+2, state);
		    opcode2(state, opcode, state->reg, state->rm);
		    break;

	case 0xC0:
	case 0xC1:  length = 2 + reg_mod(ptr[1] & 0x01, ptr+2, state);
		    opcode2(state, "XADD", state->rm, state->reg);
		    break;

	case 0xC8: case 0xC9: case 0xCA: case 0xCB:
	case 0xCC: case 0xCD: case 0xCE: case 0xCF:
		    opcode1(state, "BSWAP", dword_reg[ptr[1] & 0x07]);
		    length = 2;
		    break;
    }
    return length;
}

static int type40(UCHAR *ptr, DumpState *state)
{
char   *opcode;
UCHAR	operation, reg;

    operation = (UCHAR) (((*ptr) >> 3) & 3);
    reg = (UCHAR) ((*ptr) & 0x07);
    switch(operation)    {
	case 0x00:  { opcode = "INC";  break; }
	case 0x01:  { opcode = "DEC";  break; }
	case 0x02:  { opcode = "PUSH"; break; }
	case 0x03:  { opcode = "POP";  break; }
    }
    if(state->is32BitOperands)
	opcode1(state, opcode, dword_reg[reg]);
    else
	opcode1(state, opcode, word_reg[reg]);
    return 1;
}

static int type60(UCHAR *ptr, DumpState *state)
{
int	length;
int	t;
ULONG  *pLong;
USHORT *pShort;

    switch(ptr[0] & 0x0f) {
	case 0x00:  opcode0(state, "PUSHAD"); length = 1; break;
	case 0x01:  opcode0(state, "POPAD");  length = 1; break;
	case 0x02:  length = 1 + reg_mod(1, ptr+1, state);
		    opcode2(state, "BOUND", state->reg, state->rm);
		    break;
	case 0x03:  t = state->is32BitOperands;
		    state->is32BitOperands = 0;
		    length = 1 + reg_mod(1, ptr+1, state);
		    state->is32BitOperands = t;
		    opcode2(state, "ARPL", state->rm, state->reg);
		    break;
	case 0x04:  opcode1(state, "SEG", "FS"); length = 1; break;
	case 0x05:  opcode1(state, "SEG", "GS"); length = 1; break;
	case 0x06:  state->is32BitOperands = ! state->is32BitOperands;
		    opcode0(state, "'OPSIZE'");
		    state->ptr_offset++;
		    DispatchByte(ptr+1, state);
		    length = 1;
		    state->ptr_offset--;
		    state->is32BitOperands = ! state->is32BitOperands;
		    break;
	case 0x07:  state->is32BitAddress = ! state->is32BitAddress;
		    opcode0(state, "'ADDR'");
		    state->ptr_offset++;
		    length = 1 + DispatchByte(ptr+1, state);
		    state->ptr_offset--;
		    state->is32BitAddress = ! state->is32BitAddress;
		    break;
	case 0x08:  if(state->is32BitOperands) {
			length = 5;
			pLong = (ULONG *) &ptr[1];
			sprintf(state->temp, "0x%08x", *pLong);
			opcode1(state, "PUSHD", state->temp);
		    } else {
			length = 3;
			pShort = (USHORT *) &ptr[1];
			sprintf(state->temp, "0x%04x", *pShort);
			opcode1(state, "PUSHW", state->temp);
		    }
		    break;
	case 0x09:
	case 0x0B:  length = 1 + reg_mod(ptr[0] & 0x02, ptr+1, state);
		    if(state->is32BitOperands) {
			pLong = (ULONG *) &ptr[length];
			sprintf(state->temp, "0x%08x", *pLong);
			length += 4;
		    } else {
			pShort = (USHORT *) &ptr[length];
			sprintf(state->temp, "0x%04x", *pShort);
			length += 2;
		    }
		    opcode3(state, "IMUL", state->reg, state->rm, state->temp);
		    break;
	case 0x0A:  length = 2;
		    sprintf(state->temp, "0x%02x", (char) ptr[1]);
		    opcode1(state, "PUSH", state->temp);
		    break;
	case 0x0C:  opcode0(state, "INSB"); length = 1; break;
	case 0x0D:  if(state->is32BitOperands)
			opcode0(state, "INSD");
		    else
			opcode0(state, "INSW");
		    length = 1;
		    break;
	case 0x0E:  opcode0(state, "OUTSB"); length = 1; break;
	case 0x0F:  if(state->is32BitOperands)
			opcode0(state, "OUTSD");
		    else
			opcode0(state, "OUTSW");
		    length = 1;
		    break;

    }
    return length;
}

static int type70(UCHAR *ptr, DumpState *state)
{
char   *opcode;

    sprintf(state->temp,"$ 0x%02x", (int) ((char) ptr[1]));
    switch(ptr[0] & 0x0f) {
	case 0x00:  opcode = "JO";   break;
	case 0x01:  opcode = "JNO";  break;
	case 0x02:  opcode = "JB";   break;
	case 0x03:  opcode = "JAE";  break;
	case 0x04:  opcode = "JE";   break;
	case 0x05:  opcode = "JNE";  break;
	case 0x06:  opcode = "JBE";  break;
	case 0x07:  opcode = "JA";;  break;
	case 0x08:  opcode = "JS";   break;
	case 0x09:  opcode = "JNS";  break;
	case 0x0A:  opcode = "JP";   break;
	case 0x0B:  opcode = "JNP";  break;
	case 0x0C:  opcode = "JL";   break;
	case 0x0D:  opcode = "JGE";  break;
	case 0x0E:  opcode = "JLE";  break;
	case 0x0F:  opcode = "JG";   break;
    }
    opcode1(state, opcode, state->temp);
    return 2;
}

static int type80(UCHAR *ptr, DumpState *state)
{
int length,
    imm_dat,
    operation,
    size;

char   *opcode;
char   *op1;
char   *op2;
unsigned int byte;

    operation = *ptr & 0x0f;
    byte = (operation & 1) == 0;
    switch(operation)   {
        case 0x00:
        case 0x01:
        case 0x02:
	case 0x03:  operation = (ptr[1] & 0x38) >> 3;
		    switch(operation)	{
			case 0x00:  opcode = "ADD";  break;
			case 0x01:  opcode = "OR ";  break;
			case 0x02:  opcode = "ADC";  break;
			case 0x03:  opcode = "SBB";  break;
			case 0x04:  opcode = "AND";  break;
			case 0x05:  opcode = "SUB";  break;
			case 0x06:  opcode = "XOR";  break;
			case 0x07:  opcode = "CMP";  break;
		    }
		    length = 1 + reg_mod(ptr[0] & 0x01, ptr+1, state);
		    if(ptr[0] & 0x02)
			imm_dat = get_immediate(ptr+length, &size, 1, 0);
		    else
			imm_dat = get_immediate(ptr+length, &size,
				   !(ptr[0] & 0x01), state->is32BitOperands);
		    length += size;
		    sprintf(state->temp, "0x%08x", imm_dat);
		    opcode2(state, opcode, state->rm, state->temp);
		    break;
        case 0x04:
	case 0x05:  opcode = "TEST";
		    length = 1 + reg_mod(ptr[0]&0x01, ptr+1, state);
		    opcode2(state, opcode, state->rm, state->reg);
		    break;
        case 0x06:
	case 0x07:  opcode = "XCHG";
		    length = 1 + reg_mod(ptr[0]&0x01, ptr+1, state);
		    opcode2(state, opcode, state->reg, state->rm);
		    break;
        case 0x08:
        case 0x09:
        case 0x0A:
	case 0x0B:  opcode = "MOV";
		    length = 1 + reg_mod(ptr[0]&0x01, ptr+1, state);
		    if((ptr[0] & 0x02) == 0)	{
			op1 = state->rm;
			op2 = state->reg;
		    } else {
			op1 = state->reg;
			op2 = state->rm;
		    }
		    opcode2(state, opcode, op1, op2);
		    break;
        case 0x0C:
	case 0x0E:  opcode = "MOV";
		    length = 1 + word_reg_mod(ptr+1, state);
		    if((ptr[0] & 0x02) == 0)	{
			op1 = state->rm;
			op2 = seg_reg[(ptr[1] & 0x18) >> 3];
		    } else {
			op1 = seg_reg[(ptr[1] & 0x18) >> 3];
			op2 = state->rm;
		    }
		    opcode2(state, opcode, op1, op2);
		    break;
	case 0x0D:  opcode = "LEA";
		    length = 1 + word_reg_mod(ptr+1, state);
		    opcode2(state, opcode, state->reg, state->rm);
		    break;
	case 0x0F:  opcode = "POP";
		    length = 1 + word_reg_mod(ptr+1, state);
		    opcode1(state, opcode, state->rm);
		    break;
    }
    return length;
}

static int type90(UCHAR *ptr, DumpState *state)
{
int	length = 1;
ULONG  *pLong;
USHORT *pShort;
ULONG	addr;

    switch(ptr[0] & 0x0f) {
	case 0x00:  opcode0(state, "NOP"); length = 1; break;
	case 0x01:
	case 0x02:
	case 0x03:
	case 0x04:
	case 0x05:
	case 0x06:
	case 0x07:  if(state->is32BitOperands)
			opcode2(state, "XCHG", "EAX", dword_reg[ptr[0] & 0x07]);
		    else
			opcode2(state, "XCHG",	"AX",  word_reg[ptr[0] & 0x07]);
		    break;
	case 0x08:  opcode0(state, state->is32BitOperands ? "CBDE" : "CBW"); break;
	case 0x09:  opcode0(state, state->is32BitOperands ? "CDQ" : "CWD");  break;
	case 0x0A:  if(state->is32BitAddress) {
			length = 7;
			pLong = (ULONG *) &ptr[1];
			pShort = (USHORT *) &ptr[5];
			addr = *pLong;
			sprintf(state->temp, "%04x:%08x", *pShort, *pLong);
		    } else {
			length = 5;
			pShort = (USHORT *) &ptr[1];
			addr = *pShort;
			sprintf(state->temp, "%04:%04x", pShort[0], pShort[1]);
		    }
		    addr = addr + state->addr + state->ptr_offset + length;
		    opcode1(state, "CALL", state->temp);
		    break;
	case 0x0B:  opcode0(state, "WAIT"); break;
	case 0x0C:  opcode0(state, state->is32BitOperands ? "PUSHFD" : "PUSHF"); break;
	case 0x0D:  opcode0(state, state->is32BitOperands ? "POPFD"  : "POPF");  break;
	case 0x0E:  opcode0(state, "SAHF"); break;
	case 0x0F:  opcode0(state, "LAHF"); break;
    }
    return length;
}

static int typeA0(UCHAR *ptr, DumpState *state)
{
int	length;
char   *op1, *op2;
ULONG  *pLong;
USHORT *pShort;

    switch(ptr[0] & 0x0f) {
	case 0x00:
	case 0x01:
	case 0x02:
	case 0x03:
		    if(state->is32BitAddress) {
			pLong = (ULONG *) &ptr[1];
			sprintf(state->temp, "[0x%08x]", *pLong);
			length = 5;
		    } else {
			pShort = (USHORT *) &ptr[1];
			sprintf(state->temp, "[0x%04x]", *pShort);
			length = 3;
		    }
		    switch(ptr[0] & 0x03) {
			case 0: op1 = "AL";
				op2 = state->temp;
				break;
			case 1: op1 = state->is32BitOperands ? "EAX" : "AX";
				op2 = state->temp;
				break;
			case 2: op2 = "AL";
				op1 = state->temp;
				break;
			case 3: op2 = state->is32BitOperands ? "EAX" : "AX";
				op1 = state->temp;
				break;
		    }
		    opcode2(state, "MOV", op1, op2);
		    break;
	case 0x04:  opcode0(state, "MOVSB"); length = 1; break;
	case 0x05:  opcode0(state, state->is32BitOperands ? "MOVSD" : "MOVSW"); length = 1; break;
	case 0x06:  opcode0(state, "CMPSB"); length = 1; break;
	case 0x07:  opcode0(state, state->is32BitOperands ? "CMPSD" : "CMPSW"); length = 1; break;
	case 0x08:  length = 2;
		    sprintf(state->temp, "0x%02x", ptr[1]);
		    opcode2(state, "TEST", "AL", state->temp);
		    break;
	case 0x09:  if(state->is32BitOperands) {
			length = 5;
			pLong = (ULONG *) &ptr[1];
			sprintf(state->temp, "0x%08x", *pLong);
			opcode2(state, "TEST", "EAX", state->temp);
		    } else {
			length = 3;
			pShort = (USHORT *) &ptr[1];
			sprintf(state->temp, "0x%04x", *pShort);
			opcode2(state, "TEST", "AX", state->temp);
		    }
		    break;
	case 0x0A:  opcode0(state, "STOSB"); length = 1; break;
	case 0x0B:  opcode0(state, state->is32BitOperands ? "STOSD" : "STOSW"); length = 1; break;
	case 0x0C:  opcode0(state, "LODSB"); length = 1; break;
	case 0x0D:  opcode0(state, state->is32BitOperands ? "LODSD" : "LODSW"); length = 1; break;
	case 0x0E:  opcode0(state, "SCASB"); length = 1; break;
	case 0x0F:  opcode0(state, state->is32BitOperands ? "SCASD" : "SCASW"); length = 1; break;
    }
    return length;
}

static int typeB0(UCHAR *ptr, DumpState *state)
{
ULONG  *pLong;
USHORT *pShort;

    if(ptr[0] & 0x08) {
	if(state->is32BitOperands) {
	    pLong = (ULONG *) &ptr[1];
	    sprintf(state->temp, "0x%08x", *pLong);
	    opcode2(state, "MOV", dword_reg[ptr[0] & 0x07], state->temp);
	    return 5;
	}
	pShort = (USHORT *) &ptr[1];
	sprintf(state->temp, "0x%04x", *pShort);
	opcode2(state, "MOV", word_reg[ptr[0] & 0x07], state->temp);
	return 3;
    }
    sprintf(state->temp, "0x%02x", ptr[1]);
    opcode2(state, "MOV", byte_reg[ptr[0] & 0x07], state->temp);
    return 2;
}

static int typeC0(UCHAR *ptr, DumpState *state)
{
char   *opcode;
USHORT *pShort;
ULONG  *pLong;
int	length = 1;

    switch(ptr[0] & 0x0f) {
	case 0x03: case 0x0B:
		    opcode0(state, ptr[0] & 0x08 ? "RETF" : "RET"); break;
	case 0x02: case 0x0A:
		    pShort = (USHORT *) &ptr[1];
		    sprintf(state->temp, "0x%04x", *pShort);
		    opcode1(state, "RET", state->temp);
		    length = 3;
		    break;
	case 0x04: case 0x05:
		    opcode = ((ptr[0] & 0x01) == 0) ? "LES" : "LDS";
		    length = 1 + word_reg_mod(ptr+1, state);
		    opcode2(state, opcode, state->reg, state->rm);
		    break;
	case 0x06: case 0x07:
		    length = 1 + reg_mod(ptr[0] & 1, ptr+1, state);
		    if(ptr[0] & 0x01) {
			if(state->is32BitOperands) {
			    pLong = (ULONG *) &ptr[length];
			    sprintf(state->temp, "0x%08x", *pLong);
			    length = 5;
			} else {
			    pShort = (USHORT *) &ptr[length];
			    sprintf(state->temp, "0x%04x", *pShort);
			    length = 3;
			}
		    } else {
			sprintf(state->temp, "0x%02x", ptr[length]);
			length = 2;
		    }
		    opcode2(state, "MOV", state->rm, state->temp);
		    break;
	case 0x08:  opcode = "ENTER";
		    sprintf(state->reg, "0x%04x", ptr[length] | ptr[length+1] << 8);
		    sprintf(state->rm,	"0x%02x", ptr[length+2]);
		    length += 3;
		    opcode2(state, opcode, state->reg, state->rm);
		    break;
	case 0x09:  opcode = "LEAVE";
		    opcode0(state, opcode);
		    length = 1;
		    break;
	case 0x0C:  opcode = "INT";
		    opcode1(state, opcode, "3");
		    length = 1;
		    break;
	case 0x0D:  sprintf(state->temp, "0x%02x", ptr[1]);
		    opcode1(state, "INT", state->temp);
		    length = 2;
		    break;
	case 0x0E:  opcode0(state, "INTO");
		    length = 1;
		    break;
	case 0x0F:  opcode0(state, "IRET");
		    length = 1;
		    break;
	case 0x00:
	case 0x01:  length = 1 + reg_mod(ptr[0] & 1, ptr+1, state);
		    switch(ptr[1] >> 3 & 0x07) {
			case 0: opcode = "ROL"; break;
			case 1: opcode = "ROR"; break;
			case 2: opcode = "RCL"; break;
			case 3: opcode = "RCR"; break;
			case 4: opcode = "SHL"; break;
			case 5: opcode = "SHR"; break;
			case 6: opcode = "???"; break;
			case 7: opcode = "SAR"; break;
		    }
		    sprintf(state->temp, "%d", ptr[length]);
		    length++;
		    opcode2(state, opcode, state->rm, state->temp);
		    break;
    }
    return length;
}

static int typeD0(UCHAR *ptr, DumpState *state)
{
int	length = 1;
char   *opcode;

    switch(ptr[0] & 0x0f) {
	case 0x00:
	case 0x01:  length = 1 + reg_mod(ptr[0] & 1, ptr+1, state);
		    switch(ptr[1] >> 3 & 0x07) {
			case 0: opcode = "ROL"; break;
			case 1: opcode = "ROR"; break;
			case 2: opcode = "RCL"; break;
			case 3: opcode = "RCR"; break;
			case 4: opcode = "SHL"; break;
			case 5: opcode = "SHR"; break;
			case 6: opcode = "???"; break;
			case 7: opcode = "SAR"; break;
		    }
		    opcode2(state, opcode, state->rm, "1");
		    break;
	case 0x02:
	case 0x03:  length = 1 + reg_mod(ptr[0] & 1, ptr+1, state);
		    switch(ptr[1] >> 3 & 0x07) {
			case 0: opcode = "ROL"; break;
			case 1: opcode = "ROR"; break;
			case 2: opcode = "RCL"; break;
			case 3: opcode = "RCR"; break;
			case 4: opcode = "SHL"; break;
			case 5: opcode = "SHR"; break;
			case 6: opcode = "???"; break;
			case 7: opcode = "SAR"; break;
		    }
		    opcode2(state, opcode, state->rm, "CL");
		    break;
	case 0x04:  if(ptr[1] == 0x0A) {
			opcode0(state, "AAM");
			length = 2;
		    } else {
			opcode0(state, "???");
		    }
		    break;
	case 0x05:  if(ptr[1] == 0x0A) {
			opcode0(state, "AAD");
			length = 2;
		    } else {
			opcode0(state, "???");
		    }
		    break;
	case 0x06:  opcode0(state, "???"); break;
	case 0x07:  opcode0(state, "XLAT"); break;
	case 0x08: case 0x09: case 0x0A: case 0x0B:
	case 0x0C: case 0x0D: case 0x0E: case 0x0F:
		    length = coprosseser(ptr, state);
    }
    return length;
}

static int typeE0(UCHAR *ptr, DumpState *state)
{
int	length;
USHORT *pShort;
ULONG  *pLong;
char   *opcode;
char   *op1;
ULONG	addr;

    switch(ptr[0] & 0x0f) {
	case 0x00: case 0x01: case 0x02: case 0x03:
		    switch(ptr[0] & 0x0f) {
			case 0: opcode = "LOOPNE"; break;
			case 1: opcode = "LOOPE";  break;
			case 2: opcode = "LOOP";   break;
			case 3: opcode = state->is32BitAddress ? "JECXZ" : "JCXZ";   break;
		    }
		    pShort = (USHORT *) &ptr[1];
		    sprintf(state->temp, "$ 0x%02x", *pShort);
		    length = 2;
		    opcode1(state, opcode, state->temp);
		    break;
        case 0x04:
	case 0x05:  length = 2;
		    sprintf(state->temp, "0x%02x", ptr[1]);
		    op1 = ((ptr[0] & 0x01) == 0) ? "AL" :
						    (state->is32BitOperands ? "EAX" : "AX");
		    opcode2(state, "IN", op1, state->temp);
		    break;
        case 0x06:
	case 0x07:  length = 2;
		    sprintf(state->temp, "0x%02x", ptr[1]);
		    op1 = ((ptr[0] & 0x01) == 0) ? "AL" :
						    (state->is32BitOperands ? "EAX" : "AX");
		    opcode2(state, "OUT", state->temp, op1);
		    break;
	case 0x08:  if(state->is32BitAddress) {
			length = 5;
			pLong = (ULONG *) &ptr[1];
			addr = *pLong;
		    } else {
			length = 3;
			pShort = (USHORT *) &ptr[1];
			addr = *pShort;
		    }
		    addr = addr + state->addr + state->ptr_offset + length;
		    sprintf(state->temp, "$ 0x%08x", addr);
		    opcode1(state, "CALL", state->temp);
		    break;
	case 0x09:  if(state->is32BitAddress) {
			length = 5;
			pLong = (ULONG *) &ptr[1];
			addr = *pLong;
		    } else {
			length = 3;
			pShort = (USHORT *) &ptr[1];
			addr = *pShort;
		    }
		    addr = addr + state->addr + state->ptr_offset + length;
		    sprintf(state->temp, "0x%08x", addr);
		    opcode1(state, "JMP", state->temp);
		    break;
	case 0x0A:  if(state->is32BitAddress) {
			pLong  = (ULONG  *) &ptr[1];
			pShort = (USHORT *) &ptr[3];
			sprintf(state->temp, "%04x:%08x", *pShort, *pLong);
			length = 7;
		    } else {
			pShort = (USHORT *) &ptr[1];
			sprintf(state->temp, "%04x:%04x", pShort[0], pShort[1]);
			length = 5;
		    }
		    opcode1(state, "JMP", state->temp);
		    break;
	case 0x0B:  sprintf(state->temp,"SHORT $ 0x%02x", ptr[1]);
		    opcode1(state, "JMP", state->temp);
		    length = 2;
		    break;
        case 0x0C:
	case 0x0D:  op1 = ((ptr[0] & 0x0f) == 0x0C) ? "AL" :
						(state->is32BitOperands ? "EAX" : "AX");
		    opcode2(state, "IN", op1, "DX");
		    length = 1;
		    break;
        case 0x0E:
	case 0x0F:  op1 = ((ptr[0] & 0x0f) == 0x0E) ? "AL" :
						(state->is32BitOperands ? "EAX" : "AX");
		    opcode2(state, "OUT", "DX", op1);
		    length = 1;
		    break;
    }
    return length;
}

static int typeF0(UCHAR *ptr, DumpState *state)
{
int	length = 1;
int	operation;
char   *opcode;
USHORT *pShort;
ULONG  *pLong;

    switch(ptr[0] & 0x0f) {
	case 0x00:  opcode0(state, "LOCK"); break;
	case 0x01:  opcode0(state, "???");  break;
	case 0x02:  opcode0(state, "REPNE");break;
	case 0x03:  opcode0(state, "REP");  break;
	case 0x04:  opcode0(state, "HLT");  break;
	case 0x05:  opcode0(state, "CMC");  break;
	case 0x08:  opcode0(state, "CLC");  break;
	case 0x09:  opcode0(state, "STC");  break;
	case 0x0A:  opcode0(state, "CLI");  break;
	case 0x0B:  opcode0(state, "STI");  break;
	case 0x0C:  opcode0(state, "CLD");  break;
	case 0x0D:  opcode0(state, "STD");  break;
	case 0x06:
	case 0x07:  length = 1 + reg_mod(ptr[0] & 0x01, ptr+1, state);
		    switch((ptr[1] & 0x38) >> 3) {
			case 0x00: opcode = "TEST";
				   if((ptr[0] & 0x01) == 0) {
					sprintf(state->temp, "0x%02x", ptr[length]);
					length++;
				   } else {
					if(state->is32BitOperands) {
					    pLong = (ULONG *) &ptr[length];
					    length += 4;
					    sprintf(state->temp, "0x%08x", *pLong);
					} else {
					    pShort = (USHORT *) &ptr[length];
					    length += 2;
					    sprintf(state->temp, "0x%04x", *pShort);
					}
				   }
				   opcode2(state, opcode, state->rm, state->temp);
				   return length;

			case 0x01: opcode = "???";  break;
			case 0x02: opcode = "NOT";  break;
			case 0x03: opcode = "NEG";  break;
			case 0x04: opcode = "MUL";  break;
			case 0x05: opcode = "IMUL"; break;
			case 0x06: opcode = "DIV";  break;
			case 0x07: opcode = "IDIV"; break;
		    }
		    opcode1(state, opcode, state->rm);
		    break;
	case 0x0E:
	case 0x0F:
		    length = 1 + reg_mod(ptr[0] & 0x01, ptr+1, state);
		    operation = (ptr[1] & 0x38) >> 3;
		    switch((ptr[1] & 0x38) >> 3)   {
			    case 0: opcode = "INC";  break;
			    case 1: opcode = "DEC";  break;
			    case 2: opcode = "CALL"; break;
			    case 3: opcode = "CALL"; break;
			    case 4: opcode = "JMP";  break;
			    case 5: opcode = "JMP";  break;
			    case 6: opcode = "PUSH"; break;
			    case 7: opcode = "???";  break;
		    }
		    opcode1(state, opcode, state->rm);
		    break;
    }
    return length;
}

static int coprosseser(UCHAR *ptr, DumpState *state)
{
    switch(ptr[0]) {
	case 0xD8:  return cotypeD8(ptr, state);
	case 0xD9:  return cotypeD9(ptr, state);
	case 0xDA:  return cotypeDA(ptr, state);
	case 0xDB:  return cotypeDB(ptr, state);
	case 0xDC:  return cotypeDC(ptr, state);
	case 0xDD:  return cotypeDD(ptr, state);
	case 0xDE:  return cotypeDE(ptr, state);
	case 0xDF:  return cotypeDF(ptr, state);
    }
}

static int cotypeD8(UCHAR *ptr, DumpState *state)
{
int	length = 2;
char   *opcode;

    switch(ptr[1] & 0xf8) {
	case 0xc0:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode2(state, "FADD", "ST", state->temp);
	    return 2;
	case 0xc8:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode2(state, "FMUL", "ST", state->temp);
	    return 2;
	case 0xd0:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode2(state, "FCOM", "(REAL 32)", state->temp);
	    return 2;
	case 0xd8:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode2(state, "FCOMP", "(REAL 32)", state->temp);
	    return 2;
	case 0xe0:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode2(state, "FSUB", "ST", state->temp);
	    return 2;
	case 0xe8:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode2(state, "FSUBR", "ST", state->temp);
	    return 2;
	case 0xf0:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode2(state, "FDIV", "ST", state->temp);
	    return 2;
	case 0xf8:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode2(state, "FDIVR", "ST", state->temp);
	    return 2;
    }
    length = 1 + word_reg_mod(ptr+1, state);
    switch((ptr[1] & 0x38) >> 3) {
	case 0: opcode = "FADD";  break;
	case 1: opcode = "FMUL";  break;
	case 2: opcode = "FCOM";  break;
	case 3: opcode = "FCOMP"; break;
	case 4: opcode = "FSUB";  break;
	case 5: opcode = "FSUBR"; break;
	case 6: opcode = "FDIV";  break;
	case 7: opcode = "FDIVR"; break;
    }
    opcode2(state, opcode, "(REAL 32)", state->rm);
    return length;
}

static int cotypeD9(UCHAR *ptr, DumpState *state)
{
int	length = 2;
char   *opcode;

    switch(ptr[1]) {
	case 0xc0: case 0xc1: case 0xc2: case 0xc3:
	case 0xc4: case 0xc5: case 0xc6: case 0xc7:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode1(state, "FLD", state->temp);
	    return 2;
	case 0xc8: case 0xc9: case 0xca: case 0xcb:
	case 0xcc: case 0xcd: case 0xce: case 0xcf:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode1(state, "FXCH", state->temp);
	    return 2;
	case 0xd0:  opcode0(state, "FNOP");
		    return 2;
	case 0xe0:  opcode0(state, "FCHS");
		    return 2;
	case 0xe1:  opcode0(state, "FABS");
		    return 2;
	case 0xe4:  opcode0(state, "FTST");
		    return 2;
	case 0xe5:  opcode0(state, "FXAM");
		    return 2;
	case 0xe8:  opcode0(state, "FLD1");
		    return 2;
	case 0xe9:  opcode0(state, "FLDL2T");
		    return 2;
	case 0xea:  opcode0(state, "FLDL2E");
		    return 2;
	case 0xeb:  opcode0(state, "FLDPI");
		    return 2;
	case 0xec:  opcode0(state, "FLDG2");
		    return 2;
	case 0xed:  opcode0(state, "FLDN2");
		    return 2;
	case 0xee:  opcode0(state, "FLDZ");
		    return 2;
	case 0xf0:  opcode0(state, "F2XM1");
		    return 2;
	case 0xf1:  opcode0(state, "FYL2X");
		    return 2;
	case 0xf2:  opcode0(state, "FPTAN");
		    return 2;
	case 0xf3:  opcode0(state, "FPATAN");
		    return 2;
	case 0xf4:  opcode0(state, "FXTRACT");
		    return 2;
	case 0xf5:  opcode0(state, "FPREM1");
		    return 2;
	case 0xf6:  opcode0(state, "FDECSTP");
		    return 2;
	case 0xf7:  opcode0(state, "FINCSTP");
		    return 2;
	case 0xf8:  opcode0(state, "FPREM");
		    return 2;
	case 0xf9:  opcode0(state, "FYL2XP1");
		    return 2;
	case 0xfa:  opcode0(state, "FSQRT");
		    return 2;
	case 0xfb:  opcode0(state, "FSINCOS");
		    return 2;
	case 0xfc:  opcode0(state, "FRNDINT");
		    return 2;
	case 0xfd:  opcode0(state, "FSCALE");
		    return 2;
	case 0xfe:  opcode0(state, "FSIN");
		    return 2;
	case 0xff:  opcode0(state, "FCOS");
		    return 2;

    }
    length = 1 + word_reg_mod(ptr+1, state);
    switch((ptr[1] & 0x38) >> 3) {
	case 0: opcode = "FLD";    break;
	case 1: opcode = "???";    break;
	case 2: opcode = "FST";    break;
	case 3: opcode = "FSTP";   break;
	case 4: opcode = "FLDEVN"; break;
	case 5: opcode = "FLDCW";  break;
	case 6: opcode = "FSTENV"; break;
	case 7: opcode = "FSTCW";  break;
    }
    opcode2(state, opcode, "(REAL 32)", state->rm);
    return length;
}

static int cotypeDA(UCHAR *ptr, DumpState *state)
{
int	length = 2;
char   *opcode;

    if(ptr[1] == 0xe9) {
	opcode0(state, "FUCOMPP");
	return 2;
    }

    length = 1 + word_reg_mod(ptr+1, state);
    switch((ptr[1] & 0x38) >> 3) {
	case 0: opcode = "FIADD";  break;
	case 1: opcode = "FIMUL";  break;
	case 2: opcode = "FICOM";  break;
	case 3: opcode = "FICOMP"; break;
	case 4: opcode = "FISUB";  break;
	case 5: opcode = "FISUBR"; break;
	case 6: opcode = "FIDIV";  break;
	case 7: opcode = "FIDIVR"; break;
    }
    opcode2(state, opcode, "(INT 16)", state->rm);
    return length;
}

static int cotypeDB(UCHAR *ptr, DumpState *state)
{
int	length = 2;
char   *opSize;
char   *opcode;

    if(ptr[1] == 0xe0) {
	opcode0(state, "FENI");
	return 2;
    }

    if(ptr[1] == 0xe1) {
	opcode0(state, "FDISI");
	return 2;
    }

    if(ptr[1] == 0xe2) {
	opcode0(state, "FCLEX");
	return 2;
    }

    if(ptr[1] == 0xe3) {
	opcode0(state, "FINIT");
	return 2;
    }

    if(ptr[1] == 0xe4) {
	opcode0(state, "FSETPM");
	return 2;
    }

    length = 1 + word_reg_mod(ptr+1, state);
    switch((ptr[1] & 0x38) >> 3) {
	case 0: opcode = "FILD";  opSize = "(INT 16)";	break;
	case 1: opcode = "???";   opSize = ""; break;
	case 2: opcode = "FIST";  opSize = "(INT 16)";	break;
	case 3: opcode = "FISTP"; opSize = "(INT 16)";	break;
	case 4: opcode = "???";   opSize = ""; break;
	case 5: opcode = "FLD";   opSize = "(REAL 80)"; break;
	case 6: opcode = "FSTP";  opSize = "(REAL 80)"; break;
	case 7: opcode = "FSTP";  opSize = ""; break;
    }
    opcode2(state, opcode, opSize, state->rm);
    return length;
}

static int cotypeDC(UCHAR *ptr, DumpState *state)
{
int	length = 2;
char   *opcode;

    switch(ptr[1] & 0xf8) {
	case 0xc0:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode2(state, "FADD", state->temp, "ST");
	    return 2;
	case 0xc8:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode2(state, "FMUL", state->temp, "ST");
	    return 2;
	case 0xe0:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode2(state, "FSUBR", state->temp, "ST");
	    return 2;
	case 0xe8:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode2(state, "FSUB", state->temp, "ST");
	    return 2;
	case 0xf0:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode2(state, "FDIVR", state->temp, "ST");
	    return 2;
	case 0xf8:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode2(state, "FDIV", state->temp, "ST");
	    return 2;
    }
    length = 1 + word_reg_mod(ptr+1, state);
    switch((ptr[1] & 0x38) >> 3) {
	case 0: opcode = "FADD";  break;
	case 1: opcode = "FMUL";  break;
	case 2: opcode = "FCOM";  break;
	case 3: opcode = "FCOMP"; break;
	case 4: opcode = "FSUB";  break;
	case 5: opcode = "FSUBR"; break;
	case 6: opcode = "FDIV";  break;
	case 7: opcode = "FDIVR"; break;
    }
    opcode2(state, opcode, "(REAL 64)", state->rm);
    return length;
}

static int cotypeDD(UCHAR *ptr, DumpState *state)
{
int	length = 2;
char   *opcode;

    switch(ptr[1] & 0xf8) {
	case 0xc0:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode1(state, "FFREE", state->temp);
	    return 2;
	case 0xd0:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode1(state, "FST", state->temp);
	    return 2;
	case 0xd8:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode1(state, "FSTP", state->temp);
	    return 2;
	case 0xe0:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode1(state, "FUCOM", state->temp);
	    return 2;
	case 0xe8:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode1(state, "FUCOMP", state->temp);
	    return 2;
    }
    length = 1 + word_reg_mod(ptr+1, state);
    switch((ptr[1] & 0x38) >> 3) {
	case 0: opcode = "FLD";   break;
	case 1: opcode = "???";   break;
	case 2: opcode = "FST";   break;
	case 3: opcode = "FSTP";  break;
	case 4: opcode = "FRSTOR";break;
	case 5: opcode = "???";   break;
	case 6: opcode = "FSAVE"; break;
	case 7: opcode = "FSTSW"; break;
    }
    opcode2(state, opcode, "(REAL 64)", state->rm);
    return length;
}

static int cotypeDE(UCHAR *ptr, DumpState *state)
{
int	length = 2;
char   *opcode;

    if(ptr[1] == 0xd9) {
	opcode0(state, "FCOMPP");
	return 2;
    }
    switch(ptr[1] & 0xf8) {
	case 0xc0:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode2(state, "FADDP", state->temp, "ST");
	    return 2;
	case 0xc8:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode2(state, "FMULP", state->temp, "ST");
	    return 2;
	case 0xe0:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode2(state, "FSUBRP", state->temp, "ST");
	    return 2;
	case 0xe8:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode2(state, "FSUBP", state->temp, "ST");
	    return 2;
	case 0xf0:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode2(state, "FDIVRP", state->temp, "ST");
	    return 2;
	case 0xf8:
	    sprintf(state->temp, "ST(%d)", ptr[1] & 0x07);
	    opcode2(state, "FDIVP", state->temp, "ST");
	    return 2;
    }
    length = 1 + word_reg_mod(ptr+1, state);
    switch((ptr[1] & 0x38) >> 3) {
	case 0: opcode = "FIADD";  break;
	case 1: opcode = "FIMUL";  break;
	case 2: opcode = "FICOM";  break;
	case 3: opcode = "FICOMP"; break;
	case 4: opcode = "FISUB";  break;
	case 5: opcode = "FISUBR"; break;
	case 6: opcode = "FIDIV";  break;
	case 7: opcode = "FIDIVR"; break;
    }
    opcode2(state, opcode, "(INT 32)", state->rm);
    return length;
}

static int cotypeDF(UCHAR *ptr, DumpState *state)
{
int	length = 2;
char   *opSize;
char   *opcode;

    if(ptr[1] == 0xe0) {
	opcode1(state, "FSTSW", "AX");
	return 2;
    }

    length = 1 + word_reg_mod(ptr+1, state);
    switch((ptr[1] & 0x38) >> 3) {
	case 0: opcode = "FILD";  opSize = "(INT 32)"; break;
	case 1: opcode = "???";   opSize = "";	       break;
	case 2: opcode = "FIST";  opSize = "(INT 32)"; break;
	case 3: opcode = "FISTP"; opSize = "(INT 32)"; break;
	case 4: opcode = "FBLD";  opSize = "(BCD)";    break;
	case 5: opcode = "FILD";  opSize = "(INT 64)"; break;
	case 6: opcode = "FBSTP"; opSize = "(BCD)";    break;
	case 7: opcode = "FISTP"; opSize = "(INT 64)"; break;
    }
    opcode2(state, opcode, opSize, state->rm);
    return length;
}
