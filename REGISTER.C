/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
** Access the registers in the debuggee.
*/
#include    <stdio.h>

#define     INCL_DOSPROCESS
#include    <os2.h>
#include    "debug.h"

#include    "Debugger.h"
#include    "Register.h"

/*
** Dump/set the registers
*/
int CommandRegister(char **ptrs)
{
    if(ptrs[2] == NULL) {
	DispatchCommand(DBG_C_ReadReg);
	DumpRegs(&debugBuffer);
	return -1;
    }
    return -1;
}

/*
** Dump the debug structure to the console.
*/
void DumpRegs(DebugBuffer *buffer)
{
    fprintf(logFile, "Pid: %08x  Tid:    %08x\n", buffer->Pid, buffer->Tid);
    fprintf(logFile, "Cmd: %8d  Value:  %08x\n", buffer->Cmd, buffer->Value);
    fprintf(logFile, "Addr: %08x  Buffer: %08x\n", buffer->Addr, buffer->Buffer);
    fprintf(logFile, "Len:  %08x  Index:  %08x\n", buffer->Len, buffer->Index);
    fprintf(logFile, "MTE:  %08x\n", buffer->MTE);

    fprintf(logFile, "EAX: %08x  EBX: %08x  ECX: %08x  EDX: %08x\n",
	    buffer->EAX, buffer->EBX, buffer->ECX, buffer->EDX);
    fprintf(logFile, "ESP: %08x  EBP: %08x  ESI: %08x  EDI: %08x\n",
	    buffer->ESP, buffer->EBP, buffer->ESI, buffer->EDI);
    fprintf(logFile, "EIP: %08x  EFLAGS: %08x\n",
	    buffer->EIP & 0xffff, buffer->EFlags);
    fprintf(logFile, "  Carry Parity Aux Zero Sign Trap IntE Dir OFlow IOPL Nested Resume\n");
    fprintf(logFile, "  %s    %s     %s  %s   %s   %s   %s   %s  %s    %d   %s     %s \n",
	    buffer->EFlags & 0x00001 ? "CY" : "NC",
	    buffer->EFlags & 0x00004 ? "PE" : "PO",
	    buffer->EFlags & 0x00010 ? " 1" : " 0",
	    buffer->EFlags & 0x00040 ? " Z" : "NE",
	    buffer->EFlags & 0x00080 ? " 1" : " 0",
	    buffer->EFlags & 0x00100 ? " 1" : " 0",
	    buffer->EFlags & 0x00200 ? " 1" : " 0",
	    buffer->EFlags & 0x00400 ? "UP" : "DN",
	    buffer->EFlags & 0x00800 ? " O" : "NO",
	    buffer->EFlags & 0x03000 >> 12,
	    buffer->EFlags & 0x04000 ? " 1" : " 0",
	    buffer->EFlags & 0x10000 ? " 1" : " 0",
	    buffer->EFlags & 0x20000 ? " 1" : " 0");
    fprintf(logFile, "CSLim %08x  CSBase: %08x  CSAcc: %02x  CSAttr: %02x  CS:%04x\n",
	    buffer->CSLim, buffer->CSBase, buffer->CSAcc, buffer->CSAtr, buffer->CS);
    fprintf(logFile, "DSLim %08x  DSBase: %08x  DSAcc: %02x  DSAttr: %02x  DS:%04x\n",
	    buffer->DSLim, buffer->DSBase, buffer->DSAcc, buffer->DSAtr, buffer->DS);
    fprintf(logFile, "ESLim %08x  ESBase: %08x  ESAcc: %02x  ESAttr: %02x  ES:%04x\n",
	    buffer->ESLim, buffer->ESBase, buffer->ESAcc, buffer->ESAtr, buffer->ES);
    fprintf(logFile, "FSLim %08x  FSBase: %08x  FSAcc: %02x  FSAttr: %02x  FS:%04x\n",
	    buffer->FSLim, buffer->FSBase, buffer->FSAcc, buffer->FSAtr, buffer->FS);
    fprintf(logFile, "GSLim %08x  GSBase: %08x  GSAcc: %02x  GSAttr: %02x  GS:%04x\n",
	    buffer->GSLim, buffer->GSBase, buffer->GSAcc, buffer->GSAtr, buffer->GS);
    fprintf(logFile, "SSLim %08x  SSBase: %08x  SSAcc: %02x  SSAttr: %02x  SS:%04x\n\n",
	    buffer->SSLim, buffer->SSBase, buffer->SSAcc, buffer->SSAtr, buffer->SS);

    return;
}
