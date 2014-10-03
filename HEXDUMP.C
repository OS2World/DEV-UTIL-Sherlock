/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
#include    <stdio.h>
#include    <stdlib.h>
#include    <ctype.h>
#include    <memory.h>
#include    <math.h>
#include    <time.h>
#include    <sys\stat.h>

#define     INCL_DOSSESMGR
#define     INCL_DOSPROCESS
#include    <os2.h>
#include    "debug.h"

#include    "Debugger.h"
#include    "SrcInter.h"
#include    "Source.h"


/*
** Convert a string to an address.  Do any necessary linearization.
*/
ULONG StrToAddr(char *str, int type)
{
ULONG val;
char *end;

    val = strtoul(str, &end, 16);
    if((val & 0xffff0000) != 0)
	return val;
    DispatchCommand(DBG_C_ReadReg);
    switch(type) {
	case TOADDR_CODE:   return Linearize(val, debugBuffer.CS);
	case TOADDR_DATA:   return Linearize(val, debugBuffer.DS);
	case TOADDR_STACK:  return Linearize(val, debugBuffer.SS);
    }
    return 0;
}

/*
** Linearize an offset/segment.  This linearization will
** check whether the segment is 16/32 bit.  If 32 bit,
** just return offset.	If 16 bit, convert to linear.
*/
ULONG Linearize(ULONG offset, USHORT segment)
{
    if((offset & 0xffff0000) != 0)
	return offset;

    debugBuffer.Value = segment;
    debugBuffer.Index = offset;
    DispatchCommand(DBG_C_SelToLin);
    return debugBuffer.Addr;
}

/*
**  Dump a buffer of length to the buffer given.  Assume that length is
**  less than 16 and that the buffer is large enough to hold the result.
*/
void hexdump(unsigned char *data, int count, char *buff)
{
static char digits[] = "0123456789ABCDEF";
int i;

    count = min(count, 16);
    for(i=0; i<count; i++) {
        if(i == 8) {
            *buff++ = ' ';
            *buff++ = ' ';
        }
        *buff++ = digits[data[i]/16];
        *buff++ = digits[data[i]%16];
        *buff++ = ' ';
    }
    *buff++ = ' ';
    *buff++ = ' ';
    *buff++ = ' ';

    memcpy(buff, data, 16);
    for(i=0; i<count; i++)
	buff[i] = isgraph(buff[i]) ? buff[i] : (char) '.';
    buff[16] = '\0';
    return;
}

/*
** Dump the stack frame.
*/
void DumpStack(int threadID)
{
ULONG	lineNum;
struct {
    ULONG   ebp;
    ULONG   eip;
} info;
DebugModule *module;
ULONG	oldTid;
ULONG	objectNum;
ULONG	baseOffset;
USHORT	lastCS;
char	funcName[MAX_FUNCNAME];
char    sourceName[CCHMAXPATH];

    /*
    ** Find the base and then extract out the EIP.  Follow the chain
    ** until EBP == 0
    */
    oldTid = debugBuffer.Tid;
    debugBuffer.Tid = threadID;
    DispatchCommand(DBG_C_ReadReg);
    lastCS   = debugBuffer.CS;
    info.ebp = Linearize(debugBuffer.EBP, debugBuffer.SS);
    info.eip = Linearize(debugBuffer.EIP, debugBuffer.CS);
    while(1) {
	/*
	** End of chain.
	*/
	if((info.ebp == 0) || (info.eip == 0)) {
	    debugBuffer.Tid = oldTid;
	    return;
	}

	/*
	** Find the module.
	*/
	debugBuffer.Addr = info.eip;
	DispatchCommand(DBG_C_AddrToObject);
        module = FindModule(debugBuffer.MTE, NULL);
	if(module == NULL) {
	    fprintf(logFile, "MODULE NOT FOUND!\n");
	    debugBuffer.Tid = oldTid;
	    return;
	}

	/*
	** Dump EBP:EIP of the current stack frame.
	*/
	baseOffset = debugBuffer.Buffer;
	fprintf(logFile, "EBP:\t%08x\tEIP:\t%08x\n", info.ebp, info.eip);
	fprintf(logFile, "  Base:\t%08x\tRel:\t%08x\tLen:\t%08x\n",
		baseOffset, info.eip - baseOffset, debugBuffer.Len);

	/*
	** Find the object number associated with the address.
	*/
	for(objectNum=1;;objectNum++) {
	    debugBuffer.Value = (ULONG) objectNum;
	    debugBuffer.MTE   = module->MTE;
	    if(DispatchCommand(DBG_C_NumToAddr) != DBG_N_Success)
		break;
	    if(debugBuffer.Addr == baseOffset)
		break;
	}
	fprintf(logFile, "  Object: %08x\n", objectNum);

        /*
	** Dump the values.
	*/
	FindSource(module, info.eip,
	       funcName, sourceName, &lineNum);
	if(lineNum != 0)
	    fprintf(logFile, "  Module:   %s\n"
			    "  Size:     %u\n"
			    "  Timestamp:%s\n"
			    "  Function: %s\n"
			    "  Source:   %s\n"
			    "  Line:     %d\n\n",
		    module->name, module->fileSize, ctime(&module->fTimestamp),
		    funcName, sourceName, lineNum);
	else
	    fprintf(logFile, "  Module:   %s\n"
			    "  Size:     %u\n"
			    "  Timestamp:%s\n"
			    "  Lo Function: %s\n"
			    "  Hi Function: %s\n\n",
		    module->name, module->fileSize, ctime(&module->fTimestamp),
		    funcName, sourceName);

#ifdef SHERLOCK
        {
            DebugModule *module;
            char *mod;

	    debugBuffer.Addr = info.eip;
	    DispatchCommand(DBG_C_AddrToObject);
	    if((debugBuffer.Cmd == DBG_N_Success) &&
	       (debugBuffer.Value & 0x10000000)) {
                module = FindModule(debugBuffer.MTE, NULL);
                if(module == NULL)
                    mod = "UNKNOWN";
                else
                    mod = module->name;
		FindSource(module, info.eip,
			funcName, sourceName, &lineNum);
		fprintf(logFile, "EIP: %08x, DLL: %s Func: %s\n",
			info.eip, mod, funcName);
		DisplaySource(module, sourceName, lineNum);
		fprintf(logFile, "\n\n");
	    }
	}
#endif

	/*
	** Get prior EBP, EIP
	*/
	if(module->typeFlags & FAPPTYP_32BIT) {
            debugBuffer.Addr = info.ebp;
            debugBuffer.Len  = 8;
            debugBuffer.Buffer = (ULONG) &info.ebp;
            info.ebp = info.eip = 0;
	    DispatchCommand(DBG_C_ReadMemBuf);
	} else {
	    USHORT  codePtr[2];

	    /* Get the new code pointer. */
	    debugBuffer.Addr = info.ebp+2;
	    debugBuffer.Len  = 4;
	    debugBuffer.Buffer = (ULONG) &codePtr;
	    info.eip = 0;
	    DispatchCommand(DBG_C_ReadMemBuf);

	    /* Now, get the new base pointer. */
	    debugBuffer.Addr = info.ebp;
	    debugBuffer.Len  = 2;
            debugBuffer.Buffer = (ULONG) &info.ebp;
	    info.ebp = 0;
	    DispatchCommand(DBG_C_ReadMemBuf);
	    info.ebp = Linearize(info.ebp, debugBuffer.SS);

	    /*
	    ** Now for real hocus pocus.  Try to find out
	    ** if the pointer is a near or far call!
	    **
	    ** First, check for NULL pointer, Must be end of chain.
	    */
	    if((codePtr[0] == 0) && (codePtr[1] == 0)) {
		info.eip = 0;
	    } else {
		USHORT tmp;

		/*
		** If supposidly ring 0 or ring 1 caller, then
		** that cannot be correct, must be a near call.
		*/
		tmp = codePtr[1] & 0x03;
		if((tmp == 0) || (tmp == 1)) {
		    info.eip = Linearize(codePtr[0], lastCS);
		} else {

		    /*
		    ** Assume that it is a far pointer.
		    */
		    lastCS = codePtr[1];
		    info.eip = Linearize(codePtr[0], lastCS);
		}
	    }
	}
    }
    debugBuffer.Tid = oldTid;
    return;
}
