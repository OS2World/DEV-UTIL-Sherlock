/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
** For all the DLL's without debugging information, get the
** export list and find the addresses associated with them.
*/
#include    <stdio.h>
#include    <string.h>
#include    <malloc.h>
#include    <sys\stat.h>

#define     INCL_DOSMODULEMGR
#define     INCL_DOSPROCESS
#include    <os2.h>
#include    "debug.h"

#include    "newexe.h"
typedef unsigned long DWORD;
typedef unsigned short WORD;
#include    "exe386.h"

#include    "Debugger.h"
#include    "SrcInter.h"
#include    "Source.h"

typedef struct _DefAuxData {
    struct _DefAuxData *next;
    char               *name;
    ULONG               addr;
} DefAuxData;

/*
** Find a function based on the function with the next lower address.
*/
static int _System DefFindSource(DebugModule *module, ULONG eipOffset,
			char *funcName, char *sourceName, ULONG *lineNum)
{
DefAuxData  *top, *bottom, *mod;

    top = bottom = module->AuxData;
    for(mod=module->AuxData; mod; mod=mod->next) {

        /*
        ** Close in from the bottom.
        */
        if((mod->addr >= bottom->addr) &&
           (mod->addr <= eipOffset)) {
	    bottom = mod;
        }

        /*
        ** Close in from the top.
        */
        if((mod->addr <= top->addr) &&
           (mod->addr >= eipOffset)) {
            top = mod;
        }
    }
    if(bottom)
	strcpy(funcName, bottom->name);
    else
	strcpy(funcName, "UNKNOWN");
    if(top)
	strcpy(sourceName, top->name);
    else
	strcpy(sourceName, "UNKNOWN");
    *lineNum    = 0;
    return 0;
}

/*
** Find the address of a function.
*/
static ULONG _System DefFindFuncAddr(DebugModule *module, char *funcName)
{
DefAuxData *mod;

    for(mod = module->AuxData; mod; mod=mod->next) {
        if(stricmp(funcName, mod->name) == 0) {
            return mod->addr;
        }
    }
    return 0;
}

/*
** Free all of the collected information.
*/
static void _System DefFreeModule(DebugModule *module)
{
DefAuxData *mod, *next;

    for(mod=module->AuxData; mod;) {
        free(mod->name);
        next = mod->next;
        free(mod);
        mod = next;
    }
    module->AuxData = NULL;
}

/*
** Connect to a module without debugging information.
*/
int DefConnectModule(DebugModule *module)
{
FILE           *mod;
DefAuxData     *data, *prior;
ULONG           size;
unsigned char   cbName;
struct exe_hdr  dosHdr;
HMODULE         modHandle;
char		buff[CCHMAXPATH];
struct stat	statBuff;
union   {
    struct new_exe  os21x;
    struct e32_exe  os22x;
} header;

    /*
    ** Open the file.
    */
    if((mod = fopen(module->name, "rb")) == NULL) {
	fprintf(logFile, "Unable to open module %s.\n", module->name);
	return 0;
    }
    fstat(fileno(mod), &statBuff);
    module->fileSize   = statBuff.st_size;
    module->fTimestamp = statBuff.st_atime;

    /*
    ** Get the DOS exe header.
    */
    fread(&dosHdr, sizeof(struct exe_hdr), 1, mod);
    fseek(mod, dosHdr.e_lfanew, SEEK_SET);

    /*
    ** Read the os2 header.
    */
    fread(&header, sizeof(header), 1, mod);
    if(header.os21x.ne_magic == NEMAGIC) {
        fseek(mod, dosHdr.e_lfanew + header.os21x.ne_rsrctab, SEEK_SET);
    } else {
        fseek(mod, dosHdr.e_lfanew + header.os22x.e32_restab, SEEK_SET);
    }

    /*
    ** Read the Resident names table.
    **
    ** Skip over the module name.
    */
    fread(&cbName, 1, 1, mod);
    fseek(mod, cbName + 2, SEEK_CUR);

    /*
    ** Read the names.
    */
    fread(&cbName, 1, 1, mod);
    module->AuxData = (void *) malloc(sizeof(DefAuxData));
    data = (DefAuxData *) module->AuxData;
    data->name = NULL;
    prior = data;
    while(cbName != 0) {
        USHORT  dummy;

	data->name = (void *) malloc(cbName + 1);
        fread(data->name, cbName, 1, mod);
        data->name[cbName] = '\0';

        fread(&dummy, 2, 1, mod);
        fread(&cbName, 1, 1, mod);
	data->next = (DefAuxData *) malloc(sizeof(DefAuxData));
        prior = data;
        data = data->next;
    }

    /*
    ** Seek to the Non-Resident names table.
    */
    if(header.os21x.ne_magic == NEMAGIC) {
        fseek(mod, header.os21x.ne_nrestab, SEEK_SET);
        size = header.os21x.ne_cbnrestab;
    } else {
        fseek(mod, header.os22x.e32_nrestab, SEEK_SET);
        size = header.os22x.e32_cbnrestab;
    }

    /*
    ** Make sure that there is a non-resident table to read.
    */
    if(size != 0) {

        /*
        ** Read the comment.
        */
        fread(&cbName, 1, 1, mod);
        size -= cbName + 3;
        fseek(mod, cbName + 2, SEEK_CUR);

        /*
        ** Read the names.
        */
        fread(&cbName, 1, 1, mod);
        while((size != 0) && (cbName != 0)) {
            USHORT  dummy;

            size -= cbName + 3;
	    data->name = (char *) malloc(cbName + 1);
            fread(data->name, cbName, 1, mod);
            data->name[cbName] = '\0';

            fread(&dummy, 2, 1, mod);
            fread(&cbName, 1, 1, mod);
	    data->next = (DefAuxData *) malloc(sizeof(DefAuxData));
            prior = data;
            data = data->next;
        }
    }
    prior->next = NULL;
    if(prior == data) {
        module->AuxData = NULL;
    }
    free(data);
    fclose(mod);

    /*
    ** Find the export addresses of the functions.
    */
    DosLoadModule(buff, sizeof(buff), module->name, &modHandle);
    for(data = module->AuxData; data; data=data->next) {
	if(DosQueryProcAddr(modHandle, 0, data->name, (PFN *) &data->addr) != 0) {
#if 0
	    fprintf(logFile, "Unable to find address for %s:%s\n",
		    module->name, data->name);
#endif
            data->addr = 0;
        }
    }
    DosFreeModule(modHandle);

    /*
    ** Finally, connect the display routines.
    */
    module->FreeModule   = DefFreeModule;
    module->FindSource   = DefFindSource;
    module->FindFuncAddr = DefFindFuncAddr;
    return 1;
}
