/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
** HLL interface functions to extract symbolic information
** given a state to extract information from.
*/
#include    <stdio.h>
#include    <string.h>
#include    <malloc.h>
#include    <memory.h>
#include    <sys/stat.h>

#define     INCL_DOSPROCESS
#include    <os2.h>
#include    "..\Debug.h"

#include    "..\SrcInter.h"
#include    "HLL.h"

/*
** Global variables.
*/
static int (* _System Dispatch)(int command);
DebugBuffer *debugBuffer;

/*
** Answer the linkage priority.
** Return 1 for insert in front of list - (first crack at linking)
** Return 0 for add to end of list.	- (last crack at linking)
*/
int _System linkPriority(void)
{
    return 1;
}

/*
** Answer whether the module named is a HLL module.
** If so, set the function pointers and return true.
*/
int _System isKnownModule(DebugModule *module,
			   int (* _System DispatchCommand)(int command),
			   DebugBuffer *buffer)
{
HLLAuxData *auxData;
HLLModule  *lastModule = NULL;
FILE       *mod;
USHORT      i;
ULONG	    sectionBaseOffset;
SubSectionDictionary *sectionDictionary;

struct stat	      statBuff;
SubSectionDictHeader  dictHeader;

    debugBuffer = buffer;
    Dispatch = DispatchCommand;

    /*
    ** If this is a 16 bit module, handle it elsewhere.
    */
    if((module->typeFlags & 0x4000) == 0)
        return 0;

    /*
    ** Open the file.
    */
    if((mod = fopen(module->name, "rb")) == NULL) {
	return 0;
    }
    fstat(fileno(mod), &statBuff);
    module->fileSize   = statBuff.st_size;
    module->fTimestamp = statBuff.st_atime;

    /*
    ** Find the end header and verify the signature.
    */
    fseek(mod, -8, SEEK_END);
    module->AuxData = (void *) calloc(sizeof(HLLAuxData), 1);
    auxData = (HLLAuxData *) module->AuxData;
    fread(&auxData->tag[0], 8, 1, mod);

    /*
    ** Make sure that we have HLL information.
    */
    if(strncmp(auxData->tag, "NB04", 4) != 0) {
        fclose(mod);
        return 0;
    }

    /*
    ** Go to where the start of the header is located.
    */
    fseek(mod, -auxData->dirOffset, SEEK_END);
    sectionBaseOffset = ftell(mod);
    fread(&auxData->tag[0], 8, 1, mod);

    /*
    ** Double check that we have HLL information.
    */
    if(strncmp(auxData->tag, "NB04", 4) != 0) {
        fclose(mod);
        return 0;
    }

    /*
    ** Find the section dictionary and read it in.
    */
    fseek(mod, sectionBaseOffset + auxData->dirOffset, SEEK_SET);
    fread(&dictHeader, sizeof(dictHeader), 1, mod);
    sectionDictionary = (SubSectionDictionary *) malloc(dictHeader.numEntries * sizeof(SubSectionDictionary));
    fread(sectionDictionary, sizeof(SubSectionDictionary), dictHeader.numEntries, mod);

    /*
    ** Read each section into a module.
    */
    for(i=0; i<dictHeader.numEntries; i++) {
        USHORT sectionSize;

        sectionSize = sectionDictionary[i].sectionSize;
        fseek(mod, sectionBaseOffset +
		   sectionDictionary[i].offsetStart, SEEK_SET);

	switch(sectionDictionary[i].sectionType) {
            /*
            ** Is this a modules record
            */
            case sstModules: {
		if(auxData->moduleData == NULL) {
		    lastModule = (HLLModule *) calloc(sizeof(HLLModule), 1);
		    auxData->moduleData = lastModule;
                } else {
		    lastModule->next = (HLLModule *) calloc(sizeof(HLLModule), 1);
                    lastModule = lastModule->next;
                }
		lastModule->module = (ModulesDataEntry *) malloc(sectionSize+1);
		fread(lastModule->module, sectionSize, 1, mod);
		lastModule->module->name[lastModule->module->cbName] = '\0';
		break;
            }

            /*
            ** Is this a publics record.
            */
            case sstPublic: {
                USHORT              totalBytes;
                void               *base;
		PublicsDataEntry   *entry;
		static HLLPublic   *next;
                char               *ptr;

		/*
                ** Read the block into memory.
                */
		base = (void *) malloc(sectionSize+1);
                fread(base, sectionSize, 1, mod);

                /*
                ** Now, change it into a linked list.
                */
                entry = base;
                totalBytes = 0;
                while(totalBytes < sectionSize) {
                    USHORT  numBytes;

		    numBytes = (USHORT) entry->cbName + (USHORT) sizeof(PublicsDataEntry);
		    if(lastModule->public == NULL) {
			next = lastModule->public = (HLLPublic *)
			    malloc(sizeof(HLLPublic) + entry->cbName + 1);
                    } else {
			next->next = (HLLPublic *)
			    malloc(sizeof(HLLPublic) + entry->cbName + 1);
                        next = next->next;
                    }
		    next->next = NULL;
		    memcpy(&next->data, entry, numBytes);
		    next->data.name[entry->cbName] = '\0';
		    ptr = (char *) entry;
		    ptr += entry->cbName + sizeof(PublicsDataEntry) - 1;
		    entry = (PublicsDataEntry *) ptr;
		    totalBytes += numBytes;
                }
                free(base);
                break;
            }

            /*
            ** Is this a types record.
            */
            case sstTypes: {
		lastModule->type = (char *) malloc(sectionSize);
                lastModule->typeSize = sectionSize;
		fread(lastModule->type, sectionSize, 1, mod);
		break;
            }

            /*
            ** Is this a symbol record.
            */
	    case sstSymbols: {
		lastModule->symbols = (char *) malloc(sectionSize);
                lastModule->symbolSize = sectionSize;
		fread(lastModule->symbols, sectionSize, 1, mod);
		break;
            }

	    /*
            ** Is this a libraries record.
            */
            case sstLibraries: {
                char    *allNames;
                int     numNames;
                USHORT  index;

		/*
                ** Load the names into a scratch area.
                */
		allNames = (char *) malloc(sectionSize+1);
                fread(allNames, sectionSize, 1, mod);

                /*
                ** Find out how many name there are.
                */
                index = 0;
                numNames = 0;
                while(index < sectionSize) {
                    index += allNames[index] + 1;
                    numNames++;
                }
		auxData->libraries = (char **) malloc(numNames * sizeof(char *));

                /*
                ** Copy the names into their 'permanent' location.
                */
                index = 0;
                numNames = 0;
                while(index < sectionSize) {
		    auxData->libraries[numNames] = (char *) malloc(allNames[index] + 1);
                    strncpy(auxData->libraries[numNames], &allNames[index+1],
                            allNames[index]);
                    auxData->libraries[numNames][allNames[index]] = '\0';
                    index += allNames[index] + 1;
                    numNames++;
                }
                break;
            }

	    /*
	    ** New Line line offset information data.
            */
	    case sstNewLineData: {
		HLLLineData    *data;
		struct _tag_FirstEntry {
		    USHORT	dummy;
		    UCHAR	entryType;
		    UCHAR	res;
		    USHORT	numEntries;
		    USHORT	numPathEntries;
		} record;
		USHORT	    count;
		int	    i;

		fread(&record, sizeof(SrcLine), 1, mod);
		data = (HLLLineData *) malloc(sizeof(HLLLineData));

		/*
		** Read the entry data
		*/
		data->entryType = record.entryType;
		data->numEntries = record.numEntries;
		switch (record.entryType) {
		    case 0: count = record.numEntries * 8;
			    break;
		    case 1: count = record.numEntries * 12;
			    break;
		    case 2: count = record.numEntries * 16;
			    break;
		    default:	fprintf(stderr, "Bad line entry type\n");
				exit(1);
		}
		data->entryData.srcLines = (SrcLine *) malloc(count);
		fread(data->entryData.srcLines, count, 1, mod);

		/*
		** Read the path data.
		*/
		data->numPathEntries = record.numPathEntries;
		data->pathEntries = (struct _tag_PathEntries*) malloc(count);
		fread(&data->startRecNum,  sizeof(ULONG), 1, mod);
		fread(&data->numPrimaries, sizeof(ULONG), 1, mod);
		fread(&data->numSrcFiles,  sizeof(ULONG), 1, mod);
		data = (HLLLineData *) realloc(data, sizeof(HLLLineData) +
				     sizeof(char *) * data->numSrcFiles);
		for(i=0; i<data->numSrcFiles; i++) {
		    UCHAR   numChars;

		    fread(&numChars, 1, 1, mod);
		    data->fileNames[i] = (char *) malloc(numChars+1);
		    fread(data->fileNames[i], numChars, 1, mod);
		    data->fileNames[i][numChars] = '\0';

		}
		lastModule->newLineData = data;
		break;
	    }

	    /*
	    ** Default case - display unknown module.
	    */
	    default: {
fprintf(stderr, "Type: Unknown: %04x\n", sectionDictionary[i].sectionType);
		break;
	    }
	}
    }
    fclose(mod);
    if(auxData->tag[0] != 'N' ||
       auxData->tag[1] != 'B') {
        free(auxData);
        module->AuxData = NULL;
        return 0;
    }

    /*
    ** Set up the links to access the data.
    */
    module->FindSource	   = HLLFindSource;
    module->FindSourceLine = HLLFindSourceLine;
    module->FindFuncAddr   = HLLFindFuncAddr;

    module->GetName	   = HLLGetName;
    module->GetArray	   = HLLGetArray;
    module->GetNumMembers  = HLLGetNumMembers;
    module->GetMemberIndex = HLLGetMemberIndex;

    return 1;
}

/*
** Define the stub for connecting to the system.
*/
int DispatchCommand(int command)
{
    if(Dispatch)
	return Dispatch(command);
    return DBG_N_Error;
}
