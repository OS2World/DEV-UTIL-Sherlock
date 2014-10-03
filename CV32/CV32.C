/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
** Code view interface functions to extract symbolic information
** given a state to extract information from.
*/
#include    <stdio.h>
#include    <string.h>
#include    <malloc.h>
#include    <memory.h>
#include    <sys\stat.h>

#define     INCL_DOSPROCESS
#include    <os2.h>
#include    "..\Debug.h"

#include    "..\SrcInter.h"
#include    "CV.h"
#include    "CV32.h"

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
** Answer whether the module named is a code view module.
** If so, set the function pointers and return true.
*/
int _System isKnownModule(DebugModule *module,
		 int (* _System DispatchCommand)(int command),
		 DebugBuffer *buffer)
{
CVAuxData  *auxData;
CVModule   *lastModule = NULL;
FILE       *mod;
USHORT      i;
USHORT      numSections;
ULONG       sectionBaseOffset;
struct stat statBuff;
SubSectionDictionary *sectionDictionary;

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
    module->AuxData = (void *) calloc(sizeof(CVAuxData), 1);
    auxData = (CVAuxData *) module->AuxData;
    fread(&auxData->tag[0], 8, 1, mod);

    /*
    ** Make sure that we have Codeview information.
    */
    if(strncmp(auxData->tag, "NB00", 4) != 0) {
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
    ** Double check that we have Codeview information.
    */
    if(strncmp(auxData->tag, "NB00", 4) != 0) {
        fclose(mod);
        return 0;
    }

    /*
    ** Find the section dictionary and read it in.
    */
    fseek(mod, sectionBaseOffset + auxData->dirOffset, SEEK_SET);
    fread(&numSections, sizeof(USHORT), 1, mod);
    sectionDictionary = (SubSectionDictionary *) malloc(numSections * sizeof(SubSectionDictionary));
    fread(sectionDictionary, sizeof(SubSectionDictionary), numSections, mod);

    /*
    ** Read each section into a module.
    */
    for(i=0; i<numSections; i++) {
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
		    lastModule = (CVModule *) calloc(sizeof(CVModule), 1);
		    auxData->moduleData = lastModule;
                } else {
		    lastModule->next = (CVModule *) calloc(sizeof(CVModule), 1);
                    lastModule = lastModule->next;
                }
		lastModule->module = (ModulesDataEntry32 *) malloc(sectionSize+1);
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
                PublicsDataEntry32 *entry;
                CVPublic32         *next;
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

                    numBytes = (USHORT) entry->cbName + (USHORT) sizeof(PublicsDataEntry32);
                    if(lastModule->public == NULL) {
			next = lastModule->public = (CVPublic32 *)
                            malloc(sizeof(CVPublic32) + entry->cbName + 1);
                    } else {
			next->next = (CVPublic32 *)
                            malloc(sizeof(CVPublic32) + entry->cbName + 1);
                        next = next->next;
                    }
                    next->next = NULL;
		    memcpy(&next->data, entry, numBytes);
		    next->data.name[entry->cbName] = '\0';
		    ptr = (char *) entry;
		    ptr += entry->cbName + sizeof(PublicsDataEntry32) - 1;
                    entry = (PublicsDataEntry32 *) ptr;
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
            ** Is this a Source line number record.
            */
            case sstSrcLines: {
                char *name;
                USHORT count;
                char   cbName;
                LineOffsetEntry32 *lineData;

                /*
                ** Allocate the memory used.
                */
		lastModule->lineData = (CVLineData *) malloc(sizeof(CVLineData));

                /*
                ** Read in the name.
                */
                fread(&cbName, 1, 1, mod);
		name = (char *) malloc(cbName + 1);
                fread(name, cbName, 1, mod);
                name[cbName] = '\0';
                lastModule->lineData->fileName = name;

                /*
                ** Read in the line data.
                */
                lastModule->lineData->segment = 0;
                fread(&count, 2, 1, mod);
                lastModule->lineData->count = count;
		lineData = (LineOffsetEntry32 *) malloc(sizeof(LineOffsetEntry32) * count);
                lastModule->lineData->lineData = lineData;
                fread(lineData, sizeof(LineOffsetEntry32) * count, 1, mod);
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
            ** Compacted type record.
            */
            case sstCompacted: {
		auxData->compactedData = (char *) malloc(sectionSize+1);
                fread(auxData->compactedData, sectionSize, 1, mod);
                auxData->compactedSize = sectionSize;
                break;
            }

            /*
            ** Is this a Source line number record with segment.
            */
            case sstSrcLnSeg: {
                char *name;
                LineOffsetEntry32 *lineData;
                USHORT count;
                USHORT segment;
                char   cbName;

                /*
                ** Allocate the memory used.
                */
		lastModule->lineData = (CVLineData *) malloc(sizeof(CVLineData));

                /*
                ** Read in the name.
                */
                fread(&cbName, 1, 1, mod);
		name = (char *) malloc(cbName + 1);
                fread(name, cbName, 1, mod);
                name[cbName] = '\0';
                lastModule->lineData->fileName = name;

                /*
                ** Read in the line data.
                */
                fread(&segment, 2, 1, mod);
                lastModule->lineData->segment = segment;
                fread(&count, 2, 1, mod);
                lastModule->lineData->count = count;
		lineData = (LineOffsetEntry32 *) malloc(sizeof(LineOffsetEntry32) * count);
                lastModule->lineData->lineData = lineData;
                fread(lineData, sizeof(LineOffsetEntry32), count, mod);
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
    module->FindSource     = CVFindSource;
    module->FindSourceLine = CVFindSourceLine;
    module->FindFuncAddr   = CVFindFuncAddr;

    module->GetName	   = CVGetName;
    module->GetArray	   = CVGetArray;
    module->GetNumMembers  = CVGetNumMembers;
    module->GetMemberIndex = CVGetMemberIndex;
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
