/*
**  Sherlock - Copyright 1992, 1993, 1994
**    Harfmann Software
**    Compuserve: 73147,213
**    All rights reserved
*/
/*
** Structures
*/
#pragma pack(1)
typedef struct  {
         unsigned long   Pid;        /* Debuggee Process ID */
         unsigned long   Tid;        /* Debuggee Thread ID */
         long            Cmd;        /* Command or Notification */
         long            Value;      /* Generic Data Value */
         unsigned long   Addr;       /* Debuggee Address */
         unsigned long   Buffer;     /* Debugger Buffer Address */
         unsigned long   Len;        /* Length of Range */
         unsigned long   Index;      /* Generic Identifier Index */
         unsigned long   MTE;        /* Module Table Entry Handle */
         unsigned long   EAX;        /* Register Set */
         unsigned long   ECX;
         unsigned long   EDX;
         unsigned long   EBX;
         unsigned long   ESP;
         unsigned long   EBP;
         unsigned long   ESI;
         unsigned long   EDI;
         unsigned long   EFlags;
         unsigned long   EIP;
         unsigned long   CSLim;      /* Byte Granular Limits */
         unsigned long   CSBase;     /* Byte Granular Base */
         unsigned char   CSAcc;      /* Access Bytes */
         unsigned char   CSAtr;      /* Attribute Bytes */
         unsigned short  CS;
         unsigned long   DSLim;
         unsigned long   DSBase;
         unsigned char   DSAcc;
         unsigned char   DSAtr;
         unsigned short  DS;
         unsigned long   ESLim;
         unsigned long   ESBase;
         unsigned char   ESAcc;
         unsigned char   ESAtr;
         unsigned short  ES;
         unsigned long   FSLim;
         unsigned long   FSBase;
         unsigned char   FSAcc;
         unsigned char   FSAtr;
         unsigned short  FS;
         unsigned long   GSLim;
         unsigned long   GSBase;
         unsigned char   GSAcc;
         unsigned char   GSAtr;
         unsigned short  GS;
         unsigned long   SSLim;
         unsigned long   SSBase;
         unsigned char   SSAcc;
         unsigned char   SSAtr;
         unsigned short  SS;
} DebugBuffer;

typedef struct {
    unsigned char   DbgState;
    unsigned char   TState;
    unsigned short  TPriority;
} ThreadState;

typedef struct {
    ULONG losig;
    ULONG hisig;
    USHORT signexp;
} FPReg;

typedef struct {
    struct {
	int invalidOp:1;
	int denormal:1;
	int zeroDiv:1;
	int overflow:1;
	int underflow:1;
	int precision:1;
	int res1:1;
	int res2:1;
	int precCntl:2;
	int roundCntl:2;
	int infinity:1;
	int res3:3;
    } control;
    struct {
	int invalidOp:1;
	int denormal:1;
	int zeroDiv:1;
	int overflow:1;
	int underflow:1;
	int precision:1;
	int res1:1;
	int errStat:1;
	int cond1:3;
	int tos:3;
	int cond2:1;
	int neuBusy:1;
    } status;
    struct {
	int tag0:2;
	int tag1:2;
	int tag2:2;
	int tag3:2;
	int tag4:2;
	int tag5:2;
	int tag6:2;
	int tag7:2;
    } tags;
    ULONG ip[2];
    ULONG operand[2];
    FPReg reg[8];
} FPState;
#pragma pack()

/*
** Available debugger levels.
*/
#define DBG_L_386              1  /* Debug a 386.                           */

/*
** Command values.
*/
#define DBG_C_Null             0  /* Null                                   */
#define DBG_C_ReadMem          1  /* Read Word                              */
#define DBG_C_ReadMem_I        1  /* Read Word                              */
#define DBG_C_ReadMem_D        2  /* Read Word (same as 1)                  */
#define DBG_C_ReadReg          3  /* Read Register Set                      */
#define DBG_C_WriteMem         4  /* Write Word                             */
#define DBG_C_WriteMem_I       4  /* Write Word                             */
#define DBG_C_WriteMem_D       5  /* Write Word (same as 4)                 */
#define DBG_C_WriteReg         6  /* Write Register Set                     */
#define DBG_C_Go               7  /* Go                                     */
#define DBG_C_Term             8  /* Terminate                              */
#define DBG_C_SStep            9  /* Single Step                            */
#define DBG_C_Stop            10  /* Stop                                   */
#define DBG_C_Freeze          11  /* Freeze Thread                          */
#define DBG_C_Resume          12  /* Resume Thread                          */
#define DBG_C_NumToAddr       13  /* Object Number to Address               */
#define DBG_C_ReadCoRegs      14  /* Read Coprocessor Registers             */
#define DBG_C_WriteCoRegs     15  /* Write Coprocessor Registers            */
#define DBG_C_ThrdStat        17  /* Get Thread Status                      */
#define DBG_C_MapROAlias      18  /* Map Read-Only Alias                    */
#define DBG_C_MapRWAlias      19  /* Map Read-Write Alias                   */
#define DBG_C_UnMapAlias      20  /* Unmap Alias                            */
#define DBG_C_Connect         21  /* Connect to Debuggee                    */
#define DBG_C_ReadMemBuf      22  /* Read Memory Buffer                     */
#define DBG_C_WriteMemBuf     23  /* Write Memory Buffer                    */
#define DBG_C_SetWatch        24  /* Set Watchpoint                         */
#define DBG_C_ClearWatch      25  /* Clear Watchpoint                       */
#define DBG_C_RangeStep       26  /* Range Step                             */
#define DBG_C_Continue        27  /* Continue (Set Exception State)         */
#define DBG_C_AddrToObject    28  /* Get Memory Object Information          */
#define DBG_C_XchgOpcode      29  /* Exchange Opcode, Step, and Go	    */
#define DBG_C_LinToSel        30  /* Translate Linear to Segmented address  */
#define DBG_C_SelToLin        31  /* Translate Segmented to Linear Address  */

/*
** Notification values.
*/
#define DBG_N_Success          0  /* Successful command completion          */
#define DBG_N_Error           -1  /* Error detected during command          */
#define DBG_N_ProcTerm        -6  /* Process termination - DosExitList done */
#define DBG_N_Exception       -7  /* Exception detected                     */
#define DBG_N_ModuleLoad      -8  /* Module loaded                          */
#define DBG_N_CoError         -9  /* Coprocessor not in use error           */
#define DBG_N_ThreadTerm     -10  /* Thread termination - not in DosExitList*/
#define DBG_N_AsyncStop      -11  /* Async Stop detected                    */
#define DBG_N_NewProc        -12  /* New Process started                    */
#define DBG_N_AliasFree      -13  /* Alias needs to be freed                */
#define DBG_N_Watchpoint     -14  /* Watchpoint hit                         */
#define DBG_N_ThreadCreate   -15  /* Thread creation                        */
#define DBG_N_ModuleFree     -16  /* Module freed                           */
#define DBG_N_RangeStep      -17  /* Range Step detected                    */

/*
** DbgState in the Thread Status buffer contains info about the
** current state of debugging as follows:
*/
#define DBG_D_Thawed        0
#define DBG_D_Frozen        1

/*
** TState in the Thread Status buffer contains info about the
** scheduling about a thread as follows:
*/
#define DBG_T_Runnable      0
#define DBG_T_Suspended     1
#define DBG_T_Blocked       2
#define DBG_T_CritSec       3

/*
** Watch scopes and types.
*/
#define DBG_W_Global        0x00000001
#define DBG_W_Local         0x00000002
#define DBG_W_Execute       0x00010000
#define DBG_W_Write         0x00020000
#define DBG_W_ReadWrite     0x00030000

/*
** define the floating point manifest constants.
*/
#define TAG_VALID   0
#define TAG_ZERO    1
#define TAG_INVALID 2
#define TAG_EMPTY   3
