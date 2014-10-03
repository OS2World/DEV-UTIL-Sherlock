;	Static Name Aliases
;

	TITLE	$test

	.386P
	.387
_TEXT	SEGMENT  DWORD USE32 PUBLIC 'CODE'
_TEXT      ENDS
_DATA	SEGMENT  DWORD USE32 PUBLIC 'DATA'
cData	db	0
wData	dw	0
dData	dd	0
fData	df	0
qData	dq	0
rShort	dd	0
rLong	dq	0
rTemp	dt	0

_DATA      ENDS
CONST	SEGMENT  DWORD USE32 PUBLIC 'CONST'
CONST      ENDS
_BSS	SEGMENT  DWORD USE32 PUBLIC 'BSS'
_BSS	  ENDS
STACK	SEGMENT DWORD USE32 STACK 'STACK'
	dd	100 dup(0)
STACK	ENDS

TestOp	Macro	opcode
	opcode	eax, [esi]	    ; 00 ??? ???
	opcode	eax, [eax+2*ebx]    ; 00 100 ???    00 100 ???
	opcode	eax, [ecx+4*edx+1]  ; 00 100 ???    01 100 ???
	opcode	eax, [esi+8*edi+1234h];00 100 ???    10 100 ???
	opcode	eax, [esi + 4]	    ; 01 ??? ??? imm
	opcode	eax, [edi + 1234h] ; 10 ??? ??? imm imm imm imm
	opcode	eax, ebx	    ; 11 ??? ???
	opcode	eax, [2*eax+12h]
	opcode	eax, [bx]	    ; ADDR Override!
	opcode	eax, [bx+di+12h]
	opcode	eax, [bx+di+1234h]
	opcode	dData, eax
	opcode	ebx, dData
	opcode	dData, ebx
	opcode	eax, +1
	opcode	eax, 10000000h
	opcode	ebx, +1
	opcode	ebx, 10000000h

	opcode	ax, wData	   ; 00 ??? 101
	opcode	ax, [esi]	   ; 00 ??? ???
	opcode	ax, [eax+2*ebx]    ; 00 100 ???    00 100 ???
	opcode	ax, [ecx+4*edx+1]  ; 00 100 ???    01 100 ???
	opcode	ax, [esi+8*edi+1234h];00 100 ???    10 100 ???
	opcode	ax, [esi + 4]	   ; 01 ??? ??? imm
	opcode	ax, [edi + 1234h] ; 10 ??? ??? imm imm imm imm
	opcode	ax, bx		   ; 11 ??? ???
	opcode	ax, [2*eax+1234h]
	opcode	ax, [bx]	   ; ADDR Override!
	opcode	ax, [bx+di+1]
	opcode	ax, [bx+di+1234h]
	opcode	wData, ax
	opcode	bx, wData
	opcode	wData, bx
	opcode	ax, 1
	opcode	ax, 1234h
	opcode	bx, 1
	opcode	bx, 1234h

	opcode	al, cData	   ; 00 ??? 101
	opcode	al, [esi]	   ; 00 ??? ???
	opcode	al, [eax+2*ebx]    ; 00 100 ???    00 100 ???
	opcode	al, [ecx+4*edx+1]  ; 00 100 ???    01 100 ???
	opcode	al, [esi+8*edi+1234h];00 100 ???    10 100 ???
	opcode	al, [esi + 4]	   ; 01 ??? ??? imm
	opcode	al, [edi + 1234h] ; 10 ??? ??? imm imm imm imm
	opcode	al, cl		   ; 11 ??? ???
	opcode	al, [2*eax+1]
	opcode	al, [bx]	   ; ADDR Override!
	opcode	al, [bx+di+1]
	opcode	al, [bx+di+1234h]
	opcode	cData, al
	opcode	bl, cData
	opcode	cData, bl
	opcode	al, 1
	opcode	bl, 1
	opcode	eax, dData	    ; 00 ??? 101
	Endm

	ASSUME   CS: FLAT, DS: FLAT, SS: FLAT, ES: FLAT
PUBLIC  _main
_TEXT	SEGMENT  DWORD USE32 PUBLIC 'CODE'
_main	PROC NEAR
;   OK
;	 AAA
;   OK
;	 AAD
;   OK
;	 AAM
;   OK
;	 AAS
;   OK
;	 TestOp  ADC
;   OK
;	 TestOp  ADD
;   OK
;	 TestOp  AND
;
;   OK
;	 ARPL	 ax, bx
;
;   OK
;	 BOUND	 AX,dData
;	 BOUND	 EAX,qData
;
;   OK
;	 BSF	 AX,BX
;	 BSF	 AX,wData
;	 BSF	 EAX,EAX
;	 BSF	 EAX,dData
;
;   OK
;	 BSR	 AX,BX
;	 BSR	 AX,wData
;	 BSR	 EAX,EAX
;	 BSR	 EAX,dData
;
;UNABLE TO TEST!
;	 BSWAP	 EAX
;	 BSWAP	 EBX
;   OK
;	 BT	 AX,2
;	 BTC	 AX,3
;	 BTR	 AX,4
;	 BTS	 AX,5
;	 BT	 wData,6
;	 BTC	 wData,7
;	 BTR	 wData,8
;	 BTS	 wData,9
;   OK
;	 BT	 EAX,2
;	 BTC	 EAX,3
;	 BTR	 EAX,4
;	 BTS	 EAX,5
;	 BT	 dData,6
;	 BTC	 dData,7
;	 BTR	 dData,8
;	 BTS	 dData,9
;   OK
;	 BT	 AX,BX
;	 BTC	 AX,CX
;	 BTR	 AX,DX
;	 BTS	 AX,SI
;	 BT	 wData,AX
;	 BTC	 wData,BX
;	 BTR	 wData,CX
;	 BTS	 wData,DX
;   OK
;	 BT	 EAX,EBX
;	 BTC	 EAX,ECX
;	 BTR	 EAX,EDX
;	 BTS	 EAX,ESI
;	 BT	 dData,EAX
;	 BTC	 dData,EBX
;	 BTR	 dData,ECX
;	 BTS	 dData,EDX
;
t1	Label	near
t2	Label	far
;   OK
;	 CALL	 t1
;	 CALL	 t2
;   OK
;	 CALL	 EAX
;	 CALL	 [EAX]
;   OK
;	 CALL	 AX
;	 CALL	 [BX]
;   OK
;	 CALL	 dData
;	 CALL	 fData
;   OK
;	 CBW
;	 CDQ
;	 CLC
;	 CLD
;	 CLI
;	 CLTS
;	 CMC
;   OK
;	 TestOp  CMP
;   OK
;	 CMPSB
;	 CMPSW
;	 CMPSD
;   OK
;	 CWD
;	 CWDE
;	 DAA
;	 DAS
;   OK
;	 DEC	 AL
;	 DEC	 cData
;	 DEC	 AX
;	 DEC	 wData
;	 DEC	 EAX
;	 DEC	 dData
;   OK
;	 DIV	 DL
;	 DIV	 cData
;	 DIV	 DX
;	 DIV	 wData
;	 DIV	 EDX
;	 DIV	 dData
;   OK
;	 ENTER	 10,0
;	 HLT
;   OK
;	 IDIV	 DL
;	 IDIV	 cData
;	 IDIV	 DX
;	 IDIV	 wData
;	 IDIV	 EDX
;	 IDIV	 dData
;   OK
;	 IMUL	 DL
;	 IMUL	 cData
;	 IMUL	 DX
;	 IMUL	 wData
;	 IMUL	 EDX
;	 IMUL	 dData
;   OK
;	 IN	 AL,10h
;	 IN	 AL,DX
;	 IN	 AX,20h
;	 IN	 AX,DX
;	 IN	 EAX,40h
;	 IN	 EAX,DX
;   OK
;	 INC	 AL
;	 INC	 cData
;	 INC	 AX
;	 INC	 wData
;	 INC	 EAX
;	 INC	 dData
;   OK
;	 INSB
;	 INSW
;	 INSD
;	 REP INSB
;   OK
;	 INT	 3
;	 INT	 10h
;	 INTO
;   OK
;	 IRET
;   OK
;	 JB	 $
;	 JAE	 $
;	 JBE	 $
;	 JA	 $
;	 JE	 $
;	 JNE	 $
;	 JL	 $
;	 JGE	 $
;	 JLE	 $
;	 JG	 $
;	 JS	 $
;	 JNS	 $
;	 JO	 $
;	 JNO	 $
;	 JP	 $
;	 JNP	 $
;   OK
;	 JB	 $ + 400h
;	 JAE	 $ + 400h
;	 JBE	 $ + 400h
;	 JA	 $ + 400h
;	 JE	 $ + 400h
;	 JNE	 $ + 400h
;	 JL	 $ + 400h
;	 JGE	 $ + 400h
;	 JLE	 $ + 400h
;	 JG	 $ + 400h
;	 JS	 $ + 400h
;	 JNS	 $ + 400h
;	 JO	 $ + 400h
;	 JNO	 $ + 400h
;	 JP	 $ + 400h
;	 JNP	 $ + 400h
;   OK
;	 JCXZ	 $
;	 JECXZ	 $
;   OK
;	 JMP	 $
;	 JMP	 $+400h
;	 JMP	 $+10000000h
;	 JMP	 t1
;	 JMP	 t2
;	 JMP	 AX
;	 JMP	 EAX
;	 JMP	 wData
;	 JMP	 dData
;	 JMP	 fData
;	 JMP	 FAR PTR dData
;   OK
;	 LAHF
;   OK
;	 LAR	 AX,BX
;	 LAR	 EAX,EBX
;	 LAR	 AX,wData
;	 LAR	 EAX,dData
;   OK
;	 LDS	 SI,dData
;	 LDS	 ESI,fData
;	 LES	 SI,dData
;	 LES	 ESI,fData
;	 LFS	 SI,dData
;	 LFS	 ESI,fData
;	 LGS	 SI,dData
;	 LGS	 ESI,fData
;	 LSS	 SI,dData
;	 LSS	 ESI,fData
;   OK
;	 LEA	 AX,wData
;	 LEA	 EAX,cData
;   OK
;	 LEAVE
;   OK
;	 LGDT	 fData
;	 LIDT	 fData
;	 LLDT	 AX
;	 LLDT	 wData
;   OK
;	 LMSW	 AX
;	 LMSW	 wData
;   OK
;	 LOCK LODSB
;   OK
;	 LODSB
;	 LODSW
;	 LODSD
;   OK
;	 LOOP	 $
;   OK
;	 LOOPE	 $
;   CAN NOT TEST
;	 LOOPEW  l1
;   OK
;	 LOOPNE  $
;   CAN NOT TEST
;	 LOOPNEW l1
;   OK
;	 LSL	 AX,BX
;	 LSL	 EAX,EBX
;   OK
;	 LSL	 AX,wData
;	 LSL	 EAX,dData
;   OK
;	 LTR	 AX
;	 LTR	 wData
;   OK
;	 TestOp  Mov
;   OK
;	 MOV	 DS,AX
;	 MOV	 ES,wData
;	 MOV	 AX,DS
;	 MOV	 wData,ES
;   OK
;	 MOV	 EAX,CR0
;	 MOV	 CR2,EBX
;   OK
;	 MOV	 EDX,DR7
;	 MOV	 DR0,ECX
;   OK
;	 MOV	 EAX,TR6
;	 MOV	 TR7,EBX
;   OK
;	 MOVSB
;	 MOVSW
;	 MOVSD
;   OK
;	 MOVSX	 EAX,BX
;	 MOVSX	 AX,AL
;   OK
;	 MOVZX	 EAX,BX
;	 MOVZX	 BX,CL
;   OK
;	 MUL	 DL
;	 MUL	 cData
;	 MUL	 DX
;	 MUL	 wData
;	 MUL	 EDX
;	 MUL	 dData
;   OK
;	 NEG	 AL
;	 NEG	 cData
;	 NEG	 BX
;	 NEG	 wData
;	 NEG	 ECX
;	 NEG	 dData
;   OK
;	 NOP
;   OK
;	 NOT	 DL
;	 NOT	 cData
;	 NOT	 DX
;	 NOT	 wData
;	 NOT	 EDX
;	 NOT	 dData
;   OK
;	 TestOp  OR
;   OK
;	 OUT	 10H,AL
;	 OUT	 DX,AL
;	 OUT	 20H,AX
;	 OUT	 DX,AX
;	 OUT	 40H,EAX
;	 OUT	 DX,EAX
;   OK
;	 OUTSB
;	 OUTSW
;	 OUTSD
;   OK
;	 POP	 AX
;	 POP	 EAX
;   OK
;	 POP	 wData
;	 POP	 dData
;   OK
;	 POP	 ES
;	 POP	 FS
;   OK
;	 POPA
;	 POPAD
;	 POPF
;	 POPFD
;   OK
;	 PUSH	 AX
;	 PUSH	 EAX
;   OK
;	 PUSH	 wData
;	 PUSH	 dData
;   OK
;	 PUSH	 ES
;	 PUSH	 FS
;   OK
;	 PUSHA
;	 PUSHAD
;	 PUSHF
;	 PUSHFD
;   OK
;	 ROL	 AL,1
;	 ROL	 AX,1
;	 ROL	 EAX,1
;	 ROR	 AL,1
;	 ROR	 AX,1
;	 ROR	 EAX,1
;   OK
;	 RCL	 AL,1
;	 RCL	 AX,1
;	 RCL	 EAX,1
;	 RCR	 AL,1
;	 RCR	 AX,1
;	 RCR	 EAX,1
;   OK
;	 ROL	 cData,1
;	 ROL	 wData,1
;	 ROL	 dData,1
;	 ROR	 cData,1
;	 ROR	 wData,1
;	 ROR	 dData,1
;   OK
;	 RCL	 cData,1
;	 RCL	 wData,1
;	 RCL	 dData,1
;	 RCR	 cData,1
;	 RCR	 wData,1
;	 RCR	 dData,1
;   OK
;	 ROL	 AL,CL
;	 ROL	 AX,CL
;	 ROL	 EAX,CL
;	 ROR	 AL,CL
;	 ROR	 AX,CL
;	 ROR	 EAX,CL
;   OK
;	 RCL	 AL,CL
;	 RCL	 AX,CL
;	 RCL	 EAX,CL
;	 RCR	 AL,CL
;	 RCR	 AX,CL
;	 RCR	 EAX,CL
;   OK
;	 ROL	 cData,CL
;	 ROL	 wData,CL
;	 ROL	 dData,CL
;	 ROR	 cData,CL
;	 ROR	 wData,CL
;	 ROR	 dData,CL
;   OK
;	 RCL	 cData,CL
;	 RCL	 wData,CL
;	 RCL	 dData,CL
;	 RCR	 cData,CL
;	 RCR	 wData,CL
;	 RCR	 dData,CL
;   OK
;	 ROL	 AL,8
;	 ROL	 AX,8
;	 ROL	 EAX,8
;	 ROR	 AL,8
;	 ROR	 AX,8
;	 ROR	 EAX,8
;   OK
;	 RCL	 AL,8
;	 RCL	 AX,8
;	 RCL	 EAX,8
;	 RCR	 AL,8
;	 RCR	 AX,8
;	 RCR	 EAX,8
;   OK
;	 ROL	 cData,8
;	 ROL	 wData,8
;	 ROL	 dData,8
;	 ROR	 cData,8
;	 ROR	 wData,8
;	 ROR	 dData,8
;   OK
;	 RCL	 cData,8
;	 RCL	 wData,8
;	 RCL	 dData,8
;	 RCR	 cData,8
;	 RCR	 wData,8
;	 RCR	 dData,8
;   OK
;	 REP	 MOVSB
;	 REPE	 MOVSB
;	 REPNE	 MOVSB
;   OK
;	 RETN
;	 RETN	 16
;   OK
;	 RETF
;	 RETF	 122
;   OK
;	 SAHF
;   OK
;	 TestOp  SBB
;   OK
;	 SCASB
;	 SCASW
;	 SCASD
;   OK
;	 SETB	 AL
;	 SETAE	 AL
;	 SETBE	 AL
;	 SETA	 AL
;	 SETE	 AL
;	 SETNE	 AL
;	 SETL	 AL
;	 SETGE	 AL
;	 SETLE	 AL
;	 SETG	 AL
;	 SETS	 AL
;	 SETNS	 AL
;	 SETO	 AL
;	 SETNO	 AL
;	 SETP	 AL
;	 SETNP	 AL
;   OK
;	 SHL	 AL,1
;	 SHL	 AX,1
;	 SHL	 EAX,1
;	 SHR	 AL,1
;	 SHR	 AX,1
;	 SHR	 EAX,1
;   OK
;	 SAR	 AL,1
;	 SAR	 AX,1
;	 SAR	 EAX,1
;   OK
;	 SHL	 cData,1
;	 SHL	 wData,1
;	 SHL	 dData,1
;	 SHR	 cData,1
;	 SHR	 wData,1
;	 SHR	 dData,1
;   OK
;	 SAR	 cData,1
;	 SAR	 wData,1
;	 SAR	 dData,1
;   OK
;	 SHL	 AL,CL
;	 SHL	 AX,CL
;	 SHL	 EAX,CL
;	 SHR	 AL,CL
;	 SHR	 AX,CL
;	 SHR	 EAX,CL
;   OK
;	 SAR	 AL,CL
;	 SAR	 AX,CL
;	 SAR	 EAX,CL
;   OK
;	 SHL	 cData,CL
;	 SHL	 wData,CL
;	 SHL	 dData,CL
;	 SHR	 cData,CL
;	 SHR	 wData,CL
;	 SHR	 dData,CL
;   OK
;	 SAR	 cData,CL
;	 SAR	 wData,CL
;	 SAR	 dData,CL
;   OK
;	 SHL	 AL,8
;	 SHL	 AX,8
;	 SHL	 EAX,8
;	 SHR	 AL,8
;	 SHR	 AX,8
;	 SHR	 EAX,8
;   OK
;	 SAR	 AL,8
;	 SAR	 AX,8
;	 SAR	 EAX,8
;   OK
;	 SHL	 cData,8
;	 SHL	 wData,8
;	 SHL	 dData,8
;	 SHR	 cData,8
;	 SHR	 wData,8
;	 SHR	 dData,8
;   OK
;	 SAR	 cData,8
;	 SAR	 wData,8
;	 SAR	 dData,8
;   OK
;	 SGDT	 fData
;	 SIDT	 fData
;	 SLDT	 AX
;	 SLDT	 wData
;   OK
;	 SHLD	 AX,DX,10
;	 SHLD	 EAX,EDX,10
;   OK
;	 SHLD	 wData,AX,4
;	 SHLD	 dData,EAX,5
;   OK
;	 SHRD	 AX,DX,10
;	 SHRD	 EAX,EDX,10
;   OK
;	 SHRD	 wData,AX,4
;	 SHRD	 dData,EAX,5
;   OK
;	 SHLD	 AX,DX,CL
;	 SHLD	 EAX,EDX,CL
;   OK
;	 SHLD	 wData,AX,CL
;	 SHLD	 dData,EAX,CL
;   OK
;	 SHRD	 AX,DX,CL
;	 SHRD	 EAX,EDX,CL
;   OK
;	 SHRD	 wData,AX,CL
;	 SHRD	 dData,EAX,CL
;   OK
;	 SMSW	 AX
;	 SMSW	 wData
;   OK
;	 STC
;	 STD
;	 STI
;   OK
;	 STOSB
;	 STOSW
;	 STOSD
;   OK
;	 STR	 AX
;	 STR	 wData
;   OK
;	 TestOp  SUB
;   OK
;	 TestOp  Test
;   OK
;	 VERR	 AX
;	 VERR	 wData
;   OK
;	 VERW	 AX
;	 VERW	 wData
;   OK
;	 WAIT
;   OK
;	 XCHG	 BL,cData
;	 XCHG	 cData,BL
;	 XCHG	 BL,CL
;   OK
;	 XCHG	 BX,wData
;	 XCHG	 wData,BX
;	 XCHG	 BX,CX
;   OK
;	 XCHG	 EBX,dData
;	 XCHG	 dData,EBX
;	 XCHG	 EBX,ECX
;   OK
;	 XCHG	 AX,BX
;	 XCHG	 BX,AX
;   OK
;	 XCHG	 EAX,EBX
;	 XCHG	 EBX,EAX
;   OK
;	 XLAT
;   OK
;	 XOR	 BL,CL
;	 XOR	 cData,BL
;	 XOR	 BL,cData
;   OK
;	 XOR	 BX,CX
;	 XOR	 wData,BX
;	 XOR	 BX,wData
;   OK
;	 XOR	 EBX,ECX
;	 XOR	 dData,EBX
;	 XOR	 EBX,dData
;   OK
;	 XOR	 BL,10h
;	 XOR	 BX,10h
;	 XOR	 EBX,10h
;   OK
;	 XOR	 cData,10h
;	 XOR	 wData,10h
;	 XOR	 dData,10h
;   OK
;	 XOR	 AL,10h
;	 XOR	 AX,10h
;	 XOR	 EAX,10h
;
;   OK
;	 F2XM1
;	 FABS
;   OK
;	 FADD	 ST,ST(2)
;	 FADD	 ST(2),ST
;   OK
;	 FADDP	 ST(2),ST
;   OK
;	 FADD	 rShort
;	 FADD	 rLong
;   BAD!
;	 FIADD	 wData
;	 FIADD	 dData
;   OK
;	 FCHS
;   OK
;	 FCLEX
;	 FNCLEX
;   OK
;	 FCOM	 ST(2)
;	 FCOMP	 ST(2)
;	 FCOMPP
;   OK
;	 FCOM	 rShort
;	 FCOM	 rLong
;   BAD!
;	 FICOM	 wData
;	 FICOM	 dData
;   BAD!
;	 FICOMP  wData
;	 FICOMP  dData
;   OK
;	 FCOS
;	 FDECSTP
;   OK
;	 FDISI
;	 FNDISI
;   OK
;	 FDIV	 ST,ST(2)
;	 FDIV	 ST(2),ST
;   OK
;	 FDIVP	 ST(2),ST
;	 FDIV	 rShort
;	 FDIV	 rLong
;   OK
;	 FIDIV	 wData
;	 FIDIV	 dData
;   OK
;	 FDIVR	 ST,ST(2)
;	 FDIVR	 ST(2),ST
;   OK
;	 FDIVRP  ST(2),ST
;   OK
;	 FDIVR	 rShort
;	 FDIVR	 rLong
;   BAD!
;	 FIDIVR  wData
;	 FIDIVR  dData
;   OK
;	 FENI
;	 FNENI
;   OK
;	 FFREE	 ST(1)
;   OK
;	 FINCSTP
;   OK
;	 FINIT
;	 FNINIT
;   OK
;	 FLD	 ST(3)
;	 FLD	 rShort
;	 FLD	 rLong
;	 FLD	 rTemp
;	 FBLD	 rTemp
;   BAD!
;	 FILD	 wData
;	 FILD	 dData
;   OK
;	 FLD1
;	 FLDZ
;	 FLDPI
;	 FLDL2E
;	 FLDL2T
;	 FLDLG2
;	 FLDLN2
;   OK
;	 FLDCW	 wData
;   OK
;	 FLDENV  [bp+10]
;	 FLDENV  wData
;   OK
;	 FMUL	 ST,ST(2)
;	 FMUL	 ST(2),ST
;   OK
;	 FMULP	 ST(2),ST
;   OK
;	 FMUL	 rShort
;	 FMUL	 rLong
;   OK
;	 FIMUL	 wData
;	 FIMUL	 dData
;   OK
;	 FNOP
;	 FPATAN
;	 FPREM
;	 FPREM1
;	 FPTAN
;	 FRNDINT
;   OK
;	 FRSTOR  [BP+10]
;	 FRSTOR  wData
;   OK
;	 FSAVE	 [BP+10]
;   OK
;	 FSCALE
;	 FSETPM
;	 FSIN
;	 FSINCOS
;	 FSQRT
;   OK
;	 FST	 ST(3)
;	 FSTP	 ST(3)
;   OK
;	 FST	 rShort
;	 FST	 rLong
;   OK
;	 FSTP	 rShort
;	 FSTP	 rLong
;	 FSTP	 rTemp
;   BAD!
;	 FIST	 wData
;	 FIST	 dData
;	 FISTP	 wData
;	 FISTP	 dData
;   OK
;	 FBSTP	 rTemp
;   OK
;	 FSUB	 ST,ST(2)
;	 FSUB	 ST(2),ST
;   OK
;	 FSUBP	 ST(2),ST
;   OK
;	 FSUB	 rShort
;	 FSUB	 rLong
;   BAD!
;	 FISUB	 wData
;	 FISUB	 dData
;   OK
;	 FSUBR	 ST,ST(2)
;	 FSUBR	 ST(2),ST
;   OK
;	 FSUBRP  ST(2),ST
;   OK
;	 FSUBR	 rShort
;	 FSUBR	 rLong
;   BAD!
;	 FISUBR  wData
;	 FISUBR  dData
;   OK
;	 FSTSW	 wData
;	 FSTSW	 AX
;   OK
;	 FSTENV  [BP+10]
;   OK
;	 FTST
;   OK
;	 FUCOM	 ST(2)
;	 FUCOMP  ST(2)
;	 FUCOMPP
;   OK
;	 FWAIT
;	 FXAM
;	 FXCH	 ST(3)
;	 FXTRACT
;	 FYL2X
;	 FYL2XP1

_main	ENDP

_TEXT	ENDS
	END _main
