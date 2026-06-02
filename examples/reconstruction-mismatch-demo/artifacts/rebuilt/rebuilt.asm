	TITLE	src/rebuilt/rebuilt.cpp
	.386P
include listing.inc
if @Version gt 510
.model FLAT
else
_TEXT	SEGMENT PARA USE32 PUBLIC 'CODE'
_TEXT	ENDS
_DATA	SEGMENT DWORD USE32 PUBLIC 'DATA'
_DATA	ENDS
CONST	SEGMENT DWORD USE32 PUBLIC 'CONST'
CONST	ENDS
_BSS	SEGMENT DWORD USE32 PUBLIC 'BSS'
_BSS	ENDS
_TLS	SEGMENT DWORD USE32 PUBLIC 'TLS'
_TLS	ENDS
;	COMDAT ??0ScoreTable@@QAE@H@Z
_TEXT	SEGMENT PARA USE32 PUBLIC 'CODE'
_TEXT	ENDS
;	COMDAT ??0Reactor@@QAE@H@Z
_TEXT	SEGMENT PARA USE32 PUBLIC 'CODE'
_TEXT	ENDS
;	COMDAT ??0Door@@QAE@H@Z
_TEXT	SEGMENT PARA USE32 PUBLIC 'CODE'
_TEXT	ENDS
;	COMDAT ??0LessonLog@@QAE@H@Z
_TEXT	SEGMENT PARA USE32 PUBLIC 'CODE'
_TEXT	ENDS
FLAT	GROUP _DATA, CONST, _BSS
	ASSUME	CS: FLAT, DS: FLAT, SS: FLAT
endif
PUBLIC	?g_Title_00407030@@3PADA			; g_Title_00407030
PUBLIC	?g_Bonus_00407038@@3HA				; g_Bonus_00407038
PUBLIC	?g_Threshold_0040703C@@3HA			; g_Threshold_0040703C
PUBLIC	?g_Rotor_00407040@@3PAHA			; g_Rotor_00407040
_DATA	SEGMENT
?g_Title_00407030@@3PADA DB 'ALIEN!', 00H		; g_Title_00407030
	ORG $+1
?g_Bonus_00407038@@3HA DD 09H				; g_Bonus_00407038
?g_Threshold_0040703C@@3HA DD 0aH			; g_Threshold_0040703C
?g_Rotor_00407040@@3PAHA DD 03H				; g_Rotor_00407040
	DD	05H
	DD	08H
_DATA	ENDS
PUBLIC	?score@ScoreTable@@QBEHH@Z			; ScoreTable::score
_TEXT	SEGMENT
; File src/rebuilt/rebuilt.cpp
_value$ = 8
_this$ = -8
_total$ = -4
?score@ScoreTable@@QBEHH@Z PROC NEAR			; ScoreTable::score
; Line 44
	push	ebp
	mov	ebp, esp
	sub	esp, 8
	push	ebx
	push	esi
	push	edi
	mov	DWORD PTR _this$[ebp], ecx
; Line 45
	mov	eax, DWORD PTR _this$[ebp]
	mov	eax, DWORD PTR [eax]
	add	eax, DWORD PTR _value$[ebp]
	mov	DWORD PTR _total$[ebp], eax
; Line 46
	cmp	DWORD PTR _total$[ebp], 12		; 0000000cH
	jle	$L210
; Line 47
	mov	eax, DWORD PTR ?g_Bonus_00407038@@3HA	; g_Bonus_00407038
	add	DWORD PTR _total$[ebp], eax
; Line 49
$L210:
	mov	eax, DWORD PTR _total$[ebp]
	jmp	$L208
; Line 50
$L208:
	pop	edi
	pop	esi
	pop	ebx
	leave
	ret	4
?score@ScoreTable@@QBEHH@Z ENDP				; ScoreTable::score
_TEXT	ENDS
PUBLIC	?tick@Reactor@@QAEHH@Z				; Reactor::tick
_TEXT	SEGMENT
_coolant$ = 8
_this$ = -4
?tick@Reactor@@QAEHH@Z PROC NEAR			; Reactor::tick
; Line 54
	push	ebp
	mov	ebp, esp
	sub	esp, 4
	push	ebx
	push	esi
	push	edi
	mov	DWORD PTR _this$[ebp], ecx
; Line 55
	mov	eax, DWORD PTR _this$[ebp]
	add	DWORD PTR [eax], 3
; Line 56
	cmp	DWORD PTR _coolant$[ebp], 0
	jle	$L214
; Line 57
	xor	eax, eax
	mov	ecx, DWORD PTR _coolant$[ebp]
	lea	ecx, DWORD PTR [ecx+ecx*2]
	sub	eax, ecx
	neg	eax
	mov	ecx, DWORD PTR _this$[ebp]
	sub	DWORD PTR [ecx], eax
; Line 59
$L214:
	mov	eax, DWORD PTR _this$[ebp]
	mov	eax, DWORD PTR [eax]
	jmp	$L213
; Line 60
$L213:
	pop	edi
	pop	esi
	pop	ebx
	leave
	ret	4
?tick@Reactor@@QAEHH@Z ENDP				; Reactor::tick
_TEXT	ENDS
PUBLIC	?canOpen@Door@@QBEHH@Z				; Door::canOpen
_TEXT	SEGMENT
_passcode$ = 8
_this$ = -4
?canOpen@Door@@QBEHH@Z PROC NEAR			; Door::canOpen
; Line 64
	push	ebp
	mov	ebp, esp
	sub	esp, 4
	push	ebx
	push	esi
	push	edi
	mov	DWORD PTR _this$[ebp], ecx
; Line 65
	mov	eax, DWORD PTR _this$[ebp]
	mov	ecx, DWORD PTR _passcode$[ebp]
	cmp	DWORD PTR [eax], ecx
	jne	$L218
; Line 66
	mov	eax, 1
	jmp	$L217
; Line 68
$L218:
	xor	eax, eax
	jmp	$L217
; Line 69
$L217:
	pop	edi
	pop	esi
	pop	ebx
	leave
	ret	4
?canOpen@Door@@QBEHH@Z ENDP				; Door::canOpen
_TEXT	ENDS
PUBLIC	?severity@LessonLog@@QBEHH@Z			; LessonLog::severity
_TEXT	SEGMENT
_channel$ = 8
_this$ = -8
_severity$ = -4
?severity@LessonLog@@QBEHH@Z PROC NEAR			; LessonLog::severity
; Line 73
	push	ebp
	mov	ebp, esp
	sub	esp, 8
	push	ebx
	push	esi
	push	edi
	mov	DWORD PTR _this$[ebp], ecx
; Line 74
	mov	eax, DWORD PTR _this$[ebp]
	mov	eax, DWORD PTR [eax]
	add	eax, DWORD PTR _channel$[ebp]
	mov	DWORD PTR _severity$[ebp], eax
; Line 75
	movsx	eax, BYTE PTR ?g_Title_00407030@@3PADA	; g_Title_00407030
	cmp	eax, 65					; 00000041H
	jne	$L223
; Line 76
	mov	eax, DWORD PTR _channel$[ebp]
	and	eax, 1
	mov	eax, DWORD PTR ?g_Rotor_00407040@@3PAHA[eax*4]
	add	DWORD PTR _severity$[ebp], eax
; Line 78
$L223:
	mov	eax, DWORD PTR _severity$[ebp]
	jmp	$L221
; Line 79
$L221:
	pop	edi
	pop	esi
	pop	ebx
	leave
	ret	4
?severity@LessonLog@@QBEHH@Z ENDP			; LessonLog::severity
_TEXT	ENDS
PUBLIC	?boundary_after_reconstructed@@YAHH@Z		; boundary_after_reconstructed
_TEXT	SEGMENT
_value$ = 8
?boundary_after_reconstructed@@YAHH@Z PROC NEAR		; boundary_after_reconstructed
; Line 83
	push	ebp
	mov	ebp, esp
	push	ebx
	push	esi
	push	edi
; Line 84
	mov	eax, DWORD PTR _value$[ebp]
	inc	eax
	jmp	$L226
; Line 85
$L226:
	pop	edi
	pop	esi
	pop	ebx
	leave
	ret	0
?boundary_after_reconstructed@@YAHH@Z ENDP		; boundary_after_reconstructed
_TEXT	ENDS
PUBLIC	??0ScoreTable@@QAE@H@Z				; ScoreTable::ScoreTable
PUBLIC	??0Reactor@@QAE@H@Z				; Reactor::Reactor
PUBLIC	??0Door@@QAE@H@Z				; Door::Door
PUBLIC	??0LessonLog@@QAE@H@Z				; LessonLog::LessonLog
PUBLIC	_main
_TEXT	SEGMENT
_scores$ = -16
_reactor$ = -4
_door$ = -8
_log$ = -12
_main	PROC NEAR
; Line 88
	push	ebp
	mov	ebp, esp
	sub	esp, 16					; 00000010H
	push	ebx
	push	esi
	push	edi
; Line 89
	push	4
	lea	ecx, DWORD PTR _scores$[ebp]
	call	??0ScoreTable@@QAE@H@Z			; ScoreTable::ScoreTable
; Line 90
	push	12					; 0000000cH
	lea	ecx, DWORD PTR _reactor$[ebp]
	call	??0Reactor@@QAE@H@Z			; Reactor::Reactor
; Line 91
	push	1234					; 000004d2H
	lea	ecx, DWORD PTR _door$[ebp]
	call	??0Door@@QAE@H@Z			; Door::Door
; Line 92
	push	2
	lea	ecx, DWORD PTR _log$[ebp]
	call	??0LessonLog@@QAE@H@Z			; LessonLog::LessonLog
; Line 98
	push	7
	lea	ecx, DWORD PTR _door$[ebp]
	call	?canOpen@Door@@QBEHH@Z			; Door::canOpen
	mov	ebx, eax
	push	3
	lea	ecx, DWORD PTR _reactor$[ebp]
	call	?tick@Reactor@@QAEHH@Z			; Reactor::tick
	add	ebx, eax
	push	1
	lea	ecx, DWORD PTR _log$[ebp]
	call	?severity@LessonLog@@QBEHH@Z		; LessonLog::severity
	add	ebx, eax
	push	9
	lea	ecx, DWORD PTR _scores$[ebp]
	call	?score@ScoreTable@@QBEHH@Z		; ScoreTable::score
	add	ebx, eax
	push	5
	call	?boundary_after_reconstructed@@YAHH@Z	; boundary_after_reconstructed
	add	esp, 4
	add	eax, ebx
	jmp	$L228
; Line 99
$L228:
	pop	edi
	pop	esi
	pop	ebx
	leave
	ret	0
_main	ENDP
_TEXT	ENDS
;	COMDAT ??0ScoreTable@@QAE@H@Z
_TEXT	SEGMENT
_seed$ = 8
_this$ = -4
??0ScoreTable@@QAE@H@Z PROC NEAR			; ScoreTable::ScoreTable, COMDAT
; Line 8
	push	ebp
	mov	ebp, esp
	sub	esp, 4
	push	ebx
	push	esi
	push	edi
	mov	DWORD PTR _this$[ebp], ecx
	mov	eax, DWORD PTR _seed$[ebp]
	mov	ecx, DWORD PTR _this$[ebp]
	mov	DWORD PTR [ecx], eax
	jmp	$L169
$L169:
	mov	eax, DWORD PTR _this$[ebp]
	pop	edi
	pop	esi
	pop	ebx
	leave
	ret	4
??0ScoreTable@@QAE@H@Z ENDP				; ScoreTable::ScoreTable
_TEXT	ENDS
;	COMDAT ??0Reactor@@QAE@H@Z
_TEXT	SEGMENT
_heat$ = 8
_this$ = -4
??0Reactor@@QAE@H@Z PROC NEAR				; Reactor::Reactor, COMDAT
; Line 17
	push	ebp
	mov	ebp, esp
	sub	esp, 4
	push	ebx
	push	esi
	push	edi
	mov	DWORD PTR _this$[ebp], ecx
	mov	eax, DWORD PTR _heat$[ebp]
	mov	ecx, DWORD PTR _this$[ebp]
	mov	DWORD PTR [ecx], eax
	jmp	$L181
$L181:
	mov	eax, DWORD PTR _this$[ebp]
	pop	edi
	pop	esi
	pop	ebx
	leave
	ret	4
??0Reactor@@QAE@H@Z ENDP				; Reactor::Reactor
_TEXT	ENDS
;	COMDAT ??0Door@@QAE@H@Z
_TEXT	SEGMENT
_key$ = 8
_this$ = -4
??0Door@@QAE@H@Z PROC NEAR				; Door::Door, COMDAT
; Line 26
	push	ebp
	mov	ebp, esp
	sub	esp, 4
	push	ebx
	push	esi
	push	edi
	mov	DWORD PTR _this$[ebp], ecx
	mov	eax, DWORD PTR _key$[ebp]
	mov	ecx, DWORD PTR _this$[ebp]
	mov	DWORD PTR [ecx], eax
	jmp	$L193
$L193:
	mov	eax, DWORD PTR _this$[ebp]
	pop	edi
	pop	esi
	pop	ebx
	leave
	ret	4
??0Door@@QAE@H@Z ENDP					; Door::Door
_TEXT	ENDS
;	COMDAT ??0LessonLog@@QAE@H@Z
_TEXT	SEGMENT
_base$ = 8
_this$ = -4
??0LessonLog@@QAE@H@Z PROC NEAR				; LessonLog::LessonLog, COMDAT
; Line 35
	push	ebp
	mov	ebp, esp
	sub	esp, 4
	push	ebx
	push	esi
	push	edi
	mov	DWORD PTR _this$[ebp], ecx
	mov	eax, DWORD PTR _base$[ebp]
	mov	ecx, DWORD PTR _this$[ebp]
	mov	DWORD PTR [ecx], eax
	jmp	$L205
$L205:
	mov	eax, DWORD PTR _this$[ebp]
	pop	edi
	pop	esi
	pop	ebx
	leave
	ret	4
??0LessonLog@@QAE@H@Z ENDP				; LessonLog::LessonLog
_TEXT	ENDS
END
