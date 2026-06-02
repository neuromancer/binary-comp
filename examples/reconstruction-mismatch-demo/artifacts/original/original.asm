	TITLE	src/original/original.cpp
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
;	COMDAT ??0CleanupProbe@@QAE@PAH@Z
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
?g_Bonus_00407038@@3HA DD 07H				; g_Bonus_00407038
?g_Threshold_0040703C@@3HA DD 0aH			; g_Threshold_0040703C
?g_Rotor_00407040@@3PAHA DD 03H				; g_Rotor_00407040
	DD	05H
	DD	08H
_DATA	ENDS
PUBLIC	??1CleanupProbe@@QAE@XZ				; CleanupProbe::~CleanupProbe
_TEXT	SEGMENT
; File src/original/original.cpp
_this$ = -4
??1CleanupProbe@@QAE@XZ PROC NEAR			; CleanupProbe::~CleanupProbe
; Line 52
	push	ebp
	mov	ebp, esp
	sub	esp, 4
	push	ebx
	push	esi
	push	edi
	mov	DWORD PTR _this$[ebp], ecx
; Line 53
	mov	eax, DWORD PTR _this$[ebp]
	cmp	DWORD PTR [eax], 0
	je	$L222
; Line 54
	mov	eax, DWORD PTR _this$[ebp]
	mov	eax, DWORD PTR [eax]
	inc	DWORD PTR [eax]
; Line 56
$L222:
	jmp	$L221
$L221:
	pop	edi
	pop	esi
	pop	ebx
	leave
	ret	0
??1CleanupProbe@@QAE@XZ ENDP				; CleanupProbe::~CleanupProbe
_TEXT	ENDS
PUBLIC	?score@ScoreTable@@QBEHH@Z			; ScoreTable::score
_TEXT	SEGMENT
_value$ = 8
_this$ = -8
_total$ = -4
?score@ScoreTable@@QBEHH@Z PROC NEAR			; ScoreTable::score
; Line 59
	push	ebp
	mov	ebp, esp
	sub	esp, 8
	push	ebx
	push	esi
	push	edi
	mov	DWORD PTR _this$[ebp], ecx
; Line 60
	mov	eax, DWORD PTR _this$[ebp]
	mov	eax, DWORD PTR [eax]
	add	eax, DWORD PTR _value$[ebp]
	mov	DWORD PTR _total$[ebp], eax
; Line 61
	cmp	DWORD PTR _total$[ebp], 10		; 0000000aH
	jle	$L227
; Line 62
	mov	eax, DWORD PTR ?g_Bonus_00407038@@3HA	; g_Bonus_00407038
	add	DWORD PTR _total$[ebp], eax
; Line 64
$L227:
	mov	eax, DWORD PTR _total$[ebp]
	jmp	$L225
; Line 65
$L225:
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
; Line 68
	push	ebp
	mov	ebp, esp
	sub	esp, 4
	push	ebx
	push	esi
	push	edi
	mov	DWORD PTR _this$[ebp], ecx
; Line 69
	mov	eax, DWORD PTR _this$[ebp]
	add	DWORD PTR [eax], 3
; Line 70
	cmp	DWORD PTR _coolant$[ebp], 0
	jle	$L231
; Line 71
	xor	eax, eax
	mov	ecx, DWORD PTR _coolant$[ebp]
	add	ecx, ecx
	sub	eax, ecx
	neg	eax
	mov	ecx, DWORD PTR _this$[ebp]
	sub	DWORD PTR [ecx], eax
; Line 73
$L231:
	mov	eax, DWORD PTR _this$[ebp]
	mov	eax, DWORD PTR [eax]
	jmp	$L230
; Line 74
$L230:
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
; Line 77
	push	ebp
	mov	ebp, esp
	sub	esp, 4
	push	ebx
	push	esi
	push	edi
	mov	DWORD PTR _this$[ebp], ecx
; Line 78
	mov	eax, DWORD PTR _this$[ebp]
	mov	ecx, DWORD PTR _passcode$[ebp]
	cmp	DWORD PTR [eax], ecx
	jne	$L235
; Line 79
	mov	eax, 1
	jmp	$L234
; Line 81
$L235:
	mov	eax, DWORD PTR ?g_Bonus_00407038@@3HA	; g_Bonus_00407038
	cmp	DWORD PTR _passcode$[ebp], eax
	jne	$L236
; Line 82
	mov	eax, 1
	jmp	$L234
; Line 84
$L236:
	xor	eax, eax
	jmp	$L234
; Line 85
$L234:
	pop	edi
	pop	esi
	pop	ebx
	leave
	ret	4
?canOpen@Door@@QBEHH@Z ENDP				; Door::canOpen
_TEXT	ENDS
PUBLIC	?severity@LessonLog@@QBEHH@Z			; LessonLog::severity
PUBLIC	??0CleanupProbe@@QAE@PAH@Z			; CleanupProbe::CleanupProbe
EXTRN	__except_list:DWORD
EXTRN	___CxxFrameHandler:NEAR
xdata$x	SEGMENT
$T266	DD	019930520H
	DD	01H
	DD	FLAT:$T268
	DD	2 DUP(00H)
	DD	2 DUP(00H)
	ORG $+4
$T268	DD	0ffffffffH
	DD	FLAT:$L262
xdata$x	ENDS
_TEXT	SEGMENT
_channel$ = 8
_this$ = -28
_severity$ = -20
_probe$ = -16
$T260 = -24
__$EHRec$ = -12
?severity@LessonLog@@QBEHH@Z PROC NEAR			; LessonLog::severity
; Line 88
	push	ebp
	mov	ebp, esp
	push	-1
	push	OFFSET FLAT:$L261
	mov	eax, DWORD PTR fs:__except_list
	push	eax
	mov	DWORD PTR fs:__except_list, esp
	sub	esp, 16					; 00000010H
	push	ebx
	push	esi
	push	edi
	mov	DWORD PTR _this$[ebp], ecx
; Line 89
	mov	eax, DWORD PTR _this$[ebp]
	mov	eax, DWORD PTR [eax]
	add	eax, DWORD PTR _channel$[ebp]
	mov	DWORD PTR _severity$[ebp], eax
; Line 90
	lea	eax, DWORD PTR _severity$[ebp]
	push	eax
	lea	ecx, DWORD PTR _probe$[ebp]
	call	??0CleanupProbe@@QAE@PAH@Z		; CleanupProbe::CleanupProbe
	mov	DWORD PTR __$EHRec$[ebp+8], 0
; Line 91
	movsx	eax, BYTE PTR ?g_Title_00407030@@3PADA	; g_Title_00407030
	cmp	eax, 65					; 00000041H
	jne	$L242
; Line 92
	mov	eax, DWORD PTR _channel$[ebp]
	and	eax, 1
	mov	eax, DWORD PTR ?g_Rotor_00407040@@3PAHA[eax*4]
	add	DWORD PTR _severity$[ebp], eax
; Line 94
$L242:
	mov	eax, DWORD PTR _severity$[ebp]
	mov	DWORD PTR $T260[ebp], eax
	mov	DWORD PTR __$EHRec$[ebp+8], -1
	call	$L262
	mov	eax, DWORD PTR $T260[ebp]
	jmp	$L239
; Line 95
$L262:
	lea	ecx, DWORD PTR _probe$[ebp]
	call	??1CleanupProbe@@QAE@XZ			; CleanupProbe::~CleanupProbe
	ret	0
$L261:
	mov	eax, OFFSET FLAT:$T266
	jmp	___CxxFrameHandler
$L239:
	mov	ecx, DWORD PTR __$EHRec$[ebp]
	mov	DWORD PTR fs:__except_list, ecx
	pop	edi
	pop	esi
	pop	ebx
	leave
	ret	4
?severity@LessonLog@@QBEHH@Z ENDP			; LessonLog::severity
_TEXT	ENDS
;	COMDAT ??0CleanupProbe@@QAE@PAH@Z
_TEXT	SEGMENT
_counter$ = 8
_this$ = -4
??0CleanupProbe@@QAE@PAH@Z PROC NEAR			; CleanupProbe::CleanupProbe, COMDAT
; Line 44
	push	ebp
	mov	ebp, esp
	sub	esp, 4
	push	ebx
	push	esi
	push	edi
	mov	DWORD PTR _this$[ebp], ecx
	mov	eax, DWORD PTR _counter$[ebp]
	mov	ecx, DWORD PTR _this$[ebp]
	mov	DWORD PTR [ecx], eax
	jmp	$L219
$L219:
	mov	eax, DWORD PTR _this$[ebp]
	pop	edi
	pop	esi
	pop	ebx
	leave
	ret	4
??0CleanupProbe@@QAE@PAH@Z ENDP				; CleanupProbe::CleanupProbe
_TEXT	ENDS
PUBLIC	?boundary_after_reconstructed@@YAHH@Z		; boundary_after_reconstructed
_TEXT	SEGMENT
_value$ = 8
?boundary_after_reconstructed@@YAHH@Z PROC NEAR		; boundary_after_reconstructed
; Line 98
	push	ebp
	mov	ebp, esp
	push	ebx
	push	esi
	push	edi
; Line 99
	mov	eax, DWORD PTR _value$[ebp]
	inc	eax
	jmp	$L246
; Line 100
$L246:
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
; Line 103
	push	ebp
	mov	ebp, esp
	sub	esp, 16					; 00000010H
	push	ebx
	push	esi
	push	edi
; Line 104
	push	4
	lea	ecx, DWORD PTR _scores$[ebp]
	call	??0ScoreTable@@QAE@H@Z			; ScoreTable::ScoreTable
; Line 105
	push	12					; 0000000cH
	lea	ecx, DWORD PTR _reactor$[ebp]
	call	??0Reactor@@QAE@H@Z			; Reactor::Reactor
; Line 106
	push	1234					; 000004d2H
	lea	ecx, DWORD PTR _door$[ebp]
	call	??0Door@@QAE@H@Z			; Door::Door
; Line 107
	push	2
	lea	ecx, DWORD PTR _log$[ebp]
	call	??0LessonLog@@QAE@H@Z			; LessonLog::LessonLog
; Line 113
	push	7
	lea	ecx, DWORD PTR _door$[ebp]
	call	?canOpen@Door@@QBEHH@Z			; Door::canOpen
	mov	ebx, eax
	push	3
	lea	ecx, DWORD PTR _reactor$[ebp]
	call	?tick@Reactor@@QAEHH@Z			; Reactor::tick
	add	ebx, eax
	push	5
	call	?boundary_after_reconstructed@@YAHH@Z	; boundary_after_reconstructed
	add	esp, 4
	add	ebx, eax
	push	1
	lea	ecx, DWORD PTR _log$[ebp]
	call	?severity@LessonLog@@QBEHH@Z		; LessonLog::severity
	add	ebx, eax
	push	9
	lea	ecx, DWORD PTR _scores$[ebp]
	call	?score@ScoreTable@@QBEHH@Z		; ScoreTable::score
	add	eax, ebx
	jmp	$L248
; Line 114
$L248:
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
