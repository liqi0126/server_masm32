.386
.model flat, stdcall
option casemap :none

;==================== HEADER =======================
include ws2_32.inc
include kernel32.inc
include windows.inc
include user32.inc
include masm32rt.inc
include msvcrt.inc
include header.inc

includelib ws2_32.lib
includelib kernel32.lib
includelib masm32.lib
includelib wsock32.lib
includelib user32.lib

;==================== STRUCT =======================
client STRUCT
	username db 64 DUP(?)
	sockfd dd ?
	online db 0
client ENDS

;==================== CONST =======================
.const
BUFSIZE		EQU		104857600
BACKLOG		EQU		5

IDC_COUNT EQU 40002

CONNECT_LOGIN	EQU		48 ; ASCII '0'
CONNECT_SIGNUP	EQU		49 ; ASCII '1'

CLIENT_SEND_MSG		EQU		49 ; ASCII '1'
CLIENT_ADD_FRIEND	EQU		50 ; ASCII '2'
CLIENT_DEL_FRIEND	EQU		51 ; ASCII '3'
CLIENT_SEND_FIG		EQU		52 ; ASCII '4'

SERVER_SEND_MSG			EQU		1
SERVER_SEND_FIG			EQU		2
SERVER_ADD_FRIEND		EQU		3
SERVER_DEL_FRIEND		EQU		4
SERVER_INVALID			EQU		5

SERVER_BEC_FRIEND_ONLINE	EQU	0
SERVER_BEC_FRIEND_OFFLINE	EQU 1

SERVER_FRIEND_ONLINE	EQU		4
SERVER_FRIEND_OFFLINE	EQU		5

;==================== DATA =======================
.data
; message
BIND_PORT_HINT		db "BIND PORT:", 0
START_HINT			db "SERVER START!", 0dh, 0ah, 0
NEW_CONNECT_HINT	db "NEW CONNECT ATTEMPT", 0ah, 0dh, 0

LOGIN_SUCCESS_HINT	db "LOGIN SUCCESS", 0ah, 0dh, 0
LOGIN_FAIL_HINT		db "LOGIN FAIL", 0ah, 0dh, 0
SIGNUP_SUCCESS_HINT db "SIGNUP SUCCESS", 0ah, 0dh, 0
SIGNUP_FAIL_HINT	db "SIGNUP FAIL", 0ah, 0dh, 0

ERR_BUILD_SOCKET	db "Fail to Open Socket", 0
ERR_BIND_SOCKET		db "Fail to Bind Socket", 0

SUCCESS_HINT		db "success", 0
FAIL_HINT			db "fail", 0

INPUT_DB_FORMAT		db "%d", 0
MSG_FORMAT1			db "%d %s", 0
MSG_FORMAT2			db "%s%s %d ", 0
MSG_FORMAT3			db "%d %s %s", 0
MSG_FORMAT4			db "%d %s %d", 0


DEBUG_PARSE_FRIENDLIST db "parse results:%s", 0ah, 0dh, 0

; server
serverPort dw ?
listenSocket dd  ?

szConnect db "连接",0
 
szDisConnect db "断开",0

typeCodeZero db "0", 0
typeCodeOne db "1", 0
typeCodeTwo db "2", 0
typeCodeThree db "3", 0
typeCodeFour db "4", 0

; thread
dwThreadCounter dd ?
dwFlag dd ?
F_STOP dd ?
hWinMain dd ?


; write connection socket for each client
connSocket dd 20 DUP(?)

loginSuccess db "success", 0
loginFailure db "fail", 0

msgFormat1 db "%s %s %s", 0
msgFormat2 db "%s %s %s %s", 0
msgFormat3 db "%d %s", 0
msgFormat4 db "%s%s", 0
msgFormat5 db "%s %d ", 0
msgFormat6 db "%s%s", 0

clientlist client 100 DUP(<>)
clientnum dd 0

addFriendFail db "6 fail", 0

;=================== CODE =========================
.code

;--------------------------------------------------------------
getClientId PROC uses ebx username:ptr byte
; get client id by username
; eax = client id
; eax = -1 if not found
;--------------------------------------------------------------
	mov eax, 0 ; cur client num
	mov ebx, 0 ; cur client offset
	.while eax < clientnum
		pushad
		.if clientlist[ebx].online == 1
			invoke crt_strcmp, addr clientlist[ebx].username, username
			.if eax == 0
				popad
				ret
			.endif
		.endif
		popad
		inc eax
		add ebx, type client
	.endw
	mov eax, -1
	ret
getClientId ENDP


;--------------------------------------------------------------
getClientFd PROC uses ebx username:ptr byte, targetfd:ptr dword
; get client sockfd by username
; eax = 1 if found
; eax = 0 if not
;--------------------------------------------------------------
	invoke getClientId, username
	.if eax == -1
		mov eax, 0
		ret
	.endif

	mov ebx, type client
	mul ebx
	mov ecx, clientlist[eax].sockfd
	mov edx, targetfd
	mov [edx], ecx
	mov eax, 1
	ret
getClientFd ENDP

;--------------------------------------------------------------
addNewClient PROC uses ebx username:ptr byte, fd:dword
; add a new client to clientlist
; eax = clientid
;--------------------------------------------------------------
	mov eax, 0 ; cur client num
	mov ebx, 0 ; cur client offset
	.while eax < clientnum
		push ebx
		push eax
		invoke crt_strcmp, addr clientlist[ebx].username, username
		.if eax == 0
			mov eax, fd
			mov clientlist[ebx].sockfd, eax
			mov clientlist[ebx].online, 1
			pop eax
			ret
		.endif
		pop eax
		pop ebx

		inc eax
		add ebx, type client
	.endw
	push eax
	mov eax, fd
	mov clientlist[ebx].sockfd, eax
	mov clientlist[ebx].online, 1
	invoke crt_strcpy, addr clientlist[ebx].username, username
	inc clientnum
	pop eax
ret
addNewClient ENDP


;--------------------------------------------------------------
addNewFriend PROC user1:ptr byte, user2:ptr byte
; eax = 1 if success
; eax = 0 if not
; make user1 and user2 to be friends
;--------------------------------------------------------------
	LOCAL @msgField:ptr byte
	LOCAL @user1Online:dword
	LOCAL @user1Sockfd:dword
	LOCAL @user2Online:dword
	LOCAL @user2Sockfd:dword

	invoke ifSignIn, user1
	.if eax == 0
		ret
	.endif

	invoke ifSignIn, user2
	.if eax == 0
		ret
	.endif

	invoke ifFriends, user1, user2
	.if eax == 1
		mov eax, 0
		ret
	.endif

	invoke writeNewFriend, user1, user2

	invoke getClientFd, user1, addr @user1Sockfd
	mov @user1Online, eax
	
	invoke getClientFd, user2, addr @user2Sockfd
	mov @user2Online, eax

	mov @msgField, alloc(BUFSIZE)

	.if @user1Online == 1
		invoke RtlZeroMemory, @msgField, BUFSIZE
		invoke crt_sprintf, @msgField, addr MSG_FORMAT4, SERVER_ADD_FRIEND, user2, @user2Online
		invoke crt_strlen, @msgField
		invoke send, @user1Sockfd, @msgField, eax, 0
	.endif

	.if @user2Online == 1
		invoke RtlZeroMemory, @msgField, BUFSIZE
		invoke crt_sprintf, @msgField, addr MSG_FORMAT4, SERVER_ADD_FRIEND, user1, @user1Online
		invoke crt_strlen, @msgField
		invoke send, @user2Sockfd, @msgField, eax, 0
	.endif

	free @msgField
	mov eax, 1
	ret
addNewFriend ENDP

;--------------------------------------------------------------
parseFriendList PROC friendlist:ptr byte, msgField:ptr byte
; friendlist(input): FRIEND1 FRIEND2 FRIEND3 ...
; msgField(output): FRIEND1 on/off FRIEND2 on/off ...
;--------------------------------------------------------------
	LOCAL @tmpUsername:dword
	LOCAL @tmpFd:dword

	invoke crt_strcat, friendlist, offset SEP

	.while 1
		invoke crt_strstr, friendlist, offset SEP
		.if eax == 0
			jmp finish
		.endif

		mov bl, 0
		mov [eax], bl
		mov ebx, friendlist
		mov @tmpUsername, ebx

		push eax
		invoke getClientFd, @tmpUsername, addr @tmpFd
		invoke crt_sprintf, msgField, offset MSG_FORMAT2, msgField, @tmpUsername, eax
		pop eax

		mov friendlist, eax
		inc friendlist
	.endw

finish:
	ret
parseFriendList ENDP

;--------------------------------------------------------------
broadcastOnOffLine PROC uses ebx currentname:ptr byte, isOn:dword
; broadcase all the online friends the current user is online/offline
;--------------------------------------------------------------
	LOCAL targetname:ptr byte
	LOCAL targetfd:dword
	LOCAL @msgField[1024]:byte
	mov eax, 0
	mov ebx, 0
	.while eax < clientnum
		pushad
		.if clientlist[ebx].online == 1
			mov eax, clientlist[ebx].sockfd
			mov targetfd, eax
			add ebx, offset clientlist
			mov targetname, ebx
			invoke ifFriends, targetname, currentname
			.if eax == 1
				.if isOn == 1
					invoke crt_sprintf, addr @msgField, addr MSG_FORMAT1, SERVER_FRIEND_ONLINE, currentname
				.else
					invoke crt_sprintf, addr @msgField, addr MSG_FORMAT1, SERVER_FRIEND_OFFLINE, currentname
				.endif
				invoke crt_strlen, addr @msgField
				invoke send, targetfd, addr @msgField, eax, 0
			.endif
		.endif
		popad
		inc eax
		add ebx, type client
	.endw
	ret
broadcastOnOffLine ENDP


;--------------------------------------------------------------
parseClientCmd PROC buffer:ptr byte, targetfd:ptr dword, content:ptr byte
; possible format:
; 1 tgtUsername content (send text)
; 2 tgtUsername image (send image)
; 3 tgtUsername (add friend)
; 4 tgtUsername (delete friend)
;--------------------------------------------------------------
	LOCAL @userStart:dword
	LOCAL @msgStart:dword
	LOCAL @clientCmd:byte

	mov eax, buffer
	mov bl, [eax]
	mov @clientCmd, bl

	.if @clientCmd == CLIENT_SEND_MSG || @clientCmd == CLIENT_SEND_FIG

		mov @userStart, eax
		add @userStart, 2
		invoke crt_strstr, @userStart, offset SEP
		mov @msgStart, eax
		inc @msgStart

		mov bl, 0
		mov [eax], bl
		invoke getClientFd, @userStart, targetfd
		.if eax == 0
			mov eax, SERVER_INVALID
			ret
		.endif
		invoke crt_strcpy, content, @msgStart
		
		.if @clientCmd == CLIENT_SEND_MSG
			mov eax, SERVER_SEND_MSG
		.else 
			mov eax, SERVER_SEND_FIG
		.endif

		ret
	.elseif @clientCmd == CLIENT_ADD_FRIEND || @clientCmd == CLIENT_DEL_FRIEND
		add eax, 2
		invoke crt_strcpy, content, eax

		.if @clientCmd == CLIENT_ADD_FRIEND
			mov eax, SERVER_ADD_FRIEND
		.else 
			mov eax, SERVER_DEL_FRIEND
		.endif

		ret
	.endif

	mov eax, SERVER_INVALID
	ret
parseClientCmd ENDP


;--------------------------------------------------------------
serviceThread PROC uses ebx clientid:dword
; function to handle client request
;--------------------------------------------------------------
	LOCAL @stFdset:fd_set, @stTimeval:timeval
	LOCAL @szBuffer:ptr byte
	LOCAL @currentUsername[64]:byte
	LOCAL @targetSockfd:dword
	LOCAL @msgContent:ptr byte
	LOCAL @msgField:ptr byte
	LOCAL _hSocket:DWORD
	LOCAL @friendlist[1024]:byte
	mov @szBuffer, alloc(BUFSIZE)
	mov @msgField, alloc(BUFSIZE)
	mov @msgContent, alloc(BUFSIZE)

	mov eax, clientid
	mov ebx, type client
	mul ebx
	mov edx, clientlist[eax].sockfd
	mov _hSocket, edx
	invoke crt_strcpy, addr @currentUsername, addr clientlist[eax].username

	; read and send friend lists to current user
	invoke RtlZeroMemory, addr @friendlist, 1024
	invoke readAllFriends, addr @currentUsername, addr @friendlist
	invoke RtlZeroMemory, @msgField, BUFSIZE
	invoke parseFriendList, addr @friendlist, @msgField
	invoke crt_strlen, @msgField
	invoke send, _hSocket, @msgField, eax, 0

	; tell his friend that he is on/offline
	invoke broadcastOnOffLine, addr @currentUsername, 1

	inc dwThreadCounter
	invoke SetDlgItemInt, hWinMain, IDC_COUNT, dwThreadCounter, FALSE

	.while 1
		mov @stFdset.fd_count,1
		push _hSocket
		pop @stFdset.fd_array
		mov @stTimeval.tv_usec,200*1000 ;ms
		mov @stTimeval.tv_sec,0
		invoke select, 0, addr @stFdset, NULL, NULL, addr @stTimeval ; wait for client cmd

		.if eax == SOCKET_ERROR
			.break
		.endif
		.if eax
			invoke RtlZeroMemory, @szBuffer, BUFSIZE
			invoke recv, _hSocket, @szBuffer, BUFSIZE, 0
			.break  .if eax == SOCKET_ERROR
			.break  .if !eax
			; parse client commend
			invoke RtlZeroMemory, @msgContent, BUFSIZE
			invoke parseClientCmd, @szBuffer, addr @targetSockfd, @msgContent

			.if eax == SERVER_SEND_MSG
				invoke RtlZeroMemory, @msgField, BUFSIZE
				invoke crt_sprintf, @msgField, addr MSG_FORMAT3, SERVER_SEND_MSG, addr @currentUsername, @msgContent
				invoke crt_strlen, @msgField
				invoke send, @targetSockfd, @msgField, eax, 0
				.break  .if eax == SOCKET_ERROR

			.elseif eax == SERVER_SEND_FIG
				invoke RtlZeroMemory, @msgField, BUFSIZE
				invoke crt_sprintf, @msgField, addr msgFormat1, SERVER_SEND_FIG, addr @currentUsername, @msgContent
				invoke crt_strlen, @msgField
				invoke send, @targetSockfd, @msgField, eax, 0
				.break  .if eax == SOCKET_ERROR

			.elseif eax == SERVER_ADD_FRIEND
				invoke addNewFriend, addr @currentUsername, @msgContent
				.if eax == 0
					invoke send, _hSocket, addr addFriendFail, sizeof addFriendFail, 0
				.endif
			.elseif eax == SERVER_DEL_FRIEND
				; TBD
			.endif
		.endif
	.endw
	invoke closesocket, _hSocket
	dec dwThreadCounter
	; 从当前用户列表更改该下线用户状态
	mov eax, clientid
	mov ebx, type client
	mul ebx
	mov clientlist[eax].online, 0
	; 向好友广播其下线信息
	invoke broadcastOnOffLine, addr @currentUsername, 0

	free @msgField
	free @szBuffer
	free @msgContent
	invoke SetDlgItemInt,hWinMain,IDC_COUNT,dwThreadCounter,FALSE
	ret
serviceThread ENDP


logIn PROC sockfd:dword, username:ptr byte, password:ptr byte
	LOCAL @tempfd:dword

	; check whether this username exists
	invoke ifSignIn, username
	.if eax == 0
		invoke send, sockfd, addr FAIL_HINT, sizeof FAIL_HINT, 0
		mov eax, -1
		ret
	.endif

	; check whether password right
	invoke ifPasswordRight, username, password
	.if eax == 1
		; repeat login
		invoke getClientFd, username, addr @tempfd
		.if eax == 1
			invoke send, sockfd, addr FAIL_HINT, sizeof FAIL_HINT, 0
			mov eax, -1
			ret
		.endif

		; login success
		invoke send, sockfd, addr SUCCESS_HINT, sizeof SUCCESS_HINT, 0

		; add new client
		invoke addNewClient, username, sockfd

		ret
	.else
		invoke send, sockfd, addr FAIL_HINT, sizeof FAIL_HINT, 0
		mov eax, -1
		ret
	.endif
logIn ENDP


signIn PROC sockfd:dword, username:ptr byte, password:ptr byte
	; whether already sign in
	invoke ifSignIn, username
	.if eax == 0
		invoke writeNewUser, username, password
		invoke send, sockfd, addr SUCCESS_HINT, sizeof SUCCESS_HINT, 0
		mov eax, 1
		ret
	.else
		invoke send, sockfd, addr FAIL_HINT, sizeof FAIL_HINT, 0
		mov eax, 0
		ret
	.endif
signIn ENDP


clientConnect PROC sockfd:dword
	LOCAL @type[10]:byte
	LOCAL @username[512]:byte
	LOCAL @password[512]:byte
	invoke RtlZeroMemory, addr @username, 512
	invoke RtlZeroMemory, addr @password, 512
	invoke RtlZeroMemory, addr @type, 10

	invoke crt_printf, addr NEW_CONNECT_HINT

	; connect type
	invoke recv, sockfd, addr @type, sizeof @type, 0
	invoke send, sockfd, addr SUCCESS_HINT, sizeof SUCCESS_HINT, 0

	; username
	invoke recv, sockfd, addr @username, sizeof @username, 0
	invoke send, sockfd, addr SUCCESS_HINT, sizeof SUCCESS_HINT, 0

	; password 
	invoke recv, sockfd, addr @password, sizeof @password, 0
	invoke send, sockfd, addr SUCCESS_HINT, sizeof SUCCESS_HINT, 0

	mov al, @type
	.if al == CONNECT_LOGIN
		invoke logIn, sockfd, addr @username, addr @password
		.if eax != -1
			push eax
			invoke crt_printf, addr LOGIN_SUCCESS_HINT
			pop eax
			ret
		.else
			invoke crt_printf, addr LOGIN_FAIL_HINT
			mov eax, -1
			ret
		.endif
	.else
		invoke signIn, sockfd, addr @username, addr @password
		.if eax == 1
			invoke crt_printf, addr SIGNUP_SUCCESS_HINT
			mov eax, -1
			ret
		.else
			invoke crt_printf, addr SIGNUP_FAIL_HINT
			mov eax, -1
			ret
		.endif
	.endif

	mov eax, 0
	ret
clientConnect ENDP


main PROC
    LOCAL @stWsa:WSADATA  
    LOCAL @stSin:sockaddr_in
	LOCAL @connSock:dword
	LOCAL @clientid:dword

	; pick listen port
	invoke crt_printf, addr BIND_PORT_HINT
	invoke crt_scanf, addr INPUT_DB_FORMAT, addr serverPort
    invoke WSAStartup, 101h,addr @stWsa

    ; create socket
    invoke socket, AF_INET, SOCK_STREAM,0
    .if eax == INVALID_SOCKET
        invoke MessageBox, NULL, addr ERR_BUILD_SOCKET, addr ERR_BUILD_SOCKET, MB_OK
		ret
    .endif
    mov listenSocket, eax

	; bind socket
    invoke RtlZeroMemory, addr @stSin,sizeof @stSin
    invoke htons, serverPort
    mov @stSin.sin_port, ax
    mov @stSin.sin_family, AF_INET
    mov @stSin.sin_addr, INADDR_ANY
    invoke bind,listenSocket, addr @stSin,sizeof @stSin
    .if eax
		invoke MessageBox,NULL, addr ERR_BIND_SOCKET, addr ERR_BIND_SOCKET, MB_OK
		ret
    .endif

    ; listen socket
    invoke listen, listenSocket, BACKLOG
    invoke crt_printf, addr START_HINT

    .while TRUE
		push ecx
		; accept new socket
		invoke accept, listenSocket, NULL, 0
		.break .if eax==INVALID_SOCKET

		mov @connSock, eax

		invoke clientConnect, @connSock
		.if eax != -1 ; eax=clientid
			mov @clientid, eax
			invoke CreateThread, NULL, 0, offset serviceThread, @clientid, NULL, esp
		.else
			invoke CloseHandle, @connSock
		.endif
        pop ecx
    .endw

    invoke closesocket, listenSocket
    ret
main ENDP

end