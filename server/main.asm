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

CLIENT_SIGNUP		EQU		48 ; ASCII '0'
CLIENT_LOGIN		EQU		49 ; ASCII '1'
CLIENT_ROOM_TALK	EQU		50 ; ASCII '2'
CLIENT_1TO1_TALK	EQU		51 ; ASCII '3'
CLIENT_ADD_FRIEND	EQU		52 ; ASCII '4'
CLIENT_FRI_REPLY	EQU		53 ; ASCII '5'
CLIENT_DEL_FRIEND	EQU		54 ; ASCII '6'

SERVER_INVALID			EQU		-1
SERVER_FAIL				EQU		0
SERVER_SUCCESS			EQU		1
SERVER_ROOM_TALK		EQU		2
SERVER_1TO1_TALK		EQU		3
SERVER_FRIEND_APPLY		EQU		4
SERVER_FRIEND_LIST		EQU		5
SERVER_FRIEND_NOTIFY	EQU		6

FRIEND_ONLINE	EQU		0
FRIEND_OFFLINE	EQU		1
FRIEND_PASS		EQU		2
FRIEND_REJECT	EQU		3
FRIEND_DEL		EQU		4

IS_FRIEND_ASCII			EQU		48 ; ASCII '0'
FRIEND_ONLINE_ASCII		EQU		49 ; ASCII '1'
FRIEND_OFFLINE_ASCII	EQU		50 ; ASCII '2'

;==================== DATA =======================
.data
; message
BIND_PORT_HINT		db "BIND PORT:", 0
START_HINT			db "SERVER START!", 0dh, 0ah, 0

SUCCESS_HINT		db "1", 0
SIGNUP_SUCCESS_HINT db "USER %s SIGNUP", 0ah, 0dh, 0
SIGNUP_FAIL_HINT	db "UsER %s SIGNUP FAIL", 0ah, 0dh, 0
LOGIN_SUCCESS_HINT	db "USER %s LOGIN", 0ah, 0dh, 0
LOGIN_FAIL_HINT		db "USER %s LOGIN FAIL", 0ah, 0dh, 0


ERR_BUILD_SOCKET	db "Fail to Open Socket", 0
ERR_BIND_SOCKET		db "Fail to Bind Socket", 0
ERR_REPEAT_SIGNIN	db "User %s already sign in", 0
ERR_WRONG_PASS		db "Password is wrong", 0
ERR_NO_SUCH_USER	db "No User %s, please sign in firstly", 0
ERR_REPEAT_LOGIN	db "User %s already login", 0


MSG_FORMAT0			db "%d", 0
MSG_FORMAT1			db "%d %s", 0
MSG_FORMAT2			db "%s%s %d ", 0
MSG_FORMAT3			db "%d %s %s", 0
MSG_FORMAT4			db "%d %s %d", 0

; thread
dwThreadCounter dd ?
hWinMain dd ?

; connect client
clientlist client 256 DUP(<>)
clientnum dd 0

addFriendFail db "6 fail", 0

;=================== CODE =========================
.code

;--------------------------------------------------------------
getArrayEleByNum PROC arrayPtr:dword, eleSize:dword, Num:dword
; eax = array[Num]
;--------------------------------------------------------------
	mov eax, eleSize
	mov ebx, Num
	mul ebx
	add eax, arrayPtr
	ret
getArrayEleByNum ENDP


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
checkFriendOnOffLine PROC friendList:ptr byte
; check friend online or offline
; friendList(input): FRIEND1:status1 FRIEND2:status2 ...
; updatedFriendList(output): FRIEND1:updatedStatus1 FRIEND2:updatedStatus2 ...
; origin: 0:friend 3:pending 4:deleted
; new: 1:online 2:offline 3:pending 4:deleted
;--------------------------------------------------------------
	LOCAL @cursor:dword
	LOCAL @len:dword
	LOCAL @username[256]:byte
	LOCAL @friendType:byte
	LOCAL @sockfd:dword

	mov eax, friendList
	mov @cursor, eax

	invoke crt_strcat, friendList, offset SEP
	.while 1
		invoke crt_strstr, @cursor, offset SEP
		.if eax == 0
			jmp finish
		.endif
		dec eax
		mov bl, [eax]
		mov @friendType, bl

		mov @len, eax
		add @len, -1
		mov ebx, @cursor
		sub @len, ebx
		invoke RtlZeroMemory, addr @username, 256
		invoke crt_strncpy, addr @username, @cursor, @len

		.if @friendType == IS_FRIEND_ASCII
			invoke getClientFd, addr @username, addr @sockfd
			invoke crt_printf, offset msgFormat3, @friendType, addr @username
		.endif


		mov eax, @len
		add eax, 3
		add @cursor, eax
	.endw

finish:
	ret
checkFriendOnOffLine ENDP

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
	LOCAL @sockfd:DWORD
	LOCAL @friendlist[1024]:byte
	mov @szBuffer, alloc(BUFSIZE)
	mov @msgField, alloc(BUFSIZE)
	mov @msgContent, alloc(BUFSIZE)

	; get sockfd and username
	mov eax, clientid
	mov ebx, type client
	mul ebx
	mov edx, clientlist[eax].sockfd
	mov @sockfd, edx
	invoke crt_strcpy, addr @currentUsername, addr clientlist[eax].username

	; read and send friend lists to current user
	invoke RtlZeroMemory, addr @friendlist, 1024
	invoke readAllFriends, addr @currentUsername, addr @friendlist
	invoke RtlZeroMemory, @msgField, BUFSIZE
	invoke parseFriendList, addr @friendlist, @msgField
	invoke crt_strlen, @msgField
	invoke send, @sockfd, @msgField, eax, 0

	; tell his friend that he is on/offline
	invoke broadcastOnOffLine, addr @currentUsername, 1

	inc dwThreadCounter
	invoke SetDlgItemInt, hWinMain, IDC_COUNT, dwThreadCounter, FALSE

	.while 1
		mov @stFdset.fd_count,1
		push @sockfd
		pop @stFdset.fd_array
		mov @stTimeval.tv_usec,200*1000 ;ms
		mov @stTimeval.tv_sec,0
		invoke select, 0, addr @stFdset, NULL, NULL, addr @stTimeval ; wait for client cmd

		.if eax == SOCKET_ERROR
			.break
		.endif
		.if eax
			invoke RtlZeroMemory, @szBuffer, BUFSIZE
			invoke recv, @sockfd, @szBuffer, BUFSIZE, 0
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
					invoke send, @sockfd, addr addFriendFail, sizeof addFriendFail, 0
				.endif
			.elseif eax == SERVER_DEL_FRIEND
				; TBD
			.endif
		.endif
	.endw
	invoke closesocket, @sockfd
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

;--------------------------------------------------------------
logIn PROC sockfd:dword, username:ptr byte, password:ptr byte
; user log in
;--------------------------------------------------------------
	LOCAL @tmpMsg[512]:byte
	invoke ifSignIn, username
	.if eax == 0
		invoke crt_sprintf, addr @tmpMsg, offset MSG_FORMAT1, SERVER_FAIL, offset ERR_NO_SUCH_USER
		invoke crt_strlen, addr @tmpMsg
		invoke send, sockfd, addr @tmpMsg, eax, 0
		mov eax, -1
		ret
	.endif

	; repeat login
	invoke getClientId, username
	.if eax == 1
		invoke crt_sprintf, addr @tmpMsg, offset MSG_FORMAT1, SERVER_FAIL, offset ERR_REPEAT_LOGIN
		invoke crt_strlen, addr @tmpMsg
		invoke send, sockfd, addr @tmpMsg, eax, 0
		mov eax, -1
		ret
	.endif

	; check whether password right
	invoke ifPasswordRight, username, password
	.if eax == 0
		invoke crt_sprintf, addr @tmpMsg, offset MSG_FORMAT1, SERVER_FAIL, offset ERR_WRONG_PASS
		invoke crt_strlen, addr @tmpMsg
		invoke send, sockfd, addr @tmpMsg, eax, 0
		mov eax, -1
		ret
	.endif

	; login success
	invoke send, sockfd, addr SUCCESS_HINT, sizeof SUCCESS_HINT, 0
	invoke addNewClient, username, sockfd
	ret
logIn ENDP

;--------------------------------------------------------------
signIn PROC sockfd:dword, username:ptr byte, password:ptr byte
; user sign in
;--------------------------------------------------------------
	; whether already sign in
	LOCAL @tmpMsg[512]:byte

	invoke ifSignIn, username
	.if eax == 0
		invoke writeNewUser, username, password
		invoke send, sockfd, addr SUCCESS_HINT, sizeof SUCCESS_HINT, 0
		mov eax, 1
		ret
	.else
		invoke crt_sprintf, addr @tmpMsg, offset MSG_FORMAT1, SERVER_FAIL, offset ERR_REPEAT_SIGNIN
		invoke crt_strlen, addr @tmpMsg
		invoke send, sockfd, addr @tmpMsg, eax, 0
		mov eax, 0
		ret
	.endif
signIn ENDP

;--------------------------------------------------------------
clientConnect PROC sockfd:dword
; sign in: 0 username password
; login in: 1 username password
;--------------------------------------------------------------
	LOCAL @cursor:dword
	LOCAL @buffer[512]:byte
	LOCAL @type:byte
	LOCAL @username[256]:byte
	LOCAL @password[256]:byte

	invoke RtlZeroMemory, addr @buffer, 512
	invoke recv, sockfd, addr @buffer, sizeof @buffer, 0
	
	mov al, @buffer
	mov @type, al

	mov @cursor, addr @buffer
	add @cursor, 2
	invoke crt_strstr, @cursor, offset SEP
	push eax
	mov [eax], 0
	invoke crt_strcpy, addr @username, @cursor
	pop eax

	mov @cursor, eax
	inc @cursor
	invoke crt_strcpy, addr @password, @cursor


	.if @type == CLIENT_SIGNUP
		invoke logIn, sockfd, addr @username, addr @password
		.if eax != -1
			push eax
			invoke crt_printf, offset LOGIN_SUCCESS_HINT, addr @username
			pop eax
			ret
		.else
			invoke crt_printf, offset LOGIN_FAIL_HINT, addr @username
			mov eax, -1
			ret
		.endif
	.elseif @type == CLIENT_LOGIN
		invoke signIn, sockfd, addr @username, addr @password
		.if eax == 1
			invoke crt_printf, addr SIGNUP_SUCCESS_HINT, addr @username
			mov eax, -1
			ret
		.else
			invoke crt_printf, addr SIGNUP_FAIL_HINT, addr @username
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
	LOCAL @serverPort:dword
	LOCAL @listenSocket:dword

	; pick listen port
	invoke crt_printf, addr BIND_PORT_HINT
	invoke crt_scanf, addr MSG_FORMAT0, addr @serverPort

    ; create socket
	invoke WSAStartup, 101h,addr @stWsa
    invoke socket, AF_INET, SOCK_STREAM,0
    .if eax == INVALID_SOCKET
        invoke MessageBox, NULL, addr ERR_BUILD_SOCKET, addr ERR_BUILD_SOCKET, MB_OK
		ret
    .endif
    mov @listenSocket, eax

	; bind socket
    invoke RtlZeroMemory, addr @stSin,sizeof @stSin
    invoke htons, @serverPort
    mov @stSin.sin_port, ax
    mov @stSin.sin_family, AF_INET
    mov @stSin.sin_addr, INADDR_ANY
    invoke bind, @listenSocket, addr @stSin,sizeof @stSin
    .if eax
		invoke MessageBox,NULL, addr ERR_BIND_SOCKET, addr ERR_BIND_SOCKET, MB_OK
		ret
    .endif

    ; listen socket
    invoke listen, @listenSocket, BACKLOG
    invoke crt_printf, addr START_HINT

    .while TRUE
		push ecx
		; accept new socket
		invoke accept, @listenSocket, NULL, 0
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

    invoke closesocket, @listenSocket
    ret
main ENDP

end