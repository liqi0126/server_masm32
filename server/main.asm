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

;==================== DATA =======================
.data
; message
BIND_PORT_HINT		db "BIND PORT:", 0
START_HINT			db "SERVER START!", 0dh, 0ah, 0

SUCCESS_HINT		db "1", 0
SIGNUP_SUCCESS_HINT db "USER %s SIGNUP", 0ah, 0dh, 0
SIGNUP_FAIL_HINT	db "USER %s SIGNUP FAIL", 0ah, 0dh, 0
LOGIN_SUCCESS_HINT	db "USER %s LOGIN", 0ah, 0dh, 0
LOGIN_FAIL_HINT		db "USER %s LOGIN FAIL", 0ah, 0dh, 0
LOGOUT_HINT			db "USER %s LOGOUT", 0ah, 0dh, 0

ERR_BUILD_SOCKET	db "Fail to Open Socket", 0
ERR_BIND_SOCKET		db "Fail to Bind Socket", 0
ERR_REPEAT_SIGNIN	db "User %s already sign in", 0
ERR_WRONG_PASS		db "Password is wrong", 0
ERR_NO_SUCH_USER	db "No User %s, please sign in firstly", 0
ERR_REPEAT_LOGIN	db "User %s already login", 0


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
	LOCAL @friendTypePos:dword
	LOCAL @sockfd:dword

	invoke crt_strlen, friendList
	.if eax == 0
		ret
	.endif

	mov eax, friendList
	mov @cursor, eax

	invoke crt_strcat, friendList, offset SEP
	.while 1
		invoke crt_strstr, @cursor, offset SEP
		.if eax == 0
			jmp finish
		.endif
		dec eax
		mov @friendTypePos, eax
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
			.if eax == 1
				mov eax, @friendTypePos
				mov bl, FRIEND_ONLINE_ASCII
				mov [eax], bl
			.else
				mov eax, @friendTypePos
				mov bl, FRIEND_OFFLINE_ASCII
				mov [eax], bl
			.endif
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
; 6 Friend 1 (user online)
; 6 Friend 2 (user offline)
;--------------------------------------------------------------
	LOCAL targetname:ptr byte
	LOCAL targetfd:dword
	LOCAL @msgField[1024]:byte
	LOCAL @replyBuffer[512]:byte

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
					invoke crt_sprintf, addr @msgField, addr MSG_FORMAT4, SERVER_FRIEND_NOTIFY, currentname, FRIEND_ONLINE
				.else
					invoke crt_sprintf, addr @msgField, addr MSG_FORMAT4, SERVER_FRIEND_NOTIFY, currentname, FRIEND_OFFLINE
				.endif
				invoke crt_strlen, addr @msgField
				invoke send, targetfd, addr @msgField, eax, 0

				;invoke RtlZeroMemory, addr @replyBuffer, 512
				;invoke recv, targetfd, addr @replyBuffer, 512, 0
				;.if @replyBuffer[0] == '0'
				;	invoke crt_printf, offset MSG_FORMAT9, targetname, addr @replyBuffer
				;.endif

			.endif
		.endif
		popad
		inc eax
		add ebx, type client
	.endw
	ret
broadcastOnOffLine ENDP

;--------------------------------------------------------------
sendMsgToChatRoom PROC sourceUser:ptr byte, msg:ptr byte
; format: 2 sourceUsr Msg
;--------------------------------------------------------------
	LOCAL @msgField:dword
	LOCAL @msgLen:dword
	LOCAL @sockfd:dword
	mov @msgField, alloc(BUFSIZE)
	
	invoke crt_sprintf, @msgField, offset MSG_FORMAT3, SERVER_ROOM_TALK, sourceUser, msg
	invoke crt_strlen, @msgField
	mov @msgLen, eax

	mov eax, 0 ; cur client num
	mov ebx, 0 ; cur client offset
	.while eax < clientnum
		pushad
		.if clientlist[ebx].online == 1
			mov eax, clientlist[ebx].sockfd
			mov @sockfd, eax
			invoke crt_strcmp, sourceUser, addr clientlist[ebx].username
			.if eax != 0
				invoke send, @sockfd, @msgField, @msgLen, 0
				.if eax == SOCKET_ERROR
					mov eax, 0
					ret
				.endif
			.endif
		.endif
		popad

		inc eax
		add ebx, type client
	.endw

	free @msgField
	mov eax, 1
	ret
sendMsgToChatRoom ENDP


;--------------------------------------------------------------
sendMsgToUser PROC sourceUser:ptr byte, targetUser:ptr byte, msg:ptr byte
; format: 3 sourceUsr Msg
;--------------------------------------------------------------
	LOCAL @msgField:dword
	LOCAL @msgLen:dword
	LOCAL @sockfd:dword
	mov @msgField, alloc(BUFSIZE)
	
	invoke crt_sprintf, @msgField, offset MSG_FORMAT3, SERVER_1TO1_TALK, sourceUser, msg
	invoke crt_strlen, @msgField
	mov @msgLen, eax
	
	invoke getClientFd, targetUser, addr @sockfd
	.if eax == 0
		ret
	.endif

	invoke send, @sockfd, @msgField, @msgLen, 0
	.if eax == SOCKET_ERROR
		mov eax, 0
		ret
	.endif

	free @msgField
	mov eax, 1
	ret
sendMsgToUser ENDP

;--------------------------------------------------------------
sendFriendRequest PROC sourceUser:ptr byte, targetUser:ptr byte
; format: 4 targetUser
;--------------------------------------------------------------
	LOCAL @msgField:dword
	LOCAL @msgLen:dword
	LOCAL @sockfd:dword

	mov @msgField, alloc(BUFSIZE)

	invoke crt_sprintf, @msgField, offset MSG_FORMAT1, SERVER_FRIEND_APPLY, sourceUser
	invoke crt_strlen, @msgField
	mov @msgLen, eax

	invoke getClientFd, targetUser, addr @sockfd
	.if eax == 0
		ret
	.endif

	invoke send, @sockfd, @msgField, @msgLen, 0
	.if eax == SOCKET_ERROR
		mov eax, 0
		ret
	.endif

	free @msgField
	mov eax, 1
	ret
sendFriendRequest ENDP


;--------------------------------------------------------------
sendFriendRequestReply PROC sourceUser:ptr byte, targetUser:ptr byte, passed:dword
; format: 6 targetUser 4/5 ги4 pass / 5 reject)
;--------------------------------------------------------------
	LOCAL @msgField:dword
	LOCAL @msgLen:dword
	LOCAL @sockfd:dword

	mov @msgField, alloc(BUFSIZE)

	.if passed
		invoke crt_sprintf, @msgField, offset MSG_FORMAT4, SERVER_FRIEND_NOTIFY, sourceUser, FRIEND_APPLY_PASS
	.else
		invoke crt_sprintf, @msgField, offset MSG_FORMAT4, SERVER_FRIEND_NOTIFY, sourceUser, FRIEND_APPLY_REJ
	.endif
	invoke crt_strlen, @msgField
	mov @msgLen, eax

	invoke getClientFd, targetUser, addr @sockfd
	.if eax == 0
		ret
	.endif

	invoke send, @sockfd, @msgField, @msgLen, 0
	.if eax == SOCKET_ERROR
		mov eax, 0
		ret
	.endif

	free @msgField
	mov eax, 1
	ret
sendFriendRequestReply ENDP

;--------------------------------------------------------------
notifyFriendDeleted PROC sourceUser:ptr byte, targetUser:ptr byte
; format: 6 targetUser 6
;--------------------------------------------------------------
	LOCAL @msgField:dword
	LOCAL @msgLen:dword
	LOCAL @sockfd:dword

	mov @msgField, alloc(BUFSIZE)

	invoke crt_sprintf, @msgField, offset MSG_FORMAT4, SERVER_FRIEND_NOTIFY, sourceUser, FRIEND_DELETED
	invoke crt_strlen, @msgField
	mov @msgLen, eax

	invoke getClientFd, targetUser, addr @sockfd
	.if eax == 0
		ret
	.endif

	invoke send, @sockfd, @msgField, @msgLen, 0
	.if eax == SOCKET_ERROR
		mov eax, 0
		ret
	.endif

	free @msgField
	mov eax, 1
	ret
notifyFriendDeleted ENDP

sendRoomMembers PROC username:ptr byte
	LOCAL @sockfd:dword
	LOCAL @friendlist[2048]:dword
	LOCAL @msgField:dword
	LOCAL @msgLen:dword
	LOCAL @friendNum:dword
	LOCAL @replyBuffer[512]:byte

	mov @msgField, alloc(BUFSIZE)

	invoke RtlZeroMemory, addr @friendlist, 2048
	mov eax, 0 ; cur client num
	mov ebx, 0 ; cur client offset
	.while eax < clientnum
		pushad
		.if clientlist[ebx].online == 1
			invoke crt_strcmp, username, addr clientlist[ebx].username
			.if eax != 0
				.if @friendlist[0] != 0
					invoke crt_strcat, addr @friendlist, addr SEP
				.endif
				invoke crt_strcat, addr @friendlist, addr clientlist[ebx].username
			.endif
		.endif
		popad

		inc eax
		add ebx, type client
	.endw
	
	invoke getClientFd, username, addr @sockfd
	.if eax == 0
		free @msgField
		mov eax, 0
		ret
	.endif

	invoke crt_sprintf, @msgField, offset MSG_FORMAT1, SERVER_ROOM_MEMBERS, addr @friendlist
	invoke crt_strlen, @msgField
	mov @msgLen, eax
	invoke send, @sockfd, @msgField, @msgLen, 0
	

	;invoke RtlZeroMemory, addr @replyBuffer, 512
	;invoke recv, @sockfd, addr @replyBuffer, 512, 0
	;.if @replyBuffer[0] == '0'
;		invoke crt_printf, offset MSG_FORMAT9, username, addr @replyBuffer
;		free @msgField
;		mov eax, 0
;		ret
;	.else
;		free @msgField
;		mov eax, 1
;		ret
;	.endif

	mov eax, 1
	free @msgField
	ret
sendRoomMembers ENDP


notifyJoinOrLeaveRoom PROC username:ptr byte, join:dword
	LOCAL @sockfd:dword
	LOCAL @msgField:dword
	LOCAL @msgLen:dword
	LOCAL @szBuffer[256]:byte
	LOCAL @replyBuffer[512]:byte

	mov @msgField, alloc(BUFSIZE)

	invoke crt_sprintf, @msgField, offset MSG_FORMAT4, SERVER_JOIN_LEAVE, username, join
	invoke crt_strlen, @msgField
	mov @msgLen, eax

	mov eax, 0 ; cur client num
	mov ebx, 0 ; cur client offset
	.while eax < clientnum
		pushad
		.if clientlist[ebx].online == 1
			mov eax, clientlist[ebx].sockfd
			mov @sockfd, eax
			invoke crt_strcmp, username, addr clientlist[ebx].username
			.if eax != 0
				invoke send, @sockfd, @msgField, @msgLen, 0
				.if eax == SOCKET_ERROR
					mov eax, 0
					ret
				.endif

				;invoke RtlZeroMemory, addr @replyBuffer, 512
				;invoke recv, @sockfd, addr @replyBuffer, 512, 0
				;.if @replyBuffer[0] == '0'
				;	popad
				;	pushad
				;	invoke crt_printf, offset MSG_FORMAT9, addr clientlist[ebx].username, addr @replyBuffer
				;.endif

			.endif
		.endif
		popad

		inc eax
		add ebx, type client
	.endw

	free @msgField
	mov eax, 1
	ret
notifyJoinOrLeaveRoom ENDP

sendFriendList PROC username:ptr byte, connfd:dword
	LOCAL @friendlist[1024]:byte
	LOCAL @replyBuffer[512]:byte
	LOCAL @msgField:dword

	mov @msgField, alloc(BUFSIZE)

	; read and send friend lists to current user
	invoke RtlZeroMemory, addr @friendlist, 1024
	invoke readAllFriends, username, addr @friendlist
	invoke checkFriendOnOffLine, addr @friendlist
	invoke crt_sprintf, @msgField, offset MSG_FORMAT1, SERVER_FRIEND_LIST, addr @friendlist
	invoke crt_strlen, @msgField
	invoke send, connfd, @msgField, eax, 0

	;invoke RtlZeroMemory, addr @replyBuffer, 512
	;invoke recv, connfd, addr @replyBuffer, 512, 0
	;.if @replyBuffer[0] == '0'
;		invoke crt_printf, offset MSG_FORMAT9, username, addr @replyBuffer
;	.endif

	free @msgField
	ret
sendFriendList ENDP


;--------------------------------------------------------------
serviceThread PROC uses ebx clientid:dword
; function to handle client request
;--------------------------------------------------------------
	LOCAL @stFdset:fd_set, @stTimeval:timeval
	LOCAL @szBuffer:ptr byte
	LOCAL @currentUsername[64]:byte
	LOCAL @tgtUsername[64]:byte
	LOCAL @msgField:ptr byte
	LOCAL @msgContent:ptr byte
	LOCAL @sockfd:dword

	LOCAL @clientCmd:byte
	LOCAL @tmpCmd:dword
	LOCAL @friendRequestPassed:dword

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

	; send room members to current user
	invoke sendRoomMembers, addr @currentUsername

	; tell other members current user is joining
	invoke notifyJoinOrLeaveRoom, addr @currentUsername, 1

	; read and send friend lists to current user
	invoke sendFriendList, addr @currentUsername, @sockfd

	; tell his friend that he is online
	invoke broadcastOnOffLine, addr @currentUsername, 1

	inc dwThreadCounter
	invoke SetDlgItemInt, hWinMain, IDC_COUNT, dwThreadCounter, FALSE

	.while 1
		mov @stFdset.fd_count, 1
		push @sockfd
		pop @stFdset.fd_array
		mov @stTimeval.tv_usec,200*1000 ;ms
		mov @stTimeval.tv_sec,0
		invoke select, 0, addr @stFdset, NULL, NULL, addr @stTimeval ; wait for client cmd

		.break .if eax == SOCKET_ERROR
		.continue .if eax == 0

		invoke RtlZeroMemory, @szBuffer, BUFSIZE
		invoke recv, @sockfd, @szBuffer, BUFSIZE, 0
		.break .if eax == SOCKET_ERROR
		.break .if !eax

		mov eax, @szBuffer
		mov bl, [eax]
		mov @clientCmd, bl
		.if @clientCmd == CLIENT_ROOM_TALK_ASCII
			mov eax, @szBuffer
			add eax, 2
			invoke sendMsgToChatRoom, addr @currentUsername, eax
			.break .if eax == 0

		.elseif @clientCmd == CLIENT_1TO1_TALK_ASCII
			invoke crt_sscanf, @szBuffer, offset MSG_FORMAT6, addr @tmpCmd, addr @tgtUsername, @msgContent
			invoke sendMsgToUser, addr @currentUsername, addr @tgtUsername, @msgContent
			.break  .if eax == 0

		.elseif @clientCmd == CLIENT_FRIEND_APPLY_ASCII
			mov eax, @szBuffer
			add eax, 2

			push eax
			invoke sendFriendRequest, addr @currentUsername, eax
			.break  .if eax == 0
			pop eax

			invoke updateFriendStatus, addr @currentUsername, eax, FRIEND_PADDING

		.elseif @clientCmd == CLIENT_FRIEND_REPLY_ASCII
			invoke crt_sscanf, @szBuffer, offset MSG_FORMAT4, addr @tmpCmd, addr @tgtUsername, addr @friendRequestPassed
			invoke sendFriendRequestReply, addr @currentUsername, addr @tgtUsername, @friendRequestPassed
			.break .if eax == 0

			.if @friendRequestPassed
				invoke updateFriendStatus, addr @currentUsername, addr @tgtUsername, IS_FRIEND
				invoke updateFriendStatus, addr @tgtUsername, addr @currentUsername, IS_FRIEND
			.elseif
				invoke updateFriendStatus, addr @tgtUsername, addr @currentUsername, FRIEND_APPLY_REJ
			.endif

		.elseif @clientCmd == CLIENT_FRIEND_DELETE_ASCII
			invoke crt_sscanf, @szBuffer, offset MSG_FORMAT1, addr @tmpCmd, addr @tgtUsername
			invoke notifyFriendDeleted, addr @currentUsername, addr @tgtUsername
			.break .if eax == 0

			invoke deleteFriend, addr @currentUsername, addr @tgtUsername 
			invoke updateFriendStatus, addr @tgtUsername, addr @currentUsername, FRIEND_DELETED
		.elseif @clientCmd == CLIENT_LOGOUT_ASCII
			.break
		.endif

	.endw
	invoke closesocket, @sockfd
	dec dwThreadCounter

	mov eax, clientid
	mov ebx, type client
	mul ebx
	mov clientlist[eax].online, 0

	; tell other members current user is leaving
	invoke notifyJoinOrLeaveRoom, addr @currentUsername, 0

	; tell his friend that he is offline
	invoke broadcastOnOffLine, addr @currentUsername, 0

	invoke crt_printf, offset LOGOUT_HINT, addr @currentUsername

	free @szBuffer
	free @msgField
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
	LOCAL @buffer[512]:byte
	LOCAL @type:dword
	LOCAL @username[256]:byte
	LOCAL @password[256]:byte


	invoke RtlZeroMemory, addr @buffer, 512
	invoke recv, sockfd, addr @buffer, 512, 0
	
	invoke crt_sscanf, addr @buffer, offset MSG_FORMAT3, addr @type, addr @username, addr @password

	.if @type == CLIENT_LOGIN
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
	.elseif @type == CLIENT_SIGNUP
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