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

includelib ws2_32.lib
includelib kernel32.lib
includelib masm32.lib
includelib wsock32.lib
includelib user32.lib


;==================== DECLARE =======================
ExitProcess PROTO STDCALL:DWORD
StdOut		PROTO STDCALL:DWORD

writeNewUser PROTO :PTR BYTE,:PTR BYTE
writeNewFriend PROTO :PTR BYTE,:PTR BYTE
ifSignIn PROTO :PTR BYTE
ifFriends PROTO: PTR BYTE,:PTR BYTE
ifPasswordRight PROTO :PTR BYTE,:PTR BYTE
readAllFriends PROTO :PTR BYTE,:PTR BYTE

;==================== STRUCT =======================
client STRUCT
	username db 64 DUP(?)
	sockfd dd ?
	online db 0
client ENDS

threadParam STRUCT
	sockid dd ?
	clientid dd ?
threadParam ENDS

;==================== CONST =======================
.const
BUFSIZE		EQU		104857600
BACKLOG		EQU		5

CONNECT_LOGIN	EQU		48 ; ASCII '0'
CONNECT_SIGNUP	EQU		49 ; ASCII '1'

IDC_COUNT EQU 40002

MSG_HEADER_ONLINE	EQU		4
MSG_HEADER_OFFLINE	EQU		5

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

INPUT_DB_FORMAT		db "%d", 0

ERR_BUILD_SOCKET	db "Fail to Open Socket", 0
ERR_BIND_SOCKET		db "Fail to Bind Socket", 0

SUCCESS_HINT		db "success", 0
FAIL_HINT			db "fail", 0

MSG_FORMAT			db "%d %s", 0

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


teststring db "tang wang luo", 0
teststring2 db 10 DUP(0)
largespace db 200 DUP(?)
largespace2 db 200 DUP(?)
atab db " ", 0

addFriendFail db "6 fail", 0

;=================== CODE =========================
.code


getClientFd PROC username:ptr byte, targetfd:ptr dword
	mov eax, 0 ; cur client num
	mov ebx, 0 ; cur client offset
	.while eax < clientnum
		.if clientlist[ebx].online == 1
			pushad
			invoke crt_strcmp, addr clientlist[ebx].username, username
			pushad
			.if eax == 0
				mov eax, clientlist[ebx].sockfd
				mov edx, targetfd
				mov [edx], eax
				mov eax, 1
				ret
			.endif
		.endif
		inc eax
		add ebx, type client
	.endw

	mov eax, -1
	mov edx, targetfd
	mov [edx], eax
	mov eax, 0
	ret
getClientFd ENDP


addNewClient PROC username:ptr byte, fd:dword
	mov eax, 0 ; cur client num
	mov ebx, 0 ; cur client offset
	.while eax < clientnum
		pushad
		invoke crt_strcmp, addr clientlist[ebx].username, username
		.if eax == 0
			mov eax, fd
			mov clientlist[ebx].sockfd, eax
			mov clientlist[ebx].online, 1
			ret
		.endif
		popad
		inc eax
		add ebx, type client
	.endw
	mov eax, fd
	mov clientlist[ebx].sockfd, eax
	mov clientlist[ebx].online, 1
	invoke crt_strcpy, addr clientlist[ebx].username, username
	inc clientnum
	ret
addNewClient ENDP


parseFriendList PROC friendlist:ptr byte, msgField:ptr byte
	LOCAL @tfd:dword
	invoke crt_sprintf, friendlist, addr msgFormat6, friendlist, addr atab
	mov eax, friendlist
	mov bl, [eax]
	push eax
	.while bl != 0
		.if bl == 32
			mov bl, 0
			mov [eax], bl
			pop edx
			mov esi, eax
			inc esi
			push esi
			push eax
			push edx
			invoke crt_sprintf, msgField, addr msgFormat4, msgField, edx
			pop edx
			invoke getClientFd, edx, addr @tfd
			.if eax == 1
				invoke crt_sprintf, msgField, addr msgFormat5, msgField, 1
			.else
				invoke crt_sprintf, msgField, addr msgFormat5, msgField, 0
			.endif
			pop eax
		.endif
		inc eax
		mov bl, [eax]
	.endw
	pop edx

	invoke crt_strlen, msgField
	dec eax
	.if eax > 2
		add eax, msgField
		mov bl, 0
		mov [eax], bl
	.else
		mov eax, msgField
		mov bl, 32
		mov [eax], bl
		inc eax
		mov bl, 0
		mov [eax], bl
	.endif

	ret
parseFriendList ENDP


broadcastOnOffLine PROC currentname:ptr byte, isOn:dword
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
					invoke crt_sprintf, addr @msgField, addr MSG_FORMAT, MSG_HEADER_ONLINE, currentname
				.else
					invoke crt_sprintf, addr @msgField, addr MSG_FORMAT, MSG_HEADER_OFFLINE, currentname
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


msgParser PROC buffer:ptr byte, targetfd:ptr dword, content:ptr byte
	mov eax, buffer
	mov bl, [eax]
	.if bl == 49
		 ; 文字消息类型
		 mov edx, eax
		 add edx, 2
		 push edx
		 mov bl, [edx]
		 ; 解析对方用户名
		 .while bl != 0
			.if bl == 32
				mov bl, 0
				dec edx
				mov [edx], bl
				mov eax, edx
				inc eax
				pop edx
				push eax
				invoke getClientFd, edx, targetfd
				.if eax == 0
					mov eax, 5
					ret
				.endif
				.break
			.endif
			mov bl, [edx]
			inc edx
		 .endw
		 pop edx
		 ; 将消息文本复制到内容缓冲区
		 invoke crt_strcpy, content, edx
		 mov eax, 1
		 ret
	.elseif bl == 52
		; 图片消息类型
		mov edx, eax
		 add edx, 2
		 push edx
		 mov bl, [edx]
		 ; 解析对方用户名
		 .while bl != 0
			.if bl == 32
				mov bl, 0
				mov [edx], bl
				mov eax, edx
				inc eax
				pop edx
				push eax
				invoke getClientFd, edx, targetfd
				.if eax == 0
					mov eax, 5
					ret
				.endif
				.break
			.endif
			mov bl, [edx]
			inc edx
		 .endw
		 pop edx
		 ; 将图片内容（二进制）复制到内容缓冲区
		 invoke crt_strcpy, content, edx
		 mov eax, 2
		 ret
	.elseif bl == 50
		; 加好友
		mov edx, eax
		add edx, 2
		invoke crt_strcpy, content, edx
		mov eax, 3
		ret
	.elseif bl == 51
		; 删好友
		mov edx, eax
		add edx, 2
		invoke crt_strcpy, content, edx
		mov eax, 4
		ret
	.endif
	mov eax, 5
	ret
msgParser ENDP


serviceThread PROC params:PTR threadParam
	LOCAL @stFdset:fd_set,@stTimeval:timeval
	LOCAL @szBuffer:ptr byte
	LOCAL @currentUsername[64]:byte
	LOCAL @targetSockfd:dword
	LOCAL @msgContent:ptr byte
	LOCAL @msgField:ptr byte
	LOCAL _hSocket:DWORD
	LOCAL _clientid:DWORD
	LOCAL @friendlist[1024]:byte
	push eax
	mov @szBuffer, alloc(BUFSIZE)
	mov @msgField, alloc(BUFSIZE)
	mov @msgContent, alloc(BUFSIZE)

	invoke RtlZeroMemory, addr @currentUsername, 64
	mov esi, params
	mov eax, (threadParam PTR [esi]).sockid
	mov _hSocket, eax
	mov eax, (threadParam PTR [esi]).clientid
	mov _clientid, eax

	mov ebx, type client
	mul ebx
	add eax, offset clientlist
	invoke crt_strcpy, addr @currentUsername, eax
	pop eax
	inc dwThreadCounter

	; read and send friend lists
	invoke RtlZeroMemory, addr @friendlist, 1024
	invoke readAllFriends, addr @currentUsername, addr @friendlist
	invoke RtlZeroMemory, @msgField, BUFSIZE
	invoke parseFriendList, addr @friendlist, @msgField
	invoke crt_strlen, @msgField
	invoke send, _hSocket, @msgField, eax, 0

	invoke SetDlgItemInt,hWinMain,IDC_COUNT,dwThreadCounter,FALSE
	.while  TRUE
		mov @stFdset.fd_count,1
		push _hSocket
		pop @stFdset.fd_array
		mov @stTimeval.tv_usec,200*1000 ;ms
		mov @stTimeval.tv_sec,0
		invoke select, 0, addr @stFdset, NULL, NULL, addr @stTimeval
		.if eax == SOCKET_ERROR
			.break
		.endif
		.if eax
			invoke RtlZeroMemory, @szBuffer, BUFSIZE
			invoke recv, _hSocket, @szBuffer, BUFSIZE, 0
			push eax
			invoke StdOut, @szBuffer
			pop eax
			.break  .if eax == SOCKET_ERROR
			.break  .if !eax
			; 解析消息
			invoke RtlZeroMemory, @msgContent, BUFSIZE
			invoke msgParser, @szBuffer, addr @targetSockfd, @msgContent
			push eax
			;print " 777 ", 13, 30
			pop eax
			.if eax == 1
				; 文字消息类型
				invoke RtlZeroMemory, @msgField, BUFSIZE
				; sprintf(msg, "%s %s %s", "1", sender, content)
				invoke crt_sprintf, @msgField, addr msgFormat1, addr typeCodeOne, addr @currentUsername, @msgContent
				invoke StdOut, @msgField
				invoke crt_strlen, @msgField
				invoke send, @targetSockfd, @msgField, eax, 0
				.break  .if eax == SOCKET_ERROR
			.elseif eax == 2
				; 图片消息类型
				invoke RtlZeroMemory, @msgField, BUFSIZE
				; sprintf(msg, "%s %s %s", "2", sender, content)
				invoke crt_sprintf, @msgField, addr msgFormat1, addr typeCodeTwo, addr @currentUsername, @msgContent
				invoke crt_strlen, @msgField
				invoke send, @targetSockfd, @msgField, eax, 0
				.break  .if eax == SOCKET_ERROR
			.elseif eax == 3
				; 加好友
				invoke ifSignIn, @msgContent
				.if eax == 1
					; 用户存在
					; 检查二人是否已经是好友
					invoke ifFriends, @msgContent, addr @currentUsername
					.if eax == 0
						; 两人不是好友 可以添加
						invoke writeNewFriend, @msgContent, addr @currentUsername
						; 检查另一方是否在线，如在线，向双方广播
						invoke getClientFd, @msgContent, addr @targetSockfd
						.if eax == 1
							; 对方在线，需对双方广播

							; 向当前用户广播
							invoke RtlZeroMemory, @msgField, BUFSIZE
							; sprintf(msg, "%s %s %s", "3", name, "1")
							invoke crt_sprintf, @msgField, addr msgFormat1, addr typeCodeThree, @msgContent, addr typeCodeOne
							invoke crt_strlen, @msgField
							invoke send, _hSocket, @msgField, eax, 0

							; 向好友广播
							invoke RtlZeroMemory, @msgField, BUFSIZE
							; sprintf(msg, "%s %s %s", "3", name, "1")
							invoke crt_sprintf, @msgField, addr msgFormat1, addr typeCodeThree, addr @currentUsername, addr typeCodeOne
							invoke crt_strlen, @msgField
							invoke send, @targetSockfd, @msgField, eax, 0

						.else
							; 对方不在线，只需对一方广播
							; 向当前用户广播
							invoke RtlZeroMemory, @msgField, BUFSIZE
							; sprintf(msg, "%s %s %s", "3", name, "0")
							invoke crt_sprintf, @msgField, addr msgFormat1, addr typeCodeThree, @msgContent, addr typeCodeZero
							invoke crt_strlen, @msgField
							invoke send, _hSocket, @msgField, eax, 0
						.endif
						;invoke send, _hSocket, addr loginSuccess, sizeof loginSuccess, 0
					.else
						; 已有该好友，添加失败
						invoke send, _hSocket, addr addFriendFail, sizeof addFriendFail, 0
					.endif
				.else
					; 用户不存在，加好友失败
					invoke send, _hSocket, addr addFriendFail, sizeof addFriendFail, 0
				.endif
			.elseif eax == 4
				; 双删好友
				invoke ifSignIn, @msgContent
				.if eax == 1
					; 用户存在
					; 检查二人是否已经是好友
					invoke ifFriends, @msgContent, addr @currentUsername
					.if eax == 1
						; 两人是好友 可以双删

					.endif
				.endif
			.endif
		.endif
	.endw
	invoke closesocket,_hSocket
	dec dwThreadCounter
	; 从当前用户列表更改该下线用户状态
	mov eax, _clientid
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
		mov eax, 0
		ret
	.endif

	; check whether password right
	invoke ifPasswordRight, username, password
	.if eax == 1
		; repeat login
		invoke getClientFd, username, addr @tempfd
		.if eax == 1
			invoke send, sockfd, addr FAIL_HINT, sizeof FAIL_HINT, 0
			mov eax, 0
			ret
		.endif

		; login success
		invoke send, sockfd, addr SUCCESS_HINT, sizeof SUCCESS_HINT, 0

		; add new client
		invoke addNewClient, username, sockfd

		; broadcast on or off line
		invoke broadcastOnOffLine, username, 1
		mov eax, 1
		ret

	.else
		invoke send, sockfd, addr FAIL_HINT, sizeof FAIL_HINT, 0
		mov eax, 0
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
		.if eax == 1
			invoke crt_printf, addr LOGIN_SUCCESS_HINT
			mov eax, 1
			ret
		.else
			invoke crt_printf, addr LOGIN_FAIL_HINT
			mov eax, 0
			ret
		.endif
	.else
		invoke signIn, sockfd, addr @username, addr @password
		.if eax == 1
			invoke crt_printf, addr SIGNUP_SUCCESS_HINT
			mov eax, 0
			ret
		.else
			invoke crt_printf, addr SIGNUP_FAIL_HINT
			mov eax, 0
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
	LOCAL @param_to_thread:threadParam

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
		.if eax == 1 ; if log in
			mov edx, clientnum
			dec edx
			mov @param_to_thread.clientid, edx
			mov eax, @connSock
			mov @param_to_thread.sockid, eax
			invoke CreateThread, NULL, 0, offset serviceThread, addr @param_to_thread, NULL, esp
		.else
			invoke CloseHandle, @connSock
		.endif
        pop ecx
    .endw

    invoke closesocket, listenSocket
    ret
main ENDP


END main