.386
.model flat, stdcall
;���ִ�Сд
option casemap :none

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

;include irvine32.inc

ExitProcess PROTO STDCALL:DWORD
StdOut		PROTO STDCALL:DWORD

writeNewUser PROTO :PTR BYTE,:PTR BYTE
writeNewFriend PROTO :PTR BYTE,:PTR BYTE
ifLogged PROTO :PTR BYTE
ifFriends PROTO: PTR BYTE,:PTR BYTE
ifPasswordRight PROTO :PTR BYTE,:PTR BYTE
MemSetZero PROTO: PTR BYTE,:DWORD
readAllFriends PROTO :PTR BYTE,:PTR BYTE
myreadline PROTO :PTR BYTE,:PTR BYTE,:DWORD


;==================== DATA =======================
.data
BUFSIZE = 104857600

szConnect db "����",0
 
szDisConnect db "�Ͽ�",0
 
szErrSocket db "error !",0
szErrBind db"error bind !",0

hint_start db "start listening!",0dh,0ah,0
 
szAddr db "127.0.0.1",0
serverPort dw ?

inputHint db "please input the port you want to bind", 0dh,0ah,0
inputFormat db "%d", 0
 
szClient db "Client: %s",0dh,0ah,0
szServer db "Server: %s",0dh,0ah,0

typeCodeZero db "0", 0
typeCodeOne db "1", 0
typeCodeTwo db "2", 0
typeCodeThree db "3", 0
typeCodeFour db "4", 0

dwThreadCounter dd ?
dwFlag dd ?
F_STOP dd ?
hWinMain dd ?

IDC_COUNT equ 40002
IDD_DIALOG1 equ 102

listenSocket dd  ?
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

client STRUCT
	username db 64 DUP(?)
	sockfd dd ?
	status dd 0
client ENDS

threadParam STRUCT
	sockid dd ?
	clientid dd ?
threadParam ENDS

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

stringCopy PROC src:ptr byte, tgt:ptr byte
	push eax
	push ebx
	push ecx
	mov eax, src
	mov ecx, tgt
	mov bl, [eax]
	.while bl != 0
		mov [ecx], bl
		inc eax
		inc ecx
	.endw
	mov bl, 0
	mov [ecx], bl
	pop ecx
	pop ebx
	pop eax
	ret
stringCopy ENDP


stringCmp PROC str1:ptr byte, str2:ptr byte
	LOCAL @str1:ptr byte
	LOCAL @str2:ptr byte
	mov eax, str1
	mov @str1, eax
	mov eax, str2
	mov @str2, eax
	mov edx, @str1
	mov al, [edx]
	mov edx, @str2
	mov bl, [edx]
	.while (al != 0) && (bl != 0)
		.if al != bl
			mov eax, 0
			ret
		.endif
		inc @str1
		inc @str2
		mov edx, @str1
		mov al, [edx]
		mov edx, @str2
		mov bl, [edx]
	.endw
	.if (al == 0) && (bl == 0)
		mov eax, 1
		ret
	.endif
	mov eax, 0
	ret
stringCmp ENDP


nameToFd PROC nameStr:ptr byte, targetfd:ptr dword
	LOCAL @cursor:dword
	mov eax, clientnum
	mov @cursor, 0
	mov edx, @cursor
	mov ebx, 0
	.while edx < eax
		push edx
		.if clientlist[ebx].status == 1
			push ebx
			add ebx, offset clientlist
			invoke crt_strcmp, ebx, nameStr
			pop ebx
			.if eax == 0
				mov eax, clientlist[ebx].sockfd
				mov edx, targetfd
				mov [edx], eax
				mov eax, 1
				ret
			.endif
		.endif
		add ebx, type client
		pop edx
		inc edx
		mov eax, clientnum
	.endw
	mov eax, 0
	sub eax, 1
	mov edx, targetfd
	mov [edx], eax
	mov eax, 0
	ret
nameToFd ENDP


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
			;sprintf(msgField, "%s%s", msgField, content)
			invoke crt_sprintf, msgField, addr msgFormat4, msgField, edx
			pop edx
			invoke nameToFd, edx, addr @tfd
			;mov eax, 1
			.if eax == 1
				;sprintf(msgField, "%s %d ", msgField, 1)
				invoke crt_sprintf, msgField, addr msgFormat5, msgField, 1
			.else
				;sprintf(msgField, "%s %d ", msgField, 0)
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
	push eax
	push ebx
	push edx
	mov eax, clientnum
	mov ebx, 0
	mov edx, 0
	.while ebx < eax
		push eax
		push ebx
		push edx
		.if clientlist[edx].status == 1
			; ������ǰ�����û��б��ҳ��£��ϣ����û��ĺ���
			mov eax, clientlist[edx].sockfd
			mov targetfd, eax
			add edx, offset clientlist
			mov targetname, edx
			invoke ifFriends, targetname, currentname
			.if eax == 1
				; ������û����£��ϣ����û��ĺ��� ��������������Ϣ
				mov eax, isOn
				.if eax == 1
					invoke MemSetZero, addr @msgField, 1024
					; sprintf(msg, "%d %s", 4, name)
					invoke crt_sprintf, addr @msgField, addr msgFormat3, 4, currentname
				.else
					invoke MemSetZero, addr @msgField, 1024
					; sprintf(msg, "%d %s", 5, name)
					invoke crt_sprintf, addr @msgField, addr msgFormat3, 5, currentname
					;invoke StdOut, addr @msgField
				.endif
				; ����
				invoke crt_strlen, addr @msgField
				invoke send, targetfd, addr @msgField, eax, 0
			.endif
		.endif
		pop edx
		pop ebx
		pop eax
		add edx, type client
		inc ebx
	.endw
	pop edx
	pop ebx
	pop eax
	ret
broadcastOnOffLine ENDP


msgParser PROC buffer:ptr byte, targetfd:ptr dword, content:ptr byte
	mov eax, buffer
	mov bl, [eax]
	.if bl == 49
		 ; ������Ϣ����
		 mov edx, eax
		 add edx, 2
		 push edx
		 mov bl, [edx]
		 ; �����Է��û���
		 .while bl != 0
			.if bl == 32
				mov bl, 0
				dec edx
				mov [edx], bl
				mov eax, edx
				inc eax
				pop edx
				push eax
				invoke nameToFd, edx, targetfd
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
		 ; ����Ϣ�ı����Ƶ����ݻ�����
		 invoke crt_strcpy, content, edx
		 mov eax, 1
		 ret
	.elseif bl == 52
		; ͼƬ��Ϣ����
		mov edx, eax
		 add edx, 2
		 push edx
		 mov bl, [edx]
		 ; �����Է��û���
		 .while bl != 0
			.if bl == 32
				mov bl, 0
				mov [edx], bl
				mov eax, edx
				inc eax
				pop edx
				push eax
				invoke nameToFd, edx, targetfd
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
		 ; ��ͼƬ���ݣ������ƣ����Ƶ����ݻ�����
		 invoke crt_strcpy, content, edx
		 mov eax, 2
		 ret
	.elseif bl == 50
		; �Ӻ���
		mov edx, eax
		add edx, 2
		invoke crt_strcpy, content, edx
		mov eax, 3
		ret
	.elseif bl == 51
		; ɾ����
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
	LOCAL @type:dword
	LOCAL @currentSock:dword
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
	invoke MemSetZero, addr @currentUsername, 64
	mov esi, params
	mov eax, (threadParam PTR [esi]).sockid
	mov _hSocket, eax
	mov eax, (threadParam PTR [esi]).clientid
	mov _clientid, eax
	mov ebx, type client
	mul ebx
	add eax, offset clientlist
	invoke crt_strcpy, addr @currentUsername, eax
	invoke StdOut, addr @currentUsername
	pop eax
	inc dwThreadCounter
	;----------------FOR DEBUG--------------
	;invoke recv, _hSocket, addr @szBuffer, 512, 0
	;invoke StdOut,addr @szBuffer
	;invoke send, _hSocket, addr loginFailure, sizeof loginFailure, 0
	;-----------------------------------------

	; ���غ����б�
	invoke MemSetZero, addr @friendlist, 1024
	invoke readAllFriends, addr @currentUsername, addr @friendlist
	invoke StdOut, addr @friendlist
	invoke MemSetZero, @msgField, BUFSIZE
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
			invoke MemSetZero, @szBuffer, BUFSIZE
			invoke recv, _hSocket, @szBuffer, BUFSIZE, 0
			push eax
			invoke StdOut, @szBuffer
			pop eax
			.break  .if eax == SOCKET_ERROR
			.break  .if !eax
			; ������Ϣ
			invoke MemSetZero, @msgContent, BUFSIZE
			invoke msgParser, @szBuffer, addr @targetSockfd, @msgContent
			push eax
			;print " 777 ", 13, 30
			pop eax
			.if eax == 1
				; ������Ϣ����
				invoke MemSetZero, @msgField, BUFSIZE
				; sprintf(msg, "%s %s %s", "1", sender, content)
				invoke crt_sprintf, @msgField, addr msgFormat1, addr typeCodeOne, addr @currentUsername, @msgContent
				invoke StdOut, @msgField
				invoke crt_strlen, @msgField
				invoke send, @targetSockfd, @msgField, eax, 0
				.break  .if eax == SOCKET_ERROR
			.elseif eax == 2
				; ͼƬ��Ϣ����
				invoke MemSetZero, @msgField, BUFSIZE
				; sprintf(msg, "%s %s %s", "2", sender, content)
				invoke crt_sprintf, @msgField, addr msgFormat1, addr typeCodeTwo, addr @currentUsername, @msgContent
				invoke crt_strlen, @msgField
				invoke send, @targetSockfd, @msgField, eax, 0
				.break  .if eax == SOCKET_ERROR
			.elseif eax == 3
				; �Ӻ���
				invoke ifLogged, @msgContent
				.if eax == 1
					; �û�����
					; �������Ƿ��Ѿ��Ǻ���
					invoke ifFriends, @msgContent, addr @currentUsername
					.if eax == 0
						; ���˲��Ǻ��� �������
						invoke writeNewFriend, @msgContent, addr @currentUsername
						; �����һ���Ƿ����ߣ������ߣ���˫���㲥
						invoke nameToFd, @msgContent, addr @targetSockfd
						.if eax == 1
							; �Է����ߣ����˫���㲥

							; ��ǰ�û��㲥
							invoke MemSetZero, @msgField, BUFSIZE
							; sprintf(msg, "%s %s %s", "3", name, "1")
							invoke crt_sprintf, @msgField, addr msgFormat1, addr typeCodeThree, @msgContent, addr typeCodeOne
							invoke crt_strlen, @msgField
							invoke send, _hSocket, @msgField, eax, 0

							; ����ѹ㲥
							invoke MemSetZero, @msgField, BUFSIZE
							; sprintf(msg, "%s %s %s", "3", name, "1")
							invoke crt_sprintf, @msgField, addr msgFormat1, addr typeCodeThree, addr @currentUsername, addr typeCodeOne
							invoke crt_strlen, @msgField
							invoke send, @targetSockfd, @msgField, eax, 0

						.else
							; �Է������ߣ�ֻ���һ���㲥
							; ��ǰ�û��㲥
							invoke MemSetZero, @msgField, BUFSIZE
							; sprintf(msg, "%s %s %s", "3", name, "0")
							invoke crt_sprintf, @msgField, addr msgFormat1, addr typeCodeThree, @msgContent, addr typeCodeZero
							invoke crt_strlen, @msgField
							invoke send, _hSocket, @msgField, eax, 0
						.endif
						;invoke send, _hSocket, addr loginSuccess, sizeof loginSuccess, 0
					.else
						; ���иú��ѣ����ʧ��
						invoke send, _hSocket, addr addFriendFail, sizeof addFriendFail, 0
					.endif
				.else
					; �û������ڣ��Ӻ���ʧ��
					invoke send, _hSocket, addr addFriendFail, sizeof addFriendFail, 0
				.endif
			.elseif eax == 4
				; ˫ɾ����
				invoke ifLogged, @msgContent
				.if eax == 1
					; �û�����
					; �������Ƿ��Ѿ��Ǻ���
					invoke ifFriends, @msgContent, addr @currentUsername
					.if eax == 1
						; �����Ǻ��� ����˫ɾ

					.endif
				.endif
			.endif
		.endif
	.endw
	invoke closesocket,_hSocket
	dec dwThreadCounter
	; �ӵ�ǰ�û��б���ĸ������û�״̬
	mov eax, _clientid
	mov ebx, type client
	mul ebx
	mov clientlist[eax].status, 0
	; ����ѹ㲥��������Ϣ
	invoke broadcastOnOffLine, addr @currentUsername, 0
	free @msgField
	free @szBuffer
	free @msgContent
	invoke SetDlgItemInt,hWinMain,IDC_COUNT,dwThreadCounter,FALSE
	ret
serviceThread ENDP

login PROC sockfd:dword
	LOCAL @username[512]:byte
	LOCAL @password[512]:byte
	LOCAL @type[10]:byte
	LOCAL @tempfd:dword
	invoke MemSetZero, addr @username, 512
	invoke MemSetZero, addr @password, 512
	invoke MemSetZero, addr @type, 10
	print "connected", 13, 10
	; ��������
	invoke recv, sockfd, addr @type, sizeof @type, 0
	invoke StdOut,addr @type
	;print " ", 13, 10
	invoke send, sockfd, addr loginSuccess, sizeof loginSuccess, 0
	; �����û���
	invoke recv, sockfd, addr @username, sizeof @username, 0
	;print "finish username", 13, 10
	invoke StdOut,addr @username
	;print " ", 13, 10
	invoke send, sockfd, addr loginSuccess, sizeof loginSuccess, 0
	; ��������
	invoke recv, sockfd, addr @password, sizeof @password, 0
	invoke StdOut,addr @password
	;print " ", 13, 10
	invoke send, sockfd, addr loginSuccess, sizeof loginSuccess, 0
	; �ж�����
	mov al, @type
	.if al == 48
		; ��¼����

		; ����û����Ƿ����
		invoke ifLogged, addr @username
		.if eax == 0
			; �û��������� ��¼ʧ��
			invoke send, sockfd, addr loginFailure, sizeof loginFailure, 0
			mov eax, 0
			ret
		.endif
		; ��������Ƿ���ȷ
		invoke ifPasswordRight, ADDR @username, ADDR @password
		.if eax == 1
			; ������ȷ

			; ��֤�Ƿ��ظ���¼
			invoke nameToFd, addr @username, addr @tempfd
			.if eax == 1
				; �ظ���¼ ���ص�¼ʧ��
				invoke send, sockfd, addr loginFailure, sizeof loginFailure, 0
				mov eax, 0
				ret
			.endif

			; ��¼�ɹ�
			invoke send, sockfd, addr loginSuccess, sizeof loginSuccess, 0

			; д�뵱ǰ�����û��б�
			mov eax, clientnum
			mov ebx, type client
			mul ebx
			push eax
			add eax, offset clientlist
			mov ebx, offset client.username
			add eax, ebx
			push eax
			mov edx, eax
			invoke MemSetZero, edx, 64
			pop edx
			push edx
			invoke crt_strcpy, edx, addr @username
			pop edx
			invoke StdOut, edx
			mov eax, sockfd
			pop edx
			mov clientlist[edx].sockfd, eax
			mov clientlist[edx].status, 1
			inc clientnum
			; ����ѹ㲥��������
			invoke broadcastOnOffLine, addr @username, 1
			mov eax, 1
			ret
		.else
			; ������� ��¼ʧ��
			invoke send, sockfd, addr loginFailure, sizeof loginFailure, 0
			mov eax, 0
			ret
		.endif
	.else
		; ע������
		print "type signin", 13, 10

		invoke ifLogged, addr @username
		push eax
		print "checked", 13, 10
		pop eax
		.if eax == 0
			; �û��������� ����ע��
			print "start write", 13, 10
			invoke writeNewUser, addr @username, addr @password
			invoke send, sockfd, addr loginSuccess, sizeof loginSuccess, 0
			mov eax, 0
			ret
		.else
			; �û����Ѵ��� ע��ʧ��
			invoke send, sockfd, addr loginFailure, sizeof loginFailure, 0
			mov eax, 0
			ret
		.endif
	.endif
	
	invoke send, sockfd, addr loginFailure, sizeof loginFailure, 0
	mov eax, 0
	ret
login ENDP



sign_in PROC sockfd:dword
	LOCAL @username[512]:byte
	LOCAL @password[512]:byte
	invoke recv, sockfd, addr @username, sizeof @username, 0
	; �����û���
	invoke recv, sockfd, addr @password, sizeof @password, 0
	; ��������
	; isExisted
	; createUser
	;invoke isExisted, @username
	.if eax == 0
		;invoke createUser, @username, @password
		.if eax == 1
			invoke send, sockfd, addr loginSuccess, sizeof loginSuccess, 0
			mov eax, 1
			ret
		.endif
	.endif
	invoke send, sockfd, addr loginFailure, sizeof loginFailure, 0
	mov eax, 0
	ret
sign_in ENDP


main PROC
    LOCAL @stWsa:WSADATA  
    LOCAL @szBuffer[256]:byte
    LOCAL @stSin:sockaddr_in
	LOCAL @connSock:dword
	LOCAL @param_to_thread:threadParam
	LOCAL porttt:dword

	;---------------FOR DEBUG----------------------------------
	;invoke MemSetZero, addr largespace, 200
	;invoke MemSetZero, addr largespace2, 200
	;invoke crt_strcpy, addr largespace2, addr teststring
	;invoke parseFriendList, addr teststring2, addr largespace
	;invoke StdOut, addr largespace
	;----------------------------------------------------------
	invoke StdOut, addr inputHint
	invoke crt_scanf, addr inputFormat, addr serverPort
    invoke WSAStartup, 101h,addr @stWsa
    ;�������׽���
    invoke socket,AF_INET,SOCK_STREAM,0
    .if eax == INVALID_SOCKET
        invoke MessageBox,NULL,addr szErrSocket,addr szErrSocket,MB_OK
        ret
    .endif
    mov listenSocket,eax
    invoke RtlZeroMemory,addr @stSin,sizeof @stSin
    invoke htons,serverPort
    mov @stSin.sin_port,ax
    mov @stSin.sin_family,AF_INET
    mov @stSin.sin_addr,INADDR_ANY
    invoke bind,listenSocket,addr @stSin,sizeof @stSin
    .if eax
		invoke MessageBox,NULL,addr szErrBind,addr szErrBind,MB_OK
		invoke ExitProcess,NULL
    .endif
    ; ����
    invoke listen,listenSocket,5
    invoke StdOut,addr hint_start
    .while TRUE
		push ecx
		invoke accept, listenSocket, NULL, 0
        ;mov connSocket,eax
        ;invoke recv,connSocket,addr @szBuffer,sizeof @szBuffer,0
        ;invoke StdOut,addr @szBuffer
        ;invoke StdOut,addr hint_start
		.if eax==INVALID_SOCKET
			.break
        .endif
		mov @connSock, eax
        ;mov connSocket,eax
        ;invoke recv,connSocket,addr @szBuffer,sizeof @szBuffer,MSG_PEEK
        ;invoke StdOut,addr @szBuffer
        ;invoke send,connSocket,addr @szBuffer,sizeof @szBuffer,0

		; �ж�������ע�ỹ�ǵ�¼
		invoke login, @connSock
		.if eax == 1
			mov edx, clientnum
			dec edx
			mov @param_to_thread.clientid, edx
			mov eax, @connSock
			mov @param_to_thread.sockid, eax
			invoke CreateThread, NULL, 0, offset serviceThread, addr @param_to_thread, NULL, esp
			;print "enter thread", 13, 30
		.else
			invoke CloseHandle, @connSock
		.endif
        pop ecx
    .endw
    invoke closesocket,listenSocket
    ;invoke ExitProcess,0
main ENDP


END main