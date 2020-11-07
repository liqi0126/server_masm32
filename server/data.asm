include masm32rt.inc
include msvcrt.inc
include header.inc

includelib msvcrt.lib

.data
PASSWORD_HEADER		byte "PASSWORD", 0
FRIENDS_HEADER		byte "FRIENDS", 0

EMPTY				byte 0

USER_INFO_FOLDER	byte "./USERS", 0
FILE_FORMAT			byte "%s/%s.%s", 0
TXT_TAIL			byte "txt",0

userFileName byte 1024 dup (0)


.code

;--------------------------------------------------------------
; internal utils function
;--------------------------------------------------------------
getUserFileName PROC USES eax ecx, username:PTR BYTE
	invoke crt_sprintf, addr userFileName, addr FILE_FORMAT, addr USER_INFO_FOLDER, username, addr TXT_TAIL
    ret 
getUserFileName ENDP


writeUserFile PROC username:ptr byte, password:ptr byte, friends:ptr byte
	local @fp :dword

	invoke getUserFileName, username
	mov @fp, fcreate(addr userFileName)
	fprint @fp, offset PASSWORD_HEADER
	fprint @fp, password

	fprint @fp, offset FRIENDS_HEADER
	fprint @fp, friends

	fclose @fp
	ret
writeUserFile ENDP

;--------------------------------------------------------------
getUserInfo PROC username:ptr byte, header:ptr byte, buffer:ptr byte
; get UserInfo by header
;--------------------------------------------------------------
	local @fp				:dword
	local @flen				:dword
	local @buf				:dword
	local @linebuf			:dword
	local @file_size		:dword
	local @offset			:dword

	mov @offset, 0
	mov @buf, alloc(8096)
	mov @linebuf, alloc(1024)

	invoke getUserFileName, username
	mov @fp, fopen(addr userFileName)
	mov @flen, fsize(@fp)
	mov @file_size, fread(@fp, @buf, @flen)

	.while 1
		invoke readline, @buf, @linebuf, @offset
		mov @offset, eax
		.if @offset == 0
			mov eax, 0
			jmp finish
		.endif

		invoke crt_strcmp, header, @linebuf
		.if eax == 0
			invoke readline, @buf, buffer, @offset
			mov eax, 1
			jmp finish
		.endif
	.endw

finish:
	fclose @fp
	free @buf
	free @linebuf

	ret
getUserInfo ENDP

;--------------------------------------------------------------
; public function
;--------------------------------------------------------------


;--------------------------------------------------------------
writeNewUser PROC USES eax, username:PTR BYTE,password:PTR BYTE
; add a new user
;--------------------------------------------------------------
	invoke writeUserFile, username, password, offset EMPTY
    ret
writeNewUser ENDP

;--------------------------------------------------------------
updateFriendStatus PROC	user:PTR BYTE, friend:PTR BYTE, status:DWORD
; update friend status
; if friend doesn't exist, then create
;--------------------------------------------------------------
	LOCAL @passwordBuffer[256]:byte
	LOCAL @friendsBuffer[1024]:byte
	LOCAL @buf[1024]:byte

	invoke getUserInfo, user, offset PASSWORD_HEADER, addr @passwordBuffer
	invoke getUserInfo, user, offset FRIENDS_HEADER, addr @friendsBuffer

	invoke crt_strstr, addr @friendsBuffer, friend
	.if eax == 0 ; if user doesn't exists
		.if @friendsBuffer != 0
			invoke crt_strcat, addr @friendsBuffer, offset SEP
		.endif
		invoke crt_sprintf, addr @buf, offset MSG_FORMAT5, friend, status
		invoke crt_strcat, addr @friendsBuffer, addr @buf
	.else
		invoke crt_strstr, eax, offset SEP1
		inc eax
		mov ebx, status
		add ebx, 48 ; convert into ASCII code
		mov [eax], bl
	.endif
	invoke writeUserFile, user, addr @passwordBuffer, addr @friendsBuffer
	ret
updateFriendStatus ENDP


;--------------------------------------------------------------
deleteFriend PROC user:PTR BYTE, friend:PTR BYTE
; delete friend
;--------------------------------------------------------------
	LOCAL @passwordBuffer :dword
	LOCAL @friendsBuffer :dword
	LOCAL @newFriendsBuffer :dword
	LOCAL @len:dword
	LOCAL @cursor:dword

	mov @passwordBuffer, alloc(256)
	mov @friendsBuffer, alloc(1024)
	mov @newFriendsBuffer, alloc(1024)

	invoke getUserInfo, user, offset PASSWORD_HEADER, @passwordBuffer
	invoke getUserInfo, user, offset FRIENDS_HEADER, @friendsBuffer

	invoke crt_strstr, @friendsBuffer, friend
	.if eax == 0
		ret
	.endif
	mov @cursor, eax
	sub eax, @friendsBuffer
	mov @len, eax

	.if @len > 0 ; friend is not at the first
		dec @len
		invoke crt_strncpy, @newFriendsBuffer, @friendsBuffer, @len
	.endif

	invoke crt_strstr, @cursor, offset SEP
	.if eax != 0
		.if @len == 0
			inc eax
		.endif
		invoke crt_strcat, @newFriendsBuffer, eax
	.endif

	invoke writeUserFile, user, @passwordBuffer, @newFriendsBuffer

	free @passwordBuffer
	free @friendsBuffer
	free @newFriendsBuffer
	ret
deleteFriend ENDP

;--------------------------------------------------------------
ifSignIn PROC  username:PTR BYTE
; if already sign in
; eax = 0 if already sign in
; eax = 1 if not
;--------------------------------------------------------------
    invoke getUserFileName, username
    .if rv(exist,ADDR userFileName) != 0
		mov eax, 1
    .else
		mov eax, 0                      
    .endif
    ret
ifSignIn ENDP

;--------------------------------------------------------------
ifFriends PROC  user:PTR BYTE, friend:PTR BYTE  
; check if "friend" is "user"'s friend
; eax = 1 if yes
; eax = 0 if no
;--------------------------------------------------------------
	LOCAL @friendsBuffer[1024] :byte

	invoke getUserInfo, user, offset FRIENDS_HEADER, addr @friendsBuffer
	invoke crt_strstr, addr @friendsBuffer, friend
	.if eax != 0
		invoke crt_strstr, eax, offset SEP1
		inc eax
		mov bl, [eax]
		.if bl == IS_FRIEND_ASCII
			mov eax, 1
		.else
			mov eax, 0
		.endif
	.endif
	ret
ifFriends ENDP


;--------------------------------------------------------------
ifPasswordRight PROC  username:PTR BYTE,password:PTR BYTE
; check if password right
; eax = 1 if yes
; eax = 0 if no
;--------------------------------------------------------------
	LOCAL @passwordBuffer[256] :byte
	invoke getUserInfo, username, offset PASSWORD_HEADER, addr @passwordBuffer
	
	invoke crt_strcmp, addr @passwordBuffer, password

	.if eax == 0
		mov eax, 1
		ret
	.else
		mov eax, 0
		ret
	.endif

	ret
ifPasswordRight ENDP

;--------------------------------------------------------------
readAllFriends PROC username:PTR BYTE, friendsBuffer:PTR BYTE
; get all friends
;--------------------------------------------------------------
	invoke getUserInfo, username, offset FRIENDS_HEADER, friendsBuffer
	ret
readAllFriends ENDP
end