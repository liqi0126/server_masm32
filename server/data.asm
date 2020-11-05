include masm32rt.inc
include msvcrt.inc
include header.inc

includelib msvcrt.lib

.data
PASSWORD_HEADER		byte "PASSWORD", 0
FRIENDS_HEADER		byte "FRIENDS", 0

EMPTY				byte 0

USER_INFO_FOLDER	byte "./userInfo", 0
ALL_USER_FILE		byte "allUsers", 0
FILE_FORMAT			byte "%s/%s.%s", 0
TXT_TAIL			byte "txt",0

ERR_OPEN_FILE_HINT	byte "File is Null", 0ah, 0dh, 0


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

getUserInfo PROC username:ptr byte, header:ptr byte, buffer:ptr byte
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
    LOCAL @fp :DWORD  
    LOCAL @offset  :DWORD

    invoke getUserFileName, addr ALL_USER_FILE
    mov @fp, fopen(addr userFileName)
    mov @offset, fseek(@fp, 0, FILE_END)
    fprint @fp, username
    fclose @fp

	invoke writeUserFile, username, password, offset EMPTY
   
    ret
writeNewUser ENDP


;--------------------------------------------------------------
writeNewFriend PROC USES eax, user1:PTR BYTE, user2:PTR BYTE
; add friends list to user1 and user2
;--------------------------------------------------------------
	LOCAL @passwordBuffer[256] :byte
	LOCAL @friendsBuffer[1024] :byte
    
    invoke getUserInfo, user1, offset PASSWORD_HEADER, addr @passwordBuffer
	invoke getUserInfo, user1, offset FRIENDS_HEADER, addr @friendsBuffer
	invoke crt_strstr, addr @friendsBuffer, user2
	.if eax == 0 ; if doesn't exist
		.if @friendsBuffer != 0
			invoke crt_strcat, addr @friendsBuffer, addr SEP
		.endif
		invoke crt_strcat, addr @friendsBuffer, user2
	.endif
	invoke writeUserFile, user1, addr @passwordBuffer, addr @friendsBuffer

    invoke getUserInfo, user2, offset PASSWORD_HEADER, addr @passwordBuffer
	invoke getUserInfo, user2, offset FRIENDS_HEADER, addr @friendsBuffer
	invoke crt_strstr, addr @friendsBuffer, user1
	.if eax == 0 ; if doesn't exist
		.if @friendsBuffer != 0
			invoke crt_strcat, addr @friendsBuffer, addr SEP
		.endif
		invoke crt_strcat, addr @friendsBuffer, user1
	.endif
	invoke writeUserFile, user2, addr @passwordBuffer, addr @friendsBuffer                   
   
    ret
writeNewFriend ENDP


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
ifFriends PROC  user1:PTR BYTE,user2:PTR BYTE  
; check if user1 and user2 are friends
; eax = 1 if yes
; eax = 0 if no
;--------------------------------------------------------------
	LOCAL @friendsBuffer[1024] :byte
	
	invoke getUserInfo, user1, offset FRIENDS_HEADER, addr @friendsBuffer
	invoke crt_strstr, addr @friendsBuffer, user2
	.if eax != 0
		mov eax, 1
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