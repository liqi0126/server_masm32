
include masm32rt.inc
include msvcrt.inc
includelib msvcrt.lib

ExitProcess PROTO STDCALL:DWORD

.data

user_info_folder byte "./userInfo", 0
relativePathHead byte "./userInfo", 0
file_format byte "%s/%s.%s", 0

txtName byte 256 dup (0)
my_tab byte " ",0

txt_tail byte "txt",0

test_username byte "wyq0706",0
test_password byte "123456",0
test_buffer byte 100 dup(?)


.code

;--------------------------------------------------------
Str_length PROC USES edi, pString:PTR BYTE       ;指向字符串
;得到字符串长度
;传入：字符串地址
;结果存入eax
;--------------------------------------------------------
    mov edi, pString       ;字符计数器
    mov eax, 0             ;字符结束？
L1: cmp BYTE PTR[edi],0
    je L2                  ;是：退出
    inc edi                ;否：指向下一个字符
    inc eax                ;计数器加1
    jmp L1
L2: ret
Str_length ENDP



;----------------------------------------------------------
Str_copy PROC USES eax ecx esi edi,
    source:PTR BYTE,       ; source string
    target:PTR BYTE        ; target string
;将字符串从源串复制到目的串。
;要求：目标串必须有足够空间容纳从源复制来的串。
;-----------------------------------------------------------
    INVOKE Str_length, source      ;EAX = 源串长度
    mov ecx, eax                   ;重复计数器
    inc    ecx                     ;由于有零字节，计数器加 1
    mov esi, source
    mov edi, target
    cld                            ;方向为正向
    rep    movsb                   ;复制字符串
    ret
Str_copy ENDP



;-----------------------------------------------------------
getUserFileName PROC USES eax ecx,username:PTR BYTE
;获得该用户名的文件路径
;写入txtName
;-----------------------------------------------------------
	invoke RtlZeroMemory, addr txtName, sizeof txtName
	invoke crt_sprintf, addr txtName, addr file_format, addr user_info_folder, username, addr txt_tail
    ret 
getUserFileName ENDP


;--------------------------------------------------------------
writeNewUser PROC USES eax, username:PTR BYTE,password:PTR BYTE
;把一个新的用户写入userInfo文件夹中的allUsers.txt中
;并创建该用户的txt文件记录：
;第一行为密码；第二行及以后为好友名字
;参数：用户名，密码
;--------------------------------------------------------------

    LOCAL @hFile :DWORD                          ; file handle          
    LOCAL @cloc  :DWORD                          ; current location variable

    invoke getUserFileName, username

    mov @hFile, fopen("./userInfo/allUsers.txt")            ; open the allUsers file
    mov @cloc, fseek(@hFile,0,FILE_END)           ; set the file pointer to the end
    fprint @hFile, username    ; append username to existing data
    fclose @hFile                                ; close the file

    mov @hFile, fcreate(addr txtName)          ; create the USER.txt
    fprint @hFile, password    ; append password to existing data
    fclose @hFile                                ; close the file
   
    ret

writeNewUser ENDP


;-------------------------------------------------------------
writeNewFriend PROC USES eax, user1:PTR BYTE,user2:PTR BYTE
;把新朋友信息写入双方txt文件中
;-------------------------------------------------------------
    LOCAL @hFile :DWORD                          ; file handle          
    LOCAL @cloc  :DWORD                          ; current location variable

    invoke getUserFileName, user1
    mov @hFile, fopen(addr txtName)        
    mov @cloc, fseek(@hFile, 0, FILE_END)         
    fprint @hFile,user2 
    
    fclose @hFile                

    invoke getUserFileName, user2
    mov @hFile, fopen(addr txtName)         
    mov @cloc, fseek(@hFile, 0, FILE_END)       
    fprint @hFile,user1    
    fclose @hFile                          
   
    ret

writeNewFriend ENDP


;-------------------------------------------------------------
ifSignIn PROC  username:PTR BYTE
; 把用户名传入，检查是否注册过
; 如果注册过eax=1，反之为0
;-------------------------------------------------------------       

    invoke getUserFileName, username
    .if rv(exist,ADDR txtName) != 0               ; test if file exists
		mov eax,1
    .else
		mov eax,0                      
    .endif
    ret

ifSignIn ENDP



;----------------------------------------------------------------
Str_compare_my PROC USES ecx edx esi edi,str1:PTR BYTE,str2:PTR BYTE
; 比较两个字符串是否相等
; 传入两个字符串地址
;----------------------------------------------------------------

	LOCAL str1_len:DWORD
	LOCAL str2_len:DWORD

	invoke Str_length,str1
	mov edx,eax
	mov str1_len,edx
	invoke Str_length,str2
	cmp edx,eax
	mov str2_len,edx
	jne outno
	; 如果长度相等
	mov ecx,edx
	; eax存str1地址，ebx存str2地址
	mov eax,str1
	mov ebx,str2
	mov ecx,0

myloop:
	push eax
	push ebx
	mov al,[eax]
	mov bl,[ebx]
	cmp al,bl
	pop ebx
	pop eax
	jne outno
	inc ecx
	inc eax
	inc ebx
	cmp ecx,str1_len
	jne myloop

outyes:
    ; print结果会修改eax值
	;print "string equal!",13,10
	mov eax,0
	jmp outover

outno:
	;print "string not equal!",13,10
	mov eax,1
	jmp outover

outover:
	ret

Str_compare_my ENDP



;-------------------------------------------------------------
ifFriends PROC  user1:PTR BYTE,user2:PTR BYTE
; 传入两个名字，检查他们是否互为好友;***默认两个用户都已注册，可以找到文件记录***
; 如果是则eax=1,否则eax=0
;-------------------------------------------------------------       

    LOCAL @hFile :DWORD                          ; file handle          
    LOCAL @bwrt  :DWORD                          ; variable for bytes written
    LOCAL @flen  :DWORD                          ; file length variable
    LOCAL @hMem  :DWORD                          ; allocated memory handle
    LOCAL @cloc  :DWORD
    LOCAL @word:DWORD
    invoke getUserFileName, user1
    mov @hFile, fopen(addr txtName)        
  ; -------------------------------------------------
  ; open the file , read its content
  ; -------------------------------------------------
    mov @flen,fsize(@hFile)                     ; get its length
    mov @hMem, alloc(@flen)                       ; allocate a buffer of that size
    mov @word,alloc(20)
    mov @cloc,0

    ; 把文本内容读入内存中
    mov @bwrt, fread(@hFile,@hMem,@flen)
    ; 对文本内容进行一行行读取
	invoke readline,@hMem,@word,0
    ; Stdout结果也会修改eax的值
	;invoke StdOut,@word
	;inc eax
	;inc eax
	mov @cloc,eax

myloop:
	invoke readline,@hMem,@word,@cloc
	; 判断是否结束： readline结束标志是eax为0
	cmp eax,0
	je outno
	;如果不是，继续循环
	;inc eax
	;inc eax
	mov @cloc,eax
	;invoke StdOut,@word
	; 比较是否一样
	invoke Str_compare_my,@word,user2
	cmp eax,0
	je outyes
	jmp myloop

outyes:
    fclose @hFile
    ; 释放内存
    free @hMem                                   
    free @word
	mov eax,1
    jmp outover

outno:
    fclose @hFile
    ; 释放内存
    free @hMem                                   
    free @word
	mov eax,0
	jmp outover

outover:   
    
    ret

ifFriends ENDP



;-------------------------------------------------------------
ifPasswordRight PROC  username:PTR BYTE,password:PTR BYTE
; 传入用户名和密码，检查是否正确
; 如果正确，eax=1；否则eax=0
;-------------------------------------------------------------       

    LOCAL @hFile :DWORD                          ; file handle          
    LOCAL @bwrt  :DWORD                          ; variable for bytes written
    LOCAL @flen  :DWORD                          ; file length variable
    LOCAL @hMem  :DWORD                          ; allocated memory handle
    LOCAL @word  :DWORD
    invoke getUserFileName, username
    mov @hFile, fopen(addr txtName)        
  ; -------------------------------------------------
  ; open the file , read its content
  ; -------------------------------------------------
    mov @flen,fsize(@hFile)                     ; get its length
    mov @hMem, alloc(@flen)                       ; allocate a buffer of that size
    mov @word,alloc(20)

    ; 把文本内容读入内存中
    mov @bwrt, fread(@hFile,@hMem,@flen)
    ; 对文本内容第一行惊醒读取
	invoke readline,@hMem,@word,0
    invoke Str_compare_my,@word,password
	cmp eax,0
    jne outno

outyes:
    fclose @hFile
    ; 释放内存
    free @hMem                                   
    free @word
	mov eax,1
    jmp outover

outno:
    fclose @hFile
    ; 释放内存
    free @hMem                                   
    free @word
	mov eax,0
	jmp outover

outover:   
    
    ret

ifPasswordRight ENDP



;--------------------------------------------------------------
;读入所有用户信息，写入内存中
initializeUserInfo  PROC

initializeUserInfo  ENDP


;---------------------------------------------------
Str_merge PROC USES eax edx,firstPart:PTR BYTE,secondPart:PTR BYTE
;字符串拼接
;要求：目标串必须有足够空间容纳从源复制来的串。
;---------------------------------------------------

	invoke Str_length,firstPart
	mov edx,firstPart
	add edx,eax
	invoke Str_copy,secondPart,edx
    ret

Str_merge ENDP


;----------------------------------------------------------------------------
myreadline PROC USES edx ebx, _source:PTR BYTE,_word:PTR BYTE,_pos:DWORD
;一行行读取文本，\r\n结尾
;eax存放上次读完，下一次起始地址
;----------------------------------------------------------------------------
	LOCAL @pos:DWORD

	mov edx,_source
	mov eax,_pos
	add edx,eax
	;当前起始位置
	mov @pos,edx
	mov bl,[edx]

	.while TRUE
			.if bl==10 || bl==13
				; 如果为空格
				mov bl,0
				mov [edx],bl

				pushad
				invoke crt_strcpy,_word,@pos
				pushad
				;invoke StdOut,_word
				popad
				popad
            .break
            .elseif bl==0
                mov eax,0
                ret

			.endif

			inc edx
			mov bl,[edx]
	.endw

    mov eax,_source
	sub edx,eax
	mov eax,edx
	inc eax
    inc eax

    ret

myreadline ENDP


;--------------------------------------------------------------
readAllFriends PROC _username:PTR BYTE,_buffer:PTR BYTE
;传入需要读取用户列表的用户名，传入存入用户列表信息的字符串指针
; 形式如同： xxx xxx xxxx
;把用户所有好友信息写入字符串指针地址
;--------------------------------------------------------------

    LOCAL @hFile :DWORD                          ; file handle          
    LOCAL @bwrt  :DWORD                          ; variable for bytes written
    LOCAL @flen  :DWORD                          ; file length variable
    LOCAL @hMem  :DWORD                          ; allocated memory handle
    LOCAL @cloc  :DWORD
    LOCAL @word[30]:DWORD
    invoke getUserFileName, _username
    mov @hFile, fopen(addr txtName)        
  ; -------------------------------------------------
  ; open the file , read its content
  ; -------------------------------------------------
    mov @flen,fsize(@hFile)                     ; get its length

.if @flen==0
pushad
print "file is null. maybe cannot find file",13,10
popad
.endif

    mov @hMem, alloc(1024)                       ; allocate a buffer of that size
    ;mov @word,alloc(20)
    mov @cloc,0

    ; 把文本内容读入内存中
    mov @bwrt, fread(@hFile,@hMem,@flen)
    ; 对文本内容进行一行行读取
    invoke RtlZeroMemory,addr @word,sizeof @word
	invoke myreadline,@hMem,addr @word,0
    ; Stdout结果也会修改eax的值
	mov @cloc,eax

    invoke RtlZeroMemory,addr @word,sizeof @word
	invoke myreadline,@hMem,addr @word, @cloc
	; 判断是否结束： readline结束标志是eax为0
	cmp eax,0
	je outno
	mov @cloc,eax
    invoke Str_merge,_buffer,addr @word

myloop:
    invoke RtlZeroMemory,addr @word,sizeof @word
	invoke myreadline,@hMem,addr @word,@cloc
	; 判断是否结束： readline结束标志是eax为0
	cmp eax,0
	je outno
	mov @cloc,eax
    invoke Str_merge,_buffer,addr my_tab
    invoke Str_merge,_buffer,addr @word   
	jmp myloop


outno:
    fclose @hFile
    ; 释放内存
    free @hMem                                   
    free @word
    invoke StdOut,_buffer
	mov eax,0
    
    ret

readAllFriends ENDP


mytest PROC 
invoke readAllFriends,addr test_username,addr test_buffer
invoke ExitProcess,0
mytest ENDP

end