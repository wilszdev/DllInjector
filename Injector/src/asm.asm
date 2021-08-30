;.code
;GetLastErrCode64 proc
;	mov rax, qword ptr gs:[68h]
;	ret
;GetLastErrCode64 endp
;GetTebAddr64 proc
;	mov rax, qword ptr gs:[30h]	
;	ret
;GetTebAddr64 endp
;end