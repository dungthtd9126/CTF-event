LOAD:
 0x10ad000:	mov    rax,QWORD PTR [rsp-0x8]
   0x10ad005:	lea    rbx,[rbx-0x8]
   0x10ad009:	mov    QWORD PTR [rbx],rax
   0x10ad00c:	ret    0x8
PRIMAPPLY:
0x9a99000:	mov    r8,QWORD PTR [rsp-0x8]
   0x9a99005:	mov    rax,QWORD PTR [rbx+0x10]
   0x9a99009:	lea    rbx,[rbx-0x8]
   0x9a9900d:	mov    QWORD PTR [rbx],rax
   0x9a99010:	xor    ecx,ecx
   0x9a99012:	cmp    QWORD PTR [rbx],0x2f
   0x9a99016:	je     0x9a99059
   0x9a99018:	mov    rax,QWORD PTR [rbx]
   0x9a9901b:	lea    rbx,[rbx+0x8]
   0x9a9901f:	lea    rbx,[rbx-0x8]
   0x9a99023:	mov    QWORD PTR [rbx],rax
   0x9a99026:	and    rax,0x7
   0x9a9902a:	cmp    rax,0x1
   0x9a9902e:	mov    rax,QWORD PTR [rbx]
   0x9a99031:	lea    rbx,[rbx+0x8]
   0x9a99035:	jne    0x8008794
   0x9a9903b:	and    rax,0xfffffffffffffffe
   0x9a9903f:	mov    rdi,QWORD PTR [rax]
   0x9a99042:	mov    rax,QWORD PTR [rax+0x8]
   0x9a99046:	lea    rbx,[rbx-0x8]
   0x9a9904a:	mov    QWORD PTR [rbx],rdi
   0x9a9904d:	lea    rbx,[rbx-0x8]
   0x9a99051:	mov    QWORD PTR [rbx],rax
   0x9a99054:	inc    rcx
   0x9a99057:	jmp    0x9a99012
   0x9a99059:	lea    rbx,[rbx+0x8]
   0x9a9905d:	shl    rcx,0x2
   0x9a99061:	lea    rbx,[rbx-0x8]
   0x9a99065:	mov    QWORD PTR [rbx],rcx
   0x9a99068:	jmp    r8
JUMP:
0x70ad000:	mov    rax,QWORD PTR [rsp-0x8]
   0x70ad005:	shl    rax,0x4
   0x70ad009:	add    rsp,rax
   0x70ad00c:	ret    0x8
CJUMP:
 0xca7005:	mov    rcx,QWORD PTR [rbx]
   0xca7008:	lea    rbx,[rbx+0x8]
   0xca700c:	cmp    rcx,0x9f
   0xca7013:	je     0xca7020
   0xca7015:	cmp    rcx,0x1f
   0xca7019:	je     0xca7020
   0xca701b:	jmp    0x8008794
   0xca7020:	cmp    rcx,0x1f
   0xca7024:	je     0xca702d
   0xca7026:	shl    rax,0x4
   0xca702a:	add    rsp,rax
   0xca702d:	ret    0x8
GET:
0x9e7000:	mov    rax,QWORD PTR [rsp-0x8]
   0x9e7005:	mov    rax,QWORD PTR [rbx+rax*8]
   0x9e7009:	lea    rbx,[rbx-0x8]
   0x9e700d:	mov    QWORD PTR [rbx],rax
   0x9e7010:	ret    0x8
FORGET:
0x49e7000:	lea    rbx,[rbx+0x8]
   0x49e7004:	ret    0x8
APPLY:
  0xa991000:	mov    rcx,QWORD PTR [rbx]
   0xa991003:	lea    rbx,[rbx+0x8]
   0xa991007:	mov    rax,QWORD PTR [rbx]
   0xa99100a:	lea    rbx,[rbx+0x8]
   0xa99100e:	lea    rbx,[rbx-0x8]
   0xa991012:	mov    QWORD PTR [rbx],rax
   0xa991015:	and    rax,0x7
   0xa991019:	cmp    rax,0x6
   0xa99101d:	mov    rax,QWORD PTR [rbx]
   0xa991020:	lea    rbx,[rbx+0x8]
   0xa991024:	jne    0x8008794
   0xa99102a:	and    rax,0xfffffffffffffff8
   0xa99102e:	lea    rbx,[rbx-0x8]
   0xa991032:	mov    QWORD PTR [rbx],r12
   0xa991035:	mov    r12,rbx
   0xa991038:	lea    rbx,[rbx-0x8]
   0xa99103c:	mov    QWORD PTR [rbx],rcx
   0xa99103f:	xor    ecx,ecx
   0xa991041:	cmp    QWORD PTR [rbx],0x2f
   0xa991045:	je     0xa991088
   0xa991047:	mov    rsi,QWORD PTR [rbx]
   0xa99104a:	lea    rbx,[rbx+0x8]
   0xa99104e:	lea    rbx,[rbx-0x8]
   0xa991052:	mov    QWORD PTR [rbx],rsi
   0xa991055:	and    rsi,0x7
   0xa991059:	cmp    rsi,0x1
   0xa99105d:	mov    rsi,QWORD PTR [rbx]
   0xa991060:	lea    rbx,[rbx+0x8]
   0xa991064:	jne    0x8008794
   0xa99106a:	and    rsi,0xfffffffffffffffe
   0xa99106e:	mov    rdi,QWORD PTR [rsi]
   0xa991071:	mov    rsi,QWORD PTR [rsi+0x8]
   0xa991075:	lea    rbx,[rbx-0x8]
   0xa991079:	mov    QWORD PTR [rbx],rdi
   0xa99107c:	lea    rbx,[rbx-0x8]
   0xa991080:	mov    QWORD PTR [rbx],rsi
   0xa991083:	inc    rcx
   0xa991086:	jmp    0xa991041
   0xa991088:	lea    rbx,[rbx+0x8]
   0xa99108c:	or     rax,0x6
   0xa991090:	lea    rbx,[rbx-0x8]
   0xa991094:	mov    QWORD PTR [rbx],rax
   0xa991097:	shl    rcx,0x2
   0xa99109b:	lea    rbx,[rbx-0x8]
   0xa99109f:	mov    QWORD PTR [rbx],rcx
   0xa9910a2:	jmp    0xca11000
TAILAPPLY:
0x7991000:	mov    rcx,QWORD PTR [rbx]
   0x7991003:	lea    rbx,[rbx+0x8]
   0x7991007:	mov    rax,QWORD PTR [rbx]
   0x799100a:	lea    rbx,[rbx+0x8]
   0x799100e:	lea    rbx,[rbx-0x8]
   0x7991012:	mov    QWORD PTR [rbx],rax
   0x7991015:	and    rax,0x7
   0x7991019:	cmp    rax,0x6
   0x799101d:	mov    rax,QWORD PTR [rbx]
   0x7991020:	lea    rbx,[rbx+0x8]
   0x7991024:	jne    0x8008794
   0x799102a:	and    rax,0xfffffffffffffff8
   0x799102e:	lea    rbx,[rbx-0x8]
   0x7991032:	mov    QWORD PTR [rbx],rcx
   0x7991035:	xor    ecx,ecx
   0x7991037:	cmp    QWORD PTR [rbx],0x2f
   0x799103b:	je     0x799107e
   0x799103d:	mov    rsi,QWORD PTR [rbx]
   0x7991040:	lea    rbx,[rbx+0x8]
   0x7991044:	lea    rbx,[rbx-0x8]
   0x7991048:	mov    QWORD PTR [rbx],rsi
   0x799104b:	and    rsi,0x7
   0x799104f:	cmp    rsi,0x1
   0x7991053:	mov    rsi,QWORD PTR [rbx]
   0x7991056:	lea    rbx,[rbx+0x8]
   0x799105a:	jne    0x8008794
   0x7991060:	and    rsi,0xfffffffffffffffe
   0x7991064:	mov    rdi,QWORD PTR [rsi]
   0x7991067:	mov    rsi,QWORD PTR [rsi+0x8]
   0x799106b:	lea    rbx,[rbx-0x8]
   0x799106f:	mov    QWORD PTR [rbx],rdi
   0x7991072:	lea    rbx,[rbx-0x8]
   0x7991076:	mov    QWORD PTR [rbx],rsi
   0x7991079:	inc    rcx
   0x799107c:	jmp    0x7991037
   0x799107e:	lea    rbx,[rbx+0x8]
   0x7991082:	or     rax,0x6
   0x7991086:	lea    rbx,[rbx-0x8]
   0x799108a:	mov    QWORD PTR [rbx],rax
   0x799108d:	shl    rcx,0x2
   0x7991091:	lea    rbx,[rbx-0x8]
   0x7991095:	mov    QWORD PTR [rbx],rcx
   0x7991098:	jmp    0x7a11000
ADD:
 0xadd000:	mov    rdi,QWORD PTR [rbx]
   0xadd003:	lea    rbx,[rbx+0x8]
   0xadd007:	lea    rbx,[rbx-0x8]
   0xadd00b:	mov    QWORD PTR [rbx],rdi
   0xadd00e:	and    rdi,0x3
   0xadd012:	test   rdi,rdi
   0xadd015:	mov    rdi,QWORD PTR [rbx]
   0xadd018:	lea    rbx,[rbx+0x8]
   0xadd01c:	jne    0x8008794
   0xadd022:	sar    rdi,0x2
   0xadd026:	test   rdi,rdi
   0xadd029:	jne    0xadd039
   0xadd02b:	lea    rbx,[rbx-0x8]
   0xadd02f:	mov    QWORD PTR [rbx],0x0
   0xadd036:	ret    0x8
   0xadd039:	mov    rax,QWORD PTR [rbx]
   0xadd03c:	lea    rbx,[rbx+0x8]
   0xadd040:	lea    rbx,[rbx-0x8]
   0xadd044:	mov    QWORD PTR [rbx],rax
   0xadd047:	and    rax,0x3
   0xadd04b:	test   rax,rax
   0xadd04e:	mov    rax,QWORD PTR [rbx]
   0xadd051:	lea    rbx,[rbx+0x8]
   0xadd055:	jne    0x8008794
   0xadd05b:	sar    rax,0x2
   0xadd05f:	cmp    rdi,0x1
   0xadd063:	jne    0xadd073
   0xadd065:	shl    rax,0x2
   0xadd069:	lea    rbx,[rbx-0x8]
   0xadd06d:	mov    QWORD PTR [rbx],rax
   0xadd070:	ret    0x8
   0xadd073:	mov    rcx,QWORD PTR [rbx]
   0xadd076:	lea    rbx,[rbx+0x8]
   0xadd07a:	lea    rbx,[rbx-0x8]
   0xadd07e:	mov    QWORD PTR [rbx],rcx
   0xadd081:	and    rcx,0x3
   0xadd085:	test   rcx,rcx
   0xadd088:	mov    rcx,QWORD PTR [rbx]
   0xadd08b:	lea    rbx,[rbx+0x8]
   0xadd08f:	jne    0x8008794
   0xadd095:	sar    rcx,0x2
   0xadd099:	add    rax,rcx
   0xadd09c:	dec    rdi
   0xadd09f:	jmp    0xadd05f
SUB:
 0x50b000:	mov    rdi,QWORD PTR [rbx]
   0x50b003:	lea    rbx,[rbx+0x8]
   0x50b007:	lea    rbx,[rbx-0x8]
   0x50b00b:	mov    QWORD PTR [rbx],rdi
   0x50b00e:	and    rdi,0x3
   0x50b012:	test   rdi,rdi
   0x50b015:	mov    rdi,QWORD PTR [rbx]
   0x50b018:	lea    rbx,[rbx+0x8]
   0x50b01c:	jne    0x8008794
   0x50b022:	sar    rdi,0x2
   0x50b026:	test   rdi,rdi
   0x50b029:	jne    0x50b039
   0x50b02b:	lea    rbx,[rbx-0x8]
   0x50b02f:	mov    QWORD PTR [rbx],0x0
   0x50b036:	ret    0x8
   0x50b039:	mov    rax,QWORD PTR [rbx]
   0x50b03c:	lea    rbx,[rbx+0x8]
   0x50b040:	lea    rbx,[rbx-0x8]
   0x50b044:	mov    QWORD PTR [rbx],rax
   0x50b047:	and    rax,0x3
   0x50b04b:	test   rax,rax
   0x50b04e:	mov    rax,QWORD PTR [rbx]
   0x50b051:	lea    rbx,[rbx+0x8]
   0x50b055:	jne    0x8008794
   0x50b05b:	sar    rax,0x2
   0x50b05f:	cmp    rdi,0x1
   0x50b063:	jne    0x50b076
   0x50b065:	neg    rax
   0x50b068:	shl    rax,0x2
   0x50b06c:	lea    rbx,[rbx-0x8]
   0x50b070:	mov    QWORD PTR [rbx],rax
   0x50b073:	ret    0x8
   0x50b076:	mov    rcx,QWORD PTR [rbx]
   0x50b079:	lea    rbx,[rbx+0x8]
   0x50b07d:	lea    rbx,[rbx-0x8]
   0x50b081:	mov    QWORD PTR [rbx],rcx
   0x50b084:	and    rcx,0x3
   0x50b088:	test   rcx,rcx
   0x50b08b:	mov    rcx,QWORD PTR [rbx]
   0x50b08e:	lea    rbx,[rbx+0x8]
   0x50b092:	jne    0x8008794
   0x50b098:	sar    rcx,0x2
   0x50b09c:	sub    rax,rcx
   0x50b09f:	dec    rdi
   0x50b0a2:	cmp    rdi,0x1
   0x50b0a6:	jne    0x50b076
   0x50b0a8:	shl    rax,0x2
   0x50b0ac:	lea    rbx,[rbx-0x8]
   0x50b0b0:	mov    QWORD PTR [rbx],rax
   0x50b0b3:	ret    0x8
MUL:
0xa55000:	mov    rdi,QWORD PTR [rbx]
   0xa55003:	lea    rbx,[rbx+0x8]
   0xa55007:	lea    rbx,[rbx-0x8]
   0xa5500b:	mov    QWORD PTR [rbx],rdi
   0xa5500e:	and    rdi,0x3
   0xa55012:	test   rdi,rdi
   0xa55015:	mov    rdi,QWORD PTR [rbx]
   0xa55018:	lea    rbx,[rbx+0x8]
   0xa5501c:	jne    0x8008794
   0xa55022:	sar    rdi,0x2
   0xa55026:	test   rdi,rdi
   0xa55029:	jne    0xa55039
   0xa5502b:	lea    rbx,[rbx-0x8]
   0xa5502f:	mov    QWORD PTR [rbx],0x4
   0xa55036:	ret    0x8
   0xa55039:	mov    rax,QWORD PTR [rbx]
   0xa5503c:	lea    rbx,[rbx+0x8]
   0xa55040:	lea    rbx,[rbx-0x8]
   0xa55044:	mov    QWORD PTR [rbx],rax
   0xa55047:	and    rax,0x3
   0xa5504b:	test   rax,rax
   0xa5504e:	mov    rax,QWORD PTR [rbx]
   0xa55051:	lea    rbx,[rbx+0x8]
   0xa55055:	jne    0x8008794
   0xa5505b:	sar    rax,0x2
   0xa5505f:	cmp    rdi,0x1
   0xa55063:	jne    0xa55073
   0xa55065:	shl    rax,0x2
   0xa55069:	lea    rbx,[rbx-0x8]
   0xa5506d:	mov    QWORD PTR [rbx],rax
   0xa55070:	ret    0x8
   0xa55073:	mov    rcx,QWORD PTR [rbx]
   0xa55076:	lea    rbx,[rbx+0x8]
   0xa5507a:	lea    rbx,[rbx-0x8]
   0xa5507e:	mov    QWORD PTR [rbx],rcx
   0xa55081:	and    rcx,0x3
   0xa55085:	test   rcx,rcx
   0xa55088:	mov    rcx,QWORD PTR [rbx]
   0xa5508b:	lea    rbx,[rbx+0x8]
   0xa5508f:	jne    0x8008794
   0xa55095:	sar    rcx,0x2
   0xa55099:	mul    rcx
   0xa5509c:	dec    rdi
   0xa5509f:	jmp    0xa5505f
LT:
 0x1700000:	mov    rdi,QWORD PTR [rbx]
   0x1700003:	lea    rbx,[rbx+0x8]
   0x1700007:	lea    rbx,[rbx-0x8]
   0x170000b:	mov    QWORD PTR [rbx],rdi
   0x170000e:	and    rdi,0x3
   0x1700012:	test   rdi,rdi
   0x1700015:	mov    rdi,QWORD PTR [rbx]
   0x1700018:	lea    rbx,[rbx+0x8]
   0x170001c:	jne    0x8008794
   0x1700022:	sar    rdi,0x2
   0x1700026:	mov    esi,0x1
   0x170002b:	test   rdi,rdi
   0x170002e:	jne    0x170003e
   0x1700030:	lea    rbx,[rbx-0x8]
   0x1700034:	mov    QWORD PTR [rbx],0x9f
   0x170003b:	ret    0x8
   0x170003e:	mov    rax,QWORD PTR [rbx]
   0x1700041:	lea    rbx,[rbx+0x8]
   0x1700045:	lea    rbx,[rbx-0x8]
   0x1700049:	mov    QWORD PTR [rbx],rax
   0x170004c:	and    rax,0x3
   0x1700050:	test   rax,rax
   0x1700053:	mov    rax,QWORD PTR [rbx]
   0x1700056:	lea    rbx,[rbx+0x8]
   0x170005a:	jne    0x8008794
   0x1700060:	sar    rax,0x2
   0x1700064:	dec    rdi
   0x1700067:	test   rdi,rdi
   0x170006a:	jne    0x170007a
   0x170006c:	lea    rbx,[rbx-0x8]
   0x1700070:	mov    QWORD PTR [rbx],0x9f
   0x1700077:	ret    0x8
   0x170007a:	mov    rcx,QWORD PTR [rbx]
   0x170007d:	lea    rbx,[rbx+0x8]
   0x1700081:	lea    rbx,[rbx-0x8]
   0x1700085:	mov    QWORD PTR [rbx],rcx
   0x1700088:	and    rcx,0x3
   0x170008c:	test   rcx,rcx
   0x170008f:	mov    rcx,QWORD PTR [rbx]
   0x1700092:	lea    rbx,[rbx+0x8]
   0x1700096:	jne    0x8008794
   0x170009c:	sar    rcx,0x2
   0x17000a0:	cmp    rax,rcx
   0x17000a3:	setl   al
   0x17000a6:	and    sil,al
   0x17000a9:	mov    rax,rcx
   0x17000ac:	dec    rdi
   0x17000af:	test   rdi,rdi
   0x17000b2:	jne    0x170007a
   0x17000b4:	shl    rsi,0x7
   0x17000b8:	or     rsi,0x1f
   0x17000bc:	lea    rbx,[rbx-0x8]
   0x17000c0:	mov    QWORD PTR [rbx],rsi
   0x17000c3:	ret    0x8
EQ:
0xe3e3000:	mov    rdi,QWORD PTR [rbx]
   0xe3e3003:	lea    rbx,[rbx+0x8]
   0xe3e3007:	lea    rbx,[rbx-0x8]
   0xe3e300b:	mov    QWORD PTR [rbx],rdi
   0xe3e300e:	and    rdi,0x3
   0xe3e3012:	test   rdi,rdi
   0xe3e3015:	mov    rdi,QWORD PTR [rbx]
   0xe3e3018:	lea    rbx,[rbx+0x8]
   0xe3e301c:	jne    0x8008794
   0xe3e3022:	sar    rdi,0x2
   0xe3e3026:	mov    esi,0x1
   0xe3e302b:	test   rdi,rdi
   0xe3e302e:	jne    0xe3e303e
   0xe3e3030:	lea    rbx,[rbx-0x8]
   0xe3e3034:	mov    QWORD PTR [rbx],0x9f
   0xe3e303b:	ret    0x8
   0xe3e303e:	mov    rax,QWORD PTR [rbx]
   0xe3e3041:	lea    rbx,[rbx+0x8]
   0xe3e3045:	lea    rbx,[rbx-0x8]
   0xe3e3049:	mov    QWORD PTR [rbx],rax
   0xe3e304c:	and    rax,0x3
   0xe3e3050:	test   rax,rax
   0xe3e3053:	mov    rax,QWORD PTR [rbx]
   0xe3e3056:	lea    rbx,[rbx+0x8]
   0xe3e305a:	jne    0x8008794
   0xe3e3060:	sar    rax,0x2
   0xe3e3064:	dec    rdi
   0xe3e3067:	test   rdi,rdi
   0xe3e306a:	jne    0xe3e307a
   0xe3e306c:	lea    rbx,[rbx-0x8]
   0xe3e3070:	mov    QWORD PTR [rbx],0x9f
   0xe3e3077:	ret    0x8
   0xe3e307a:	mov    rcx,QWORD PTR [rbx]
   0xe3e307d:	lea    rbx,[rbx+0x8]
   0xe3e3081:	lea    rbx,[rbx-0x8]
   0xe3e3085:	mov    QWORD PTR [rbx],rcx
   0xe3e3088:	and    rcx,0x3
   0xe3e308c:	test   rcx,rcx
   0xe3e308f:	mov    rcx,QWORD PTR [rbx]
   0xe3e3092:	lea    rbx,[rbx+0x8]
   0xe3e3096:	jne    0x8008794
   0xe3e309c:	sar    rcx,0x2
   0xe3e30a0:	cmp    rax,rcx
   0xe3e30a3:	sete   al
   0xe3e30a6:	and    sil,al
   0xe3e30a9:	mov    rax,rcx
   0xe3e30ac:	dec    rdi
   0xe3e30af:	test   rdi,rdi
   0xe3e30b2:	jne    0xe3e307a
   0xe3e30b4:	shl    rsi,0x7
   0xe3e30b8:	or     rsi,0x1f
   0xe3e30bc:	lea    rbx,[rbx-0x8]
   0xe3e30c0:	mov    QWORD PTR [rbx],rsi
   0xe3e30c3:	ret    0x8
EQP:
0x3e3e000:	mov    rdi,QWORD PTR [rbx]
   0x3e3e003:	lea    rbx,[rbx+0x8]
   0x3e3e007:	lea    rbx,[rbx-0x8]
   0x3e3e00b:	mov    QWORD PTR [rbx],rdi
   0x3e3e00e:	and    rdi,0x3
   0x3e3e012:	test   rdi,rdi
   0x3e3e015:	mov    rdi,QWORD PTR [rbx]
   0x3e3e018:	lea    rbx,[rbx+0x8]
   0x3e3e01c:	jne    0x8008794
   0x3e3e022:	sar    rdi,0x2
   0x3e3e026:	mov    esi,0x1
   0x3e3e02b:	test   rdi,rdi
   0x3e3e02e:	jne    0x3e3e03e
   0x3e3e030:	lea    rbx,[rbx-0x8]
   0x3e3e034:	mov    QWORD PTR [rbx],0x9f
   0x3e3e03b:	ret    0x8
   0x3e3e03e:	mov    rax,QWORD PTR [rbx]
   0x3e3e041:	lea    rbx,[rbx+0x8]
   0x3e3e045:	dec    rdi
   0x3e3e048:	test   rdi,rdi
   0x3e3e04b:	jne    0x3e3e05b
   0x3e3e04d:	lea    rbx,[rbx-0x8]
   0x3e3e051:	mov    QWORD PTR [rbx],0x9f
   0x3e3e058:	ret    0x8
   0x3e3e05b:	mov    rcx,QWORD PTR [rbx]
   0x3e3e05e:	lea    rbx,[rbx+0x8]
   0x3e3e062:	cmp    rax,rcx
   0x3e3e065:	sete   al
   0x3e3e068:	and    sil,al
   0x3e3e06b:	mov    rax,rcx
   0x3e3e06e:	dec    rdi
   0x3e3e071:	test   rdi,rdi
   0x3e3e074:	jne    0x3e3e05b
   0x3e3e076:	shl    rsi,0x7
   0x3e3e07a:	or     rsi,0x1f
   0x3e3e07e:	lea    rbx,[rbx-0x8]
   0x3e3e082:	mov    QWORD PTR [rbx],rsi
   0x3e3e085:	ret    0x8
ZEROP: has lots of bad bytes
STRING:
0x571f000:	mov    rdi,QWORD PTR [rbx]
   0x571f003:	lea    rbx,[rbx+0x8]
   0x571f007:	lea    rbx,[rbx-0x8]
   0x571f00b:	mov    QWORD PTR [rbx],rdi
   0x571f00e:	and    rdi,0x3
   0x571f012:	test   rdi,rdi
   0x571f015:	mov    rdi,QWORD PTR [rbx]
   0x571f018:	lea    rbx,[rbx+0x8]
   0x571f01c:	jne    0x8008794
   0x571f022:	sar    rdi,0x2
   0x571f026:	sub    rbp,rdi
   0x571f029:	and    rbp,0xfffffffffffffff8
   0x571f02d:	sub    rbp,0x8
   0x571f031:	mov    rax,rbp
   0x571f034:	mov    QWORD PTR [rbp+0x0],rdi
   0x571f038:	xor    esi,esi
   0x571f03a:	test   rdi,rdi
   0x571f03d:	jne    0x571f04d
   0x571f03f:	or     rax,0x3
   0x571f043:	lea    rbx,[rbx-0x8]
   0x571f047:	mov    QWORD PTR [rbx],rax
   0x571f04a:	ret    0x8
   0x571f04d:	mov    rcx,QWORD PTR [rbx]
   0x571f050:	lea    rbx,[rbx+0x8]
   0x571f054:	lea    rbx,[rbx-0x8]
   0x571f058:	mov    QWORD PTR [rbx],rcx
   0x571f05b:	and    rcx,0xff
   0x571f062:	cmp    rcx,0xf
   0x571f066:	mov    rcx,QWORD PTR [rbx]
   0x571f069:	lea    rbx,[rbx+0x8]
   0x571f06d:	lea    rbx,[rbx-0x8]
   0x571f071:	mov    QWORD PTR [rbx],rcx
   0x571f074:	cmovne rcx,QWORD PTR [rip+0x28e971a]        # 0x8008796
   0x571f07c:	sub    rcx,0xf
   0x571f080:	cmp    rcx,0x7f00
   0x571f087:	mov    rcx,QWORD PTR [rbx]
   0x571f08a:	lea    rbx,[rbx+0x8]
   0x571f08e:	jbe    0x571f095
   0x571f090:	jmp    0x8008794
   0x571f095:	shr    rcx,0x8
   0x571f099:	mov    BYTE PTR [rax+rsi*1+0x8],cl
   0x571f09d:	inc    rsi
   0x571f0a0:	dec    rdi
   0x571f0a3:	jmp    0x571f03a
STRINGREF:
 0x571e000:	mov    rcx,QWORD PTR [rbx]
   0x571e003:	lea    rbx,[rbx+0x8]
   0x571e007:	lea    rbx,[rbx-0x8]
   0x571e00b:	mov    QWORD PTR [rbx],rcx
   0x571e00e:	and    rcx,0x3
   0x571e012:	test   rcx,rcx
   0x571e015:	mov    rcx,QWORD PTR [rbx]
   0x571e018:	lea    rbx,[rbx+0x8]
   0x571e01c:	jne    0x571e069
   0x571e01e:	sar    rcx,0x2
   0x571e022:	mov    rax,QWORD PTR [rbx]
   0x571e025:	lea    rbx,[rbx+0x8]
   0x571e029:	lea    rbx,[rbx-0x8]
   0x571e02d:	mov    QWORD PTR [rbx],rax
   0x571e030:	and    rax,0x7
   0x571e034:	cmp    rax,0x3
   0x571e038:	mov    rax,QWORD PTR [rbx]
   0x571e03b:	lea    rbx,[rbx+0x8]
   0x571e03f:	jne    0x571e069
   0x571e041:	and    rax,0xfffffffffffffffc
   0x571e045:	mov    rdi,QWORD PTR [rax]
   0x571e048:	cmp    rcx,rax
   0x571e04b:	jae    0x571e069
   0x571e04d:	mov    al,BYTE PTR [rax+rcx*1+0x8]
   0x571e051:	and    rax,0xff
   0x571e057:	shl    rax,0x8
   0x571e05b:	or     rax,0xf
   0x571e05f:	lea    rbx,[rbx-0x8]
   0x571e063:	mov    QWORD PTR [rbx],rax
   0x571e066:	ret    0x8
   0x571e069:	ud2
STRINGSET:
pwndbg> x/30i 0x5715000
   0x5715000:	mov    rsi,QWORD PTR [rbx]
   0x5715003:	lea    rbx,[rbx+0x8]
   0x5715007:	lea    rbx,[rbx-0x8]
   0x571500b:	mov    QWORD PTR [rbx],rsi
   0x571500e:	and    rsi,0xff
   0x5715015:	cmp    rsi,0xf
   0x5715019:	mov    rsi,QWORD PTR [rbx]
   0x571501c:	lea    rbx,[rbx+0x8]
   0x5715020:	lea    rbx,[rbx-0x8]
   0x5715024:	mov    QWORD PTR [rbx],rsi
   0x5715027:	cmovne rsi,QWORD PTR [rip+0x28f3767]        # 0x8008796
   0x571502f:	sub    rsi,0xf
   0x5715033:	cmp    rsi,0x7f00
   0x571503a:	mov    rsi,QWORD PTR [rbx]
   0x571503d:	lea    rbx,[rbx+0x8]
   0x5715041:	jbe    0x5715045
   0x5715043:	ud2
   0x5715045:	shr    rsi,0x8
   0x5715049:	mov    rcx,QWORD PTR [rbx]
   0x571504c:	lea    rbx,[rbx+0x8]
   0x5715050:	lea    rbx,[rbx-0x8]
   0x5715054:	mov    QWORD PTR [rbx],rcx
   0x5715057:	and    rcx,0x3
   0x571505b:	test   rcx,rcx
   0x571505e:	mov    rcx,QWORD PTR [rbx]
   0x5715061:	lea    rbx,[rbx+0x8]
   0x5715065:	jne    0x57150b3
   0x5715067:	sar    rcx,0x2
   0x571506b:	mov    rax,QWORD PTR [rbx]
   0x571506e:	lea    rbx,[rbx+0x8]
   0x5715072:	lea    rbx,[rbx-0x8]
   0x5715076:	mov    QWORD PTR [rbx],rax
   0x5715079:	and    rax,0x7
   0x571507d:	cmp    rax,0x3
   0x5715081:	mov    rax,QWORD PTR [rbx]
   0x5715084:	lea    rbx,[rbx+0x8]
   0x5715088:	jne    0x57150b3
   0x571508a:	and    rax,0xfffffffffffffffc
   0x571508e:	mov    rdi,QWORD PTR [rax]
   0x5715091:	cmp    rcx,rax
   0x5715094:	jae    0x57150b3
   0x5715096:	mov    BYTE PTR [rax+rcx*1+0x8],sil
   0x571509b:	and    rax,0xff
   0x57150a1:	shl    rax,0x8
   0x57150a5:	or     rax,0xf
   0x57150a9:	lea    rbx,[rbx-0x8]
   0x57150ad:	mov    QWORD PTR [rbx],rax
   0x57150b0:	ret    0x8
   0x57150b3:	ud2
STRINGAPPEND:
pwndbg> x/30i 0x571A000
   0x571a000:	mov    rdx,QWORD PTR [rbx]
   0x571a003:	lea    rbx,[rbx+0x8]
   0x571a007:	lea    rbx,[rbx-0x8]
   0x571a00b:	mov    QWORD PTR [rbx],rdx
   0x571a00e:	and    rdx,0x3
   0x571a012:	test   rdx,rdx
   0x571a015:	mov    rdx,QWORD PTR [rbx]
   0x571a018:	lea    rbx,[rbx+0x8]
   0x571a01c:	jne    0x8008794
   0x571a022:	sar    rdx,0x2
   0x571a026:	test   rdx,rdx
   0x571a029:	jne    0x571a048
   0x571a02b:	sub    rbp,0x8
   0x571a02f:	mov    QWORD PTR [rbp+0x0],0x0
   0x571a037:	mov    rax,rbp
   0x571a03a:	or     rax,0x3
   0x571a03e:	lea    rbx,[rbx-0x8]
   0x571a042:	mov    QWORD PTR [rbx],rax
   0x571a045:	ret    0x8
   0x571a048:	xor    ecx,ecx
   0x571a04a:	xor    eax,eax
   0x571a04c:	cmp    rcx,rdx
   0x571a04f:	je     0x571a07d
   0x571a051:	mov    rsi,QWORD PTR [rbx+rcx*8]
   0x571a055:	lea    rbx,[rbx-0x8]
   0x571a059:	mov    QWORD PTR [rbx],rsi
   0x571a05c:	and    rsi,0x7
   0x571a060:	cmp    rsi,0x3
   0x571a064:	mov    rsi,QWORD PTR [rbx]
   0x571a067:	lea    rbx,[rbx+0x8]
   0x571a06b:	jne    0x8008794
   0x571a071:	and    rsi,0xfffffffffffffffc
   0x571a075:	add    rax,QWORD PTR [rsi]
   0x571a078:	inc    rcx
   0x571a07b:	jmp    0x571a04c
   0x571a07d:	sub    rbp,rax
   0x571a080:	and    rbp,0xfffffffffffffff8
   0x571a084:	sub    rbp,0x8
   0x571a088:	mov    QWORD PTR [rbp+0x0],rax
   0x571a08c:	lea    rdi,[rbp+0x8]
   0x571a090:	test   rdx,rdx
   0x571a093:	je     0x571a0ca
   0x571a095:	mov    rsi,QWORD PTR [rbx]
   0x571a098:	lea    rbx,[rbx+0x8]
   0x571a09c:	lea    rbx,[rbx-0x8]
   0x571a0a0:	mov    QWORD PTR [rbx],rsi
   0x571a0a3:	and    rsi,0x7
   0x571a0a7:	cmp    rsi,0x3
   0x571a0ab:	mov    rsi,QWORD PTR [rbx]
   0x571a0ae:	lea    rbx,[rbx+0x8]
   0x571a0b2:	jne    0x8008794
   0x571a0b8:	and    rsi,0xfffffffffffffffc
   0x571a0bc:	mov    rcx,QWORD PTR [rsi]
   0x571a0bf:	add    rsi,0x8
   0x571a0c3:	rep movs BYTE PTR [rdi],BYTE PTR [rsi]
   0x571a0c5:	dec    rdx
   0x571a0c8:	jmp    0x571a090
   0x571a0ca:	mov    rax,rbp
   0x571a0cd:	or     rax,0x3
   0x571a0d1:	lea    rbx,[rbx-0x8]
   0x571a0d5:	mov    QWORD PTR [rbx],rax
   0x571a0d8:	ret    0x8
VECTOR:
pwndbg> x/30i 0x5ECF000
   0x5ecf000:	mov    rdi,QWORD PTR [rbx]
   0x5ecf003:	lea    rbx,[rbx+0x8]
   0x5ecf007:	lea    rbx,[rbx-0x8]
   0x5ecf00b:	mov    QWORD PTR [rbx],rdi
   0x5ecf00e:	and    rdi,0x3
   0x5ecf012:	test   rdi,rdi
   0x5ecf015:	mov    rdi,QWORD PTR [rbx]
   0x5ecf018:	lea    rbx,[rbx+0x8]
   0x5ecf01c:	jne    0x8008794
   0x5ecf022:	sar    rdi,0x2
   0x5ecf026:	neg    rdi
   0x5ecf029:	lea    rbp,[rbp+rdi*8-0x8]
   0x5ecf02e:	neg    rdi
   0x5ecf031:	mov    rax,rbp
   0x5ecf034:	mov    QWORD PTR [rbp+0x0],rdi
   0x5ecf038:	xor    esi,esi
   0x5ecf03a:	test   rdi,rdi
   0x5ecf03d:	jne    0x5ecf04d
   0x5ecf03f:	or     rax,0x2
   0x5ecf043:	lea    rbx,[rbx-0x8]
   0x5ecf047:	mov    QWORD PTR [rbx],rax
   0x5ecf04a:	ret    0x8
   0x5ecf04d:	mov    rcx,QWORD PTR [rbx]
   0x5ecf050:	lea    rbx,[rbx+0x8]
   0x5ecf054:	mov    QWORD PTR [rax+rsi*8+0x8],rcx
   0x5ecf059:	inc    rsi
   0x5ecf05c:	dec    rdi
   0x5ecf05f:	jmp    0x5ecf03a
VECTORREF:
pwndbg> x/30i 0x5ECE000
   0x5ece000:	mov    rcx,QWORD PTR [rbx]
   0x5ece003:	lea    rbx,[rbx+0x8]
   0x5ece007:	lea    rbx,[rbx-0x8]
   0x5ece00b:	mov    QWORD PTR [rbx],rcx
   0x5ece00e:	and    rcx,0x3
   0x5ece012:	test   rcx,rcx
   0x5ece015:	mov    rcx,QWORD PTR [rbx]
   0x5ece018:	lea    rbx,[rbx+0x8]
   0x5ece01c:	jne    0x8008794
   0x5ece022:	sar    rcx,0x2
   0x5ece026:	mov    rax,QWORD PTR [rbx]
   0x5ece029:	lea    rbx,[rbx+0x8]
   0x5ece02d:	lea    rbx,[rbx-0x8]
   0x5ece031:	mov    QWORD PTR [rbx],rax
   0x5ece034:	and    rax,0x7
   0x5ece038:	cmp    rax,0x2
   0x5ece03c:	mov    rax,QWORD PTR [rbx]
   0x5ece03f:	lea    rbx,[rbx+0x8]
   0x5ece043:	jne    0x8008794
   0x5ece049:	and    rax,0xfffffffffffffffc
   0x5ece04d:	mov    rdi,QWORD PTR [rax]
   0x5ece050:	cmp    rcx,rax
   0x5ece053:	jae    0x5eca048
   0x5ece059:	mov    rax,QWORD PTR [rax+rcx*8+0x8]
   0x5ece05e:	lea    rbx,[rbx-0x8]
   0x5ece062:	mov    QWORD PTR [rbx],rax
   0x5ece065:	ret    0x8
   0x5ece068:	add    BYTE PTR
VECTORSET:
pwndbg> x/30i 0x5EC5000
   0x5ec5000:	mov    rsi,QWORD PTR [rbx]
   0x5ec5003:	lea    rbx,[rbx+0x8]
   0x5ec5007:	mov    rcx,QWORD PTR [rbx]
   0x5ec500a:	lea    rbx,[rbx+0x8]
   0x5ec500e:	lea    rbx,[rbx-0x8]
   0x5ec5012:	mov    QWORD PTR [rbx],rcx
   0x5ec5015:	and    rcx,0x3
   0x5ec5019:	test   rcx,rcx
   0x5ec501c:	mov    rcx,QWORD PTR [rbx]
   0x5ec501f:	lea    rbx,[rbx+0x8]
   0x5ec5023:	jne    0x8008794
   0x5ec5029:	sar    rcx,0x2
   0x5ec502d:	mov    rax,QWORD PTR [rbx]
   0x5ec5030:	lea    rbx,[rbx+0x8]
   0x5ec5034:	lea    rbx,[rbx-0x8]
   0x5ec5038:	mov    QWORD PTR [rbx],rax
   0x5ec503b:	and    rax,0x7
   0x5ec503f:	cmp    rax,0x2
   0x5ec5043:	mov    rax,QWORD PTR [rbx]
   0x5ec5046:	lea    rbx,[rbx+0x8]
   0x5ec504a:	jne    0x8008794
   0x5ec5050:	and    rax,0xfffffffffffffffc
   0x5ec5054:	mov    rdi,QWORD PTR [rax]
   0x5ec5057:	cmp    rcx,rax
   0x5ec505a:	jae    0x5eca048
   0x5ec5060:	mov    QWORD PTR [rax+rcx*8+0x8],rsi
   0x5ec5065:	lea    rbx,[rbx-0x8]
   0x5ec5069:	mov    QWORD PTR [rbx],rax
   0x5ec506c:	ret    0x8
VECTORAPPEND:
pwndbg> x/30i 0x5ECA000
   0x5eca000:	mov    rdx,QWORD PTR [rbx]
   0x5eca003:	lea    rbx,[rbx+0x8]
   0x5eca007:	lea    rbx,[rbx-0x8]
   0x5eca00b:	mov    QWORD PTR [rbx],rdx
   0x5eca00e:	and    rdx,0x3
   0x5eca012:	test   rdx,rdx
   0x5eca015:	mov    rdx,QWORD PTR [rbx]
   0x5eca018:	lea    rbx,[rbx+0x8]
   0x5eca01c:	jne    0x8008794
   0x5eca022:	sar    rdx,0x2
   0x5eca026:	test   rdx,rdx
   0x5eca029:	jne    0x5eca048
   0x5eca02b:	sub    rbp,0x8
   0x5eca02f:	mov    QWORD PTR [rbp+0x0],0x0
   0x5eca037:	mov    rax,rbp
   0x5eca03a:	or     rax,0x2
   0x5eca03e:	lea    rbx,[rbx-0x8]
   0x5eca042:	mov    QWORD PTR [rbx],rax
   0x5eca045:	ret    0x8
   0x5eca048:	xor    ecx,ecx
   0x5eca04a:	xor    eax,eax
   0x5eca04c:	cmp    rcx,rdx
   0x5eca04f:	je     0x5eca07d
   0x5eca051:	mov    rsi,QWORD PTR [rbx+rcx*8]
   0x5eca055:	lea    rbx,[rbx-0x8]
   0x5eca059:	mov    QWORD PTR [rbx],rsi
   0x5eca05c:	and    rsi,0x7
   0x5eca060:	cmp    rsi,0x2
   0x5eca064:	mov    rsi,QWORD PTR [rbx]
   0x5eca067:	lea    rbx,[rbx+0x8]
   0x5eca06b:	jne    0x8008794
   0x5eca071:	and    rsi,0xfffffffffffffffc
   0x5eca075:	add    rax,QWORD PTR [rsi]
   0x5eca078:	inc    rcx
   0x5eca07b:	jmp    0x5eca04c
   0x5eca07d:	neg    rax
   0x5eca080:	lea    rbp,[rbp+rax*8-0x8]
   0x5eca085:	neg    rax
   0x5eca088:	mov    QWORD PTR [rbp+0x0],rax
   0x5eca08c:	lea    rdi,[rbp+0x8]
   0x5eca090:	test   rdx,rdx
   0x5eca093:	je     0x5eca0cb
   0x5eca095:	mov    rsi,QWORD PTR [rbx]
   0x5eca098:	lea    rbx,[rbx+0x8]
   0x5eca09c:	lea    rbx,[rbx-0x8]
   0x5eca0a0:	mov    QWORD PTR [rbx],rsi
   0x5eca0a3:	and    rsi,0x7
   0x5eca0a7:	cmp    rsi,0x2
   0x5eca0ab:	mov    rsi,QWORD PTR [rbx]
   0x5eca0ae:	lea    rbx,[rbx+0x8]
   0x5eca0b2:	jne    0x8008794
   0x5eca0b8:	and    rsi,0xfffffffffffffffc
   0x5eca0bc:	mov    rcx,QWORD PTR [rsi]
   0x5eca0bf:	add    rsi,0x8
   0x5eca0c3:	rep movs QWORD PTR [rdi],QWORD PTR [rsi]
   0x5eca0c6:	dec    rdx
   0x5eca0c9:	jmp    0x5eca090
   0x5eca0cb:	mov    rax,rbp
   0x5eca0ce:	or     rax,0x2
   0x5eca0d2:	lea    rbx,[rbx-0x8]
   0x5eca0d6:	mov    QWORD PTR [rbx],rax
   0x5eca0d9:	ret    0x8
INTEGERP:
x/30i 0x1234000
  0x1234000:	mov    rax,QWORD PTR [rbx]
   0x1234003:	lea    rbx,[rbx+0x8]
   0x1234007:	lea    rbx,[rbx-0x8]
   0x123400b:	mov    QWORD PTR [rbx],rax
   0x123400e:	and    rax,0x3
   0x1234012:	test   rax,rax
   0x1234015:	mov    rax,QWORD PTR [rbx]
   0x1234018:	lea    rbx,[rbx+0x8]
   0x123401c:	jne    0x123402c
   0x123401e:	lea    rbx,[rbx-0x8]
   0x1234022:	mov    QWORD PTR [rbx],0x9f
   0x1234029:	ret    0x8
   0x123402c:	lea    rbx,[rbx-0x8]
   0x1234030:	mov    QWORD PTR [rbx],0x1f
   0x1234037:	ret    0x8
BOOLEANP:
pwndbg> x/30i 0xB001000
 0xb001000:	mov    rax,QWORD PTR [rbx]
   0xb001003:	lea    rbx,[rbx+0x8]
   0xb001007:	cmp    rax,0x9f
   0xb00100d:	je     0xb001023
   0xb00100f:	cmp    rax,0x1f
   0xb001013:	je     0xb001023
   0xb001015:	lea    rbx,[rbx-0x8]
   0xb001019:	mov    QWORD PTR [rbx],0x1f
   0xb001020:	ret    0x8
   0xb001023:	lea    rbx,[rbx-0x8]
   0xb001027:	mov    QWORD PTR [rbx],0x9f
   0xb00102e:	ret    0x8
CHARP:
pwndbg> x/30i 0xCACA000
   0xcaca000:	mov    rax,QWORD PTR [rbx]
   0xcaca003:	lea    rbx,[rbx+0x8]
   0xcaca007:	lea    rbx,[rbx-0x8]
   0xcaca00b:	mov    QWORD PTR [rbx],rax
   0xcaca00e:	and    rax,0xff
   0xcaca014:	cmp    rax,0xf
   0xcaca018:	mov    rax,QWORD PTR [rbx]
   0xcaca01b:	lea    rbx,[rbx+0x8]
   0xcaca01f:	lea    rbx,[rbx-0x8]
   0xcaca023:	mov    QWORD PTR [rbx],rax
   0xcaca026:	cmovne rax,QWORD PTR [rip+0xfffffffffb53e768]        # 0x8008796
   0xcaca02e:	sub    rax,0xf
   0xcaca032:	cmp    rax,0x7f00
   0xcaca038:	mov    rax,QWORD PTR [rbx]
   0xcaca03b:	lea    rbx,[rbx+0x8]
   0xcaca03f:	jbe    0xcaca04f
   0xcaca041:	lea    rbx,[rbx-0x8]
   0xcaca045:	mov    QWORD PTR [rbx],0x1f
   0xcaca04c:	ret    0x8
   0xcaca04f:	lea    rbx,[rbx-0x8]
   0xcaca053:	mov    QWORD PTR [rbx],0x9f
   0xcaca05a:	ret    0x8
NULLP:
pwndbg> x/30i 0x4321000
   0x4321000:	mov    rax,QWORD PTR [rbx]
   0x4321003:	lea    rbx,[rbx+0x8]
   0x4321007:	cmp    rax,0x2f
   0x432100b:	je     0x432101b
   0x432100d:	lea    rbx,[rbx-0x8]
   0x4321011:	mov    QWORD PTR [rbx],0x1f
   0x4321018:	ret    0x8
   0x432101b:	lea    rbx,[rbx-0x8]
   0x432101f:	mov    QWORD PTR [rbx],0x9f
   0x4321026:	ret    0x8
NOT:
pwndbg> x/30i 0x7777000
   0x7777000:	mov    rax,QWORD PTR [rbx]
   0x7777003:	lea    rbx,[rbx+0x8]
   0x7777007:	cmp    rax,0x9f
   0x777700d:	je     0x7777023
   0x777700f:	cmp    rax,0x1f
   0x7777013:	je     0x7777023
   0x7777015:	lea    rbx,[rbx-0x8]
   0x7777019:	mov    QWORD PTR [rbx],0x1f
   0x7777020:	ret    0x8
   0x7777023:	shr    rax,0x7
   0x7777027:	not    rax
   0x777702a:	and    rax,0x1
   0x777702e:	shl    rax,0x7
   0x7777032:	or     rax,0x1f
   0x7777036:	lea    rbx,[rbx-0x8]
   0x777703a:	mov    QWORD PTR [rbx],rax
   0x777703d:	ret    0x8
INTTOCHAR:
pwndbg> x/30i 0x170C000
   0x170c000:	mov    rax,QWORD PTR [rbx]
   0x170c003:	lea    rbx,[rbx+0x8]
   0x170c007:	lea    rbx,[rbx-0x8]
   0x170c00b:	mov    QWORD PTR [rbx],rax
   0x170c00e:	and    rax,0x3
   0x170c012:	test   rax,rax
   0x170c015:	mov    rax,QWORD PTR [rbx]
   0x170c018:	lea    rbx,[rbx+0x8]
   0x170c01c:	jne    0x8008794
   0x170c022:	sar    rax,0x2
   0x170c026:	cmp    rax,0x80
   0x170c02c:	jae    0x8008794
   0x170c032:	shl    rax,0x8
   0x170c036:	or     rax,0xf
   0x170c03a:	lea    rbx,[rbx-0x8]
   0x170c03e:	mov    QWORD PTR [rbx],rax
   0x170c041:	ret    0x8
CHARTOINT:
pwndbg> x/30i 0xC701000
 0xc701000:	mov    rax,QWORD PTR [rbx]
   0xc701003:	lea    rbx,[rbx+0x8]
   0xc701007:	lea    rbx,[rbx-0x8]
   0xc70100b:	mov    QWORD PTR [rbx],rax
   0xc70100e:	and    rax,0xff
   0xc701014:	cmp    rax,0xf
   0xc701018:	mov    rax,QWORD PTR [rbx]
   0xc70101b:	lea    rbx,[rbx+0x8]
   0xc70101f:	lea    rbx,[rbx-0x8]
   0xc701023:	mov    QWORD PTR [rbx],rax
   0xc701026:	cmovne rax,QWORD PTR [rip+0xfffffffffb907768]        # 0x8008796
   0xc70102e:	sub    rax,0xf
   0xc701032:	cmp    rax,0x7f00
   0xc701038:	mov    rax,QWORD PTR [rbx]
   0xc70103b:	lea    rbx,[rbx+0x8]
   0xc70103f:	jbe    0xc701046
   0xc701041:	jmp    0x8008794
   0xc701046:	shr    rax,0x8
   0xc70104a:	shl    rax,0x2
   0xc70104e:	lea    rbx,[rbx-0x8]
   0xc701052:	mov    QWORD PTR [rbx],rax
   0xc701055:	ret    0x8
FRAME:
pwndbg> x/30i 0x57AC000
   0x57ac000:	lea    rbx,[rbx-0x8]
   0x57ac004:	mov    QWORD PTR [rbx],r12
   0x57ac007:	mov    r12,rbx
   0x57ac00a:	ret    0x8
CONS:
pwndbg> x/30i 0xC0C0000
   0xc0c0000:	mov    rax,QWORD PTR [rbx]
   0xc0c0003:	lea    rbx,[rbx+0x8]
   0xc0c0007:	mov    rcx,QWORD PTR [rbx]
   0xc0c000a:	lea    rbx,[rbx+0x8]
   0xc0c000e:	sub    rbp,0x10
   0xc0c0012:	mov    rdi,rbp
   0xc0c0015:	mov    QWORD PTR [rdi],rcx
   0xc0c0018:	mov    QWORD PTR [rdi+0x8],rax
   0xc0c001c:	or     rdi,0x1
   0xc0c0020:	lea    rbx,[rbx-0x8]
   0xc0c0024:	mov    QWORD PTR [rbx],rdi
   0xc0c0027:	ret    0x8
CAR:
pwndbg> x/30i 0xCA00000
   0xca00000:	mov    rax,QWORD PTR [rbx]
   0xca00003:	lea    rbx,[rbx+0x8]
   0xca00007:	lea    rbx,[rbx-0x8]
   0xca0000b:	mov    QWORD PTR [rbx],rax
   0xca0000e:	and    rax,0x7
   0xca00012:	cmp    rax,0x1
   0xca00016:	mov    rax,QWORD PTR [rbx]
   0xca00019:	lea    rbx,[rbx+0x8]
   0xca0001d:	je     0xca00024
   0xca0001f:	jmp    0x8008794
   0xca00024:	and    rax,0xfffffffffffffffe
   0xca00028:	mov    rax,QWORD PTR [rax]
   0xca0002b:	lea    rbx,[rbx-0x8]
   0xca0002f:	mov    QWORD PTR [rbx],rax
   0xca00032:	ret    0x8
CDR:
pwndbg> x/30i 0xCD00000
   0xcd00000:	mov    rax,QWORD PTR [rbx]
   0xcd00003:	lea    rbx,[rbx+0x8]
   0xcd00007:	lea    rbx,[rbx-0x8]
   0xcd0000b:	mov    QWORD PTR [rbx],rax
   0xcd0000e:	and    rax,0x7
   0xcd00012:	cmp    rax,0x1
   0xcd00016:	mov    rax,QWORD PTR [rbx]
   0xcd00019:	lea    rbx,[rbx+0x8]
   0xcd0001d:	je     0xcd00024
   0xcd0001f:	jmp    0x8008794
   0xcd00024:	and    rax,0xfffffffffffffffe
   0xcd00028:	mov    rax,QWORD PTR [rax+0x8]
   0xcd0002c:	lea    rbx,[rbx-0x8]
   0xcd00030:	mov    QWORD PTR [rbx],rax
   0xcd00033:	ret    0x8
LAMBDA:
pwndbg> x/30i 0xBAAA000
   0xbaaa000:	mov    rdx,QWORD PTR [rsp-0x8]
   0xbaaa005:	mov    rcx,QWORD PTR [rbx]
   0xbaaa008:	lea    rbx,[rbx+0x8]
   0xbaaa00c:	lea    rbx,[rbx-0x8]
   0xbaaa010:	mov    QWORD PTR [rbx],rcx
   0xbaaa013:	and    rcx,0x3
   0xbaaa017:	test   rcx,rcx
   0xbaaa01a:	mov    rcx,QWORD PTR [rbx]
   0xbaaa01d:	lea    rbx,[rbx+0x8]
   0xbaaa021:	jne    0x8008794
   0xbaaa027:	sar    rcx,0x2
   0xbaaa02b:	mov    rax,QWORD PTR [rbx]
   0xbaaa02e:	lea    rbx,[rbx+0x8]
   0xbaaa032:	lea    rbx,[rbx-0x8]
   0xbaaa036:	mov    QWORD PTR [rbx],rax
   0xbaaa039:	and    rax,0x7
   0xbaaa03d:	cmp    rax,0x2
   0xbaaa041:	mov    rax,QWORD PTR [rbx]
   0xbaaa044:	lea    rbx,[rbx+0x8]
   0xbaaa048:	jne    0x8008794
   0xbaaa04e:	and    rax,0xfffffffffffffffc
   0xbaaa052:	sub    rbp,0x18
   0xbaaa056:	mov    QWORD PTR [rbp+0x0],rdx
   0xbaaa05a:	mov    QWORD PTR [rbp+0x8],rax
   0xbaaa05e:	mov    QWORD PTR [rbp+0x10],rcx
   0xbaaa062:	mov    rax,rbp
   0xbaaa065:	or     rax,0x6
   0xbaaa069:	lea    rbx,[rbx-0x8]
   0xbaaa06d:	mov    QWORD PTR [rbx],rax
   0xbaaa070:	ret    0x8
CALL:
pwndbg> x/30i 0xCA11000
   0xca11000:	mov    rdi,QWORD PTR [rbx]
   0xca11003:	lea    rbx,[rbx+0x8]
   0xca11007:	lea    rbx,[rbx-0x8]
   0xca1100b:	mov    QWORD PTR [rbx],rdi
   0xca1100e:	and    rdi,0x3
   0xca11012:	test   rdi,rdi
   0xca11015:	mov    rdi,QWORD PTR [rbx]
   0xca11018:	lea    rbx,[rbx+0x8]
   0xca1101c:	jne    0x8008794
   0xca11022:	sar    rdi,0x2
   0xca11026:	mov    rax,QWORD PTR [rbx]
   0xca11029:	lea    rbx,[rbx+0x8]
   0xca1102d:	lea    rbx,[rbx-0x8]
   0xca11031:	mov    QWORD PTR [rbx],rax
   0xca11034:	and    rax,0x7
   0xca11038:	cmp    rax,0x6
   0xca1103c:	mov    rax,QWORD PTR [rbx]
   0xca1103f:	lea    rbx,[rbx+0x8]
   0xca11043:	jne    0x8008794
   0xca11049:	and    rax,0xfffffffffffffff8
   0xca1104d:	mov    rdx,QWORD PTR [rax+0x10]
   0xca11051:	cmp    rdx,0x0
   0xca11055:	jge    0xca110ac
   0xca11057:	mov    rcx,rdi
   0xca1105a:	mov    rsi,rdx
   0xca1105d:	not    rsi
   0xca11060:	sub    rcx,rsi
   0xca11063:	cmp    rcx,0x0
   0xca11067:	jl     0x8008794
   0xca1106d:	mov    rsi,0x2f
   0xca11074:	lea    rbx,[rbx-0x8]
   0xca11078:	mov    QWORD PTR [rbx],rsi
   0xca1107b:	cmp    rcx,0x0
   0xca1107f:	je     0xca110a7
   0xca11081:	mov    rsi,QWORD PTR [rbx]
   0xca11084:	lea    rbx,[rbx+0x8]
   0xca11088:	mov    r8,QWORD PTR [rbx]
   0xca1108b:	lea    rbx,[rbx+0x8]
   0xca1108f:	sub    rbp,0x10
   0xca11093:	mov    QWORD PTR [rbp+0x0],r8
   0xca11097:	mov    QWORD PTR [rbp+0x8],rsi
   0xca1109b:	mov    rsi,rbp
   0xca1109e:	or     rsi,0x1
   0xca110a2:	dec    rcx
   0xca110a5:	jmp    0xca11074
   0xca110a7:	neg    rdx
   0xca110aa:	jmp    0xca110b5
   0xca110ac:	cmp    rdi,rdx
   0xca110af:	jne    0x8008794
   0xca110b5:	mov    rdx,QWORD PTR [rax+0x8]
   0xca110b9:	mov    rcx,QWORD PTR [rdx]
   0xca110bc:	test   rcx,rcx
   0xca110bf:	je     0xca110d1
   0xca110c1:	mov    rsi,QWORD PTR [rdx+rcx*8]
   0xca110c5:	lea    rbx,[rbx-0x8]
   0xca110c9:	mov    QWORD PTR [rbx],rsi
   0xca110cc:	dec    rcx
   0xca110cf:	jmp    0xca110bc
   0xca110d1:	mov    rdi,rax
   0xca110d4:	or     rdi,0x6
   0xca110d8:	lea    rbx,[rbx-0x8]
   0xca110dc:	mov    QWORD PTR [rbx],rdi
   0xca110df:	lea    rbx,[rbx-0x8]
   0xca110e3:	mov    QWORD PTR [rbx],r13
   0xca110e6:	mov    r13,rsp
   0xca110e9:	mov    rsp,QWORD PTR [rax]
   0xca110ec:	shl    rsp,0x4
   0xca110f0:	add    rsp,r15
   0xca110f3:	ret    0x8
TAILCALL:
pwndbg> x/30i 0x7A11000
   0x7a11000:	mov    rdi,QWORD PTR [rbx]
   0x7a11003:	lea    rbx,[rbx+0x8]
   0x7a11007:	lea    rbx,[rbx-0x8]
   0x7a1100b:	mov    QWORD PTR [rbx],rdi
   0x7a1100e:	and    rdi,0x3
   0x7a11012:	test   rdi,rdi
   0x7a11015:	mov    rdi,QWORD PTR [rbx]
   0x7a11018:	lea    rbx,[rbx+0x8]
   0x7a1101c:	jne    0x8008794
   0x7a11022:	sar    rdi,0x2
   0x7a11026:	mov    rax,QWORD PTR [rbx]
   0x7a11029:	lea    rbx,[rbx+0x8]
   0x7a1102d:	lea    rbx,[rbx-0x8]
   0x7a11031:	mov    QWORD PTR [rbx],rax
   0x7a11034:	and    rax,0x7
   0x7a11038:	cmp    rax,0x6
   0x7a1103c:	mov    rax,QWORD PTR [rbx]
   0x7a1103f:	lea    rbx,[rbx+0x8]
   0x7a11043:	jne    0x8008794
   0x7a11049:	and    rax,0xfffffffffffffff8
   0x7a1104d:	mov    rdx,QWORD PTR [rax+0x10]
   0x7a11051:	cmp    rdx,0x0
   0x7a11055:	jge    0x7a110ac
   0x7a11057:	mov    rcx,rdi
   0x7a1105a:	mov    rsi,rdx
   0x7a1105d:	not    rsi
   0x7a11060:	sub    rcx,rsi
   0x7a11063:	cmp    rcx,0x0
   0x7a11067:	jl     0x8008794
   0x7a1106d:	mov    rsi,0x2f
   0x7a11074:	lea    rbx,[rbx-0x8]
   0x7a11078:	mov    QWORD PTR [rbx],rsi
   0x7a1107b:	cmp    rcx,0x0
   0x7a1107f:	je     0x7a110a7
   0x7a11081:	mov    rsi,QWORD PTR [rbx]
   0x7a11084:	lea    rbx,[rbx+0x8]
   0x7a11088:	mov    r8,QWORD PTR [rbx]
   0x7a1108b:	lea    rbx,[rbx+0x8]
   0x7a1108f:	sub    rbp,0x10
   0x7a11093:	mov    QWORD PTR [rbp+0x0],r8
   0x7a11097:	mov    QWORD PTR [rbp+0x8],rsi
   0x7a1109b:	mov    rsi,rbp
   0x7a1109e:	or     rsi,0x1
   0x7a110a2:	dec    rcx
   0x7a110a5:	jmp    0x7a11074
   0x7a110a7:	neg    rdx
   0x7a110aa:	jmp    0x7a110b5
   0x7a110ac:	cmp    rdi,rdx
   0x7a110af:	jne    0x8008794
   0x7a110b5:	mov    r8,QWORD PTR [rbx+rdx*8]
   0x7a110b9:	mov    rcx,rdx
   0x7a110bc:	test   rcx,rcx
   0x7a110bf:	je     0x7a110d9
   0x7a110c1:	mov    rdi,QWORD PTR [rbx+rcx*8-0x8]
   0x7a110c6:	mov    rsi,rdx
   0x7a110c9:	sub    rsi,rcx
   0x7a110cc:	neg    rsi
   0x7a110cf:	mov    QWORD PTR [r12+rsi*8-0x8],rdi
   0x7a110d4:	dec    rcx
   0x7a110d7:	jmp    0x7a110bc
   0x7a110d9:	neg    rdx
   0x7a110dc:	lea    rbx,[r12+rdx*8]
   0x7a110e0:	neg    rdx
   0x7a110e3:	mov    rdx,QWORD PTR [rax+0x8]
   0x7a110e7:	mov    rcx,QWORD PTR [rdx]
   0x7a110ea:	test   rcx,rcx
   0x7a110ed:	je     0x7a110ff
   0x7a110ef:	mov    rsi,QWORD PTR [rdx+rcx*8]
   0x7a110f3:	lea    rbx,[rbx-0x8]
   0x7a110f7:	mov    QWORD PTR [rbx],rsi
   0x7a110fa:	dec    rcx
   0x7a110fd:	jmp    0x7a110ea
   0x7a110ff:	mov    rdi,rax
   0x7a11102:	or     rdi,0x6
   0x7a11106:	lea    rbx,[rbx-0x8]
   0x7a1110a:	mov    QWORD PTR [rbx],rdi
   0x7a1110d:	lea    rbx,[rbx-0x8]
   0x7a11111:	mov    QWORD PTR [rbx],r8
   0x7a11114:	mov    rsp,QWORD PTR [rax]
   0x7a11117:	shl    rsp,0x4
   0x7a1111b:	add    rsp,r15
   0x7a1111e:	ret    0x8
RETURN:
pwndbg> x/30i 0xDB22000
   0xdb22000:	mov    rdx,QWORD PTR [rbx]
   0xdb22003:	lea    rbx,[rbx+0x8]
   0xdb22007:	mov    rsp,r13
   0xdb2200a:	mov    r13,QWORD PTR [rbx]
   0xdb2200d:	lea    rbx,[rbx+0x8]
   0xdb22011:	mov    rbx,r12
   0xdb22014:	mov    r12,QWORD PTR [rbx]
   0xdb22017:	lea    rbx,[rbx+0x8]
   0xdb2201b:	lea    rbx,[rbx-0x8]
   0xdb2201f:	mov    QWORD PTR [rbx],rdx
   0xdb22022:	ret    0x8
DONE:
pwndbg> x/30i 0xD0D0000
   0xd0d0000:	test   r12,r12
   0xd0d0003:	jne    0x8008794
   0xd0d0009:	mov    rdi,QWORD PTR [rbx]
   0xd0d000c:	mov    rsp,rbp
   0xd0d000f:	and    rsp,0xfffffffffffffff0
   0xd0d0013:	call   0x8008190