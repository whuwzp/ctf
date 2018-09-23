---
title: IDA-逆向工程(1)-CrackMe分析1
date: 2018-05-06 18:35:33
tags: [逆向, crackme, ida]
categories: 科研
mathjax: true
---

> 逆向分析首篇，以freebuf大神[VillanCh](http://www.freebuf.com/author/villanch)的博客<sup>[[1]](http://www.freebuf.com/news/others/86147.html)</sup>为例，进行实例重现。大神博客大体介绍了逆向的基础知识，本节主要是涉及一些逆向资料，IDA PRO的使用，crackme分析。

## CrackMe分析

主要目的是找到CrackMe-Brad Soblesky.1.exe的破解密码。

### 环境配置

1. 系统：windows XP SP3；
2. 分析工具：IDA PRO；
3. 分析文件：CrackMe-Brad Soblesky.1.exe（password验证）；

### 初步判断

首先运行Brad Soblesky.1.exe，发现出现输入对话框，可知可能是**C++ MFC**；需要输入字符，所以可能**采用GetDlgItemText函数**（这个就需要正向编程经验的积累了）；通过输入和点击`Check`，发现弹出对话框，可以猜想，一定有**条件语句**比对输入是否正确。

经过上述初步分析，有以下关注重点：

1. 应该查找MFC的GetDlgItemText的调用情况；
2. 找出其中的条件语句。

### 分析步骤

#### GetDlgItemText

首先，IDA 打开exe文件，然后搜索"GetDlgItemText"（可用快捷键Alt+T进入搜索，同时最好勾选Find all occurences，这样就不会漏了），双击第一个，得到以下调用代码块：

```nasm
.text:00401512 sub_401512 proc near                    ; DATA XREF: .rdata:004024FCo
.text:00401512
.text:00401512 var_20= dword ptr -20h
.text:00401512 String2= byte ptr -1Ch
.text:00401512 var_18= dword ptr -18h
.text:00401512 var_14= word ptr -14h
.text:00401512 var_10= dword ptr -10h
.text:00401512 String1= byte ptr -0Ch
.text:00401512 var_A= dword ptr -0Ah
.text:00401512 var_6= dword ptr -6
.text:00401512
.text:00401512 push    ebp
.text:00401513 mov     ebp, esp
.text:00401515 sub     esp, 20h
.text:00401518 mov     [ebp+var_20], ecx
.text:0040151B mov     ax, word_40315C
.text:00401521 mov     word ptr [ebp+String1], ax
.text:00401525 xor     ecx, ecx
.text:00401527 mov     [ebp+var_A], ecx
.text:0040152A mov     [ebp+var_6], ecx
.text:0040152D mov     edx, dword_403020
.text:00401533 mov     dword ptr [ebp+String2], edx
.text:00401536 mov     eax, dword_403024
.text:0040153B mov     [ebp+var_18], eax
.text:0040153E mov     cx, word_403028
.text:00401545 mov     [ebp+var_14], cx
.text:00401549 push    0Ah
.text:0040154B lea     edx, [ebp+String1]
.text:0040154E push    edx
.text:0040154F push    3E8h
.text:00401554 mov     ecx, [ebp+var_20]
.text:00401557 call    ?GetDlgItemTextA@CWnd@@QBEHHPADH@Z ; CWnd::GetDlgItemTextA(int,char *,int)
.text:0040155C lea     eax, [ebp+String1]
.text:0040155F push    eax                             ; lpString
.text:00401560 call    ds:lstrlenA
.text:00401566 mov     [ebp+var_10], eax
.text:00401569 cmp     [ebp+var_10], 1
.text:0040156D jnb     short loc_401585
.text:0040156F push    40h
.text:00401571 push    offset aCrackme                 ; "CrackMe"
.text:00401576 push    offset aEnterRegistrat          ; "Enter Registration Number"
.text:0040157B mov     ecx, [ebp+var_20]
.text:0040157E call    ?MessageBoxA@CWnd@@QAEHPBD0I@Z  ; CWnd::MessageBoxA(char const *,char const *,uint)
.text:00401583 jmp     short loc_4015C1
.text:00401585 ; ---------------------------------------------------------------------------
.text:00401585
.text:00401585 loc_401585:                             ; CODE XREF: sub_401512+5Bj
.text:00401585 lea     ecx, [ebp+String2]
.text:00401588 push    ecx                             ; lpString2
.text:00401589 lea     edx, [ebp+String1]
.text:0040158C push    edx                             ; lpString1
.text:0040158D call    ds:lstrcmpA
.text:00401593 test    eax, eax
.text:00401595 jnz     short loc_4015AD
.text:00401597 push    40h
.text:00401599 push    offset aCrackme_0               ; "CrackMe"
.text:0040159E push    offset aCorrectWayToGo          ; "Correct way to go!!"
.text:004015A3 mov     ecx, [ebp+var_20]
.text:004015A6 call    ?MessageBoxA@CWnd@@QAEHPBD0I@Z  ; CWnd::MessageBoxA(char const *,char const *,uint)
.text:004015AB jmp     short loc_4015C1
.text:004015AD ; ---------------------------------------------------------------------------
.text:004015AD
.text:004015AD loc_4015AD:                             ; CODE XREF: sub_401512+83j
.text:004015AD push    40h
.text:004015AF push    offset aCrackme_1               ; "CrackMe"
.text:004015B4 push    offset aIncorrectTryAg          ; "Incorrect try again!!"
.text:004015B9 mov     ecx, [ebp+var_20]
.text:004015BC call    ?MessageBoxA@CWnd@@QAEHPBD0I@Z  ; CWnd::MessageBoxA(char const *,char const *,uint)
.text:004015C1
.text:004015C1 loc_4015C1:                             ; CODE XREF: sub_401512+71j
.text:004015C1                                         ; sub_401512+99j
.text:004015C1 mov     esp, ebp
.text:004015C3 pop     ebp
.text:004015C4 retn
.text:004015C4 sub_401512 endp
```

### if条件语句

从上面可以初步看到三个条件分之，分别对应：

1. 未输入字符情况；
2. 输入错误情况；
3. 输入正确情况。

当然从后面弹出的对话框（Correct）的字符串也可以轻易找出来：

```nasm
.text:00401599 push    offset aCrackme_0               ; "CrackMe"
.text:0040159E push    offset aCorrectWayToGo          ; "Correct
```

还有一种方法就是右键，进入图形模式，可以非常清楚的看出条件语句的分支（绿色True，红色False）。

于是可以清楚的得到控制逻辑：

1. 未输入：弹出"Enter Registration Number"；
2. 已输入：
   + 错误：弹出"Incorrect try again!!"；
   + 正确：弹出"Correct way to go!!"。

我们要找密码，所以只需关注输入正确的分支代码。

#### 关键代码

输入正确的分支代码（if条件语句）如下：

```nasm
loc_401585:
lea     ecx, [ebp+String2]
push    ecx             ; lpString2
lea     edx, [ebp+String1]
push    edx             ; lpString1
call    ds:lstrcmpA	;比较两个字符串是否相等，相等为0，结果保存于eax
test    eax, eax	;看eax是否为0
jnz     short loc_4015AD	;不为0则跳转
```

可以看到调用了**lstrcmpA**函数，可以猜到是比较字符串是否相同的，搜索后确认。`test`这个判断eax是否为0。所以关键就在于**edx和ecx两个寄存器，其中一个就是密码**。静态调试肯定不行，需要exe运行起来，所以下面进入动态调试。

#### 动态调试

按选择`调试器`（或按F9），我选的是windbg，之后进入（此时运行到输入框，我们输入123，然后点击check），我们在这里设置断点（当然也可以直接到两个寄存器那儿）：

```nasm
00401512 push    ebp
```

点击并按F4跳转至光标：

```nasm
call    ds:lstrcmpA
```

之后查看edx，ecx两个寄存器（右上角，把鼠标停放在edx和ecx上，会显示各自的内容），其中ecx为`<Brd-Sob>`，而edx为我们最初输入的123，因此，**密码即为`<Brd-Sob>`**，输入后确认正确。

### 代码详细分析

#### 栈初始化

```nasm
.text:00401512 var_20= dword ptr -20h
.text:00401512 String2= byte ptr -1Ch
.text:00401512 var_18= dword ptr -18h
.text:00401512 var_14= word ptr -14h
.text:00401512 var_10= dword ptr -10h
.text:00401512 String1= byte ptr -0Ch
.text:00401512 var_A= dword ptr -0Ah
.text:00401512 var_6= dword ptr -6
```
这相当于申请了栈空间，例如使用:

```nasm
mov     [ebp+var_20], ecx	;把ecx的内容拷贝进ebp+var_20栈地址
```

因为栈是高位在下，低位在上，高位向低位生长的，ebp为这个栈的基址（最高位），另外每个进程都有自己的栈。所以ebp+var_20=ebp-20h，也就是上面的地址，加上`[]`就相当于C中的`*ptr`。

#### 清空String1

String1将保存我们输入的字符。

```nasm
.text:0040151B mov     ax, word_40315C
.text:00401521 mov     word ptr [ebp+String1], ax
.text:00401525 xor     ecx, ecx;	此时ecx为0
.text:00401527 mov     [ebp+var_A], ecx
.text:0040152A mov     [ebp+var_6], ecx
```

将word_40315C的值赋给了[ebp+String1]，可双击word_40315C，跳转至data区（字符常量区），常看word_40315C的值为0：

```nasm
.data:0040315C word_40315C dw 0
```

1. 初始时的string1是byte，然后这里转换为了word，也就是2byte，var_string1和var_A刚好也相差2byte；
2. 然后加上var_A的4byte（var_A到var_6刚好4字节）；
3. var_6的4byte（dword为4字节）。

**所以，总共string1相当于是占了2+4+4=10字节。**

然后按`Esc`跳转回来。

#### String2存入栈

String2为密码。

```nasm
.text:0040152D mov     edx, dword_403020
.text:00401533 mov     dword ptr [ebp+String2], edx
.text:00401536 mov     eax, dword_403024
.text:0040153B mov     [ebp+var_18], eax
.text:0040153E mov     cx, word_403028
.text:00401545 mov     [ebp+var_14], cx
```

同上，将dword_403020和dword_403024存入，String2，可以看到：

1. 初始时string2为word，这里转换为了dword，刚好string2和var_18相差4byte；
2. 然后var_18也保存了dword_403024，4个字节，刚好var_18和var_14相差4byte；
3. 最后var_14中存入word，2字节；

**所以，总共string2相当于是占了4+4+2=10字节。**（和string1相等）

其中，前8个字节就是密码`<Brd-Sob>`，后两个不知道有什么意义（可能是混淆？）

可以看出string1和string2的存入字节数方式不同，不知道是不是为了混淆，但最终都是10字节。

####  GetDlgItemTextA

```nasm
.text:00401549 push    0Ah
.text:0040154B lea     edx, [ebp+String1]
.text:0040154E push    edx
.text:0040154F push    3E8h
.text:00401554 mov     ecx, [ebp+var_20]
.text:00401557 call    ?GetDlgItemTextA@CWnd@@QBEHHPADH@Z ; CWnd::GetDlgItemTextA(int,char *,int)
```

由cdecl约定，GetDlgItemTextA前有3个push（果然也如此），因为GetDlgItemTextA需要三个参数，GetDlgItemTextA(int,char *,int)，从左到右：对话框句柄？字符串缓存区（得到的字符保存的地址，char\*指针），最大字节数。由cdecl约定，可知（由cdecl约定，由右自左压入栈）：

1. 最大字节数为10字节，0A；
2. buf地址：ebp+String1；需要注意的是：

```nasm
.text:0040154B lea     edx, [ebp+String1]
```

为什么这句得到的是地址ebp+String1，可以看附录：lea和mov的区别。

#### 查看是否输入

同理，lstrlenA函数需要一个参数（查看字符串长度），push的就是该参数。

```nasm
.text:0040155F push    eax                             ; lpString
.text:00401560 call    ds:lstrlenA
```

剩下的就比较简单了，不作介绍。

## 附录

### 经验总结

#### 调用函数-cdecl约定

cdecl约定规定由调用者从右向左向栈里连续的压入参数，在函数返回之
后，再清理掉压入的参数以保证堆栈平衡。

**所以在调用函数前的push操作就是参数**。

### 汇编相关

#### Debug  和  Release 

1. Debug  通常称为调试版本，它包含调试信息，并且不作任何优化，便于程序员调试程序。
2. Release  称为发布版本，它往往是进行了各种优化，使得程序在代码大小和运行速度上都是最优的，以便用户很好地使用。   

#### 寄存器

- EAX： 累加器
- EBX： 基址寄存器
- ECX： 计数器 
- EDX： 数据寄存器 
- ESI： 源变址寄存器 
- EDI： 目的变址寄存器 
- EBP： 扩展基址指针寄存器 
- ESP： 栈指针寄存器 
- EIP： 指令指针寄存器 

#### lea和mov的区别

参考网址：https://zhidao.baidu.com/question/70811404.html

> lea SI,D1 是把D1的地址放入SI寄存器中。 所以SI中的值会变的，变成的是D1的地址。而D1则是用户定义的一个内存数据的助记符。 如果是mov SI，D1就会把D1的值放进SI。 例如，D1 dw 0x0000 汇编以后可能变成： 地址 值 0x9000 00 0x9001 00 那么lea SI，D1，SI的值是0x9000而不是0000，要用mov就是0000了 

#### lstrcmp函数

比较字符大小的，参数2个，比较ASCII码，相等则为0。

#### test操作

和`And`指令类似，按位相与，但是结果不保存在寄存器中，例如：

```nasm
test eax 100b	;看看eax的最高位的第三个是否为0，但是eax的内容不变，只改变标识符sf等
And eax 100b	;按位相与，结果保存于eax中
```

#### text和data

+ `text`中为指令；
+ `data`中为数据常量。

### IDA PRO使用 

#### 快捷键

1. Alt+T：搜索；
2. 点击跳转之后，用Esc，调回来；
3. IDA动态调试：按F9（初始时会让选择哪种DBG调试器），选择之后，可以设置断点，再按F9就进入了调试；
4. F2：调式模式下，加入断点；
5. Ctrl+F2：停止调试；

####  Hex-View和Stack-View

逆序。

### 参考资料

1. 逆向工程（一）：汇编、逆向工程基础篇，freebuf：[VillanCh](http://www.freebuf.com/author/villanch)  ，http://www.freebuf.com/news/others/86147.html
2. 逆向工厂（一）：从hello world开始， freebuf：[追影人](http://www.freebuf.com/author/%e8%bf%bd%e5%bd%b1%e4%ba%ba) ， http://www.freebuf.com/special/114231.html
3. C++逆向学习三步走，看雪：A1Pass，https://bbs.pediy.com/thread-113689.htm 
4. 看雪知识库，https://www.kanxue.com/chm.htm