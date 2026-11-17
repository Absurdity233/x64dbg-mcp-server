# 反调试 / 反反虚拟机 / 虚拟化对抗 / 破解逆向 加强

本文件记录 2.5.0 这一轮加强的实际内容、**每一处修改背后的实测证据**，以及仍然
做不到的部分。写法刻意偏"为什么"而不是"做了什么"——因为这个领域里几乎每一个
看起来对的实现都是错的，而错法只有实测才能发现。

四个需求对应四块能力：

| 需求 | 落地位置 | 关键点 |
|---|---|---|
| 1. 反调试加强到驱动级 | `plugin/src/util/antidebug_hard.*` + `driver/` | 用户态三级 harden + EPROCESS 驱动的内核组件 |
| 2. 反反虚拟机检查 | `plugin/src/util/anti_vm.*` + `probe_scan.*` | 指令级 stub，不是断点 |
| 3. 虚拟化混淆对抗 | `plugin/src/handlers/vm_handler.cpp` | 熵/段扫描 → dispatcher → handler 聚类 |
| 4. 破解 / 游戏逆向调试 | `plugin/src/handlers/crack_handler.cpp` | 分支补丁、特征码、IAT 重定向、比较表 |

---

## 1. 反调试：为什么不能只清 PEB

原来的 `hide_debugger` 只清两个 PEB 字段。这挡不住任何真实保护，原因很具体：

- **每次 resume 之后线程重新读 PEB**，保护层可以把它写回 1；
- **`NtQueryInformationProcess(ProcessDebugPort/ObjectHandle/Flags)` 走内核**，
  用户态改不到；
- **Heap.Flags 的"清白值"不是 0**。

最后一条实测推翻了原实现：

```
原生（未被调试）:  Flags = 0x2   ForceFlags = 0x0
被调试:            Flags 低位被置 1
检查式:            if (Flags != 2 || ForceFlags != 0) -> "被调试"
```

原 `harden` 把 `Flags` 清成 `0`——**制造了一个真实进程不会有的堆,检查照样命中**。
现在写回 `0x2`。实测目标端 `Heap flags/force` 从 `1` 变成 `0`。

三级 harden（`POST /api/antidebug/harden {level}`）：

- `basic`：PEB.BeingDebugged + NtGlobalFlag
- `deep`（默认）：+ 堆标志 + 线程遍历 + DR 寄存器；**写后读回校验**，写不进去的
  字段进 `failed` 而不是谎报成功
- `paranoid`：+ ntdll stub + 内核组件（若驱动已加载）

`guard: true` 会起一个后台 worker，**只在 pause 时**重清 PEB。不在运行中写——
运行中写是撕裂写，目标能观察到，产生的 bug 报告无法证伪。

## 2. 反反虚拟机：断点一定是错的

这是本轮最重要的结论，值得单独写清楚。

**软件断点在指令执行前触发。** 所以对 `cpuid` 站点挂断点并执行
`ecx=ecx&0x7FFFFFFF;run`，写进去的值会被紧接着执行的 `cpuid` 覆盖。

> 实测：2026.05.27，`cpuid` 站点 + `silent=1 fast_resume=1` + 寄存器改写命令，
> 目标看到的 `ecx` 完全没变。

`rdtsc` 更糟：检查看的是**两次读数的差**，改单次读数形状就不对。

**能生效的只有指令级 stub**：把探针指令搬到一段自己分配的页里执行,过滤它的输出,
再跳回去。

### stub 的布局是唯一正确的写法

踩过的坑按顺序记录,因为每一条都会让功能"看起来装上了但完全无效":

1. **必须执行真实的 `cpuid`**,不能删掉。删掉会破坏 eax/ebx/ecx/edx 的副作用。
2. **过滤器必须紧跟在探针指令之后**,不能被搬走的后续指令夹在中间。
   实测：`cpuid` 被搬走时连带搬了目标自己的 `shr ecx, 0x1F`,过滤器在移位**之后**
   才跑,`and ecx, 0x7FFFFFFF` 拿到的已经不是含高位的值——检查仍然报 VM。
   正确顺序：`[cpuid][filter][被搬走的后续指令][跳回]`。
3. **cpuid 的过滤器跳转偏移必须算出来,不能手数。** 手写 `jne +12` 差了 2 字节,
   跳进 `and ecx, imm32` 中间,目标直接 `STATUS_ILLEGAL_INSTRUCTION (0xC000001D)`。
   现在 `cpuid_filter()` 从实际指令长度反推。
4. **桩页必须落在 2 GB 内。** 入口补丁只有 5 字节,只能是相对跳转。`alloc` 在 64 位
   进程里返回的页经常差 40 TB。实测本机 `alloc` **忽略地址提示**(传地址则返回 0),
   所以改用 `VirtualAllocEx` 从站点向两侧按 64 KB 粒度找可执行页。
5. **`VirtualAllocEx` 允许的低地址不能执行。** 实测把 dispatcher 放在 `0x10000`
   会分配成功、读回正确,然后一执行就 access violation。现在有 `0x10000` 下限。
6. **被搬走的相对跳转要重新编码,而不是拒绝。** 检查例程里的 `cpuid` 后面经常紧跟
   `jnz`,而补丁必须吃掉 5 字节,于是这个 `jnz` 落进搬移区。早先版本直接跳过该站点——
   而它恰恰就是决定检查结果的那一条。现在把 rel8 的 `jcc` 拓宽成 `0F 8x rel32`、
   `EB` 拓宽成 `E9`,位移按新地址重算;`jrcxz` 没有长形式,仍然拒绝。
7. **判断"是不是 vendor 查询"不能比 `eax == 0x40000000`。** `cpuid` 会把结果写回
   eax,所以过滤器看到的 eax 已经是**答案**(本机 `0x4000000C`),不是调用方请求的
   leaf。这个看起来最自然的写法永远不成立,而且症状极具误导性：反虚拟机位那条 stub
   正常工作,vendor leaf 那条永远不生效。现在改成 `eax >= 0x40000000` 归入 vendor 空间。

实测结果（`plugin/test/cpuidstub.cpp`）:

```
改前: leaf1 hypervisor_bit=1   rdtsc delta=550
改后: leaf1 hypervisor_bit=0   rdtsc delta=0
```

过滤动作：

| 探针 | 过滤 |
|---|---|
| `cpuid` | leaf1 清 ecx bit31；leaf `0x40000000` 四寄存器清零 |
| `rdtsc`/`rdtscp` | eax:edx 清零 → 任何时间差都是 0 |
| VMware backdoor | 在 `mov dx,0x5658` 之后的 `in` 上清 ebx（抹掉 `VMXh`）|

搬不动的站点（相对跳转 / RIP 相对寻址）**拒绝并说明原因**,不生成会崩的 trampoline。

### ntdll：两种布局，两个坑

`NtQueryInformationProcess` 在不同 Windows 上是不同形态,必须分别处理：

- **直接 syscall stub**：`mov r10,rcx / mov eax,ssn / ... 0F 05` —— 需要 trampoline。
- **hotpatch 跳板**（Win11 实测）：`nop / jmp qword ptr [rip+0] / <绝对地址>` ——
  入口不是代码而是指针槽,**改 8 字节指针即可**,不受 2 GB 限制。

实测踩到的两个坑：

1. **输出缓冲区是 `r8`,不是 `rcx`。** x64 参数序是 rcx,rdx,r8,r9。写 `[rcx]`
   等于写进程句柄——当前进程是伪句柄 `-1`,目标当场 access violation。
2. **写 4 字节,不是 8 字节。** 调用方给这组信息类传 4 字节缓冲区是合法的,
   写 8 字节会盖掉后面紧邻的变量。实测：盖掉了循环计数器,导致**下一次调用**的
   信息类变成垃圾值,后两类全部落到默认分支——看起来像 dispatcher 的 bug。

还有一个纯逻辑错误：多个信息类串成检查链时,**每个 `jne` 要跳到下一个检查,
只有最后一个才跳默认分支**。初版把所有 `jne` 都指向同一个出口,结果只有第一个类
能命中。实测表现为：`DebugPort` 正常,`DebugObject`/`DebugFlags` 返回
`STATUS_INVALID_PARAMETER`。

最终实测（目标端自报）：

```
ProcessDebugPort         = 0
ProcessDebugObjectHandle = 0
ProcessDebugFlags        = 0
```

## 3. 虚拟化混淆

按 `docs/vm-analysis.md` 的流水线实现成四条路由：

- `POST /api/vm/region` — 段熵 + 候选保护段（熵 ≥ 7.0、可执行、≥ 64 KB）
- `POST /api/vm/discover` — CIP 流 → dispatcher 打分
  （`visits × 前驱多样性 / 后继数`,后继只允许 1~2 个）
- `POST /api/vm/handlers` — xref 回溯 + 指令助记符序列 FNV-1a 聚类（合并同一 handler）
- `POST /api/vm/exception_flow` — 异常驱动 VM 的判定（同一 code 占比 ≥ 60% 且地址集 ≤ 16）

trace 行会**折叠连续重复**：x64dbg 会重复记录同一指令,不折叠会让每个 dispatcher
的 visits 虚高。

## 4. 破解 / 游戏逆向

- `branch_patch` — `invert`/`always`/`never`,**保持指令长度**,写后读回校验,可还原
- `sig_make` — 操作数感知的通配特征码 + 模块内唯一性验证
- `iat_redirect` — 按**槽值**（而不是导入名）找到所有指向同一函数的位置,
  重定向到植入的 stub（`succeed`/`fail`/`constant`）,可还原
- `compare_trace` — 在函数内每条 `cmp`/`test` 上挂日志断点,
  把序列号比较变成一张表,不用单步

## 5. 内核组件（可选）

`driver/` 是一个独立的 WDM 驱动,只做用户态做不到的事：清 `EPROCESS.DebugPort`
等字段,让 `NtQueryInformationProcess` 从内核视角也回答"没被调试"。

- 偏移**运行时解析**(反汇编 `PsGetProcessDebugPort`),不硬编码版本。
  实测 Win11 26200：`DebugPort = 0x308`（`48 8B 81 08 03 00 00`）。
- **不** hook SSDT、**不**改内核代码——PatchGuard 会看到,而且对被检目标没用。
- 没有 WDK 就无法编译,`build-driver.ps1` 会明确告诉你要装什么,不会假装构建。
- HVCI/内存完整性开启时未签名驱动会被拒;本机就是这种情况(见下)。

## 6. 实测记录

环境：Win11 26200,HVCI/VBS 开启（因此 CPUID 在本机真实地报告
`hypervisor_bit=1`,这是一台物理机的正常状态）。

测试目标 `plugin/test/adtest.cpp` 自己实现了全部检查并输出判定。

**加保护前（仅被调试）**：PEB/Heap/Kernel 全部报"被调试",CPUID 报 VM。

**加保护后**：

```
[1] PEB                     全 0
[2] Kernel                  全 0
[3] CPUID hypervisor bit    0     <- 由 1 变 0
[3] CPUID vendor leaf       0     <- 由 1 变 0（需要第 6、7 条修复）
[3] RDTSC delta             0
[4] 序列号                   valid=0（未打补丁,符合预期）
```

## 6.1 会话结束自动还原

打过的补丁如果留在目标里,下次用别的调试器打开或直接把文件发出去,代码里就带着一条
跳进不存在页面的 `jmp`,表现是目标自己崩溃。

`CB_STOPDEBUG` 里调用 `anti_vm::teardown()` 和 `ntdll_hook::teardown()`,把原始字节
写回并把登记表清空。

**这里有个必须写下来的坑**:这个回调是在调试会话拆掉**之后**才跑的,此时
`DbgIsDebugging()` 已经是 false。第一版用 `if (DbgIsDebugging())` 包了一层,结果每次
都跳过还原,而 `session_stop` 事件照常记录——功能看起来实现了、测试也"通过",实际上
一次都没执行过。现在无条件调用,teardown 自身能处理"进程已消失"的情况:
能写就写回,写不了就只清登记表(否则这些地址会被下一次会话还原进无关进程)。

---

## 7. 计时侧信道：API 层（2.6.0 新增）

RDTSC 只是最有名的那一个。真正被现代保护大量使用的是 API 层计时器,原因很实际：
RDTSC 的频率取决于主机,原始差值必须先标定才有意义;而 `QueryPerformanceCounter`
已经是固定标定单位。测一段代码"花了多久"的检查,第一反应是 QPC。

三类计时器形态不同,所以 stub 也不同：

| 计时器 | 返回方式 | stub 做什么 |
|---|---|---|
| `QueryPerformanceCounter` | 通过**指针**参数写出 | 写内存,不是寄存器 |
| `GetTickCount64` / `GetTickCount` | 返回值在 rax/eax | 让两次调用返回同一个数 |
| `QueryPerformanceFrequency` | 返回值 | **故意不动** |

共同目标：让被测量区间的计数器"不前进",于是每个 delta 读出来都是 0 —— 这是最紧的
答案,也是快机器会给出的答案。

`QueryPerformanceFrequency` 故意不桩：它定义了 QPC 差值的单位,改它会让目标算出的
每个时长按这个比例失真,那是比计数器停住**更响**的信号。

### 实测踩到的四个坑

1. **`kernel32.GetTickCount64` 不是转发。** 本机实测它是独立实现
   (`8B 0C 25 04 00 FE 7F` 直接读 `KUSER_SHARED_DATA`),不走 kernelbase。
   只桩 kernelbase 时,程序 import 的是 kernel32,调用**完全没被碰到**——hook 装上、
   verify 通过、delta 一点没变。现在遍历**所有**导出该名字且地址不同的模块分别安装。

2. **种子必须写在代码之后。** 生成的 stub 末尾就是 8 字节数据槽,生成器用 0 填充。
   先写种子再写代码,代码会把种子清零,于是冻结的时钟返回 0 —— 而所有报告都写着
   "installed, verified"。现在先写代码、再写种子、再读回校验。

3. **冻结值不能是 0。** 开机后时钟读数恰好为 0 本身就是指纹,而且看起来像 hook 坏了
   (正是这样发现的)。但 x64dbg 的表达式引擎**不调用目标内的函数**,暂停时
   `eval_expression("GetTickCount64()")` 返回 0,所以读不到真值。最终用由桩地址推导
   出的非零常量：会话内稳定、每个计时器不同、看起来很单调。

4. **`mov rax,[rip+disp32]` 的位移基准。** RIP 指向**下一条**指令。算错基准会让 load
   读取自己后面几个字节(新分配页里就是 0),计数器永远返回 0 而 hook 显示一切正常。
   现在位移由指令起止位置计算,不再手数。

实测（`plugin/test/timetest.cpp`,目标自报）：

```
加桩前:  QPC delta=39    tick64 delta=63  tick32 delta=62   全部 DETECTED
加桩后:  QPC delta=0     tick64 delta=0   tick32 delta=0    全部 clean
```

---

## 8. ntdll 覆盖面扩展（2.6.0 新增）

原来只支持 `NtQueryInformationProcess`。现在加了三类常见 oracle,**参数寄存器位置不同**：

| 函数 | class 寄存器 | buffer 寄存器 | 拦截的 class |
|---|---|---|---|
| `NtQueryInformationProcess` | rdx | r8 | 7 / 0x1E / 0x1F |
| `NtQueryObject` | rdx | r8 | 1（ObjectTypeInformation）|
| `NtQuerySystemInformation` | **rcx** | **rdx** | 0x23（内核调试器状态）|
| `NtSetInformationThread` | rdx | r8 | 0x11（ThreadHideFromDebugger）|

`NtQuerySystemInformation` 是特殊的：它没有 handle 参数,所有参数左移一个寄存器。
把寄存器搞错是**静默失败**——桩比较了错的寄存器、从不匹配、落到默认分支,现象和
"hook 没装上"一模一样。

实测（`plugin/test/nttest.cpp`）：

```
未 hook: NtQueryObject status=0x00000000   (成功,泄露对象类型)
hook 后: NtQueryObject status=0xC000000D   (拒绝)
未 hook: NtQuerySystemInformation(0x23) present=0 notpresent=1
hook 后: NtQuerySystemInformation(0x23) present=0 notpresent=0
```

`NtSetInformationThread(ThreadHideFromDebugger)` 一旦被目标成功调用,当前线程会对
调试器隐身——那会直接毁掉会话,所以它的 stub 是**返回成功但不执行**。

---

## 9. 扫描性能（2.6.0 新增）

`probe_scan` 原来对每个字节前缀匹配都调一次 `DbgDisasmAt`。在几百 MB 的保护段上这是
几十万次跨进程调用——恰好在这个功能最有用的目标上不可用。

现在分两趟：先在缓冲区里收全部原始前缀匹配(纯内存操作,零 API 调用),按地址排序,
**每个地址只反汇编一次**,这一次同时服务所有在该地址命中的探针。重叠前缀很常见
(`0F 01` 同时是 sidt/sgdt/smsw 的前缀),所以这一趟直接消掉很大比例的调用。

响应里新增 `disasm_calls`,可以对比命中数看实际节省。

---

## 10. KUSER_SHARED_DATA 直接读时钟（2.7.0）

这是计时侧信道里最隐蔽的一层：共享页在所有进程里以只读方式映射在 `0x7FFE0000`,
目标可以用**一条指令**读到 tick,不经过任何导出、没有系统调用、也没有任何 API hook
能看到。实测 `kernel32.GetTickCount64` 本身就是 `mov ecx,[0x7FFE0004]`。

### 两种形态,只有一种能按地址匹配

| 形态 | 编码 | 能否按模式定位 |
|---|---|---|
| 绝对寻址 | `8B 04 25 04 00 FE 7F` (`mov eax,[0x7FFE0004]`) | **能** —— 地址在指令字节里 |
| 寄存器间接 | `BB 04 00 FE 7F` 然后 `8B 3B` | **不能** —— 读取指令里没有地址 |

第二种是编译器实际生成的形态。我用 `dumpbin` 确认过：

```
mov ebx, 7FFE0004h
mov edi, dword ptr [rbx]      <- 读取在这里，字节里只有 8B 3B
```

所以「扫描 KUSER 绝对读」在真实目标上一个都找不到,而扫描 `mov <reg>, 0x7FFE0004`
能找到——但那是**地址加载**,不是读取本身。

### 打桩的边界,以及为什么共享页不能直接改

第一反应是"直接冻结 `0x7FFE0000` 页"。实测**不可行**：

```
VirtualProtect 改 RW         -> 成功
DbgMemWrite 到 0x7FFE0014    -> 失败
```

该页是共享映射,写入不能按进程隔离。改它会影响宿主,得不偿失。

绝对寻址的读取可以**原地替换**为等长立即数(`B8+r imm32` + NOP 填充),这是唯一
不需要重定位、不需要桩页、也不会踩到前面那两个坑的处理方式。寄存器间接的读取
无法从字节识别,只报告地址加载点供人工定位。

响应里对这一点说得很直白,不假装覆盖了没覆盖的情况。

---

## 11. ntdll 类扩展（2.7.0）

补上了 `ProcessDebugObject (0x0D)` —— 它**不是** `0x1E` 的重复：`0x1E` 返回调试对象
句柄,`0x0D` 返回整个 `DEBUG_OBJECT` 结构(首字段是同一个句柄),走的是真实函数里
另一条分支。漏掉它就意味着目标换一个类号就能拿到真答案。

`SystemKernelDebuggerInformation (0x23)` 改用显式字节模式 `{0x00, 0x01}`,而不是
清零。原因：结构是 `{DebuggerPresent, DebuggerNotPresent}`,「无内核调试器」是
`{0,1}`,全零是一个任何真实机器都不会报告的状态,本身就是指纹。

为此新增了 `fake_pattern_success` 动作：按调用方给定的字节串写入,并**逐字节检查
缓冲区指针非空**——某些类允许 `Buffer=NULL, Length=0`,在那里解引用会造成我们
自己制造的崩溃。写入长度等于模式长度,不会溢出短缓冲区。

实测(目标自报)：

```
未 hook: ProcessDebugObject(0x0D)  status=0xC0000003  handle=0xAAAA...  DETECTED
hook 后: ProcessDebugObject(0x0D)  status=0x00000000  handle=0            clean
未 hook: KernelDebugger(0x23)      present=0 notpresent=1                 clean
hook 后: KernelDebugger(0x23)      present=0 notpresent=1  (显式写入，不再是清零)
```

`0x0D` 第一次修的时候只写了 4 字节(`fake_zero_success`),`status` 变成成功但 handle
字段的高 4 字节仍是 `0xAAAA……`——因为调用方传的是 `sizeof(DEBUG_OBJECT)` 并读取
前 8 字节。改用 8 字节模式后才真正清零。

复现命令：

```powershell
# 重编译测试目标
cd plugin\test
cl /nologo /O1 adtest.cpp /link /SUBSYSTEM:CONSOLE /OUT:adtest.exe

# 一条命令跑完整会话（装 stub + ntdll hook + harden + 跑目标 + 打印自报结果）
.\scripts\live-check.ps1 -Target .\plugin\test\adtest.exe `
    -Report .\plugin\test\out.txt -Arms cpuid,rdtsc -HookNtdll -Harden
```

## 7. 明确做不到的

写出来是为了避免"harden 成功 = 隐身"的误读：

- **内核态直接读 EPROCESS** —— 需要加载驱动;本机 HVCI 开着,未签名驱动会被拒。
- **已经持有调试对象句柄的检查** —— 句柄在目标自己的表里,清 EPROCESS 不影响它。
- **每次写后立刻重新保护页面的保护层** —— 每次安装都会 verify,失败会明说并回滚,
  但无法赢过持续对抗。
- **硬件层面的 CPUID 计时** —— 物理机与虚拟机的差异只能靠 stub 掩盖单点。
- **hotpatch 布局的副作用**：替换整个函数后,未被拦截的信息类会返回
  `STATUS_INVALID_PARAMETER`。这是"一次写、无范围限制"的代价,响应里 `caveat`
  字段会明说。
