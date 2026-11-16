# x64dbg_mcp_hide — 内核态反反调试驱动

给 x64dbg MCP 插件用的内核辅助驱动。用户态够不到的 `EPROCESS` 调试字段由它在
内核里改掉，让目标进程对 `NtQueryInformationProcess` 和内核态读取都表现为
"没被调试"，同时调试器本身继续正常工作。

纯 WDM，不依赖 KMDF/WDF，没有 C++，没有外部库。x64 only。

> **这是实验/分析工具。** 见文末"失败模式"和"HVCI"两节再决定要不要用。

---

## 1. 它到底改了什么

调试关系里有三块信息，用户态只能看到前两块：

| 位置 | 谁在读 | 驱动怎么做 |
|---|---|---|
| `EPROCESS.DebugPort` | `NtQueryInformationProcess(ProcessDebugPort=7)`、`PsIsProcessBeingDebugged()` | 清 0 |
| `EPROCESS.Flags` 的 bit 1（`NoDebugInherit`） | `NtQueryInformationProcess(ProcessDebugFlags=0x1F)` | 清除该位 |
| `KPROCESS.DebugActive` | 只有内核自己看 | **不碰**（见下） |

### 为什么清掉 DebugPort 调试器还能正常工作

调试对象（debug object）的句柄在**调试器进程**手里，调试事件的投递由那个对象
驱动，不依赖内核重新读一次被调试进程的 `EPROCESS.DebugPort`。所以把被调试方的
该字段清零，只影响"别人来问你是不是被调试了"这个查询，不影响 x64dbg 收事件、
下断点、单步。

### `NoDebugInherit` 的极性（容易搞反，已实测确认）

内核在 `NtQueryInformationProcess` 里的原始代码是：

```
8B 81 F4 01 00 00   mov  eax, [rcx+1F4h]     ; EPROCESS.Flags
D1 E8               shr  eax, 1               ; 取 bit 1 = NoDebugInherit
F7 D0               not  eax
83 E0 01            and  eax, 1               ; DebugFlags = !NoDebugInherit
```

即 `DebugFlags = !NoDebugInherit`。在 Win11 26200 上实测：

| 进程状态 | `DebugFlags` 返回值 | 推论 |
|---|---|---|
| 干净进程 | `1` | `NoDebugInherit = 0` |
| 用 `DebugActiveProcess` 挂上后 | `0` | `NoDebugInherit = 1` |

**结论：被调试时该位是 1。要伪装成干净进程，必须"清除"这一位，不是置位。**
字段名读起来是反的（叫 "no debug inherit" 却在被调试时置位），所以以实测为准。

---

## 2. IOCTL

全部 `METHOD_BUFFERED`，设备名 `\\.\x64dbg_mcp_hide`。

| IOCTL | 方向 | 说明 |
|---|---|---|
| `IOCTL_X64MCP_GET_VERSION` (0) | out `X64MCP_VERSION` | 拿 ABI 版本、OS build、解析到的偏移、偏移来源 |
| `IOCTL_X64MCP_ATTACH` (1) | in `X64MCP_ATTACH_REQ` | 校验 pid 活着，记住它 |
| `IOCTL_X64MCP_DETACH` (2) | 无 | 还原所有已改字段并忘记目标 |
| `IOCTL_X64MCP_APPLY` (3) | in `X64MCP_APPLY_REQ` → out `X64MCP_STATUS` | 按 mask 施加，返回实际成功/失败的位 |
| `IOCTL_X64MCP_QUERY` (4) | out `X64MCP_STATUS` | 当前状态，不改任何东西 |

`IoStatus.Information` 一律设置为实际写回的 `sizeof`，失败路径清 0。

### 结构体尺寸（用户态/内核必须一致）

```
X64MCP_VERSION     56
X64MCP_ATTACH_REQ   8
X64MCP_APPLY_REQ   24
X64MCP_STATUS      40   <- 注意不是 48：pid 后 4 字节填充，两个 ULONG64 才对齐
```

头文件里用 `C_ASSERT` 在**内核侧**钉死这四个值。用户态如果 pack 设置不同会
在这里暴露出来。

### 标志位

| 位 | 值 | 含义 | 实际行为 |
|---|---|---|---|
| `X64MCP_HIDE_DEBUGPORT` | `0x1` | 清 `EPROCESS.DebugPort` | 已实现，偏移运行时解析 |
| `X64MCP_HIDE_FLAGS` | `0x2` | 处理 `NoDebugInherit` | 已实现，**清除** bit 1；偏移需用户态提供 |
| `X64MCP_HIDE_CROSSSESSION` | `0x4` | 清跨会话调试标志 dword | 已实现，偏移需用户态提供 |
| `X64MCP_HIDE_KDPRINT` | `0x8` | 清 `KPROCESS.DebugActive` | **有意不支持**，见 §5 |

`X64MCP_STATUS.failed` 会如实回报没能施加的位，不会假装成功。

---

## 3. 偏移解析

### `EPROCESS.DebugPort`：运行时解析，不写死

1. `MmGetSystemRoutineAddress(L"PsGetProcessDebugPort")` 找导出函数
   （Win8.1+ 由 ntoskrnl 导出；找不到就走第 3 步）。
2. 反汇编开头几个字节，认这四种 x64 编码，取 `disp` 作为偏移：

   | 字节 | 指令 | 出现在 |
   |---|---|---|
   | `48 8B 81 <disp32>` | `mov rax,[rcx+d]` | 26100 / 26200（已验证） |
   | `48 8B 89 <disp32>` | `mov rcx,[rcx+d]` | 部分构建 |
   | `8B 81 <disp32>` | `mov eax,[rcx+d]` | 部分构建 |
   | `8B 41 <disp8>` | `mov eax,[rcx+d]` | 部分构建 |

3. **校验**：偏移必须 4 字节对齐、落在 `0x100..0x1000`；并且拿当前进程
   （System 进程，永远不会被调试）按该偏移读一次必须是 0。这条检查能挡掉绝大
   多数反汇编误判——读错位置几乎不可能正好是 0。

在本机 Win11 26200 上：`PsGetProcessDebugPort` = `48 8B 81 08 03 00 00 C3`
→ 偏移 `0x308`，与 PDB 符号 `_EPROCESS.DebugPort` 的 `0x308` 一致。

### `EPROCESS.Flags`：没有导出，只能外部提供

`NoDebugInherit` 是 `EPROCESS.Flags` 里的位域，内核没有导出它的 getter，所以
驱动无法像 DebugPort 那样自己解析。驱动程序的做法是：

- 初始为 `0`（未解析）；
- 由用户态通过 `X64MCP_APPLY_REQ.ep_flags_offset` 传入，驱动做同样的范围/对齐校验；
- 没传或校验不过 → `X64MCP_HIDE_FLAGS` 记为 **failed**，**不往猜的地址写**。

`X64MCP_VERSION.flags_source` 说明来源：

| 值 | 含义 |
|---|---|
| `0` `X64MCP_OFFSET_SOURCE_AUTO` | 由导出函数 + 反汇编解析得到（DebugPort 用） |
| `1` `X64MCP_OFFSET_SOURCE_SUPPLIED` | 调用方提供 |
| `2` `X64MCP_OFFSET_SOURCE_UNRESOLVED` | 没解析出来 |

本机 26200 上 `Flags` = `0x1F4`，`NoDebugInherit` = bit 1。**换系统版本前请重新
确认这个数**——这是整个 ABI 里唯一需要人工补的偏移。

---

## 4. 加载 / 卸载

```powershell
# 需要管理员权限
sc.exe create x64dbg_mcp_hide type= kernel binPath= "F:\...\driver\build\x64dbg_mcp_hide.sys"
sc.exe start  x64dbg_mcp_hide

# 查看
sc.exe query x64dbg_mcp_hide

# 卸载（会先还原所有改动，再删设备）
sc.exe stop   x64dbg_mcp_hide
sc.exe delete x64dbg_mcp_hide
```

`DriverUnload` 的顺序是：**先 `X64McpRevertAll` 还原**，再删符号链接、删设备
对象、删 ERESOURCE。也就是说 `sc stop` 不会把被调试进程留在半改状态。

同样，最后一个文件句柄关闭时（`IRP_MJ_CLEANUP`）也会自动还原全部改动。插件
崩了、进程被杀了，都不会留下被改过的目标。

### 构建

```powershell
.\build-driver.ps1            # 编译
.\build-driver.ps1 -TestSign  # 编译 + 自签名 + 装测试证书
.\build-driver.ps1 -Load      # 编译 + sc create + sc start
.\build-driver.ps1 -Unload    # sc stop + sc delete
```

找不到 WDK 时脚本**不会假装构建**，会打印要装什么并以退出码 `2` 退出。

---

## 5. 它能做什么、不能做什么（精确版）

### 能做

- 清 `EPROCESS.DebugPort` —— 骗过 `ProcessDebugPort` 查询和
  `PsIsProcessBeingDebugged`。
- 清除 `EPROCESS.Flags` 的 `NoDebugInherit` 位 —— 骗过 `ProcessDebugFlags`。
- 偏移全部运行时解析 + 校验，不写死单一 build。
- 卸载/关闭句柄时自动还原，不留残留。

### 不能做，以及为什么

| 做不到 | 原因 |
|---|---|
| **不 hook SSDT / 不 inline hook** | PatchGuard 会周期性校验内核代码段与关键表，改了就是 `CRITICAL_STRUCTURE_CORRUPTION`（0x109）蓝屏。清 `EPROCESS` 字段是改**数据**，不触发这项检查。 |
| **不给 ring-3 代码伪造 CPUID** | 那需要改 `KUSER_SHARED_DATA` / 拦截 `cpuid` 指令 / 上 VT-x，全都在 PatchGuard 或 hypervisor 范围内。要反 CPUID 型反调试，得在用户态用插件侧手段处理。 |
| **不隐藏句柄表条目** | 句柄表在内核池里，结构无导出、布局随版本变，改它极易踩到引用计数和 PatchGuard。且 `NtQuerySystemInformation` 的句柄枚举走的是完全不同的路径。 |
| **不碰 `KPROCESS.DebugActive`** | `KPROCESS` 是内核私有的，没有稳定布局也没有导出访问器；而且**没有任何 ring-3 读者会看这个字段**，改了纯属给自己加 PatchGuard 风险。所以 `X64MCP_HIDE_KDPRINT` 一律回报 failed。 |
| **不改 PEB 的 `BeingDebugged`** | 那在用户态地址空间里，插件自己就能写，不需要驱动。 |

一句话：**这个驱动只做"改 EPROCESS 里的调试数据字段"这一件事**，因为这是唯一
既能生效、又不会触发内核完整性检查的层面。

---

## 6. 失败模式

| 现象 | 原因 | 处理 |
|---|---|---|
| `GET_VERSION` 返回 `ep_debugport_offset = 0`，`flags_source = 2` | 该 build 的 `PsGetProcessDebugPort` 序言不认识，或校验没过 | 换 `X64MCP_HIDE_DEBUGPORT` 之外的路径；或按 `PsGetProcessDebugPort` 的实际字节更新解码器 |
| `APPLY` 返回 `failed & X64MCP_HIDE_FLAGS` | 没传 `ep_flags_offset`，或传的值非法 | 从 PDB / 目标 build 取 `_EPROCESS.Flags` 偏移后传入 |
| `ATTACH` 返回 `0xC000000B`（`STATUS_INVALID_PARAMETER`） | pid 是 0 或 4（Idle/System） | 驱动拒绝操作这两个，属于预期行为 |
| `APPLY` 返回 `0xC000010A` | 目标正在退出 | 重新选目标 |
| `APPLY` 成功但目标仍检测到调试 | 目标查的不是 `ProcessDebugPort`/`ProcessDebugFlags`，而是 PEB、`NtQueryObject` 的 `DebugObject`、时序检测等 | 这些要在插件侧用别的手段处理 |
| `sc start` 失败 `577` / `1275` | 签名问题：没签名、测试签名没开、或 HVCI 拦截 | 见 §7 |
| 装完蓝屏 `0x109` | 不太可能是本驱动（它只写数据字段），更可能是同时装了别的 hook 类驱动 | 逐个卸载排查 |

---

## 7. 测试签名

```powershell
# 1. 开测试签名（需要重启）
bcdedit /set testsigning on

# 2. 重启

# 3. 编译 + 自签名（脚本会建证书、导入 Root 和 TrustedPublisher）
.\build-driver.ps1 -TestSign

# 4. 加载
.\build-driver.ps1 -Load
```

`-TestSign` 会附加 `/INTEGRITYCHECK`。**不加**这个标志是有意的：测试签名的镜像
并不需要它，而在某些配置下把它加到一个非正式签名的二进制上，CI 反而会直接拒绝
加载。所以它跟 `-TestSign` 绑定，不做默认。

关掉测试签名：

```powershell
bcdedit /set testsigning off
```

开着的时候桌面右下角会有水印，这是正常的。

---

## 8. HVCI / 内存完整性

Win11 22H2 起，**内存完整性（HVCI / Hypervisor-Enforced Code Integrity）默认开启**，
24H2+ 上更严格。开启时：

- 未签名驱动、以及很多自签名驱动**会被直接拒绝加载**；
- 即使开了测试签名也不一定放行——HVCI 的检查在 hypervisor 层，绕过测试签名开关。

查当前状态：

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object -ExpandProperty SecurityServicesRunning
# 2 = HVCI 正在运行
```

或者在「Windows 安全中心 → 设备安全性 → 内核隔离 → 内存完整性」里看。

要做实验，需要：

1. 关掉内存完整性并**重启**；
2. 开测试签名并**重启**；
3. 再加载驱动。

**这是一个分析/实验用工具**：它修改内核数据结构，改动只应该发生在你自己的测试
机器和你自己的目标进程上。

---

## 9. 自检清单（写代码时逐条核对过）

每一条都在写完代码后对着源码确认，不是想当然。

- [x] **纯 C / 纯 WDM** — 无 C++ 语法、无 `class`/`template`/`namespace`，
      只 `#include <ntddk.h>` + `<ntstrsafe.h>` + `<wdmsec.h>` + `<devioctl.h>`，
      没有 WDF/ATL 头。
- [x] **`PsLookupProcessByProcessId` 配平 `ObDereferenceObject`**
      — 全文件只有 3 处 lookup：`ATTACH`（查完立刻 deref，同一分支）、
      `APPLY`（成功/失败路径各一次 deref，且都在唯一出口前）、
      `REVERT`（目标消失时提前 return 且**未持有引用**，正常路径结尾 deref）。
      无泄漏、无重复释放。
- [x] **每条 IRP 路径都设 `IoStatus.Status` 并只 `IoCompleteRequest` 一次**
      — 所有 `IRP_MJ_*` 处理器都在自己的末尾完成；`DEVICE_CONTROL` 的分发器
      统一做 `if (!NT_SUCCESS) Information = 0;` 再 `IoCompleteRequest`，
      各 case 内部不完成 IRP。异常路径返回 `NTSTATUS` 给分发器，不重复完成。
- [x] **无 `strcpy`/`sprintf`** — 唯一的字符串写入是
      `RtlStringCchCopyA(out->tag, RTL_NUMBER_OF(out->tag), ...)`，带长度上限；
      日志走 `DbgPrint`/`vDbgPrintEx`，格式串全是字面量。
- [x] **结构体尺寸两侧一致** — 内核侧 `C_ASSERT` 钉死
      `56/8/24/40`；用 MSVC 实际编译用户态小程序打印 `sizeof`，得到
      同样的 `56/8/24/40`。`X64MCP_STATUS` 是 **40 不是 48**（`pid` 后有 4 字节
      填充）。
- [x] **`METHOD_BUFFERED` + `Information` 正确** — 每个成功 case 设成对应结构体的
      `sizeof`；`APPLY` 因为输入输出共用 SystemBuffer 且输出更大，**先把请求
      `RtlCopyMemory` 到局部变量**再让处理器写响应；失败一律 `Information = 0`。
- [x] **无锁保护的全局可变状态** — 唯一的全局状态 `g_State` 由 `ERESOURCE`
      保护（`g_StateLock`），所有读写都在 `X64McpLock/Unlock` 内。锁定跨函数时
      用 ERESOURCE 而不是 spinlock（不在全局存 IRQL，避免多核下 release 用到错的
      IRQL）。只读的 `g_EpDebugPortOffset` 等在 `DriverEntry` 单线程阶段写完，
      之后不再变。
- [x] **卸载安全** — `DriverUnload` 先还原再拆设备/链接/资源；`CLEANUP` 也还原；
      两者都幂等（还原后 `g_State` 清零，再调直接返回）。
- [x] **不操作 PID 0 / 4** — `ATTACH` 和 `APPLY` 都显式拒绝。
- [x] **拒绝时不留半改状态** — 每个字段单独 `__try/__except`，
      某个字段写失败只把该位记进 `failed`，其他字段照常，且原值已保存供还原。
- [x] **实际编译验证** — 在没有 WDK 的机器上用手写的最小 DDK 桩头文件，
      以 `cl /W4 /c` 编译 `x64dbg_mcp_hide.c`，**0 error 0 warning**。
      这只证明语法/类型/签名正确，**不证明**链接通过（缺真实 `ntoskrnl.lib` 等）。
      拿到装好 WDK 的机器后仍需跑一次 `build-driver.ps1` 确认链接。

### 需要 Lead 复核的地方

1. **`X64MCP_STATUS` 尺寸**：需求里没写期望值，实测是 **40**。如果用户态那边
   按 48 写了 `C_ASSERT` 或做 buffer 大小比较，会不一致——以头文件里的
   `C_ASSERT` 为准。
2. **`ep_flags_offset` 必须由用户态提供**（`0x1F4` on 26200）。这是唯一没法
   运行时自解析的偏移，换 build 要重取。
3. **`X64MCP_HIDE_KDPRINT` 恒失败**：按"不动 `KPROCESS`"的取舍实现，
   如果确实需要清 `KPROCESS.DebugActive`，要单独评估 PatchGuard 风险。
4. **链接未验证**：本机无 WDK，只做了编译期验证；`IoCreateDeviceSecure` /
   `ntstrsafe.lib` / `wdmsec.lib` 的链接需要在有 WDK 的机器上确认一次。
