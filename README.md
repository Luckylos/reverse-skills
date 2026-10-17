[English](README_EN.md) | 中文

# 逆向工程技能集 (Reverse Engineering Skills)

逆向工程分析技能，支持 40+ 种 AI 编程工具。

**专为 [IDA-NO-MCP](https://github.com/P4nda0s/IDA-NO-MCP) 设计** - 从 IDA 导出反编译结果，然后使用 AI 编程工具进行分析。

## 包含的技能

| 技能 | 描述 |
|------|------|
| `rev-symbol` | 从导出表/导入表或反编译代码分析函数符号 |
| `rev-struct` | 从反编译函数重建数据结构 |
| `rev-frida` | 使用现代 Frida API 生成动态插桩脚本 |
| `rev-unicorn-debug` | 使用 Unicorn 引擎模拟执行和调试指定代码片段 |
| `rev-dex-dumper` | 从运行中的 Android 应用内存中 dump DEX 文件，用于整体加固脱壳 |
| `rev-u3d-dump` | 从 Unity IL2CPP 构建中提取 C# 符号地址，生成 IDA/Ghidra 导入脚本 |
| `rev-idapython` | IDAPython / IDALib 脚本参考，涵盖调试、内存操作、反编译、混淆辅助、批量分析等 |
| `rev-ios-dump` | 使用 frida-ios-dump 对越狱设备上的 iOS 应用进行砸壳，导出解密后的 IPA 用于安全分析 |
| `rev-lief` | 使用官方 LIEF Python SDK，只读导出 ELF/PE/Mach-O 的结构、依赖、导入/导出及多架构信息 |
| `rev-angr` | 使用 angr 有界求解 argv/stdin 输入，并在模型中重放候选输入；不原生执行样本 |

### 本 fork 的 LIEF 只读扩展

`rev-lief` 可独立使用，不依赖 IDA-NO-MCP，也不是反编译器或二进制修改工具。需要已有、已验证可导入 `lief` 的 Python 环境；不会自动安装依赖、修改样本或连接第三方 MCP。

在 magpie 的 App Library 中导入此子目录链接，选择 `rev-lief`：

```text
https://github.com/Luckylos/reverse-skills/tree/main/skills/rev-lief
```

新增技能需要单独安装，更新既有技能不会自动加入它。在 Pi 中可用 `/skill:rev-lief` 指定任务；运行前仍须批准目标、只读动作及新输出目录。包装脚本面向 POSIX，Linux 已实测；原生 Windows 不支持，macOS 尚未实测。详见[使用说明与边界](skills/rev-lief/references/usage.md)。

### 本 fork 的 angr 有界求解扩展

`rev-angr` 补充官方 angr MCP 未提供的符号路径求解，独立运行，不依赖 MCP 或 IDA-NO-MCP。静态分析可使用官方 angr MCP；本技能需要已有、已验证可导入 `angr` 的 Python 环境，不会自动安装依赖或修改客户端配置。

求解有时间、内存、步数和活动状态数上限；候选输入须在模型中重放验证。仿真不是原生执行验证，“未找到路径”不等于不可达，资源限制也不是安全沙箱。

在 magpie 的 App Library 中导入此子目录链接，选择 `rev-angr`，单独安装：

```text
https://github.com/Luckylos/reverse-skills/tree/main/skills/rev-angr
```

更新既有技能不会自动加入它。在 Pi 中可用 `/skill:rev-angr` 指定任务；运行前仍须批准目标、分析动作及新输出目录。包装脚本面向 POSIX，Linux 已实测；原生 Windows 不支持，macOS 尚未实测。详见[使用说明与报告解读](skills/rev-angr/references/usage.md)。

## 安装

```bash
npx skills add Luckylos/reverse-skills
```

### 更新与卸载

```bash
# 检查更新
npx skills check

# 更新
npx skills update

# 卸载
npx skills remove rev-symbol rev-struct
```

## 许可证

MIT
