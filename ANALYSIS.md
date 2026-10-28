# 灵感来源：[gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)

- 星标：30,410
- 许可证：MIT
- 语言：Go
- 它承诺解决：把「这个仓库里有没有硬编码的密钥」变成一个可以塞进 CI 的、有退出码的命令。

## 它做对了什么

**1. 先按关键词粗筛，再跑正则。**
`detect/detect.go` 里给每条规则配了 `keywords`，全部塞进一棵 Aho-Corasick 前缀树（`BobuSumisu/aho-corasick`）。
一个文件里连 `password`、`token` 这些词都没出现过，那 222 条正则一条都不用跑。
这是纯正则方案跑得动大仓库的唯一原因——先花 O(n) 判断「值不值得花 O(n×规则数)」。

**2. 把「哪些文件根本不用看」写成配置，而不是散在代码里。**
`config/gitleaks.toml` 顶部的 `[allowlist]` 里有 26 条路径规则：`node_modules`、`vendor/`、
各种 lock 文件、`*.min.js`、`site-packages`…… 这些地方的东西 99% 是别人写的、你改不了的。
跳过它们不是偷懒，是让剩下的告警有意义。

**3. 指纹（fingerprint）而不是行号来记住「这条我看过了」。**
`.gitleaksignore` 记的是 `commit:file:rule:line` 这样的指纹。行号会随着代码改动漂移，
指纹不会。这个设计让「暂时放行」不会在下次提交时又冒出来。

**4. 会往下解码。**
`detect/codec/` 里有 base64 / hex / percent / unicode 四个解码器，`--max-decode-depth` 控制递归层数。
密钥被 base64 藏一层是最常见的「伪混淆」，这一层做了就比没做强。

**5. 一个二进制，零运行时依赖。**
Go 编译出来单文件，Docker 镜像、GitHub Action、pre-commit 钩子都能直接用。
一个安全工具如果需要先 `pip install` 一堆东西，它在 CI 里活不过第一个季度。

## 它在哪里让人痛苦

### 痛点一：值在什么「语法位置」上，正则不知道

issue [#908](https://github.com/gitleaks/gitleaks/issues/908)（2022 年开的，到现在还开着）：

> If a generic API key is stored in an XML tag, the secret is not being detected.
> ... Modifying the REgex and adding `'<'` as one of the end characters of the secret is catching it.

提 issue 的人自己找到了原因：`generic-api-key` 这条正则的结尾是

```
(?:[\x60'"\s;]|\\[nr]|$)
```

也就是「值后面必须是反引号、引号、空白、分号或者行尾」。`<apiKey>xxx</apiKey>` 里 `xxx` 后面是 `<`，
不在这个字符集里，于是整条匹配失败。改一个字符类就能修——但四年过去没人改，
因为改它可能让别的规则多报。

同一个根因的另外两个 issue：[#1361](https://github.com/gitleaks/gitleaks/issues/1361)（YAML 里的密钥扫不到）、
[#1078](https://github.com/gitleaks/gitleaks/issues/1078)（用户为了扫 `.properties` 手写了一条 200 字符的正则，还是不行）。

我在自己造的语料上复现了这件事：40 个真密钥文件，gitleaks 漏了 13 个，其中 XML 那个就是被这个字符类挡住的。

### 痛点二：没有「上下文」，误报只能靠加排除规则

issue [#1766](https://github.com/gitleaks/gitleaks/issues/1766)：

> Gitleaks findings report the line, match, and secret, however, this isn't always enough context to be useful.
> Some false-positives ... require _n_ lines of surrounding context for the allowlist to be effective.
> This is also required for `gitleaks:allow` to work with findings where `gitleaks:allow` cannot be place on the same line.

翻译过来：一条告警只告诉你「这一行有个像密钥的东西」，不告诉你「它被赋给了谁、为什么被判成密钥」。
于是你没法一眼判断真假，只能去写 allowlist；而 allowlist 又是按正则匹配的，
写宽了误杀，写窄了不生效。

### 痛点三：示例密钥会被反复误报，而排除规则要每个项目写一遍

issue [#1864](https://github.com/gitleaks/gitleaks/issues/1864)：

> With the integration of gitleaks into gitlab and other tools its especially frustrating to have to add
> an exclusion to vendor dependancies each time I create a new project when using Go and things like the AWS SDK for Go.

AWS SDK 的测试数据里带着 `AKIAIOSFODNN7EXAMPLE`——AWS 官方文档里那个示例 key。
任何 Go 项目 `go mod vendor` 之后都有一份。工具认不出「这是文档示例」，
用户就只能每个新项目手动加一条排除。

我的实测数据更直接：拿 gitleaks 扫我自己那 11 个仓库（103 个文件），它报了 4 条，
其中 1 条是误报——`tests/test_leakcheck.py` 里那行 `"-----BEGIN RSA PRIVATE KEY-----\n"` 字符串常量。
只有头、没有身子的一段 base64，它照样当成私钥。

### 痛点四：配置本身变成了一个需要维护的东西

issue [#1557](https://github.com/gitleaks/gitleaks/issues/1557)：

> The `--config` flag doesn't support remote download so there is an expectation that the rules file is already
> present in the local dir... This requires a little more effort to make sure teammates are using the latest custom rules.

而配置的优先级有四级（`--config` → `GITLEAKS_CONFIG` → `GITLEAKS_CONFIG_TOML` → 目标目录的 `.gitleaks.toml`），
谁覆盖了谁，出问题时很难查。加上 22 个命令行参数、5 种报告格式、3 个命令（还有 2 个已废弃但没删的），
一个「扫一下有没有密钥」的动作，前置知识比很多人想象的多。

### 还有一个不是 issue 的信号

README 第一段现在写着：

> Gitleaks is feature complete. I'm not merging new features into Gitleaks. Future releases will be security patches only.

一个 3 万星、每天被塞进无数 CI 的工具，作者宣布功能冻结了。
上面那四个 issue 全都还开着。这不是批评——一个项目能走到「功能完备」是成功——
但它意味着这些痛点不会在上游被解决。

## 我们的取舍

**砍掉的：**

| 砍掉 | 为什么 |
|---|---|
| 222 条厂商规则 | 规则越多越难维护，而误报的大头恰恰来自那些为了「尽量全」写得最松的规则。留 16 种有公开文档格式的，加一条通用路径。 |
| TOML 配置和四级优先级 | 一个必填项都没有的工具有资格谈「零配置」。自定义靠代码里的常量，改一行就行。 |
| git 历史扫描 | 工作区扫描覆盖了 pre-commit 和 CI 两个主场景。历史扫描是另一个问题（要处理重写、要处理大仓库），塞进来会让核心逻辑翻倍。 |
| 5 种报告格式 | 文本给人看，JSON 给机器看。SARIF 可以拿 JSON 自己转。 |
| 编码层解码 | 每层解码要重跑全部规则，代价是线性的。而且 base64 里的密钥，人眼也看不出来，先让它留在那儿。 |
| baseline / `.gitleaksignore` | 行内 `leakcheck:allow` 加「本行或上一行」就够了。真需要批量放行的时候，说明规则该改了。 |

**保留的：**

- 关键词预筛的思路（换成一条 `_HINT_RE` 字面量门槛，效果一样，代码三行）。
- 熵作为一条证据（但不再当唯一门槛，也不再一刀切 3.5）。
- 打码输出（而且做得更彻底：连 `line_text` 里那一行也替换掉）。
- 单文件、零依赖、有退出码。

**加的：**

| 加的 | 解决什么 |
|---|---|
| 结构化取值（名字 + 值） | #908 / #1361 / #1078：不关心值是写在 `=` 后面、`:` 后面还是 `<tag>` 里面 |
| 61 个占位词 + 模板语法 + 掩码 + 键盘串识别 | #1864：`AKIAIOSFODNN7EXAMPLE`、`changeme`、`${DB_PASSWORD}` 直接不报 |
| 引用识别（`os.getenv` / 环境变量名 / 文件路径 / 裸标识符） | 「值是指向别处，不是值本身」这一类误报 |
| 英文单词识别 | 标准库第一版扫出 56 条误报，全是 `token = "unstructured"` 这种 |
| 每条结论带证据和分数 | #1766：一眼看出凭什么报，不用去读规则 |
| `--paranoid` 列出「被判不是」的候选和原因 | 回答「为什么这个你没报」 |

### 核心算法怎么工作的

对一个候选值 `v`（名字 `n`，来自同一行）：

1. **硬性排除**（任何一条命中就丢）：长度 < 6、占位词、模板语法、掩码、纯数字、
   键盘串、名字在值里出现两次、引用（环境变量名 / 点号路径 / 函数调用 / 文件路径）。
2. **形状匹配**：16 种格式，命中就 +0.55。其中三种要过验证器——
   JWT 的头必须能 base64 解出带 `alg` 的 JSON；URL 的密码位不能是占位词；
   私钥必须真的有身子（头后面至少 40 个 base64 字符）。
3. **加权**：形状 +0.55 / 强键名 +0.30 / 弱键名 +0.10 / 熵 ≥ 3.0 加 0.25、
   ≥ 2.0 加 0.10 / 长度 ≥ 16 加 0.10、≥ 8 加 0.05 / 密码类键名再加 0.15。
4. **阈值**：≥ 0.65 高置信，≥ 0.45 报，< 0.45 压掉并记一笔原因。

举个例子，`DB_PASSWORD=hunter2`：

```
name:DB_PASSWORD    +0.30
entropy>=2.0        +0.10   (2.81 bit)
password-name       +0.15
                    0.55  → 报，medium
```

换成 `DB_PASSWORD=changeme`，第 1 步就出局（占位词）。
换成 `auth_header = "Authorization"`，第 1 步的「英文单词」判据出局。
换成 `self.passwd = password_mgr`，值的右边是裸标识符且文件是 `.py`，判为引用出局。

## 与原版的差异

| 维度 | gitleaks 8.30.1 | leakcheck |
|---|---|---|
| 规则数量 | 222 条（`config/gitleaks.toml`，3,209 行） | 16 种形状 + 1 条通用路径 |
| 判定依据 | 单条正则 + 熵阈值 | 形状 / 键名 / 随机度 加权 |
| 配置 | 4 级优先级的 TOML | 无配置文件 |
| 命令行参数 | 22 个 | 6 个 |
| 报告格式 | json / csv / junit / sarif / 模板 | 文本 + JSON |
| 扫描范围 | 工作区 / git 历史 / stdin / 压缩包 / 编码层 | 工作区 / stdin |
| 占位符识别 | 靠 allowlist 正则 | 61 个词 + 模板 + 掩码 + 键盘串 + 名字自引用 |
| 结论可解释性 | RuleID + 熵值 | 每条证据及权重 |
| 代码量 | 454 个文件（132 个规则源文件，215 个测试样本） | 1 个文件 901 行 |
| 吞吐 | 11.7 MB/s（Go） | 2.2 MB/s（纯 Python） |
| 标注语料召回 | 27 / 40 文件 | 40 / 40 文件 |
| 标注语料误报 | 0 / 40 文件 | 0 / 40 文件 |

## 许可证说明

gitleaks 采用 MIT 许可证。本项目**没有复用它的任何代码**：
`config/gitleaks.toml` 里的 222 条规则一条都没有抄，正则全部按各厂商公开文档的格式重写；
`detect/` 的流程是读源码理解之后用自己的结构重新实现的。

本项目自身采用 MIT 许可证，见 [LICENSE](LICENSE)。
