# leakcheck

**按形状、键名、上下文找硬编码密钥。一个文件，零依赖，零配置。**

```bash
python examples/make_demo.py     # 造一个「到处是密钥」的演示目录
python leakcheck.py examples/demo
```

输出长这样（这是本机真实结果）：

```
examples/demo/.env
  2:19   high   0.90  AWS access key id
         AKIA********6FM
         why  shape:aws_access_key +0.55 · entropy>=3.0 +0.25 · len>=16 +0.10
         >    AWS_ACCESS_KEY_ID=AKIA********6FM
  3:23   high   0.65  疑似密钥
         dktA********GPW
         why  name:AWS_SECRET_ACCESS_KEY +0.30 · entropy>=3.0 +0.25 · len>=16 +0.10
         >    AWS_SECRET_ACCESS_KEY=dktA********GPW
  4:13   high   0.65  疑似密钥
         dktA********6dk
         why  name:DB_PASSWORD +0.30 · entropy>=2.0 +0.10 · len>=16 +0.10 · password-name +0.15
         >    DB_PASSWORD=dktA********6dk

examples/demo/config.yaml
  4:15   high   0.80  疑似密钥
         dipu********nty
         why  name:password +0.30 · entropy>=3.0 +0.25 · len>=16 +0.10 · password-name +0.15
         >    password: dipu********nty

examples/demo/deploy.xml
  3:11   high   0.65  疑似密钥
         dnxG********epy
         why  name:apiKey +0.30 · entropy>=3.0 +0.25 · len>=16 +0.10
         >    <apiKey>dnxG********epy</apiKey>

examples/demo/settings.properties
  2:13   high   0.75  疑似密钥
         dqBN********nzL
         why  name:db.password +0.30 · entropy>=3.0 +0.25 · len>=8 +0.05 · password-name +0.15
         >    db.password=dqBN********nzL

6 leaks · 6 high  ·  6 files · 588 B · 0.28 s · 6 条候选被判为不是密钥（no-context 3、placeholder 3）
```

演示目录里还有两个文件**没有**被报：一个是文档里的 `AKIAIOSFODNN7EXAMPLE`（AWS 官方示例），
一个是 `DB_PASSWORD=changeme` 加 `${API_TOKEN}`。想看它们为什么被放过，加 `--paranoid`：

```
dismissed  6 条（证据不足，--paranoid 才列出）
  .../examples/demo/docs.md         3  placeholder    AKIA********PLE
  .../examples/demo/template.env    1  placeholder    ch******
  .../examples/demo/template.env    2  placeholder    ${AP********KEN
  .../examples/demo/.env            1  no-context     eu-w********t-1
```

## 为什么又造一个

密钥扫描的难点从来不是「找出像密钥的东西」，是**别在没密钥的地方喊狼来了**。

喊错一次的代价不是多看一眼，是这个工具从此被 `continue-on-error` 掉、被写进 allowlist、
被团队默默忽略。而几乎所有扫描器最后都走到同一条路上：内置几百条正则，误报了就让用户加排除规则。
排除规则越加越多，配置文件越写越长，最后没人知道哪些规则还生效。

leakcheck 换个方向：**一个字符串是不是密钥，看三件事，而不是看一条正则。**

| 证据 | 例子 | 分量 |
|---|---|---|
| 形状 | `AKIA…`（20 位，AWS 文档的格式）、`ghp_…`、`xoxb-…`、`-----BEGIN … PRIVATE KEY-----` | +0.55 |
| 键名 | `DB_PASSWORD`、`client_secret`、`AWS_SECRET_ACCESS_KEY` | +0.30 |
| 随机度 | 香农熵 ≥ 3.0、长度 ≥ 16、至少两类字符 | +0.25 / +0.10 |

三条都占，分数 0.90，报。只有键名占，0.30，不报。**默认阈值 0.45**——
分数不到 0.45 的候选会被压掉，并在结尾统计成「N 条候选被判为不是密钥」，
让你知道它看过、也想过了。

这不是概率模型，是一把手工刻的尺子。但它有个好处：每条结论都能说清楚凭什么。

## 它比正则多知道的三件事

**1. 值是被赋给谁的。**

`db.password=xxx`、`"apiKey": "xxx"`、`<apiKey>xxx</apiKey>`、`AUTH = ("svc", "xxx")`
在正则眼里是四种完全不同的形状，在 leakcheck 眼里都是「名字 + 值」。
所以 YAML、properties、XML、INI、TOML、JSON、Python 关键字参数，一套逻辑全覆盖。

**2. 什么值不可能是密钥。**

61 个占位词（`changeme`、`your-key-here`、`placeholder`）、模板语法（`${DB_PASSWORD}`、`{{ .Values.token }}`）、
掩码（`********`）、纯数字、顺手敲的键盘串（`qwertyuiop`）、
引用而不是值（`os.getenv(...)`、`DB_PASSWORD`、`/etc/ssl/server.key`）、
代码里的裸标识符（`self.passwd = password_mgr` 右边那个是变量名）、
英文单词（`auth_header = "Authorization"`）、
以及 AWS 文档里那个 `AKIAIOSFODNN7EXAMPLE`——**光这一条就够让每个 Go 项目 vendor 一份 SDK 后天天误报**。

**3. 上下文里的名字。**

```hcl
variable "db_password" {
  default = "…"        # 名字在上一行
}
```
`default` 本身什么都不说明，往上找一层才知道这是谁的默认值。leakcheck 会往上找。

## 安装

不需要安装。Python 3.9+，只用标准库：

```bash
git clone https://github.com/z15346183030/leakcheck.git
cd leakcheck
python leakcheck.py .
```

## 用法

```bash
python leakcheck.py                    # 扫当前目录（在 git 仓库里就跟着 .gitignore 走）
python leakcheck.py src/ .env          # 扫指定路径
python leakcheck.py --json             # 机器可读
python leakcheck.py --quiet            # 一行一条，给 CI 用
python leakcheck.py --paranoid         # 连「看着像但其实不是」的也列出来，带原因
python leakcheck.py --walk             # 不用 git 的文件列表，直接遍历目录
python leakcheck.py --max-size 5       # 跳过大于 5MB 的文件（默认 2MB）
```

退出码：有发现返回 1，干净返回 0。直接当 pre-commit 钩子用：

```bash
# .git/hooks/pre-commit
#!/bin/sh
python path/to/leakcheck.py --quiet .
```

### 放行一条

行内注释，写在本行或上一行都行（跨行匹配不用再挤到同一行）：

```python
STRIPE_KEY = "sk_live_…"   # leakcheck:allow
```

```yaml
# leakcheck:allow
legacy_token: "…"
```

### 输出里的密钥

一律打码成 `AKIA********6FM`——星号数量固定，连长度都不泄露。
连 `line_text` 里那一行也一起替换掉了。报告本身是要贴进 issue 的，不能顺手把密钥再泄露一次。

## 它不做什么

- **不扫 git 历史。** 只看工作区当前的文件。历史里的旧密钥要另外处理（`git log -p` + 本工具扫 stdin 也行，但那是你的脚本）。
- **不做解码。** 不展开 base64 / hex / percent 编码后的内容，也不钻压缩包。上游工具会（`--max-decode-depth`），代价是每层解码都要重跑全部规则。
- **不认 200 家厂商。** 只认 16 种有公开文档格式的凭据，加上「名字 + 随机度」这条通用路径。冷门厂商的 token 只能靠名字捞。
- **不做自动修复、不建 baseline、不出 SARIF。** 一个 JSON 输出，够 CI 用了。

## 和原版的差异

| | gitleaks 8.30 | leakcheck |
|---|---|---|
| 规则 | 222 条，3,209 行 TOML | 16 种形状 + 1 条通用路径，写死在代码里 |
| 配置 | 4 级优先级（`--config` / 两个环境变量 / 目标目录的 `.gitleaks.toml`） | 0 个必填项，没有配置文件 |
| 判断依据 | 正则命中 + 熵阈值 + allowlist | 形状 / 键名 / 随机度 三条证据加权 |
| 输出 | 5 种格式 + 模板引擎 | 文本 + JSON |
| 参数 | 22 个 | 6 个 |
| 扫描范围 | 工作区、git 历史、stdin、压缩包、编码层 | 工作区、stdin |
| 误报处理 | 加 allowlist 规则 | 认得出占位符和引用，默认就不报 |

更详细的拆解写在 [ANALYSIS.md](ANALYSIS.md)。

## 实测

同一份标注语料（40 个真密钥文件 / 40 个「长得像但不是」的文件）：

| | 抓到 | 漏 | 误报 |
|---|---|---|---|
| gitleaks 8.30.1 | 27 / 40 文件 | 13 | 0 / 40 |
| leakcheck | 40 / 40 文件 | 0 | 0 / 40 |

CPython 3.13 标准库（543 个文件 / 9.5 MB / 27.1 万行）：

```
1 leaks · 1 high · 543 files · 9.5 MB · 4.10 s · 32427 条候选被判为不是密钥
```

那一条是 `urllib/request.py` 文档字符串里的示例密码 `passwd='geheim$parole'`——
严格说它确实是写在源码里的密码，只是写在注释里。gitleaks 在同目录下报 0 条。

速度和精度都不是免费的：纯 Python 逐行匹配，每 MB 大约 0.46 秒，gitleaks（Go）是 0.09 秒。
差五倍是语言差距，不是设计差距。

## 测试

```bash
python -m unittest discover -s tests
```

104 个用例，全部是纯函数和临时目录，不依赖网络和外部命令。

## 许可证

MIT。灵感来源 [gitleaks](https://github.com/gitleaks/gitleaks)（MIT），未复用其代码。
