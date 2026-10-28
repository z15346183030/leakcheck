#!/usr/bin/env python3
"""leakcheck —— 按形状、键名、上下文判断硬编码密钥。

一个文件，零依赖，零配置。默认只报有把握的：证据够多才说话。
每条结果都说清楚「凭什么」——哪几条证据、各占多少分。

    python leakcheck.py                 # 扫当前目录（有 git 就跟着 .gitignore 走）
    python leakcheck.py src/ config.yaml
    python leakcheck.py --json          # 机器可读
    python leakcheck.py --paranoid      # 连「看着像但其实不是」的也列出来

设计只有一条主线：**一个字符串是不是密钥，取决于三件事，而不是一条正则。**
形状（它长得像谁的密钥）、键名（它被赋给了谁）、上下文（它是不是模板/占位/引用）。
三样都对上才叫高置信；只对上一半，就压低置信度或者干脆不报。
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# 扫描范围
# ---------------------------------------------------------------------------

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".nox", "dist", "build", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", "site-packages", ".idea", ".vscode", "target", ".cache",
}

SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".svg",
    ".pdf", ".zip", ".gz", ".bz2", ".xz", ".7z", ".tar", ".whl", ".jar",
    ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".lib", ".pyc", ".pyo",
    ".class", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4",
    ".mov", ".avi", ".mkv", ".wav", ".flac", ".sqlite", ".db", ".pack",
}

ALLOW_MARK = "leakcheck:allow"

# ---------------------------------------------------------------------------
# 证据权重
#
# 分数不是概率，只是「这几条证据同时成立有多罕见」的一个手工刻度。
# 阈值定得偏高，因为漏报的代价是「少一条提示」，误报的代价是「以后没人看」。
# ---------------------------------------------------------------------------

W_SHAPE = 0.55          # 值本身就是某个厂商的密钥格式
W_NAME_STRONG = 0.30    # 键名明确说是密码 / token / secret
W_NAME_WEAK = 0.10      # 键名只说了个 key / salt / sig
W_PASSWORD_NAME = 0.15  # 键名是 password 一类，值可以很短很弱
W_ENT_HIGH = 0.25       # 香农熵 >= 3.0
W_ENT_MID = 0.10        # 香农熵 >= 2.0
W_LEN_LONG = 0.10       # 长度 >= 16
W_LEN_MID = 0.05        # 长度 >= 8

SCORE_HIGH = 0.65
SCORE_MEDIUM = 0.45
SCORE_LOW = 0.30

# ---------------------------------------------------------------------------
# 键名词表
#
# 只认整词，不做子串匹配：TOKENIZER_PATH 里的 "token" 不是 token。
# ---------------------------------------------------------------------------

STRONG_WORDS = {
    "password", "passwd", "pwd", "pass", "passphrase", "secret", "secrets",
    "token", "credential", "credentials", "auth", "authorization", "bearer",
    "dsn", "apikey", "webhook", "sessionid", "jsessionid",
}

# 两个词拼起来才算强证据：api_key、access_key、client_secret……
STRONG_PAIRS = {
    ("api", "key"), ("access", "key"), ("secret", "key"), ("private", "key"),
    ("client", "secret"), ("account", "key"), ("signing", "key"),
    ("encryption", "key"), ("master", "key"), ("session", "key"),
    ("subscription", "key"), ("access", "token"), ("auth", "token"),
    ("api", "secret"), ("app", "secret"), ("app", "key"), ("service", "key"),
    ("storage", "key"), ("encrypt", "key"), ("sign", "key"),
}

WEAK_WORDS = {"key", "sig", "signature", "salt", "hash", "pin", "seed", "nonce"}

PASSWORD_WORDS = {"password", "passwd", "pwd", "pass", "passphrase"}

# ---------------------------------------------------------------------------
# 占位符：这些东西长得像密钥，但其实谁都能写出来
#
# 这一层是「不喊狼来了」的主力。上游工具的同类问题（示例密钥被反复误报）
# 最后都变成用户在配置里加一条条排除规则；这里的答案是让工具自己认得出来。
# ---------------------------------------------------------------------------

PLACEHOLDER_WORDS = {
    "password", "passwd", "pass", "secret", "token", "key", "apikey",
    "api_key", "api-key", "changeme", "change_me", "changeit", "changethis",
    "example", "sample", "dummy", "test", "testing", "fake", "placeholder",
    "redacted", "hidden", "masked", "removed", "todo", "fixme", "none",
    "null", "nil", "undefined", "true", "false", "empty", "string", "value",
    "your_password", "your-password", "yourpassword", "your_token",
    "your-key", "your_key", "your_api_key", "yourapikey", "your_secret",
    "insert_key_here", "replace_me", "not_a_real_key", "foobar", "foo",
    "bar", "baz", "abc", "abc123", "123456", "12345678", "qwerty",
    "asdfgh", "secret_key", "my_secret", "mysecret", "topsecret",
}

PLACEHOLDER_RE = re.compile(
    r"""(?ix)
      example | sample | dummy | placeholder | redacted
    | change[_-]?me | insert[_-] | replace[_-]?me | not[_-]?a[_-]?real
    | your[_-]?(?:api[_-]?)?(?:key|token|secret|password|pass)
    | (?:^|[^a-z0-9])x{3,}(?:[^a-z0-9]|$)
    | \.\.\. | \*\*\*
    | ^<[^<>]*>$ | ^\{[^{}]*\}$ | ^%[^%]*%$ | ^\[[^\[\]]*\]$
    | \$\( | \$\{ | %\( | \{\{ | \}\}
    """
)

# 明显是「引用」而不是「值」：环境变量名、点号路径、函数调用、文件路径
REFERENCE_RES = [
    re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$"),                 # DB_PASSWORD
    re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$"),  # cfg.db.pw
    re.compile(r"(?i)\b(?:os\.environ|getenv|process\.env|environ\[|System\.getenv|ENV\[)"),
    re.compile(r"^[A-Za-z_][\w.]*\s*\("),                            # load_secret(...)
    re.compile(r"^(?:/|\./|\.\./|~|[A-Za-z]:[\\/])"),                 # 绝对/相对路径
    re.compile(r"(?i)\.(?:pem|key|crt|cer|json|ya?ml|toml|ini|conf|env|txt|sh|py|js|ts)$"),
]

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# 一个普通的英文单词（可带连字符/下划线分段），没有数字、没有符号
WORDLIKE_RE = re.compile(r"^[A-Z]?[a-z]+(?:[\-_][A-Z]?[a-z]+)*$")

# 裸标识符：代码里这种「值」是变量名，不是字面量
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

CODE_EXTS = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".go", ".rs", ".rb",
    ".php", ".java", ".cs", ".kt", ".swift", ".c", ".h", ".cc", ".cpp",
    ".scala", ".pl", ".lua", ".ex", ".exs", ".m", ".groovy",
}

KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "abcdefghijklmnopqrstuvwxyz", "0123456789")
_KEYBOARD_SEQS = tuple(s * 3 for r in KEYBOARD_ROWS for s in (r, r[::-1]))


def is_sequential(value):
    """qwertyuiop、abcdefgh、98765432：顺手敲出来的，不是随机串。"""
    low = value.lower()
    if len(low) < 6 or len(low) > 40:
        return False
    for seq in _KEYBOARD_SEQS:
        if low in seq:
            return True
    steps = {ord(b) - ord(a) for a, b in zip(low, low[1:])}
    return len(steps) == 1 and steps.pop() in (1, -1)

# ---------------------------------------------------------------------------
# 形状表：只收「有公开文档格式」的密钥
#
# 故意不做 200 条厂商规则。规则越多，能命中的越多，但能维护的越少，
# 而误报里的绝大多数来自那些为了「尽量全」而写得很松的通用规则。
# ---------------------------------------------------------------------------

SHAPES = [
    ("private_key", "私钥块",
     r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----"),
    ("discord_webhook", "Discord webhook",
     r"https://(?:discord|discordapp)\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_\-]{60,}"),
    ("jwt", "JSON Web Token",
     r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    ("aws_access_key", "AWS access key id",
     r"(?<![A-Za-z0-9])(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|ANPA|ANVA|APKA)[A-Z0-9]{16}(?![A-Za-z0-9])"),
    ("github_pat", "GitHub token",
     r"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{36,255}"),
    ("github_fine_pat", "GitHub fine-grained token",
     r"(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{22,255}"),
    ("slack_token", "Slack token",
     r"(?<![A-Za-z0-9])xox[abposr]-[A-Za-z0-9\-]{10,250}"),
    ("stripe_key", "Stripe key",
     r"(?<![A-Za-z0-9])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,99}"),
    ("google_api_key", "Google API key",
     r"(?<![A-Za-z0-9])AIza[A-Za-z0-9_\-]{35}"),
    ("openai_key", "OpenAI key",
     r"(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_\-]{32,}"),
    ("anthropic_key", "Anthropic key",
     r"(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_\-]{24,}"),
    ("npm_token", "npm token",
     r"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}"),
    ("sendgrid_key", "SendGrid key",
     r"(?<![A-Za-z0-9])SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),
]

# 这几条没有足够独特的前缀，正则引擎在每一行每个位置都要往前扫几十个字符。
# 单独拎出来，靠一个便宜的字面量门槛挡住绝大多数行。
WIDE_SHAPES = [
    # 前面排除 "-"：sha512-xxxx== 这种校验值长度和形状都跟它一样
    ("azure_storage_key", "Azure 存储密钥",
     r"(?<![A-Za-z0-9+/\-])[A-Za-z0-9+/]{86}==", "=="),
    # 用户名可以是空的：redis://:password@host
    ("url_credential", "带密码的 URL",
     r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]{0,64}:[^\s/@]{4,128}@[^\s\"'`]+", "://"),
    ("twilio_key", "Twilio key",
     r"(?<![A-Za-z0-9])SK[0-9a-f]{32}(?![0-9a-f])", "SK"),
]

SHAPE_LABELS = {name: label for name, label, _ in SHAPES + [(n, l, p) for n, l, p, _ in WIDE_SHAPES]}
_SHAPE_RE = re.compile("|".join("(?P<%s>%s)" % (n, p) for n, _, p in SHAPES))
_WIDE_RES = [(n, re.compile(p), gate) for n, _, p, gate in WIDE_SHAPES]

# 便宜的守门员：一行里连这些字面量都没有，就不用跑那 14 条形状正则了。
_HINT_RE = re.compile("|".join(re.escape(h) for h in (
    "AKIA", "ASIA", "ABIA", "ACCA", "AGPA", "AIDA", "AROA", "ANPA", "ANVA", "APKA",
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "xox", "sk-", "sk_",
    "rk_", "AIza", "npm_", "SG.", "eyJ", "-----BEGIN", "discord",
)))


def _jwt_ok(value):
    """JWT 的头必须是 base64url 编码的 JSON，且里面有 alg。光看三段点号不够。"""
    import base64

    head = value.split(".")[0]
    pad = "=" * (-len(head) % 4)
    try:
        raw = base64.urlsafe_b64decode(head + pad)
        obj = json.loads(raw.decode("utf-8"))
    except Exception:
        return False
    return isinstance(obj, dict) and "alg" in obj


def _url_credential_ok(value):
    """URL 里的密码位不能是模板变量，也不能是纯数字端口。"""
    m = re.match(r"[a-zA-Z][a-zA-Z0-9+.\-]*://([^\s:/@]{0,64}):([^\s/@]{4,128})@", value)
    if not m:
        return False
    user, password = m.group(1), m.group(2)
    if not password or password.isdigit():
        return False
    if password.lower() in PLACEHOLDER_WORDS:
        return False
    return not PLACEHOLDER_RE.search(password)


# 只有头没有身子的「私钥」不是私钥：文档、注释、模板里到处都有这个头
_PEM_BODY_RE = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----[\sA-Za-z0-9+/=]{40,}")


def _pem_ok(value):
    return bool(_PEM_BODY_RE.search(value))


SHAPE_VALIDATORS = {
    "jwt": lambda matched, text: _jwt_ok(matched),
    "url_credential": lambda matched, text: _url_credential_ok(matched),
    "private_key": lambda matched, text: _pem_ok(text),
}


# ---------------------------------------------------------------------------
# 纯函数层：全部可以单独测，不碰文件系统
# ---------------------------------------------------------------------------


def entropy(value):
    """香农熵，按 bit/字符。随机密钥一般在 4 以上，英文单词在 2.5 上下。"""
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def tokenize(name):
    """把 apiKey / api_key / API-KEY / apiKey2 都拆成小写词表。"""
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    s = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", s)
    s = re.sub(r"(?<=[A-Za-z])(?=[0-9])", "_", s)
    return [p for p in re.split(r"[^A-Za-z]+", s.lower()) if p]


def name_strength(name):
    """键名有多像是在存一个密钥：strong / weak / none。"""
    words = tokenize(name)
    if not words:
        return "none"
    if any(w in STRONG_WORDS for w in words):
        return "strong"
    for i in range(len(words) - 1):
        if (words[i], words[i + 1]) in STRONG_PAIRS:
            return "strong"
    if len(words) >= 2 and (words[0], words[-1]) in STRONG_PAIRS:
        return "strong"
    if any(w in WEAK_WORDS for w in words):
        return "weak"
    return "none"


def is_password_name(name):
    return any(w in PASSWORD_WORDS for w in tokenize(name))


def is_placeholder(value):
    """这个值是不是「谁都能写出来」的东西：示例、模板、掩码、占位词。"""
    if not value:
        return True
    low = value.lower()
    if low in PLACEHOLDER_WORDS:
        return True
    if len(set(value)) == 1:          # ******、xxxxxx、000000
        return True
    if value.isdigit():               # 纯数字：端口、账号、年份
        return True
    if "EXAMPLE" in value:            # AWS 文档里的 AKIA...EXAMPLE
        return True
    if is_sequential(value):          # qwertyuiop、abcdefgh
        return True
    if PLACEHOLDER_RE.search(value):
        return True
    if " " in value and not _SHAPE_RE.search(value):
        return True                   # 带空格的句子，不是密钥
    return False


def is_reference(value):
    """这个值是「指向别处」而不是「值本身」：环境变量名、函数调用、文件路径。"""
    return any(r.search(value) for r in REFERENCE_RES)


def iter_shape_hits(text):
    """遍历文本里所有形状命中，产出 (形状 id, match)。"""
    if _HINT_RE.search(text):
        for m in _SHAPE_RE.finditer(text):
            kind = m.lastgroup
            if not kind:
                continue
            check = SHAPE_VALIDATORS.get(kind)
            if check and not check(m.group(0), text):
                continue
            yield kind, m
    for kind, rx, gate in _WIDE_RES:
        if gate not in text:
            continue
        for m in rx.finditer(text):
            check = SHAPE_VALIDATORS.get(kind)
            if check and not check(m.group(0), text):
                continue
            yield kind, m


def match_shape(value):
    """返回 (形状 id, 展示名) 或 None。"""
    for kind, _ in iter_shape_hits(value):
        return kind, SHAPE_LABELS[kind]
    return None


def char_classes(value):
    """这个值用了几类字符：小写、大写、数字、符号（连字符下划线点不算符号）。"""
    return sum((
        any(c.islower() for c in value),
        any(c.isupper() for c in value),
        any(c.isdigit() for c in value),
        any(not c.isalnum() and c not in "-_." for c in value),
    ))


def generic_ok(value, ent=None):
    """不是任何厂商格式，但长得像一段随机串。

    熵高不代表是密钥——英文单词的熵也有 3.5 到 4.0。真正把单词和密钥分开的是
    字符类：`unstructured` 只有小写一类，随机密钥至少混两类。
    """
    if len(value) < 8:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=_\-.:]{8,400}", value):
        return False
    if char_classes(value) < 2:
        return False
    if ent is None:
        ent = entropy(value)
    return ent >= 2.0


def clean_value(raw):
    """去掉引号、行尾注释、JSON 逗号、括号——只留值本身。"""
    v = raw.strip()
    if v and v[0] in "\"'`":
        end = v.find(v[0], 1)
        if end > 0:
            return v[1:end].strip()
    v = re.split(r"\s+#", v, maxsplit=1)[0].strip()
    while v and v[-1] in ",;)]}":
        v = v[:-1].strip()
    return v


def mask(value):
    """留头留尾，中间一律星号。长度本身也会泄露信息，所以星号数量固定。"""
    if len(value) <= 8:
        return value[:2] + "*" * 6
    return value[:4] + "*" * 8 + value[-3:]


@dataclass
class Candidate:
    name: str
    value: str
    col: int
    text: str
    line: int = 0
    quoted: bool = True


@dataclass
class Finding:
    path: str
    line: int
    col: int
    name: str
    value: str
    kind: str
    label: str
    score: float
    evidence: list = field(default_factory=list)
    text: str = ""

    @property
    def confidence(self):
        if self.score >= SCORE_HIGH:
            return "high"
        if self.score >= SCORE_MEDIUM:
            return "medium"
        return "low"

    def redacted_text(self):
        """输出里绝不带出完整密钥——报告本身也是会被到处贴的东西。"""
        return self.text.strip().replace(self.value, mask(self.value))

    @property
    def display_path(self):
        """统一用正斜杠，Windows 上贴进 issue 也不难看。"""
        return self.path.replace("\\", "/")

    def to_dict(self):
        return {
            "path": self.display_path,
            "line": self.line,
            "column": self.col,
            "name": self.name,
            "kind": self.kind,
            "label": self.label,
            "confidence": self.confidence,
            "score": round(self.score, 2),
            "masked": mask(self.value),
            "length": len(self.value),
            "entropy": round(entropy(self.value), 2),
            "evidence": [{"signal": s, "weight": round(w, 2)} for s, w in self.evidence],
            "line_text": self.redacted_text()[:400],
        }


def judge(cand, path=""):
    """一个候选值要不要报。返回 Finding 或 (None, 压掉的原因)。"""
    value = clean_value(cand.value)
    if len(value) < 6:
        return None, ""
    if is_placeholder(value):
        return None, "placeholder"
    # 名字本身出现在值里两次：pwd#module-pwd 这种自引用，不是密钥
    for token in tokenize(cand.name):
        if len(token) >= 3 and value.lower().count(token) >= 2:
            return None, "placeholder"

    shape = match_shape(value)
    if shape is None:
        if is_reference(value):
            return None, "reference"
        ext = os.path.splitext(path)[1].lower()
        if not cand.quoted and ext in CODE_EXTS and IDENT_RE.match(value):
            return None, "reference"   # 代码里的裸标识符是变量名，不是字面量
        if (not is_password_name(cand.name) and len(value) <= 30
                and not any(c.isdigit() for c in value) and WORDLIKE_RE.match(value)):
            return None, "wordlike"    # 一个普通英文单词

    evidence = []
    score = 0.0

    if shape:
        kind, label = shape
        evidence.append(("shape:" + kind, W_SHAPE))
        score += W_SHAPE
    else:
        kind, label = "generic", "疑似密钥"
        strength = name_strength(cand.name)
        if strength == "strong":
            evidence.append(("name:" + cand.name.strip("\"'")[:40], W_NAME_STRONG))
            score += W_NAME_STRONG
        elif strength == "weak":
            evidence.append(("name:" + cand.name.strip("\"'")[:40], W_NAME_WEAK))
            score += W_NAME_WEAK

    ent = entropy(value)
    if ent >= 3.0:
        evidence.append(("entropy>=3.0", W_ENT_HIGH))
        score += W_ENT_HIGH
    elif ent >= 2.0:
        evidence.append(("entropy>=2.0", W_ENT_MID))
        score += W_ENT_MID

    if len(value) >= 16:
        evidence.append(("len>=16", W_LEN_LONG))
        score += W_LEN_LONG
    elif len(value) >= 8:
        evidence.append(("len>=8", W_LEN_MID))
        score += W_LEN_MID

    if not shape and is_password_name(cand.name):
        # 人挑的密码普遍很短、熵很低，靠名字撑起来
        evidence.append(("password-name", W_PASSWORD_NAME))
        score += W_PASSWORD_NAME

    if not shape:
        # 没有形状支撑时，要求至少还有名字这条证据，否则只是「一段乱码」
        strength = name_strength(cand.name)
        if HEX_RE.match(value) and len(value) >= 32 and strength != "strong":
            return None, "hash"
        if strength == "none":
            return None, "no-context"
        # 人挑的密码不遵循「随机串」的字符分布，别拿这条卡它
        if not is_password_name(cand.name) and not generic_ok(value, ent):
            return None, "not-random"

    score = min(score, 1.0)
    return Finding(
        path="", line=cand.line, col=cand.col, name=cand.name.strip("\"'"),
        value=value, kind=kind, label=label, score=score,
        evidence=evidence, text=cand.text,
    ), ""


# ---------------------------------------------------------------------------
# 抽取：一行里可能同时有名字和值，也可能只有值
# ---------------------------------------------------------------------------

# KEY=value / key: value / export KEY=value / - key: value
_ASSIGN_RE = re.compile(
    r"""^\s*(?:-\s+)?(?:export\s+|set\s+)?
        (?P<name>[A-Za-z_][\w.\-]{0,63})
        \s*(?P<sep>:=|=>|=|:)\s*
        (?P<value>.+?)\s*$""",
    re.X,
)

# "key": "value" / key='value' / password="value"
_PAIR_RE = re.compile(
    r"""(?P<name>"[^"\n]{1,64}"|'[^'\n]{1,64}'|[A-Za-z_][\w.\-]{0,63})
        \s*(?::=|=>|=|:)\s*
        (?P<quote>["'`])(?P<value>[^"'\n]{6,400})(?P=quote)""",
    re.X,
)

# <apiKey>value</apiKey>
_XML_RE = re.compile(r"<(?P<name>[A-Za-z_][\w.\-]{0,63})>(?P<value>[^<>\n]{6,400})</(?P=name)>")

# 元组形式的凭据：AUTH = ("svc", "password")、auth=("user", "pass")
_TUPLE_RE = re.compile(
    r"""\(\s*(?:"[^"\n]{0,64}"|'[^'\n]{0,64}'|[^,()\n]{0,64})\s*,\s*
        (?P<quote>["'])(?P<value>[^"'\n]{6,400})(?P=quote)\s*\)""",
    re.X,
)

# 名字写在上一行的情况：Terraform 的 variable "db_password"、k8s 的 name:
_CTX_RE = re.compile(r"""(?x)
      ^\s*variable\s+"(?P<var>[A-Za-z_][\w\-]{0,63})"
    | ^\s*(?:name|secretName|secret_name)\s*:\s*"?(?P<k8s>[A-Za-z_][\w.\-]{0,63})"?
    """)

# 这些键名本身不说明任何事，得往上找它属于谁
SLOT_NAMES = {"default", "value", "val", "data", "stringdata", "string_data"}

# 私钥块跨行，单独处理
_PEM_RE = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")

# 一行里没有这些字符，就不可能是赋值/键值对
_TRIGGER = re.compile(r"[=:\"'<]")


def extract(line):
    """从一行里抽出所有 (名字, 值) 候选。"""
    cands = []
    spans = []
    has_quote = '"' in line or "'" in line or "`" in line

    if has_quote:
        for m in _PAIR_RE.finditer(line):
            cands.append(Candidate(m.group("name"), m.group("value"), m.start("value"), line))
            spans.append((m.start("value"), m.end("value")))

    if "<" in line and ">" in line:
        for m in _XML_RE.finditer(line):
            cands.append(Candidate(m.group("name"), m.group("value"), m.start("value"), line))
            spans.append((m.start("value"), m.end("value")))

    if has_quote and "(" in line:
        for m in _TUPLE_RE.finditer(line):
            before = line[:m.start()]
            named = re.search(r"([A-Za-z_][\w.\-]*)\s*=\s*$", before)
            cands.append(Candidate(named.group(1) if named else "", m.group("value"),
                                   m.start("value"), line))
            spans.append((m.start("value"), m.end("value")))

    if "=" in line or ":" in line:
        m = _ASSIGN_RE.match(line)
        if m:
            start, end = m.start("value"), m.end("value")
            if not any(s < end and start < e for s, e in spans):
                cands.append(Candidate(m.group("name"), m.group("value"), start, line,
                                       quoted=False))

    # 没有名字但形状对得上的（Authorization: Bearer xxx、curl 里的 URL、裸贴的 token）
    named_values = [c.value for c in cands]
    for kind, sm in iter_shape_hits(line):
        hit = sm.group(0)
        if any(hit in v for v in named_values):
            continue
        cands.append(Candidate("", hit, sm.start(), line))

    return cands


def scan_text(text, path, min_score=SCORE_MEDIUM):
    """扫一段文本，返回 (findings, dismissed)。"""
    findings = []
    dismissed = []
    lines = text.splitlines()
    ctx_name = ""
    ctx_line = -99

    for m in _PEM_RE.finditer(text):
        start = m.start()
        if not _PEM_BODY_RE.search(text[start:start + 4000]):
            continue
        line_no = text.count("\n", 0, start) + 1
        line_start = text.rfind("\n", 0, start) + 1
        body_end = text.find("-----END", m.end())
        score = 0.55 + 0.10 + 0.25
        if body_end > 0:
            score += 0.05
        findings.append(
            Finding(
                path=path, line=line_no, col=start - line_start, name="",
                value="-----BEGIN PRIVATE KEY-----", kind="private_key",
                label=SHAPE_LABELS["private_key"], score=min(score, 1.0),
                evidence=[("shape:private_key", W_SHAPE), ("len>=16", W_LEN_LONG),
                          ("entropy>=3.0", W_ENT_HIGH)],
                text=lines[line_no - 1] if line_no - 1 < len(lines) else "",
            )
        )

    for i, line in enumerate(lines):
        cm = _CTX_RE.search(line)
        if cm:
            ctx_name = cm.group("var") or cm.group("k8s") or ""
            ctx_line = i
        if len(line) < 6:
            continue
        if not _TRIGGER.search(line):
            continue
        allowed = ALLOW_MARK in line or (i > 0 and ALLOW_MARK in lines[i - 1])
        for cand in extract(line):
            cand.line = i + 1
            # 名字写在上一行：default = "..." 属于 variable "db_password"
            if ctx_name and i - ctx_line <= 6 and cand.name.strip("\"'").lower() in SLOT_NAMES:
                cand = Candidate("%s (in %s)" % (cand.name.strip("\"'"), ctx_name),
                                 cand.value, cand.col, cand.text)
            finding, reason = judge(cand, path)
            if finding is None:
                if reason:
                    dismissed.append((path, i + 1, clean_value(cand.value), reason))
                continue
            finding.path = path
            if allowed:
                dismissed.append((path, i + 1, finding.value, "inline-allow"))
                continue
            if finding.score < min_score:
                dismissed.append((path, i + 1, finding.value, "weak"))
                continue
            findings.append(finding)

    return _dedupe(findings), dismissed


def _dedupe(findings):
    """同一行同一个值只留分数最高的那条（名字比裸值更有信息量）。"""
    best = {}
    for f in findings:
        key = (f.path, f.line, f.value)
        old = best.get(key)
        if old is None or f.score > old.score:
            best[key] = f
    return sorted(best.values(), key=lambda f: (f.path, f.line, f.col))


# ---------------------------------------------------------------------------
# 文件遍历
# ---------------------------------------------------------------------------


def git_files(root):
    """有 git 就直接问它要文件列表——.gitignore 不用自己实现。"""
    try:
        proc = subprocess.run(
            ["git", "-C", root, "ls-files", "-z", "-co", "--exclude-standard"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    names = proc.stdout.decode("utf-8", "replace").split("\0")
    return [os.path.join(root, n) for n in names if n]


def walk_files(root, max_bytes):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".git"))
        for name in sorted(filenames):
            if os.path.splitext(name)[1].lower() in SKIP_EXTS:
                continue
            full = os.path.join(dirpath, name)
            try:
                if os.path.getsize(full) > max_bytes:
                    continue
            except OSError:
                continue
            yield full


def read_text(path, max_bytes):
    try:
        if os.path.getsize(path) > max_bytes:
            return None
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", "replace")


def collect_files(paths, use_git, max_bytes):
    for p in paths:
        if os.path.isfile(p):
            yield p
        elif os.path.isdir(p):
            listed = git_files(p) if use_git else None
            if listed is None:
                for f in walk_files(p, max_bytes):
                    yield f
            else:
                for f in listed:
                    if os.path.isfile(f) and os.path.getsize(f) <= max_bytes:
                        if os.path.splitext(f)[1].lower() not in SKIP_EXTS:
                            yield f


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------


def _human_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0
    return "%.1f GB" % n


def render_text(findings, dismissed, stats, paranoid):
    out = []
    if findings:
        current = None
        for f in findings:
            if f.display_path != current:
                if current is not None:
                    out.append("")
                current = f.display_path
                out.append(current)
            out.append("  %d:%-3d  %-6s %.2f  %s" % (f.line, f.col + 1, f.confidence, f.score, f.label))
            out.append("         %s" % mask(f.value))
            why = " · ".join("%s +%.2f" % (s, w) for s, w in f.evidence)
            out.append("         why  %s" % why)
            text = f.redacted_text()
            if len(text) > 110:
                text = text[:107] + "..."
            out.append("         >    %s" % text)
        out.append("")

    if paranoid and dismissed:
        out.append("dismissed  %d 条（证据不足，--paranoid 才列出）" % len(dismissed))
        for path, line, value, reason in dismissed[:200]:
            out.append("  %-40s %5d  %-14s %s" % (path[-40:], line, reason, mask(value)))
        out.append("")

    if findings:
        counts = {}
        for f in findings:
            counts[f.confidence] = counts.get(f.confidence, 0) + 1
        parts = ["%d %s" % (counts[k], k) for k in ("high", "medium", "low") if k in counts]
        head = "%d leaks · %s" % (len(findings), " ".join(parts))
    else:
        head = "no leaks found"

    tail = "%d files · %s · %.2f s" % (stats["files"], _human_bytes(stats["bytes"]), stats["seconds"])
    if dismissed and not paranoid:
        by_reason = {}
        for _, _, _, reason in dismissed:
            by_reason[reason] = by_reason.get(reason, 0) + 1
        tail += " · %d 条候选被判为不是密钥" % len(dismissed)
        tail += "（%s）" % "、".join("%s %d" % (k, v) for k, v in sorted(by_reason.items()))

    out.append("%s  ·  %s" % (head, tail))
    return "\n".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="leakcheck",
        description="按形状、键名、上下文找硬编码密钥。零配置。",
    )
    parser.add_argument("paths", nargs="*", help="要扫描的文件或目录（默认当前目录）")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--paranoid", action="store_true", help="连低置信和「被判不是」的也列出来")
    parser.add_argument("--max-size", type=float, default=2.0, metavar="MB", help="跳过大于这个体积的文件")
    parser.add_argument("--walk", action="store_true", help="不借用 git 的文件列表，直接遍历目录")
    parser.add_argument("--quiet", action="store_true", help="只输出结果，不输出统计")
    parser.add_argument("--version", action="version", version="leakcheck " + __version__)
    args = parser.parse_args(argv)

    paths = args.paths or ["."]
    max_bytes = int(args.max_size * 1024 * 1024)
    started = time.time()

    findings = []
    dismissed = []
    files = 0
    total_bytes = 0
    min_score = SCORE_LOW if args.paranoid else SCORE_MEDIUM

    for path in collect_files(paths, not args.walk, max_bytes):
        text = read_text(path, max_bytes)
        if text is None:
            continue
        files += 1
        total_bytes += len(text)
        found, skipped = scan_text(text, path, min_score)
        findings.extend(found)
        dismissed.extend(skipped)

    findings.sort(key=lambda f: (f.path, f.line, f.col))
    stats = {"files": files, "bytes": total_bytes, "seconds": time.time() - started}

    if args.json:
        payload = {
            "version": __version__,
            "findings": [f.to_dict() for f in findings],
            "dismissed": (
                [{"path": p, "line": l, "masked": mask(v), "reason": r} for p, l, v, r in dismissed]
                if args.paranoid else []
            ),
            "stats": {"files": files, "bytes": total_bytes,
                      "seconds": round(stats["seconds"], 3)},
        }
        sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    elif args.quiet:
        for f in findings:
            sys.stdout.write("%s:%d:%d %s %s\n" % (f.path, f.line, f.col + 1, f.confidence, mask(f.value)))
    else:
        sys.stdout.write(render_text(findings, dismissed, stats, args.paranoid) + "\n")

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
