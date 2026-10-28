#!/usr/bin/env python3
"""生成 examples/demo/ —— 一个「到处是密钥」的小项目，用来看输出长什么样。

里面的密钥都是运行时拼出来的假货，仓库里不存任何形似真密钥的字面量。
跑完可以直接删掉 examples/demo/，它是被 .gitignore 忽略的。
"""

import os

HERE = os.path.dirname(os.path.abspath(__file__))
DEMO = os.path.join(HERE, "demo")

ALNUM = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def tok(n, alphabet=ALNUM, step=7):
    return "".join(alphabet[(i * step + 3) % len(alphabet)] for i in range(n))


FILES = {
    ".env": (
        "AWS_REGION=eu-west-1\n"
        "AWS_ACCESS_KEY_ID=AKIA" + tok(16, B32) + "\n"
        "AWS_SECRET_ACCESS_KEY=" + tok(40, ALNUM + "/+") + "\n"
        "DB_PASSWORD=" + tok(18) + "\n"
    ),
    "config.yaml": (
        "spring:\n"
        "  datasource:\n"
        "    url: jdbc:postgresql://db:5432/app\n"
        "    password: " + tok(16, ALNUM, 5) + "\n"
    ),
    "settings.properties": "db.user=app\ndb.password=" + tok(14, ALNUM, 11) + "\n",
    "deploy.xml": (
        "<config>\n"
        "  <endpoint>https://api.internal/v1</endpoint>\n"
        "  <apiKey>" + tok(28, ALNUM, 9) + "</apiKey>\n"
        "</config>\n"
    ),
    # 下面两个文件不该报：一个是文档里的示例密钥，一个是占位符
    "docs.md": (
        "Set the credentials in your environment:\n\n"
        "    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n\n"
        "The key above is the one printed in the AWS documentation.\n"
    ),
    "template.env": "DB_PASSWORD=changeme\nAPI_TOKEN=${API_TOKEN}\n",
}


def main():
    os.makedirs(DEMO, exist_ok=True)
    for name, body in FILES.items():
        with open(os.path.join(DEMO, name), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(body)
    print("wrote %d files to %s" % (len(FILES), DEMO))
    print("now run:  python leakcheck.py examples/demo")


if __name__ == "__main__":
    main()
