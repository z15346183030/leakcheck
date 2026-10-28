#!/usr/bin/env python3
"""leakcheck 的测试。

密钥样本全部在运行时拼出来，仓库里不存任何形似真密钥的字面量——
否则把仓库推上去的时候，托管方的推送保护会先一步把它拦下来。
"""

import base64
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import leakcheck as L  # noqa: E402

ALNUM = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def tok(n, alphabet=ALNUM):
    """确定性的伪随机串，熵足够高。"""
    return "".join(alphabet[(i * 7 + 3) % len(alphabet)] for i in range(n))


def b64(nbytes):
    return base64.b64encode(bytes((i * 37 + 11) % 256 for i in range(nbytes))).decode()


AWS = "AKIA" + tok(16, B32)
GH = "ghp_" + tok(36)


class EntropyTest(unittest.TestCase):
    def test_empty_is_zero(self):
        self.assertEqual(L.entropy(""), 0.0)

    def test_single_repeated_char_is_zero(self):
        self.assertEqual(L.entropy("aaaaaa"), 0.0)

    def test_two_equal_halves_is_one_bit(self):
        self.assertAlmostEqual(L.entropy("aaaabbbb"), 1.0, places=6)

    def test_all_distinct_is_log2_of_length(self):
        self.assertAlmostEqual(L.entropy("abcd"), 2.0, places=6)

    def test_random_string_beats_english_word(self):
        self.assertGreater(L.entropy(tok(20)), L.entropy("unstructured"))


class TokenizeTest(unittest.TestCase):
    def test_camel_case(self):
        self.assertEqual(L.tokenize("apiKey"), ["api", "key"])

    def test_upper_snake(self):
        self.assertEqual(L.tokenize("API_KEY"), ["api", "key"])

    def test_dotted(self):
        self.assertEqual(L.tokenize("db.password"), ["db", "password"])

    def test_digits_split_off(self):
        self.assertEqual(L.tokenize("apiKey2"), ["api", "key"])

    def test_empty(self):
        self.assertEqual(L.tokenize(""), [])


class NameStrengthTest(unittest.TestCase):
    def test_password_is_strong(self):
        self.assertEqual(L.name_strength("DB_PASSWORD"), "strong")

    def test_pair_api_key_is_strong(self):
        self.assertEqual(L.name_strength("apiKey"), "strong")

    def test_pair_client_secret_is_strong(self):
        self.assertEqual(L.name_strength("clientSecret"), "strong")

    def test_tokenizer_is_not_token(self):
        # 整词匹配：TOKENIZER 里的 token 不算证据
        self.assertEqual(L.name_strength("TOKENIZER_PATH"), "none")

    def test_bare_key_is_weak(self):
        self.assertEqual(L.name_strength("sort_key"), "weak")

    def test_unrelated_name(self):
        self.assertEqual(L.name_strength("timeout"), "none")

    def test_password_name(self):
        self.assertTrue(L.is_password_name("db_passwd"))
        self.assertFalse(L.is_password_name("api_token"))


class PlaceholderTest(unittest.TestCase):
    def test_known_words(self):
        for value in ("changeme", "placeholder", "your-key-here", "null", "test"):
            self.assertTrue(L.is_placeholder(value), value)

    def test_template_syntax(self):
        for value in ("${DB_PASSWORD}", "{{ .Values.token }}", "%(password)s", "<your-token>"):
            self.assertTrue(L.is_placeholder(value), value)

    def test_masked_and_repeated(self):
        self.assertTrue(L.is_placeholder("********"))
        self.assertTrue(L.is_placeholder("xxxxxxxx"))
        self.assertTrue(L.is_placeholder("000000"))

    def test_all_digits(self):
        self.assertTrue(L.is_placeholder("8675309"))

    def test_aws_documented_sample(self):
        # AWS 文档里那个 AKIA...EXAMPLE，每个 Go 项目 vendor 一份 SDK 都会带进来
        self.assertTrue(L.is_placeholder("AKIAIOSFODNN7EXAMPLE"))

    def test_keyboard_mash(self):
        self.assertTrue(L.is_placeholder("qwertyuiop"))
        self.assertTrue(L.is_placeholder("abcdefgh"))

    def test_prose_is_placeholder(self):
        self.assertTrue(L.is_placeholder("rotate this token every ninety days"))

    def test_real_looking_value_is_not(self):
        self.assertFalse(L.is_placeholder(tok(20)))
        self.assertFalse(L.is_placeholder("hunter2"))


class SequentialTest(unittest.TestCase):
    def test_rows(self):
        for value in ("qwertyuiop", "asdfgh", "zxcvbnm", "abcdef", "987654"):
            self.assertTrue(L.is_sequential(value), value)

    def test_reverse_rows(self):
        self.assertTrue(L.is_sequential("poiuytrewq"))

    def test_random_is_not_sequential(self):
        self.assertFalse(L.is_sequential("aB3xY9qLmN2p"))

    def test_short_is_not(self):
        self.assertFalse(L.is_sequential("abc"))


class ReferenceTest(unittest.TestCase):
    def test_env_var_name(self):
        self.assertTrue(L.is_reference("DB_PASSWORD"))

    def test_dotted_path(self):
        self.assertTrue(L.is_reference("config.settings.SECRET_KEY"))

    def test_function_call(self):
        self.assertTrue(L.is_reference("load_secret()"))
        self.assertTrue(L.is_reference("os.getenv"))

    def test_file_path(self):
        self.assertTrue(L.is_reference("/etc/ssl/private/server.key"))
        self.assertTrue(L.is_reference("./certs/ca.pem"))
        self.assertTrue(L.is_reference("C:\\keys\\id_rsa"))

    def test_plain_value_is_not_reference(self):
        self.assertFalse(L.is_reference(tok(20)))


class CharClassTest(unittest.TestCase):
    def test_single_class(self):
        self.assertEqual(L.char_classes("unstructured"), 1)
        self.assertEqual(L.char_classes("dot-atom-text"), 1)

    def test_two_classes(self):
        self.assertEqual(L.char_classes("aB3xY9"), 3)

    def test_symbol_counts(self):
        self.assertEqual(L.char_classes("ab!cd"), 2)


class ShapeTest(unittest.TestCase):
    def test_aws(self):
        self.assertEqual(L.match_shape(AWS)[0], "aws_access_key")

    def test_github(self):
        self.assertEqual(L.match_shape(GH)[0], "github_pat")

    def test_github_fine_grained(self):
        value = "github_pat_" + tok(22) + "_" + tok(59)
        self.assertEqual(L.match_shape(value)[0], "github_fine_pat")

    def test_slack(self):
        value = "xoxb-" + tok(12, "0123456789") + "-" + tok(13, "0123456789") + "-" + tok(24)
        self.assertEqual(L.match_shape(value)[0], "slack_token")

    def test_stripe(self):
        self.assertEqual(L.match_shape("sk_live_" + tok(24))[0], "stripe_key")

    def test_google(self):
        self.assertEqual(L.match_shape("AIza" + tok(35))[0], "google_api_key")

    def test_openai(self):
        self.assertEqual(L.match_shape("sk-" + tok(48))[0], "openai_key")

    def test_npm(self):
        self.assertEqual(L.match_shape("npm_" + tok(36))[0], "npm_token")

    def test_sendgrid(self):
        value = "SG." + tok(22) + "." + tok(43)
        self.assertEqual(L.match_shape(value)[0], "sendgrid_key")

    def test_twilio(self):
        value = "SK" + "".join("%x" % (i % 16) for i in range(32))
        self.assertEqual(L.match_shape(value)[0], "twilio_key")

    def test_azure_storage_key(self):
        # 64 字节的 base64 正好 88 个字符，以 == 结尾，和 Azure 的密钥一模一样
        value = b64(64)
        self.assertEqual(len(value), 88)
        self.assertTrue(value.endswith("=="))
        self.assertEqual(L.match_shape(value)[0], "azure_storage_key")

    def test_sha512_integrity_is_not_azure_key(self):
        # 长度和结尾都一样，只有前缀不同
        self.assertIsNone(L.match_shape("sha512-" + b64(64)))

    def test_url_with_password(self):
        value = "postgres://app:" + tok(16) + "@db.internal:5432/app"
        self.assertEqual(L.match_shape(value)[0], "url_credential")

    def test_url_with_empty_user(self):
        value = "redis://:" + tok(20) + "@cache.internal:6379/0"
        self.assertEqual(L.match_shape(value)[0], "url_credential")

    def test_url_without_password(self):
        self.assertIsNone(L.match_shape("https://api.internal/v1/items"))

    def test_url_with_placeholder_password(self):
        self.assertIsNone(L.match_shape("redis://:password@localhost:6379/0"))

    def test_jwt_valid(self):
        header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
        body = base64.urlsafe_b64encode(b'{"sub":"1"}').decode().rstrip("=")
        self.assertEqual(L.match_shape(header + "." + body + "." + tok(32))[0], "jwt")

    def test_jwt_with_bad_header_is_not_jwt(self):
        # 三段点号、都以 eyJ 开头，但头部解出来不是 JSON
        value = "eyJ" + "x" * 20 + ".eyJ" + "y" * 20 + "." + tok(32)
        self.assertIsNone(L.match_shape(value))

    def test_pem_with_body(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\n" + b64(48) + "\n-----END RSA PRIVATE KEY-----"
        self.assertEqual(L.match_shape(text)[0], "private_key")

    def test_pem_header_alone_is_not_a_key(self):
        self.assertIsNone(L.match_shape("-----BEGIN PRIVATE KEY-----"))

    def test_plain_text_has_no_shape(self):
        self.assertIsNone(L.match_shape("just some words here"))


class CleanValueTest(unittest.TestCase):
    def test_double_quotes(self):
        self.assertEqual(L.clean_value('"abc123"'), "abc123")

    def test_single_quotes_with_paren(self):
        self.assertEqual(L.clean_value("'geheim$parole')"), "geheim$parole")

    def test_trailing_comma(self):
        self.assertEqual(L.clean_value('"abc123",'), "abc123")

    def test_inline_comment(self):
        self.assertEqual(L.clean_value("abc123  # the token"), "abc123")

    def test_unquoted(self):
        self.assertEqual(L.clean_value("  abc123  "), "abc123")

    def test_empty(self):
        self.assertEqual(L.clean_value("   "), "")

    def test_quoted_value_keeps_inner_paren(self):
        self.assertEqual(L.clean_value('"abc)"'), "abc)")


class MaskTest(unittest.TestCase):
    def test_short(self):
        self.assertEqual(L.mask("abcdef"), "ab******")

    def test_long_keeps_head_and_tail(self):
        masked = L.mask(tok(20))
        self.assertTrue(masked.startswith(tok(20)[:4]))
        self.assertTrue(masked.endswith(tok(20)[-3:]))
        self.assertIn("*", masked)

    def test_length_is_not_leaked(self):
        self.assertEqual(len(L.mask(tok(12))), len(L.mask(tok(40))))


class ExtractTest(unittest.TestCase):
    def test_env_assignment(self):
        cands = L.extract("AWS_ACCESS_KEY_ID=" + AWS)
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0].name, "AWS_ACCESS_KEY_ID")
        self.assertEqual(cands[0].value, AWS)

    def test_yaml_quoted(self):
        cands = L.extract('  password: "abc123def"')
        self.assertEqual(cands[0].name, "password")

    def test_json_two_pairs_on_one_line(self):
        line = '{"client_id": "svc-1234", "client_secret": "%s"}' % tok(32)
        names = [c.name.strip('"') for c in L.extract(line)]
        self.assertIn("client_secret", names)
        self.assertEqual(len(names), 2)

    def test_xml_element(self):
        cands = L.extract("<apiKey>%s</apiKey>" % tok(28))
        self.assertEqual(cands[0].name, "apiKey")
        self.assertEqual(cands[0].value, tok(28))

    def test_tuple_credential(self):
        cands = L.extract('AUTH = ("svc", "%s")' % tok(19))
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0].name, "AUTH")
        self.assertEqual(cands[0].value, tok(19))

    def test_bare_token_without_name(self):
        cands = L.extract('curl -H "Authorization: Bearer %s"' % GH)
        self.assertTrue(any(c.value == GH for c in cands))

    def test_column_points_at_value(self):
        line = "KEY=" + AWS
        cands = L.extract(line)
        self.assertEqual(cands[0].col, line.index(AWS))


class JudgeTest(unittest.TestCase):
    def test_shape_is_high_confidence(self):
        finding, _ = L.judge(L.Candidate("", AWS, 0, "x=" + AWS))
        self.assertEqual(finding.confidence, "high")
        self.assertGreaterEqual(finding.score, L.SCORE_HIGH)

    def test_name_and_randomness_is_medium_or_better(self):
        value = tok(20)
        finding, _ = L.judge(L.Candidate("APP_SIGNING_SECRET", value, 0, ""))
        self.assertIn(finding.confidence, ("high", "medium"))

    def test_short_password_uses_name_evidence(self):
        finding, _ = L.judge(L.Candidate("DB_PASSWORD", "hunter2", 0, ""))
        self.assertIsNotNone(finding)
        self.assertGreaterEqual(finding.score, L.SCORE_MEDIUM)

    def test_placeholder_is_dismissed(self):
        finding, reason = L.judge(L.Candidate("DB_PASSWORD", "changeme", 0, ""))
        self.assertIsNone(finding)
        self.assertEqual(reason, "placeholder")

    def test_name_repeated_in_value_is_placeholder(self):
        finding, reason = L.judge(L.Candidate("pwd", "pwd#module-pwd", 0, ""))
        self.assertIsNone(finding)
        self.assertEqual(reason, "placeholder")

    def test_english_word_is_dismissed(self):
        finding, reason = L.judge(L.Candidate("auth_header", "Authorization", 0, ""))
        self.assertIsNone(finding)
        self.assertEqual(reason, "wordlike")

    def test_hex_without_strong_name_is_hash(self):
        value = "".join("%x" % (i % 16) for i in range(40))
        finding, reason = L.judge(L.Candidate("revision", value, 0, ""))
        self.assertIsNone(finding)
        self.assertEqual(reason, "hash")

    def test_hex_with_strong_name_is_reported(self):
        value = "".join("%x" % (i % 16) for i in range(64))
        finding, _ = L.judge(L.Candidate("secret_key_base", value, 0, ""))
        self.assertIsNotNone(finding)

    def test_no_name_no_shape_is_dismissed(self):
        finding, reason = L.judge(L.Candidate("", tok(32), 0, ""))
        self.assertIsNone(finding)
        self.assertEqual(reason, "no-context")

    def test_bare_identifier_in_code_is_reference(self):
        finding, reason = L.judge(L.Candidate("passwd", "password_mgr", 0, "", quoted=False), "a.py")
        self.assertIsNone(finding)
        self.assertEqual(reason, "reference")

    def test_bare_identifier_in_config_is_a_value(self):
        finding, _ = L.judge(L.Candidate("DB_PASSWORD", "hunter2", 0, "", quoted=False), "a.env")
        self.assertIsNotNone(finding)

    def test_env_var_reference(self):
        finding, reason = L.judge(L.Candidate("password", "${DB_PASSWORD}", 0, ""))
        self.assertIsNone(finding)
        self.assertEqual(reason, "placeholder")


class ScanTextTest(unittest.TestCase):
    def test_reports_line_and_column(self):
        text = "host=db\npassword=" + tok(16) + "\n"
        findings, _ = L.scan_text(text, "x.env")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 2)
        self.assertEqual(findings[0].col, len("password="))

    def test_dedupes_bare_and_named_hit(self):
        findings, _ = L.scan_text("AWS_KEY=" + AWS + "\n", "x.env")
        self.assertEqual(len(findings), 1)

    def test_inline_allow_same_line(self):
        text = "password=" + tok(16) + "  # leakcheck:allow\n"
        findings, dismissed = L.scan_text(text, "x.env")
        self.assertEqual(findings, [])
        self.assertEqual(dismissed[0][3], "inline-allow")

    def test_inline_allow_on_previous_line(self):
        text = "# leakcheck:allow\npassword=" + tok(16) + "\n"
        findings, _ = L.scan_text(text, "x.env")
        self.assertEqual(findings, [])

    def test_pem_block(self):
        text = "key:\n  " + "-----BEGIN RSA PRIVATE KEY-----\n  " + b64(48) + "\n  -----END RSA PRIVATE KEY-----\n"
        findings, _ = L.scan_text(text, "x.yaml")
        self.assertTrue(any(f.kind == "private_key" for f in findings))

    def test_context_name_from_terraform_variable(self):
        text = 'variable "db_password" {\n  default = "%s"\n}\n' % tok(18)
        findings, _ = L.scan_text(text, "main.tf")
        self.assertEqual(len(findings), 1)
        self.assertIn("db_password", findings[0].name)

    def test_clean_file_has_no_findings(self):
        text = "port=8080\nhost=db.internal\ndebug=false\n"
        findings, _ = L.scan_text(text, "x.env")
        self.assertEqual(findings, [])

    def test_low_score_filtered_by_default(self):
        text = "sort_key = \"created_at\"\n"
        findings, _ = L.scan_text(text, "x.py")
        self.assertEqual(findings, [])
        findings_paranoid, _ = L.scan_text(text, "x.py", L.SCORE_LOW)
        self.assertEqual(findings_paranoid, [])


class CliTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def _write(self, name, body):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        return path

    def _run(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = L.main(list(args))
        return code, out.getvalue()

    def test_exit_code_zero_on_clean_tree(self):
        self._write("a.env", "port=8080\n")
        code, out = self._run(self.dir, "--walk")
        self.assertEqual(code, 0)
        self.assertIn("no leaks found", out)

    def test_exit_code_one_on_finding(self):
        self._write("a.env", "DB_PASSWORD=" + tok(16) + "\n")
        code, out = self._run(self.dir, "--walk")
        self.assertEqual(code, 1)
        self.assertIn("1 leaks", out)

    def test_json_output(self):
        self._write("a.env", "DB_PASSWORD=" + tok(16) + "\n")
        code, out = self._run(self.dir, "--walk", "--json")
        payload = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(len(payload["findings"]), 1)
        self.assertEqual(payload["findings"][0]["name"], "DB_PASSWORD")
        self.assertIn("masked", payload["findings"][0])
        self.assertNotIn(tok(16), out)

    def test_quiet_output_is_one_line_per_finding(self):
        self._write("a.env", "DB_PASSWORD=" + tok(16) + "\n")
        code, out = self._run(self.dir, "--walk", "--quiet")
        self.assertEqual(len(out.strip().splitlines()), 1)

    def test_skips_binary_file(self):
        path = os.path.join(self.dir, "blob.bin")
        with open(path, "wb") as fh:
            fh.write(b"\x00\x01\x02password=" + tok(16).encode())
        code, out = self._run(self.dir, "--walk")
        self.assertEqual(code, 0)

    def test_skips_large_file(self):
        self._write("big.env", "DB_PASSWORD=" + tok(16) + "\n" + "x" * 5000)
        code, _ = self._run(self.dir, "--walk", "--max-size", "0.001")
        self.assertEqual(code, 0)

    def test_paranoid_lists_dismissed(self):
        self._write("a.env", "DB_PASSWORD=changeme\n")
        code, out = self._run(self.dir, "--walk", "--paranoid")
        self.assertEqual(code, 0)
        self.assertIn("dismissed", out)
        self.assertIn("placeholder", out)

    def test_single_file_path(self):
        path = self._write("a.env", "DB_PASSWORD=" + tok(16) + "\n")
        code, out = self._run(path)
        self.assertEqual(code, 1)

    def test_stats_line_reports_file_count(self):
        self._write("a.env", "port=8080\n")
        self._write("b.env", "host=db\n")
        _, out = self._run(self.dir, "--walk")
        self.assertIn("2 files", out)


if __name__ == "__main__":
    unittest.main()
