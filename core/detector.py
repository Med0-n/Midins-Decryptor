import re
import base64
import binascii
import codecs
import gzip
import zlib
import math
import time
import logging
import urllib.parse
import html
from typing import Dict, List, Optional, Tuple, Callable
from collections import Counter

logger = logging.getLogger("midins.detector")

MAX_PAYLOAD_BYTES = 2_500_000
MAX_RECURSION_DEPTH = 5
SNIPPET_PREVIEW = 220

_RX_BASE64 = re.compile(r"^[A-Za-z0-9+/=\s]+$")
_RX_BASE64_STRICT = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_RX_HEX = re.compile(r"^[0-9A-Fa-f\s]+$")
_RX_URL_ENC = re.compile(r"%[0-9A-Fa-f]{2}")
_RX_HTML_ENT = re.compile(r"&(?:#\d+|#x[0-9A-Fa-f]+|[a-zA-Z]{2,8});")
_RX_UNICODE_ESC = re.compile(r"\\u[0-9A-Fa-f]{4}")
_RX_HEX_ESC = re.compile(r"\\x[0-9A-Fa-f]{2}")
_RX_ROT_HINT = re.compile(r"^[A-Za-z\s.,!?\-']+$")
_RX_PRINTABLE = re.compile(r"[\x20-\x7e\r\n\t]")
_RX_BINARY_NOISE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_MIN_EMBEDDED_BASE64_LEN = 32
_PLAINTEXT_KEYWORDS = {
    "powershell",
    "hidden",
    "nop",
    "cmd",
    "echo",
    "exec",
    "base64",
    "wget",
    "curl",
    "http",
    "https",
    "shell",
    "bash",
    "sh",
    "python",
    "perl",
    "cmd.exe",
    "powershell.exe",
}


def _printable_ascii_ratio(buffer: str) -> float:
    if not buffer:
        return 0.0
    printable = sum(1 for ch in buffer if 32 <= ord(ch) <= 126)
    return printable / len(buffer)


def _count_keyword_tokens(buffer: str) -> Tuple[int, int, float]:
    tokens = buffer.split()
    if not tokens:
        return 0, 0, 0.0
    recognized = 0
    for token in tokens:
        normalized = token.strip(".,;:()[]{}\"'").lower()
        if normalized in _PLAINTEXT_KEYWORDS:
            recognized += 1
    return recognized, len(tokens), recognized / len(tokens)


def _should_finalize_plaintext(
    buffer: str,
    ignore_printable_ratio: bool = False,
) -> Tuple[bool, Dict[str, object]]:
    recognized, total_tokens, keyword_ratio = _count_keyword_tokens(buffer)
    contains_spaces = " " in buffer
    has_keyword = recognized > 0
    if has_keyword or contains_spaces:
        return True, {
            "recognized_keyword_count": recognized,
            "keyword_ratio": round(keyword_ratio, 4),
            "contains_spaces": contains_spaces,
            "finality_reason": "plaintext_keyword" if has_keyword else "plaintext_space",
        }
    return False, {
        "recognized_keyword_count": recognized,
        "keyword_ratio": round(keyword_ratio, 4),
        "contains_spaces": contains_spaces,
    }


class DecoderError(Exception):
    pass


class PayloadOverflowError(DecoderError):
    pass


class _SkipLayer(Exception):
    pass


def shannon_entropy(buffer: str) -> float:
    if not buffer:
        return 0.0
    counts = Counter(buffer)
    total = len(buffer)
    accumulator = 0.0
    for freq in counts.values():
        probability = freq / total
        accumulator -= probability * math.log2(probability)
    return round(accumulator, 4)


def _printable_ratio(buffer: str) -> float:
    if not buffer:
        return 0.0
    return len(_RX_PRINTABLE.findall(buffer)) / len(buffer)


def _looks_like_base64(payload: str) -> bool:
    stripped = re.sub(r"\s+", "", payload)
    if len(stripped) < 8 or len(stripped) % 4 != 0:
        return False
    if not _RX_BASE64_STRICT.match(stripped):
        return False
    if stripped.isalpha() and stripped.isupper() and len(stripped) < 24:
        return False
    return True


def _looks_like_hex(payload: str) -> bool:
    stripped = re.sub(r"\s+", "", payload)
    if len(stripped) < 8 or len(stripped) % 2 != 0:
        return False
    return bool(_RX_HEX.match(stripped))


def _find_embedded_candidate(buffer: str) -> Optional[str]:
    # try to find long base64-like substrings first
    b64_candidates = re.findall(r"[A-Za-z0-9+/]{12,}={0,2}", buffer)
    if b64_candidates:
        b64_candidates.sort(key=len, reverse=True)
        for cand in b64_candidates:
            stripped = re.sub(r"\s+", "", cand)
            if (
                len(stripped) >= _MIN_EMBEDDED_BASE64_LEN
                and _RX_BASE64_STRICT.match(stripped)
                and re.search(r"[+/=]", stripped)
            ):
                return cand

    # next try percent-encoded sequences
    pct = re.findall(r"(?:%[0-9A-Fa-f]{2}){6,}", buffer)
    if pct:
        return pct[0]

    # finally try long hex runs
    hex_candidates = re.findall(r"[0-9A-Fa-f]{8,}", buffer)
    if hex_candidates:
        hex_candidates.sort(key=len, reverse=True)
        return hex_candidates[0]

    return None


def _decode_base64(payload: str) -> str:
    if not _looks_like_base64(payload):
        raise _SkipLayer("base64 signature mismatch")
    try:
        stripped = re.sub(r"\s+", "", payload)
        raw = base64.b64decode(stripped, validate=True)
        if raw.startswith(b"\x1f\x8b"):
            try:
                decompressed = gzip.decompress(raw)
                return decompressed.decode("utf-8", errors="strict")
            except (zlib.error, OSError, UnicodeDecodeError) as exc:
                raise _SkipLayer(f"gzip base64 failed: {exc}")
        decoded = raw.decode("utf-8", errors="strict")
        return decoded
    except (binascii.Error, UnicodeDecodeError, zlib.error) as exc:
        raise _SkipLayer(f"base64 failed: {exc}")


def _decode_base32(payload: str) -> str:
    stripped = re.sub(r"\s+", "", payload).upper()
    if len(stripped) < 8 or len(stripped) % 8 != 0:
        raise _SkipLayer("base32 length invalid")
    if not re.match(r"^[A-Z2-7=]+$", stripped):
        raise _SkipLayer("base32 charset mismatch")
    try:
        raw = base64.b32decode(stripped)
        decoded = raw.decode("utf-8", errors="strict")
        return decoded
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise _SkipLayer(f"base32 failed: {exc}")


def _decode_hex(payload: str) -> str:
    if not _looks_like_hex(payload):
        raise _SkipLayer("hex signature mismatch")
    try:
        stripped = re.sub(r"\s+", "", payload)
        raw = bytes.fromhex(stripped)
        decoded = raw.decode("utf-8", errors="strict")
        return decoded
    except (ValueError, UnicodeDecodeError) as exc:
        raise _SkipLayer(f"hex failed: {exc}")


def _decode_url(payload: str) -> str:
    if not _RX_URL_ENC.search(payload):
        raise _SkipLayer("no percent-encoding present")
    decoded = urllib.parse.unquote_plus(payload, errors="strict")
    if decoded == payload:
        raise _SkipLayer("url-decode no-op")
    return decoded


def _decode_html_entities(payload: str) -> str:
    if not _RX_HTML_ENT.search(payload):
        raise _SkipLayer("no html entities found")
    decoded = html.unescape(payload)
    if decoded == payload:
        raise _SkipLayer("html unescape no-op")
    return decoded


def _decode_unicode_escapes(payload: str) -> str:
    if not (_RX_UNICODE_ESC.search(payload) or _RX_HEX_ESC.search(payload)):
        raise _SkipLayer("no escape sequences")
    try:
        decoded = codecs.decode(payload, "unicode_escape")
        if decoded == payload:
            raise _SkipLayer("escape-decode no-op")
        return decoded
    except UnicodeDecodeError as exc:
        raise _SkipLayer(f"unicode escape failed: {exc}")


def _decode_rot13(payload: str) -> str:
    if not _RX_ROT_HINT.match(payload[:200]):
        raise _SkipLayer("rot13 charset mismatch")
    rotated = codecs.decode(payload, "rot_13")
    if rotated == payload:
        raise _SkipLayer("rot13 identity")
    return rotated


def _decode_reverse(payload: str) -> str:
    if len(payload) < 12:
        raise _SkipLayer("reverse skipped on short buffer")
    raise _SkipLayer("reverse heuristic disabled in default chain")


_DECODER_CHAIN: List[Tuple[str, Callable[[str], str]]] = [
    ("url_decode", _decode_url),
    ("html_entities", _decode_html_entities),
    ("unicode_escape", _decode_unicode_escapes),
    ("base64", _decode_base64),
    ("base32", _decode_base32),
    ("hex", _decode_hex),
    ("rot13", _decode_rot13),
]


class CascadeDecoder:
    def __init__(
        self,
        max_depth: int = MAX_RECURSION_DEPTH,
        ignore_printable_ratio: bool = False,
    ):
        self.max_depth = max_depth
        self.ignore_printable_ratio = ignore_printable_ratio

    def _validate(self, payload: str) -> None:
        if not isinstance(payload, str):
            raise DecoderError("payload must be a string buffer")
        if len(payload.encode("utf-8", errors="ignore")) > MAX_PAYLOAD_BYTES:
            raise PayloadOverflowError(
                f"payload exceeds {MAX_PAYLOAD_BYTES} byte safety boundary"
            )

    def _classify_entropy(self, score: float, buffer: str) -> Optional[str]:
        stripped = re.sub(r"\s+", "", buffer)
        if not stripped:
            return None
        if _RX_HEX.match(stripped) and score > 4.5:
            return "HIGH_ENTROPY_HEX"
        if _RX_BASE64_STRICT.match(stripped) and score > 5.0:
            return "HIGH_ENTROPY_BASE64"
        if score > 5.5:
            return "HIGH_ENTROPY_GENERIC"
        return None

    def _snippet(self, buffer: str) -> str:
        flat = buffer.replace("\n", "\\n").replace("\r", "")
        if len(flat) <= SNIPPET_PREVIEW:
            return flat
        return f"{flat[:SNIPPET_PREVIEW]}…"

    def run(self, raw_data: str) -> Dict:
        self._validate(raw_data)

        timeline: List[Dict] = []
        recipe_path: List[str] = []
        current = raw_data
        seen_fingerprints = {hash(current)}

        # If the input looks like a larger log blob, try to extract an embedded
        # encoded candidate (base64/percent-enc/hex) so decoders can operate on it.
        candidate = _find_embedded_candidate(raw_data)
        candidate_extracted = False
        if candidate and candidate != raw_data:
            elapsed_ms = 0.0
            timeline.append({
                "layer_index": 0,
                "decoder": "extract_candidate",
                "elapsed_ms": elapsed_ms,
                "timestamp_ms": round(time.time() * 1000),
                "input_length": len(raw_data),
                "output_length": len(candidate),
                "step_delta": len(candidate) - len(raw_data),
                "entropy_before": shannon_entropy(raw_data),
                "entropy_after": shannon_entropy(candidate),
                "entropy_drop": round(shannon_entropy(raw_data) - shannon_entropy(candidate), 4),
                "entropy_flag": None,
                "preview_before": self._snippet(raw_data),
                "preview_after": self._snippet(candidate),
            })
            current = candidate
            seen_fingerprints = {hash(current)}
            candidate_extracted = True

        pipeline_start = time.perf_counter()

        pipeline_finalized = False
        plaintext_gate_reason: Optional[str] = None

        for depth in range(self.max_depth):
            layer_advanced = False

            for decoder_name, decoder_fn in _DECODER_CHAIN:
                layer_start = time.perf_counter()
                try:
                    transformed = decoder_fn(current)
                except _SkipLayer:
                    continue
                except DecoderError as exc:
                    logger.warning("decoder %s raised %s", decoder_name, exc)
                    continue

                fingerprint = hash(transformed)
                if fingerprint in seen_fingerprints:
                    continue
                seen_fingerprints.add(fingerprint)

                elapsed_ms = round((time.perf_counter() - layer_start) * 1000, 4)
                pre_entropy = shannon_entropy(current)
                post_entropy = shannon_entropy(transformed)
                step_delta = len(transformed) - len(current)
                entropy_flag = self._classify_entropy(post_entropy, transformed)

                timeline.append({
                    "layer_index": depth + 1,
                    "decoder": decoder_name,
                    "elapsed_ms": elapsed_ms,
                    "timestamp_ms": round(time.time() * 1000),
                    "input_length": len(current),
                    "output_length": len(transformed),
                    "step_delta": step_delta,
                    "entropy_before": pre_entropy,
                    "entropy_after": post_entropy,
                    "entropy_drop": round(pre_entropy - post_entropy, 4),
                    "entropy_flag": entropy_flag,
                    "preview_before": self._snippet(current),
                    "preview_after": self._snippet(transformed),
                })

                recipe_path.append(decoder_name)
                current = transformed
                layer_advanced = True

                finalize, gate_metadata = _should_finalize_plaintext(
                    current,
                    self.ignore_printable_ratio,
                )
                if finalize:
                    pipeline_finalized = True
                    plaintext_gate_reason = gate_metadata["finality_reason"]
                    timeline[-1].update({
                        "recognized_keyword_count": gate_metadata["recognized_keyword_count"],
                        "keyword_ratio": gate_metadata["keyword_ratio"],
                        "contains_spaces": gate_metadata["contains_spaces"],
                        "plaintext_gate": True,
                    })
                    break

                break

            if pipeline_finalized:
                break
            if not layer_advanced:
                break

        if candidate_extracted and not recipe_path:
            current = raw_data
            if timeline:
                timeline[0].update({
                    "candidate_extraction": "failed_to_decode",
                })
            recipe_path = []
            pipeline_finalized = False
            plaintext_gate_reason = None
            seen_fingerprints = {hash(current)}

        total_ms = round((time.perf_counter() - pipeline_start) * 1000, 4)
        final_entropy = shannon_entropy(current)

        return {
            "final_payload": current,
            "final_entropy": final_entropy,
            "final_entropy_flag": self._classify_entropy(final_entropy, current),
            "recipe_path": recipe_path,
            "timeline": timeline,
            "depth_reached": len(recipe_path),
            "pipeline_elapsed_ms": total_ms,
            "original_length": len(raw_data),
            "final_length": len(current),
            "plaintext_gate_engaged": pipeline_finalized,
            "plaintext_gate_reason": plaintext_gate_reason,
            "plaintext_gate_ignored_printable_ratio": self.ignore_printable_ratio,
        }
