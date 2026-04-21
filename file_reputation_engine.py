"""
file_reputation_engine.py
==========================
PCAP 패킷에서 실행 파일을 추출하고 VirusTotal API v3 로 해시를 조회하여
악성 파일 탐지 Snort 룰을 자동 생성하는 엔진.

지원 추출 경로
--------------
  HTTP  : multipart/form-data 업로드, Content-Disposition: attachment
  FTP   : STOR 명령으로 전송되는 파일 (Raw payload)
  SMTP  : Base64 인코딩 첨부 파일 (Content-Transfer-Encoding: base64)

탐지 대상 파일 유형
-------------------
  실행파일: .exe .dll .sys .com .scr .pif
  스크립트: .ps1 .bat .cmd .vbs .js .hta .wsf
  아카이브: .zip .rar .7z .tar .gz (내부 실행파일 포함 가능)
  문서형 악성: .doc .docm .xls .xlsm .pdf (매크로 포함)
  웹셸:       .php .asp .aspx .jsp (의심 업로드)

VirusTotal API v3 /files/{hash}
--------------------------------
  - 무료 키: 4 req/분, 500 req/일
  - 키 설정: keywords/ai_config.yaml → virustotal.api_key
  - 판정 기준: malicious ≥ 5 → MALICIOUS, suspicious ≥ 3 → SUSPICIOUS
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── 설정 ──────────────────────────────────────────────────────────────────────
_CFG_FILE = Path(__file__).parent / "keywords" / "ai_config.yaml"

VT_FILE_URL   = "https://www.virustotal.com/api/v3/files/{hash}"
REQUEST_TIMEOUT = 15

# 악성 판정 임계값
MALICIOUS_THRESHOLD  = 5   # malicious 엔진 수 ≥ 이 값
SUSPICIOUS_THRESHOLD = 3   # suspicious 엔진 수 ≥ 이 값

# 탐지 대상 확장자
EXECUTABLE_EXTS = {
    '.exe', '.dll', '.sys', '.com', '.scr', '.pif',
    '.ps1', '.bat', '.cmd', '.vbs', '.js', '.hta', '.wsf', '.vbe',
}
ARCHIVE_EXTS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.cab', '.iso'}
DOCUMENT_EXTS = {'.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm', '.pdf'}
WEBSHELL_EXTS = {'.php', '.asp', '.aspx', '.jsp', '.jspx', '.cgi', '.pl'}

ALL_SUSPICIOUS_EXTS = EXECUTABLE_EXTS | ARCHIVE_EXTS | DOCUMENT_EXTS | WEBSHELL_EXTS

# 실행파일 매직 바이트 (파일 헤더)
MAGIC_BYTES: Dict[bytes, str] = {
    b'MZ':                      "PE Executable (Windows)",
    b'\x7fELF':                 "ELF Executable (Linux)",
    b'\xca\xfe\xba\xbe':       "Mach-O Fat Binary (macOS)",
    b'\xfe\xed\xfa\xce':       "Mach-O 32-bit",
    b'\xfe\xed\xfa\xcf':       "Mach-O 64-bit",
    b'PK\x03\x04':             "ZIP Archive",
    b'Rar!':                    "RAR Archive",
    b'7z\xbc\xaf\x27\x1c':    "7-Zip Archive",
    b'%PDF':                    "PDF Document",
    b'\xd0\xcf\x11\xe0':       "MS Office OLE2 (doc/xls/ppt)",
    b'PK':                      "OOXML (docx/xlsx/pptx)",
    b'#!/':                     "Shell Script",
    b'<?php':                   "PHP Script",
    b'<%':                      "ASP/JSP Script",
    b'\x4d\x5a':               "PE (MZ header)",
}


# ──────────────────────────────────────────────────────────────────────────────
# 1. 데이터 구조
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ExtractedFile:
    """추출된 파일 정보"""
    filename:   str   = ""
    ext:        str   = ""
    data:       bytes = field(default_factory=bytes)
    source:     str   = ""      # "http_upload" | "ftp_stor" | "smtp_attachment"
    frame_no:   int   = 0
    md5:        str   = ""
    sha256:     str   = ""
    file_type:  str   = ""      # 매직 바이트 기반 판별
    size:       int   = 0


@dataclass
class FileVerdict:
    """VT 조회 결과"""
    filename:   str   = ""
    md5:        str   = ""
    sha256:     str   = ""
    verdict:    str   = "UNKNOWN"   # MALICIOUS | SUSPICIOUS | CLEAN | UNKNOWN
    malicious:  int   = 0
    suspicious: int   = 0
    total:      int   = 0
    engine_names: List[str] = field(default_factory=list)
    source:     str   = ""
    frame_no:   int   = 0
    file_type:  str   = ""
    reason:     str   = ""


# ──────────────────────────────────────────────────────────────────────────────
# 2. 파일 추출
# ──────────────────────────────────────────────────────────────────────────────

def _calc_hashes(data: bytes) -> Tuple[str, str]:
    """MD5 + SHA256 계산"""
    return (
        hashlib.md5(data).hexdigest(),
        hashlib.sha256(data).hexdigest(),
    )


def _detect_file_type(data: bytes) -> str:
    """매직 바이트로 파일 유형 판별"""
    for magic, ftype in MAGIC_BYTES.items():
        if data[:len(magic)] == magic:
            return ftype
    return "Unknown"


def _make_extracted(data: bytes, filename: str, source: str, frame_no: int) -> ExtractedFile:
    md5, sha256 = _calc_hashes(data)
    ext = Path(filename).suffix.lower() if filename else ""
    return ExtractedFile(
        filename=filename, ext=ext, data=data,
        source=source, frame_no=frame_no,
        md5=md5, sha256=sha256,
        file_type=_detect_file_type(data),
        size=len(data),
    )


def extract_from_http(payload: bytes, frame_no: int = 0) -> List[ExtractedFile]:
    """
    HTTP payload에서 업로드 파일 추출.
    multipart/form-data 와 Content-Disposition: attachment 지원.
    """
    files: List[ExtractedFile] = []
    try:
        text = payload.decode("utf-8", errors="replace")

        # ── multipart/form-data 파싱 ────────────────────────────────────────
        boundary_m = re.search(
            r'Content-Type:\s*multipart/form-data;\s*boundary=([^\r\n\s;]+)',
            text, re.I
        )
        if boundary_m:
            boundary = boundary_m.group(1).strip('"\'')
            parts = payload.split(f"--{boundary}".encode())
            for part in parts[1:]:
                if part.strip() in (b"--", b""):
                    continue
                # 헤더와 바디 분리
                sep = part.find(b"\r\n\r\n")
                if sep < 0:
                    sep = part.find(b"\n\n")
                if sep < 0:
                    continue
                header_raw = part[:sep].decode("utf-8", errors="replace")
                body       = part[sep+4:].rstrip(b"\r\n--")

                # filename 추출
                fn_m = re.search(r'filename=["\']?([^"\'\r\n;]+)["\']?', header_raw, re.I)
                if not fn_m or not body:
                    continue
                filename = fn_m.group(1).strip()
                ext      = Path(filename).suffix.lower()
                if ext in ALL_SUSPICIOUS_EXTS or _detect_file_type(body) != "Unknown":
                    files.append(_make_extracted(body, filename, "http_upload", frame_no))

        # ── Content-Disposition: attachment ─────────────────────────────────
        attach_m = re.search(
            r'Content-Disposition:\s*attachment;\s*filename=["\']?([^"\'\r\n;]+)',
            text, re.I
        )
        if attach_m:
            filename = attach_m.group(1).strip()
            ext      = Path(filename).suffix.lower()
            # 헤더 이후 바디 추출
            sep = payload.find(b"\r\n\r\n")
            if sep >= 0:
                body = payload[sep+4:]
                if body and ext in ALL_SUSPICIOUS_EXTS:
                    files.append(_make_extracted(body, filename, "http_upload", frame_no))

    except Exception:
        pass
    return files


def extract_from_ftp(payload: bytes, frame_no: int = 0) -> List[ExtractedFile]:
    """
    FTP payload에서 실행 파일 추출.
    STOR 명령 다음 패킷의 Raw 데이터를 분석.
    """
    files: List[ExtractedFile] = []
    try:
        text = payload.decode("utf-8", errors="replace").strip()

        # STOR 명령 (파일 업로드)
        stor_m = re.match(r'^STOR\s+(\S+)', text, re.I)
        if stor_m:
            filename = stor_m.group(1)
            ext      = Path(filename).suffix.lower()
            # STOR 명령 자체에는 데이터가 없음 → 다음 패킷이 실제 데이터
            # 여기서는 파일명만 기록 (프레임 번호로 추적)
            if ext in ALL_SUSPICIOUS_EXTS:
                # 더미 추출 (파일명 기록용 — 실제 데이터는 다음 패킷)
                files.append(ExtractedFile(
                    filename=filename, ext=ext, data=b"",
                    source="ftp_stor_cmd", frame_no=frame_no,
                    file_type="FTP STOR command (data in next packet)",
                ))
            return files

        # STOR 이후 실제 파일 데이터 패킷 — 매직 바이트로 판별
        ftype = _detect_file_type(payload)
        if ftype != "Unknown" and len(payload) >= 16:
            files.append(_make_extracted(payload, f"ftp_payload_frame{frame_no}", "ftp_stor", frame_no))

    except Exception:
        pass
    return files


def extract_from_smtp(payload: bytes, frame_no: int = 0) -> List[ExtractedFile]:
    """
    SMTP payload에서 Base64 인코딩 첨부 파일 추출.
    """
    files: List[ExtractedFile] = []
    try:
        text = payload.decode("utf-8", errors="replace")

        # MIME 파트 탐지
        parts = re.split(r'--[^\r\n]+', text)
        for part in parts:
            fn_m = re.search(r'(?:filename|name)=["\']?([^"\'\r\n;]+)', part, re.I)
            enc_m = re.search(r'Content-Transfer-Encoding:\s*base64', part, re.I)
            if not (fn_m and enc_m):
                continue

            filename = fn_m.group(1).strip()
            ext      = Path(filename).suffix.lower()
            if ext not in ALL_SUSPICIOUS_EXTS:
                continue

            # base64 디코딩
            b64_m = re.search(r'\r?\n\r?\n([A-Za-z0-9+/=\r\n]+)', part)
            if not b64_m:
                continue
            try:
                data = base64.b64decode(b64_m.group(1).replace('\r', '').replace('\n', ''))
                if data:
                    files.append(_make_extracted(data, filename, "smtp_attachment", frame_no))
            except Exception:
                pass

    except Exception:
        pass
    return files


# ──────────────────────────────────────────────────────────────────────────────
# 3. VirusTotal API v3 파일 해시 조회
# ──────────────────────────────────────────────────────────────────────────────

_vt_key_cache: str = ""
_vt_key_mtime: float = 0.0


def _get_vt_api_key() -> str:
    """ai_config.yaml 에서 VT API 키 로드"""
    global _vt_key_cache, _vt_key_mtime
    try:
        import yaml
        mtime = _CFG_FILE.stat().st_mtime
        if mtime == _vt_key_mtime and _vt_key_cache:
            return _vt_key_cache
        with open(_CFG_FILE, encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        key = cfg.get("virustotal", {}).get("api_key", "").strip()
        _vt_key_cache = key
        _vt_key_mtime = mtime
        return key
    except Exception:
        return ""


# 메모리 캐시 (hash → verdict) — 동일 해시 중복 조회 방지
_hash_cache: Dict[str, FileVerdict] = {}


def query_vt_file_hash(
    sha256:   str,
    filename: str = "",
    frame_no: int = 0,
    file_type: str = "",
) -> FileVerdict:
    """
    VirusTotal API v3 /files/{hash} 로 파일 해시를 조회.

    Returns
    -------
    FileVerdict — verdict: MALICIOUS | SUSPICIOUS | CLEAN | UNKNOWN
    """
    if sha256 in _hash_cache:
        return _hash_cache[sha256]

    vt_key = _get_vt_api_key()
    result = FileVerdict(
        filename=filename, sha256=sha256,
        frame_no=frame_no, file_type=file_type,
    )

    if not vt_key:
        result.verdict = "UNKNOWN"
        result.reason  = "VirusTotal API 키 미설정 — ai_config.yaml 에서 등록하세요"
        return result

    url = VT_FILE_URL.format(hash=sha256)
    try:
        req = urllib.request.Request(
            url,
            headers={"x-apikey": vt_key, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as r:
            data = json.loads(r.read().decode("utf-8"))

        stats = (data.get("data", {})
                     .get("attributes", {})
                     .get("last_analysis_stats", {}))
        results_detail = (data.get("data", {})
                              .get("attributes", {})
                              .get("last_analysis_results", {}))

        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values())

        # 악성 엔진 이름 수집 (상위 10개)
        engine_names = [
            eng for eng, detail in results_detail.items()
            if detail.get("category") in ("malicious", "suspicious")
        ][:10]

        result.malicious     = malicious
        result.suspicious    = suspicious
        result.total         = total
        result.engine_names  = engine_names

        if malicious >= MALICIOUS_THRESHOLD:
            result.verdict = "MALICIOUS"
            result.reason  = (f"VT: {malicious}/{total} 악성 엔진 탐지 "
                              f"[{', '.join(engine_names[:3])}]")
        elif suspicious >= SUSPICIOUS_THRESHOLD:
            result.verdict = "SUSPICIOUS"
            result.reason  = (f"VT: {suspicious}/{total} 의심 엔진 탐지")
        else:
            result.verdict = "CLEAN"
            result.reason  = f"VT: {malicious}/{total} — 정상 판정"

    except urllib.error.HTTPError as e:
        if e.code == 404:
            result.verdict = "UNKNOWN"
            result.reason  = "VT: 해시 미등록 (신규 파일 또는 희귀 파일)"
        elif e.code == 429:
            result.verdict = "UNKNOWN"
            result.reason  = "VT: API 호출 한도 초과"
        elif e.code == 403:
            result.verdict = "UNKNOWN"
            result.reason  = "VT: API 키 권한 없음"
        else:
            result.verdict = "UNKNOWN"
            result.reason  = f"VT: HTTP {e.code}"
    except Exception as e:
        result.verdict = "UNKNOWN"
        result.reason  = f"VT: 조회 실패 {str(e)[:60]}"

    _hash_cache[sha256] = result
    return result


# ──────────────────────────────────────────────────────────────────────────────
# 4. Snort 룰 생성
# ──────────────────────────────────────────────────────────────────────────────

def build_file_reputation_rules(
    verdict:   FileVerdict,
    hdr:       dict,
    rule_id:   int,
) -> List[str]:
    """
    VT 판정 결과를 기반으로 Snort 룰 생성.

    생성 조건: verdict == MALICIOUS 또는 SUSPICIOUS
    """
    if verdict.verdict not in ("MALICIOUS", "SUSPICIOUS"):
        return []

    rules = []
    sev   = "CRITICAL" if verdict.verdict == "MALICIOUS" else "HIGH"
    proto = hdr.get("proto", "tcp").lower()
    src   = hdr.get("src_ip", "any")
    dst   = hdr.get("dst_ip", "any")
    dport = hdr.get("dst_port", "any")
    sport = hdr.get("src_port", "any")

    mal_info = (f"VT:{verdict.malicious}/{verdict.total}" if verdict.total
                else "VT:unknown")

    # ── 룰 1: SHA256 해시 기반 (가장 정밀) ─────────────────────────────────
    # Snort content 에 16진수 해시 일부 포함 (전체 64자는 너무 길어 앞 16바이트만)
    sha256_hex16 = verdict.sha256[:32]   # 32 hex chars = 16 bytes
    hex_content  = "|" + " ".join(
        sha256_hex16[i:i+2] for i in range(0, len(sha256_hex16), 2)
    ) + "|"

    msg_hash = (
        f"{sev} Malicious File Transfer Detected ({mal_info}) "
        f"SHA256:{verdict.sha256[:16]}... [{verdict.file_type}]"
    )
    rules.append(
        f'alert {proto} any any -> any any '
        f'(msg:"{msg_hash}"; '
        f'content:"{hex_content}"; '
        f'sid:{rule_id}; rev:1;)'
    )
    rule_id += 1

    # ── 룰 2: 파일명 기반 (filename이 있을 때) ──────────────────────────────
    if verdict.filename and len(verdict.filename) >= 3:
        fname_safe = verdict.filename.replace('"', '\\"')[:40]
        msg_fname  = (
            f"{sev} Malicious File Upload: {fname_safe} ({mal_info})"
        )
        # HTTP 업로드
        if verdict.source in ("http_upload",):
            rules.append(
                f'alert tcp any any -> any $HTTP_PORTS '
                f'(msg:"{msg_fname}"; '
                f'content:"filename=\\"{fname_safe}\\""; http_client_body; nocase; '
                f'sid:{rule_id}; rev:1;)'
            )
            rule_id += 1
        # FTP 업로드
        elif verdict.source in ("ftp_stor", "ftp_stor_cmd"):
            rules.append(
                f'alert tcp any any -> any 21 '
                f'(msg:"{msg_fname}"; '
                f'content:"STOR {fname_safe}"; nocase; '
                f'sid:{rule_id}; rev:1;)'
            )
            rule_id += 1
        # SMTP 첨부
        elif verdict.source == "smtp_attachment":
            rules.append(
                f'alert tcp any any -> any 25 '
                f'(msg:"{msg_fname}"; '
                f'content:"filename=\\"{fname_safe}\\""; nocase; '
                f'sid:{rule_id}; rev:1;)'
            )
            rule_id += 1

    return rules


# ──────────────────────────────────────────────────────────────────────────────
# 5. 통합 파이프라인 함수
# ──────────────────────────────────────────────────────────────────────────────

def analyze_file_in_packet(
    payload:  bytes,
    protocol: str,
    hdr:      dict,
    frame_no: int,
    rule_id:  int,
) -> dict:
    """
    단일 패킷 payload에서 파일 추출 → VT 조회 → 룰 생성.

    Returns
    -------
    {
      "extracted_files": [ExtractedFile, ...],
      "verdicts":        [FileVerdict, ...],
      "rules":           [str, ...],
      "next_rule_id":    int,
    }
    """
    result = {
        "extracted_files": [],
        "verdicts":        [],
        "rules":           [],
        "next_rule_id":    rule_id,
    }

    # 파일 추출
    extracted: List[ExtractedFile] = []
    proto_up = protocol.upper()

    if proto_up == "HTTP":
        extracted = extract_from_http(payload, frame_no)
    elif proto_up == "FTP":
        extracted = extract_from_ftp(payload, frame_no)
    elif proto_up == "SMTP":
        extracted = extract_from_smtp(payload, frame_no)

    result["extracted_files"] = extracted

    # VT 조회 + 룰 생성
    for ef in extracted:
        if not ef.data or not ef.sha256:
            continue

        verdict = query_vt_file_hash(
            sha256    = ef.sha256,
            filename  = ef.filename,
            frame_no  = ef.frame_no,
            file_type = ef.file_type,
        )
        verdict.source = ef.source
        result["verdicts"].append(verdict)

        # 악성/의심 판정 시 룰 생성
        new_rules = build_file_reputation_rules(verdict, hdr, result["next_rule_id"])
        result["rules"].extend(new_rules)
        result["next_rule_id"] += len(new_rules)

    return result


def get_file_rep_summary() -> dict:
    """현재 세션 파일 평판 캐시 요약"""
    total     = len(_hash_cache)
    malicious = sum(1 for v in _hash_cache.values() if v.verdict == "MALICIOUS")
    suspicious= sum(1 for v in _hash_cache.values() if v.verdict == "SUSPICIOUS")
    clean     = sum(1 for v in _hash_cache.values() if v.verdict == "CLEAN")
    unknown   = sum(1 for v in _hash_cache.values() if v.verdict == "UNKNOWN")
    return {
        "total": total, "malicious": malicious,
        "suspicious": suspicious, "clean": clean, "unknown": unknown,
    }


def clear_hash_cache():
    """해시 메모리 캐시 초기화"""
    _hash_cache.clear()
