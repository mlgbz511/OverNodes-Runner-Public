#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP 纯净度评估（综合可用口径）

6 个维度加权，缺失维度自动归一化（不因数据源失败而误判低分）：
1. ASN 归属        —— 候选来自 Cloudflare CIDR 时直接认定
2. TLS 证书        —— 真实 SNI 证书链 + 主机名校验
3. 业务反代探针    —— 传 --domain 时，该 IP:端口 能正常反代
4. DNSBL 黑名单    —— Spamhaus(XBL/SBL) / Barracuda / SORBS / SpamCop
5. Scamalytics     —— fraud score + proxy/VPN/Tor 标记
6. IPPure 风险系数 —— 官方内部接口（同连接 HMAC 签名），0-100，越大越危险
"""
import hashlib
import hmac
import http.client
import json
import os
import re
import socket
import ssl
import time
import urllib.request
from typing import Dict, List, Optional, Tuple

DNSBL_ZONES = [
    ("zen.spamhaus.org", "Spamhaus"),
    ("b.barracudacentral.org", "Barracuda"),
    ("dnsbl.sorbs.net", "SORBS"),
    ("bl.spamcop.net", "SpamCop"),
]
SPAMHAUS_PBL_CODES = {"127.0.0.10", "127.0.0.11"}  # 云厂商常驻策略段，不计罚分
CACHE_TTL = 12 * 3600

# 权重（缺失维度会按剩余权重归一化）
WEIGHTS_WITH_PROBE = {"asn": 12, "tls": 22, "probe": 26, "dnsbl": 16, "scam": 12, "ippure": 12}
WEIGHTS_NO_PROBE = {"asn": 20, "tls": 30, "probe": 0, "dnsbl": 22, "scam": 16, "ippure": 12}


def _http_json(url: str, timeout: float = 6.0) -> Optional[Dict]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; CF-OverScan/1.0)"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return None


def _http_text(url: str, timeout: float = 6.0) -> Optional[str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace")
    except Exception:
        return None


def check_dnsbl(ip: str, timeout: float = 1.5) -> Tuple[int, List[str], int]:
    rev = ".".join(reversed(ip.split(".")))
    hits: List[str] = []
    checked = 0
    for zone, label in DNSBL_ZONES:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            answers = socket.gethostbyname_ex(f"{rev}.{zone}")[2]
            checked += 1
            bad = [a for a in answers if not (label == "Spamhaus" and a in SPAMHAUS_PBL_CODES)]
            if bad:
                hits.append(f"{label}:{','.join(sorted(set(bad)))}")
        except socket.gaierror:
            checked += 1
        except Exception:
            pass
        finally:
            socket.setdefaulttimeout(old)
    return len(hits), hits, checked


def check_tls(ip: str, port: int, sni: str, timeout: float = 5.0) -> bool:
    for _ in range(2):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=sni) as ss:
                    ss.getpeercert()
            return True
        except Exception:
            time.sleep(0.2)
    return False


def check_asn(ip: str, timeout: float = 6.0) -> Tuple[bool, str, Optional[bool], bool]:
    d = _http_json(f"http://ip-api.com/json/{ip}?fields=status,as,isp,proxy,hosting,mobile", timeout)
    if not d or d.get("status") != "success":
        return False, "unknown", None, False
    as_info = f"{d.get('as', '')} {d.get('isp', '')}"
    ok = "AS13335" in as_info or "cloudflare" in as_info.lower()
    return ok, as_info.strip(), bool(d.get("proxy")), True


def check_risk(ip: str, timeout: float = 6.0) -> Dict:
    result = {"fraud_score": None, "proxy": None, "vpn": None, "tor": None, "source": ""}
    html = _http_text(f"https://scamalytics.com/ip/{ip}", timeout)
    if html:
        m = re.search(r"Fraud Score[^0-9]{0,40}(\d+)", html)
        if m:
            result["fraud_score"] = int(m.group(1))
        result["proxy"] = bool(re.search(r">\s*Proxy\s*<", html))
        result["vpn"] = bool(re.search(r">\s*VPN\s*<", html))
        result["tor"] = bool(re.search(r">\s*Tor\s*<", html))
        result["source"] = "scamalytics"
    return result


class IPPureClient:
    """IPPure 内部风控接口客户端。

    其前端使用 HMAC 签名且 x-k 绑定在同一条 HTTP 连接上：
    同一连接内先发一次无签名的 bootstrap 请求拿到 x-k/x-t，再携带
    x-t = "{time}-{HMAC_SHA256(x-k, 'GET-{url}--{time}')}" 发起真正查询。
    """
    HOST = "api.123169.xyz"
    HEADERS = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json",
        "Origin": "https://ippure.com",
        "Referer": "https://ippure.com/",
    }

    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout
        self.conn: Optional[http.client.HTTPSConnection] = None

    def _reset(self):
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
        self.conn = None

    def _get(self, path: str, extra: Optional[Dict] = None) -> Tuple[int, Dict, str]:
        if not self.conn:
            self.conn = http.client.HTTPSConnection(self.HOST, timeout=self.timeout)
        headers = dict(self.HEADERS)
        if extra:
            headers.update(extra)
        self.conn.request("GET", path, headers=headers)
        resp = self.conn.getresponse()
        body = resp.read().decode("utf-8", "replace")
        return resp.status, dict(resp.getheaders()), body

    def risk_score(self, ip: str) -> Optional[int]:
        path = f"/api/info/ip-risk/{ip}"
        url = f"https://{self.HOST}{path}"
        for _ in range(2):
            try:
                _, h1, _ = self._get(path)
                key, ts = h1.get("x-k"), h1.get("x-t")
                if not key or not ts:
                    self._reset()
                    continue
                sig = hmac.new(key.encode(), f"GET-{url}--{ts}".encode(), hashlib.sha256).hexdigest()
                status, _, body = self._get(path, {"x-k": key, "x-t": f"{ts}-{sig}"})
                data = json.loads(body) if body else {}
                if status == 200 and data.get("ok") and isinstance(data.get("data"), dict):
                    score = data["data"].get("risk_score")
                    if isinstance(score, (int, float)):
                        return int(score)
                self._reset()
            except Exception:
                self._reset()
                continue
        return None

    def close(self):
        self._reset()


def evaluate_ip(ip: str, port: int, probe_domain: Optional[str] = None,
                probe_fn=None, timeout: float = 6.0, assume_cf: bool = False,
                ippure_client: Optional[IPPureClient] = None) -> Dict:
    own_client = False
    if ippure_client is None:
        ippure_client = IPPureClient(timeout=timeout)
        own_client = True

    if assume_cf:
        asn_ok, as_info, asn_proxy, asn_known = True, "Cloudflare (CF-CIDR)", None, True
    else:
        asn_ok, as_info, asn_proxy, asn_known = check_asn(ip, timeout)

    sni = probe_domain or "speed.cloudflare.com"
    tls_ok = check_tls(ip, port, sni, timeout)

    probe_ok = None
    if probe_domain and probe_fn is not None:
        try:
            probe_ok = bool(probe_fn(ip, port, probe_domain, timeout=max(2.0, timeout)))
        except Exception:
            probe_ok = False

    hits, hit_list, checked = check_dnsbl(ip, timeout=min(1.5, timeout))
    bl_ratio = 1.0 - (hits / max(1, checked)) if checked else None

    risk = check_risk(ip, timeout)
    if asn_proxy is not None:
        risk["proxy"] = bool(risk.get("proxy")) or asn_proxy
    fraud = risk.get("fraud_score")
    scam_factor = None
    if fraud is not None:
        base = max(0, 100 - int(fraud))
        if risk.get("proxy"):
            base *= 0.6
        if risk.get("tor"):
            base = 0
        if risk.get("vpn"):
            base *= 0.9
        scam_factor = base / 100.0

    ippure_risk = ippure_client.risk_score(ip)
    ippure_factor = None
    if ippure_risk is not None:
        ippure_factor = max(0.0, min(1.0, (100 - ippure_risk) / 100.0))

    weights = dict(WEIGHTS_WITH_PROBE if probe_domain else WEIGHTS_NO_PROBE)
    components: Dict[str, Tuple[float, float]] = {}
    components["asn"] = (weights["asn"], 1.0 if asn_ok else (0.5 if not asn_known else 0.0))
    components["tls"] = (weights["tls"], 1.0 if tls_ok else 0.0)
    if probe_domain:
        components["probe"] = (weights["probe"], 1.0 if probe_ok else 0.0)
    if bl_ratio is not None:
        components["dnsbl"] = (weights["dnsbl"], bl_ratio)
    if scam_factor is not None:
        components["scam"] = (weights["scam"], scam_factor)
    if ippure_factor is not None:
        components["ippure"] = (weights["ippure"], ippure_factor)

    total_w = sum(w for w, _ in components.values()) or 1.0
    score = 100.0 * sum(w * f for w, f in components.values()) / total_w

    if own_client:
        ippure_client.close()

    return {
        "ip": ip, "port": port,
        "purity": int(round(max(0, min(100, score)))),
        "asn_ok": asn_ok, "asn": as_info, "assume_cf": assume_cf,
        "tls_ok": tls_ok, "probe_ok": probe_ok,
        "dnsbl_hits": hit_list, "dnsbl_checked": checked,
        "fraud_score": fraud, "proxy": risk.get("proxy"),
        "vpn": risk.get("vpn"), "tor": risk.get("tor"),
        "ippure_risk": ippure_risk,
        "components": {k: round(v[1], 3) for k, v in components.items()},
        "sni": sni, "_v": 2, "ts": int(time.time()),
    }


def load_cache(path: Optional[str]) -> Dict:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_cache(path: Optional[str], cache: Dict) -> None:
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        now = int(time.time())
        cache = {k: v for k, v in cache.items() if now - int(v.get("ts", 0)) < CACHE_TTL}
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=1)
        os.replace(tmp, path)
    except Exception:
        pass


def enrich_nodes(nodes: List[Dict], probe_domain: Optional[str] = None,
                 probe_fn=None, timeout: float = 6.0, cache_path: Optional[str] = None,
                 delay: float = 0.3, assume_cf: bool = False, log=print) -> List[Dict]:
    cache = load_cache(cache_path)
    client = IPPureClient(timeout=max(6.0, timeout))
    seen = set()
    try:
        for n in nodes:
            key = f"{n['ip']}:{n['port']}"
            if key in seen:
                continue
            seen.add(key)
            cached = cache.get(key)
            if cached and cached.get("_v") == 2 and (time.time() - int(cached.get("ts", 0))) < CACHE_TTL:
                res = cached
            else:
                res = evaluate_ip(n["ip"], n["port"], probe_domain, probe_fn, timeout,
                                  assume_cf=assume_cf, ippure_client=client)
                cache[key] = res
                time.sleep(delay)
            n["purity"] = res["purity"]
            n["purity_detail"] = res
    finally:
        client.close()
    save_cache(cache_path, cache)
    return nodes


def format_report(nodes: List[Dict]) -> str:
    header = "ip:port\tpurity\tasn\ttls\tprobe\tdnsbl\tfraud\tproxy\tvpn\ttor\tippure_risk"
    lines = [header]
    for n in nodes:
        d = n.get("purity_detail") or {}
        lines.append("\t".join([
            f"{n['ip']}:{n['port']}",
            str(n.get("purity", "")),
            "ok" if d.get("asn_ok") else "fail",
            "ok" if d.get("tls_ok") else "fail",
            "ok" if d.get("probe_ok") else ("skip" if d.get("probe_ok") is None else "fail"),
            ",".join(d.get("dnsbl_hits") or []) or "clean",
            "-" if d.get("fraud_score") is None else str(d.get("fraud_score")),
            str(d.get("proxy")), str(d.get("vpn")), str(d.get("tor")),
            "-" if d.get("ippure_risk") is None else str(d.get("ippure_risk")),
        ]))
    return "\n".join(lines) + "\n"
