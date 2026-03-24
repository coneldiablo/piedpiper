#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ThreatInquisitor/analyzer/network_analysis.py

Сетевой анализ: DNS, HTTP/HTTPS, beacon detection, C2 communication.
"""

import logging
import math
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from statistics import mean, pstdev
from typing import Any, Dict, List, Optional, Tuple, Union

try:  # Optional dependency
    from scapy.all import DNS, DNSQR, IP, IPv6, TCP, UDP, Raw, rdpcap  # type: ignore
    try:
        from scapy.layers.tls.handshake import TLSClientHello  # type: ignore
    except Exception:  # pragma: no cover - optional layer
        TLSClientHello = None  # type: ignore
except Exception:  # pragma: no cover - optional dependency might be missing
    DNS = DNSQR = IP = IPv6 = TCP = UDP = Raw = TLSClientHello = None  # type: ignore
    rdpcap = None  # type: ignore


logger = logging.getLogger("network_analysis")


class NetworkAnalyzer:
    """Анализатор сетевого трафика"""

    def __init__(self):
        self.reset()

    def reset(self) -> None:
        self.connections: List[Dict[str, Any]] = []
        self.dns_queries: List[Dict[str, Any]] = []
        self.http_requests: List[Dict[str, Any]] = []
        self.tls_handshakes: List[Dict[str, Any]] = []
        self._payload_samples: List[Dict[str, Any]] = []
        self._flow_stats: Dict[str, Any] = {}
        self._last_beacon_results: List[Dict[str, Any]] = []

    def analyze_connections(self, connections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Анализ сетевых соединений"""
        self.connections = connections

        results = {
            "total_connections": len(connections),
            "unique_ips": set(),
            "suspicious_ports": [],
            "c2_candidates": [],
            "beaconing_detected": [],
            "dns_tunneling": [],
            "http_analysis": {}
        }

        # Анализ IP адресов
        for conn in connections:
            remote_ip = conn.get("remote_ip")
            if remote_ip:
                results["unique_ips"].add(remote_ip)

            # Подозрительные порты
            remote_port = conn.get("remote_port", 0)
            if self._is_suspicious_port(remote_port):
                results["suspicious_ports"].append({
                    "ip": remote_ip,
                    "port": remote_port,
                    "protocol": conn.get("protocol", "")
                })

        results["unique_ips"] = list(results["unique_ips"])

        # Детект beaconing
        beacon_results = self.detect_beaconing()
        self._last_beacon_results = beacon_results
        results["beaconing_detected"] = beacon_results

        # C2 detection
        results["c2_candidates"] = self.detect_c2_communication(beacon_results)
        results["dns_queries"] = self.dns_queries
        results["http_requests"] = self.http_requests
        results["tls_handshakes"] = self.tls_handshakes

        return results

    def analyze_pcap(self, pcap_path: Union[str, os.PathLike[str]]) -> Dict[str, Any]:
        """
        Load a PCAP file, run connection analysis and deep packet inspection, and
        return a combined report.
        """
        pcap_summary = self.parse_pcap(pcap_path)
        analysis = self.analyze_connections(self.connections)
        dpi_results = self.perform_deep_packet_inspection()
        analysis["pcap_summary"] = pcap_summary
        analysis["deep_packet_inspection"] = dpi_results
        analysis["dns_queries"] = self.dns_queries
        analysis["http_requests"] = self.http_requests
        analysis["tls_handshakes"] = self.tls_handshakes
        return analysis

    def parse_pcap(self, pcap_path: Union[str, os.PathLike[str]]) -> Dict[str, Any]:
        """
        Parse packets from a PCAP file and populate internal caches.
        """
        if rdpcap is None:
            raise RuntimeError("PCAP parsing requires scapy (rdpcap is unavailable)")
        path = Path(pcap_path)
        if not path.exists():
            raise FileNotFoundError(f"PCAP file not found: {path}")
        logger.info("Loading PCAP file %s", path)
        self.reset()
        try:
            packets = rdpcap(str(path))
        except Exception as exc:  # pragma: no cover - depends on scapy internals
            logger.error("Failed to parse PCAP %s: %s", path, exc)
            raise
        summary: Dict[str, Any] = {
            "pcap_path": str(path),
            "packet_count": len(packets),
            "protocols": Counter(),
            "file_size_bytes": path.stat().st_size if path.exists() else None,
            "start_time": None,
            "end_time": None,
        }
        for packet in packets:
            ts = getattr(packet, "time", None)
            iso_ts: Optional[str] = None
            if ts is not None:
                try:
                    dt = datetime.fromtimestamp(float(ts))
                    iso_ts = dt.isoformat()
                except (OverflowError, ValueError):
                    iso_ts = None
                if summary["start_time"] is None and iso_ts:
                    summary["start_time"] = iso_ts
                if iso_ts:
                    summary["end_time"] = iso_ts

            ip_layer = None
            if IP and packet.haslayer(IP):
                ip_layer = packet[IP]
            elif IPv6 and packet.haslayer(IPv6):
                ip_layer = packet[IPv6]
            if ip_layer is None:
                continue

            protocol = "TCP" if TCP and packet.haslayer(TCP) else "UDP" if UDP and packet.haslayer(UDP) else ip_layer.name
            summary["protocols"][protocol] += 1

            src_ip = getattr(ip_layer, "src", None)
            dst_ip = getattr(ip_layer, "dst", None)
            src_port: Optional[int] = None
            dst_port: Optional[int] = None
            payload_bytes = b""

            if TCP and packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                payload_bytes = bytes(tcp_layer.payload)
            elif UDP and packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
                payload_bytes = bytes(udp_layer.payload)

            connection_entry = {
                "timestamp": iso_ts,
                "protocol": protocol,
                "local_ip": src_ip,
                "local_port": src_port,
                "remote_ip": dst_ip,
                "remote_port": dst_port,
                "bytes": len(payload_bytes),
            }
            self.connections.append(connection_entry)

            if payload_bytes:
                ascii_preview = payload_bytes[:256].decode("utf-8", errors="ignore")
                self._payload_samples.append(
                    {
                        "timestamp": iso_ts,
                        "protocol": protocol,
                        "direction": f"{src_ip}:{src_port}->{dst_ip}:{dst_port}",
                        "preview": payload_bytes[:64].hex(),
                        "ascii": ascii_preview,
                    }
                )
                if len(self._payload_samples) > 200:
                    self._payload_samples.pop(0)

            if DNS and packet.haslayer(DNS):
                dns_layer = packet[DNS]
                if dns_layer.qr == 0 and DNSQR in dns_layer:
                    query = dns_layer[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                    self.dns_queries.append(
                        {
                            "timestamp": iso_ts,
                            "query": query,
                            "type": dns_layer[DNSQR].qtype,
                            "source": src_ip,
                        }
                    )

            if payload_bytes:
                self._process_application_payload(payload_bytes, iso_ts, src_ip, dst_ip, src_port, dst_port)

        if summary["start_time"] and summary["end_time"]:
            try:
                start_dt = datetime.fromisoformat(summary["start_time"])
                end_dt = datetime.fromisoformat(summary["end_time"])
                summary["duration_seconds"] = (end_dt - start_dt).total_seconds()
            except Exception:
                summary["duration_seconds"] = None
        else:
            summary["duration_seconds"] = None

        summary["protocols"] = dict(summary["protocols"])
        return summary

    def _process_application_payload(
        self,
        payload: bytes,
        timestamp: Optional[str],
        src_ip: Optional[str],
        dst_ip: Optional[str],
        src_port: Optional[int],
        dst_port: Optional[int],
    ) -> None:
        if not payload:
            return

        sni = self._extract_tls_sni(payload)
        if sni:
            self.tls_handshakes.append(
                {
                    "timestamp": timestamp,
                    "sni": sni,
                    "destination": dst_ip,
                    "port": dst_port,
                }
            )

        try:
            text = payload.decode("utf-8", errors="ignore")
        except Exception:
            text = ""

        if not text:
            return

        http_methods = ("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ")
        if text.startswith(http_methods):
            lines = text.split("\r\n")
            request_line = lines[0]
            parts = request_line.split(" ")
            method = parts[0] if parts else "GET"
            path = parts[1] if len(parts) > 1 else "/"
            headers: Dict[str, str] = {}
            for line in lines[1:]:
                if not line:
                    break
                if ": " in line:
                    key, value = line.split(": ", 1)
                    headers[key.strip()] = value.strip()
            entry = {
                "timestamp": timestamp,
                "method": method,
                "path": path,
                "host": headers.get("Host"),
                "user_agent": headers.get("User-Agent"),
                "source": src_ip,
                "destination": dst_ip,
            }
            if "Content-Length" in headers:
                entry["content_length"] = headers["Content-Length"]
            self.http_requests.append(entry)

    @staticmethod
    def _extract_tls_sni(payload: bytes) -> Optional[str]:
        if len(payload) < 5 or payload[0] != 0x16:
            return None
        try:
            handshake_type = payload[5]
            if handshake_type != 0x01:
                return None
            idx = 9  # record header (5) + handshake header (4)
            idx += 2  # version
            idx += 32  # random
            if idx >= len(payload):
                return None
            session_id_len = payload[idx]
            idx += 1 + session_id_len
            if idx + 2 > len(payload):
                return None
            cipher_suites_len = int.from_bytes(payload[idx:idx + 2], "big")
            idx += 2 + cipher_suites_len
            if idx >= len(payload):
                return None
            compression_len = payload[idx]
            idx += 1 + compression_len
            if idx + 2 > len(payload):
                return None
            extensions_len = int.from_bytes(payload[idx:idx + 2], "big")
            idx += 2
            end = idx + extensions_len
            while idx + 4 <= end and idx + 4 <= len(payload):
                ext_type = int.from_bytes(payload[idx:idx + 2], "big")
                ext_len = int.from_bytes(payload[idx + 2:idx + 4], "big")
                idx += 4
                if ext_type == 0:
                    if idx + 2 > len(payload):
                        return None
                    list_len = int.from_bytes(payload[idx:idx + 2], "big")
                    idx += 2
                    list_end = idx + list_len
                    while idx + 3 <= list_end and idx + 3 <= len(payload):
                        name_type = payload[idx]
                        name_len = int.from_bytes(payload[idx + 1:idx + 3], "big")
                        idx += 3
                        sni = payload[idx:idx + name_len].decode("utf-8", errors="ignore")
                        idx += name_len
                        if name_type == 0 and sni:
                            return sni
                    return None
                else:
                    idx += ext_len
            return None
        except Exception:
            return None

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        counts = Counter(value)
        length = len(value)
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return entropy

    def perform_deep_packet_inspection(self) -> Dict[str, Any]:
        suspicious_http: List[Dict[str, Any]] = []
        suspicious_dns: List[Dict[str, Any]] = []
        payload_alerts: List[Dict[str, Any]] = []

        dangerous_extensions = (".exe", ".dll", ".js", ".hta", ".vbs", ".ps1", ".bat", ".scr", ".jar")
        for req in self.http_requests:
            path = (req.get("path") or "").lower()
            host = req.get("host") or ""
            if any(path.endswith(ext) for ext in dangerous_extensions):
                suspicious_http.append(
                    {
                        "host": host,
                        "path": path,
                        "method": req.get("method"),
                        "reason": "Suspicious binary download",
                        "severity": "high",
                    }
                )
            user_agent = (req.get("user_agent") or "").lower()
            for keyword in ("powershell", "curl", "wget", "python-requests", "python-urllib"):
                if keyword in user_agent:
                    suspicious_http.append(
                        {
                            "host": host,
                            "path": path,
                            "method": req.get("method"),
                            "reason": f"Unusual user agent: {req.get('user_agent')}",
                            "severity": "medium",
                        }
                    )
                    break

        for dns in self.dns_queries:
            query = dns.get("query") or ""
            normalized = query.replace(".", "")
            entropy = self._shannon_entropy(normalized)
            if len(normalized) > 40 and entropy > 3.5:
                suspicious_dns.append(
                    {
                        "query": query,
                        "entropy": round(entropy, 3),
                        "reason": "High-entropy domain (possible DGA)",
                        "severity": "medium",
                    }
                )

        for handshake in self.tls_handshakes:
            sni = handshake.get("sni") or ""
            entropy = self._shannon_entropy(sni.replace(".", ""))
            if len(sni) > 40 and entropy > 3.5:
                suspicious_dns.append(
                    {
                        "query": sni,
                        "entropy": round(entropy, 3),
                        "reason": "High-entropy TLS SNI",
                        "severity": "medium",
                    }
                )

        pattern_keywords = ("powershell", "cmd.exe", "invoke-webrequest", "/bin/sh", "base64")
        for sample in self._payload_samples:
            ascii_preview = sample.get("ascii") or ""
            lowered = ascii_preview.lower()
            if any(keyword in lowered for keyword in pattern_keywords):
                payload_alerts.append(
                    {
                        "direction": sample.get("direction"),
                        "reason": "Command execution indicators in payload",
                        "excerpt": ascii_preview[:160],
                        "severity": "high",
                    }
                )
            else:
                base64_match = re.search(r"[A-Za-z0-9+/]{60,}={0,2}", ascii_preview)
                if base64_match:
                    payload_alerts.append(
                        {
                            "direction": sample.get("direction"),
                            "reason": "Large base64 sequence detected",
                            "excerpt": base64_match.group(0)[:120],
                            "severity": "medium",
                        }
                    )

        return {
            "http_findings": suspicious_http,
            "dns_findings": suspicious_dns,
            "payload_findings": payload_alerts,
        }
    def _is_suspicious_port(self, port: int) -> bool:
        """Проверка подозрительного порта"""
        # Известные порты малвари
        malware_ports = [
            4444,  # Metasploit default
            5555,  # Android Debug Bridge
            6666, 6667,  # IRC
            8080, 8888,  # Альтернативные HTTP
            31337,  # Elite/leet
            12345,  # NetBus
            1337  # leet
        ]
        return port in malware_ports

    def detect_beaconing(self) -> List[Dict[str, Any]]:
        """
        Detect beaconing behaviour with tighter jitter and size heuristics.
        """
        beacons: List[Dict[str, Any]] = []
        connections_by_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for conn in self.connections:
            remote_ip = conn.get("remote_ip")
            timestamp = conn.get("timestamp")
            if not remote_ip or not timestamp:
                continue
            connections_by_ip[remote_ip].append({
                "timestamp": timestamp,
                "bytes_sent": max(conn.get("bytes_sent", 0), 0),
                "bytes_recv": max(conn.get("bytes_recv", 0), 0),
            })

        for ip, conns in connections_by_ip.items():
            if len(conns) < 3:
                continue

            enriched = []
            for entry in sorted(conns, key=lambda x: x["timestamp"]):
                try:
                    dt_obj = datetime.fromisoformat(entry["timestamp"])
                except Exception:
                    logger.debug("[beacon] invalid timestamp for %s: %s", ip, entry.get("timestamp"))
                    continue
                enriched.append({
                    "dt": dt_obj,
                    "timestamp": entry["timestamp"],
                    "payload": entry["bytes_sent"] + entry["bytes_recv"],
                })

            if len(enriched) < 3:
                continue

            intervals = [
                (enriched[i]["dt"] - enriched[i - 1]["dt"]).total_seconds()
                for i in range(1, len(enriched))
            ]
            if not intervals:
                continue

            avg_interval = mean(intervals)
            interval_std = pstdev(intervals) if len(intervals) > 1 else 0.0
            jitter_ratio = interval_std / avg_interval if avg_interval else 0.0

            payload_sizes = [item["payload"] for item in enriched]
            avg_payload = mean(payload_sizes)
            payload_std = pstdev(payload_sizes) if len(payload_sizes) > 1 else 0.0

            score = self._score_beacon_candidate(
                count=len(enriched),
                avg_interval=avg_interval,
                jitter_ratio=jitter_ratio,
                avg_payload=avg_payload,
                payload_std=payload_std,
            )

            if score >= 0.5:
                beacons.append({
                    "ip": ip,
                    "connection_count": len(enriched),
                    "avg_interval_seconds": round(avg_interval, 2),
                    "interval_jitter": round(jitter_ratio, 3),
                    "average_payload_size": round(avg_payload, 2),
                    "payload_std_dev": round(payload_std, 2),
                    "beacon_score": round(score, 2),
                    "first_seen": enriched[0]["timestamp"],
                    "last_seen": enriched[-1]["timestamp"],
                    "likely_c2": score >= 0.8,
                })

        return beacons

    def detect_c2_communication(self, beacon_candidates: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """Derive C2 indicators from HTTP patterns and aggregate flow behaviour."""
        if beacon_candidates is None:
            beacon_candidates = self._last_beacon_results or self.detect_beaconing()

        beacon_index = {item.get("ip"): item for item in beacon_candidates if item.get("ip")}
        indicators: List[Dict[str, Any]] = []

        indicators.extend(self._find_http_c2_patterns())

        connection_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for conn in self.connections:
            remote_ip = conn.get("remote_ip")
            if not remote_ip:
                continue
            connection_groups[remote_ip].append(conn)

        self._flow_stats = {}
        for ip, group in connection_groups.items():
            summary = self._summarize_flow(group)
            if not summary:
                continue

            score, metrics = summary
            if ip in beacon_index:
                score = min(score + 0.2, 1.0)
                metrics["beacon_correlation"] = beacon_index[ip].get("beacon_score")

            self._flow_stats[ip] = metrics

            if score >= 0.6:
                indicators.append({
                    "type": "connection_pattern",
                    "ip": ip,
                    "score": round(score, 2),
                    "metrics": metrics,
                    "likely_c2": score >= 0.8,
                })

        return indicators

    def _find_http_c2_patterns(self) -> List[Dict[str, Any]]:
        indicators: List[Dict[str, Any]] = []
        if not self.http_requests:
            return indicators

        c2_url_patterns = [
            r"/panel/[a-z0-9]{16,}",
            r"/gate\.php",
            r"/api/v\d+/[A-Za-z0-9]{10,}",
            r"/[A-Za-z0-9]{16,}/checkin",
        ]
        suspicious_headers = {"x-callback-id", "x-implant-id", "x-operator", "x-session-id"}

        for req in self.http_requests:
            url = req.get("url", "") or ""
            method = (req.get("method") or "").upper()
            score = 0.0
            reasons: List[str] = []

            for pattern in c2_url_patterns:
                if re.search(pattern, url):
                    score += 0.5
                    reasons.append(f"URL matches pattern {pattern}")
                    break

            user_agent = req.get("user_agent", "")
            if user_agent and self._is_suspicious_user_agent(user_agent):
                score += 0.2
                reasons.append("Suspicious User-Agent")

            headers_obj = req.get("headers")
            if isinstance(headers_obj, dict):
                header_blob = "\n".join(f"{k}: {v}" for k, v in headers_obj.items())
            else:
                header_blob = str(req.get("raw_request") or req.get("raw_headers") or "")

            host = req.get("host") or self._extract_http_header(header_blob, "Host")

            header_blob_lower = header_blob.lower()
            if any(h in header_blob_lower for h in suspicious_headers):
                score += 0.15
                reasons.append("Custom callback headers present")

            body_size = req.get("body_size", 0) or 0
            if method == "POST" and 0 < body_size < 1024:
                score += 0.1
                reasons.append("Tiny POST body typical for beacon profile")

            if score >= 0.5:
                indicators.append({
                    "type": "http_pattern",
                    "url": url,
                    "method": method,
                    "host": host,
                    "score": round(min(score, 1.0), 2),
                    "reasons": reasons,
                })

        return indicators

    def _summarize_flow(self, flow: List[Dict[str, Any]]) -> Optional[Tuple[float, Dict[str, Any]]]:
        if len(flow) < 3:
            return None

        valid_records = []
        ports = set()
        for entry in flow:
            timestamp = entry.get("timestamp")
            if not timestamp:
                continue
            try:
                dt_obj = datetime.fromisoformat(timestamp)
            except Exception:
                logger.debug("[flow] invalid timestamp: %s", timestamp)
                continue
            sent = max(entry.get("bytes_sent", 0), 0)
            recv = max(entry.get("bytes_recv", 0), 0)
            ports.add(entry.get("remote_port"))
            valid_records.append({
                "dt": dt_obj,
                "timestamp": timestamp,
                "bytes_sent": sent,
                "bytes_recv": recv,
            })

        if len(valid_records) < 3:
            return None

        valid_records.sort(key=lambda item: item["dt"])
        intervals = [
            (valid_records[i]["dt"] - valid_records[i - 1]["dt"]).total_seconds()
            for i in range(1, len(valid_records))
        ]

        avg_interval = mean(intervals) if intervals else 0.0
        interval_jitter = (pstdev(intervals) / avg_interval) if len(intervals) > 1 and avg_interval else 1.0

        payloads = [rec["bytes_sent"] + rec["bytes_recv"] for rec in valid_records]
        avg_payload = mean(payloads)
        payload_std = pstdev(payloads) if len(payloads) > 1 else 0.0

        total_sent = sum(rec["bytes_sent"] for rec in valid_records)
        total_recv = sum(rec["bytes_recv"] for rec in valid_records)
        total_bytes = total_sent + total_recv
        direction_ratio = (total_sent / total_bytes) if total_bytes else 0.5

        duration_seconds = (valid_records[-1]["dt"] - valid_records[0]["dt"]).total_seconds()

        score = 0.0
        if len(valid_records) >= 10:
            score += 0.25
        elif len(valid_records) >= 6:
            score += 0.15
        if avg_interval and avg_interval <= 600:
            score += 0.15
        if interval_jitter <= 0.25:
            score += 0.2
        elif interval_jitter <= 0.4:
            score += 0.1
        if avg_payload <= 1024:
            score += 0.15
        if payload_std <= max(avg_payload * 0.3, 120):
            score += 0.1
        if ports and len([p for p in ports if p]) <= 2:
            score += 0.05
        if direction_ratio <= 0.2 or direction_ratio >= 0.8:
            score += 0.1

        metrics = {
            "connection_count": len(valid_records),
            "avg_interval_seconds": round(avg_interval, 2),
            "interval_jitter": round(interval_jitter, 3),
            "avg_payload_size": round(avg_payload, 2),
            "payload_std_dev": round(payload_std, 2),
            "unique_ports": sorted(p for p in ports if p),
            "duration_seconds": round(duration_seconds, 2),
            "bytes_sent_total": int(total_sent),
            "bytes_recv_total": int(total_recv),
            "direction_ratio": round(direction_ratio, 3),
        }

        return min(score, 1.0), metrics

    def _score_beacon_candidate(
        self,
        *,
        count: int,
        avg_interval: float,
        jitter_ratio: float,
        avg_payload: float,
        payload_std: float,
    ) -> float:
        score = 0.0
        if count >= 10:
            score += 0.3
        elif count >= 6:
            score += 0.2
        if avg_interval and avg_interval <= 600:
            score += 0.2
        if jitter_ratio <= 0.1:
            score += 0.3
        elif jitter_ratio <= 0.2:
            score += 0.2
        if avg_payload <= 1024:
            score += 0.15
        if payload_std <= max(avg_payload * 0.25, 120):
            score += 0.15
        return min(score, 1.0)

    @staticmethod
    def _extract_http_header(header_blob: str, header_name: str) -> str:
        if not header_blob:
            return ""
        pattern = re.compile(rf"^{re.escape(header_name)}:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
        match = pattern.search(header_blob)
        return match.group(1).strip() if match else ""

    @staticmethod
    def _safe_decode_bytes(data: bytes) -> str:
        for encoding in ("utf-8", "latin-1"):
            try:
                return data.decode(encoding)
            except Exception:
                continue
        return ""

    def parse_pcap(self, pcap_path: str) -> Dict[str, List[Dict[str, Any]]]:
        parsed = {"connections": [], "dns": [], "http": []}
        if not pcap_path or not os.path.isfile(pcap_path):
            logger.error("PCAP file not found: %s", pcap_path)
            return parsed
        try:
            from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, rdpcap  # type: ignore
        except ImportError:
            logger.warning("scapy is not installed; PCAP parsing skipped")
            return parsed
        try:
            packets = rdpcap(pcap_path)
        except Exception as exc:
            logger.error("Failed to read PCAP %s: %s", pcap_path, exc)
            return parsed

        flow_map: Dict[Tuple[str, str, int, int, str], Dict[str, Any]] = {}
        dns_entries: List[Dict[str, Any]] = []
        http_entries: List[Dict[str, Any]] = []

        for pkt in packets:
            if IP not in pkt:
                continue
            ip_layer = pkt[IP]
            protocol = "TCP" if TCP in pkt else "UDP" if UDP in pkt else str(ip_layer.proto)
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = int(pkt[TCP].sport) if TCP in pkt else int(pkt[UDP].sport) if UDP in pkt else 0
            dst_port = int(pkt[TCP].dport) if TCP in pkt else int(pkt[UDP].dport) if UDP in pkt else 0
            timestamp = datetime.utcfromtimestamp(float(pkt.time)).isoformat()

            key = (src_ip, dst_ip, src_port, dst_port, protocol)
            flow = flow_map.setdefault(key, {
                "source_ip": src_ip,
                "source_port": src_port,
                "remote_ip": dst_ip,
                "remote_port": dst_port,
                "protocol": protocol,
                "bytes_outbound": 0,
                "packet_count": 0,
                "first_seen": timestamp,
                "last_seen": timestamp,
            })
            flow["bytes_outbound"] += len(pkt)
            flow["packet_count"] += 1
            flow["last_seen"] = timestamp

            if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
                try:
                    qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                except Exception:
                    qname = str(pkt[DNSQR].qname)
                dns_entries.append({"domain": qname, "type": pkt[DNSQR].qtype})

            if TCP in pkt and Raw in pkt:
                payload_text = self._safe_decode_bytes(bytes(pkt[Raw].load))
                if payload_text and re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s", payload_text):
                    http_entries.append({
                        "method": payload_text.split()[0],
                        "url": payload_text.split()[1] if len(payload_text.split()) > 1 else "",
                        "timestamp": timestamp,
                        "host": self._extract_http_header(payload_text, "Host"),
                        "user_agent": self._extract_http_header(payload_text, "User-Agent"),
                        "body_size": len(pkt[Raw].load),
                        "raw_request": payload_text[:2048],
                    })

        processed: set = set()
        connections: List[Dict[str, Any]] = []
        for key, flow in flow_map.items():
            if key in processed:
                continue
            reverse_key = (key[1], key[0], key[3], key[2], key[4])
            reverse_flow = flow_map.get(reverse_key)
            processed.add(key)
            processed.add(reverse_key)

            bytes_recv = reverse_flow["bytes_outbound"] if reverse_flow else 0
            first_seen = min(flow["first_seen"], reverse_flow["first_seen"]) if reverse_flow else flow["first_seen"]
            last_seen = max(flow["last_seen"], reverse_flow["last_seen"]) if reverse_flow else flow["last_seen"]

            connections.append({
                "source_ip": flow["source_ip"],
                "source_port": flow["source_port"],
                "remote_ip": flow["remote_ip"],
                "remote_port": flow["remote_port"],
                "protocol": flow["protocol"],
                "bytes_sent": flow["bytes_outbound"],
                "bytes_recv": bytes_recv,
                "packet_count": flow["packet_count"] + (reverse_flow["packet_count"] if reverse_flow else 0),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "timestamp": last_seen,
            })

        parsed["connections"] = connections
        parsed["dns"] = dns_entries
        parsed["http"] = http_entries
        return parsed

    def analyze_dns(self, dns_queries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Анализ DNS запросов"""
        self.dns_queries = dns_queries

        results = {
            "total_queries": len(dns_queries),
            "unique_domains": set(),
            "suspicious_domains": [],
            "dga_candidates": [],
            "dns_tunneling_detected": []
        }

        for query in dns_queries:
            domain = query.get("domain", "")
            results["unique_domains"].add(domain)

            # DGA detection
            if self._is_dga_domain(domain):
                results["dga_candidates"].append(domain)

            # DNS tunneling detection
            if self._is_dns_tunneling(query):
                results["dns_tunneling_detected"].append({
                    "domain": domain,
                    "query_type": query.get("type", ""),
                    "reason": "Suspiciously long subdomain or high entropy"
                })

        results["unique_domains"] = list(results["unique_domains"])

        return results

    def _is_dga_domain(self, domain: str) -> bool:
        """Детектирование DGA (Domain Generation Algorithm)"""
        # Удаляем TLD
        domain_parts = domain.split(".")
        if len(domain_parts) < 2:
            return False

        sld = domain_parts[-2]  # Second-level domain

        # Эвристики DGA:
        # 1. Длина > 10 символов
        # 2. Мало гласных
        # 3. Высокая энтропия

        if len(sld) < 10:
            return False

        vowels = "aeiou"
        vowel_count = sum(1 for c in sld.lower() if c in vowels)
        vowel_ratio = vowel_count / len(sld)

        # Низкий процент гласных = подозрительно
        if vowel_ratio < 0.2:
            return True

        return False

    def _is_dns_tunneling(self, query: Dict[str, Any]) -> bool:
        """Детектирование DNS tunneling"""
        domain = query.get("domain", "")

        # DNS tunneling часто использует длинные поддомены
        parts = domain.split(".")
        for part in parts[:-2]:  # Исключаем TLD и SLD
            if len(part) > 50:  # Подозрительно длинный поддомен
                return True

        return False

    def analyze_http_traffic(self, http_requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Анализ HTTP/HTTPS трафика"""
        self.http_requests = http_requests

        results = {
            "total_requests": len(http_requests),
            "methods": Counter(),
            "user_agents": Counter(),
            "suspicious_headers": [],
            "data_exfiltration": []
        }

        for req in http_requests:
            method = req.get("method", "GET")
            results["methods"][method] += 1

            user_agent = req.get("user_agent", "")
            results["user_agents"][user_agent] += 1

            # Подозрительные User-Agent
            if self._is_suspicious_user_agent(user_agent):
                results["suspicious_headers"].append({
                    "type": "Suspicious User-Agent",
                    "value": user_agent,
                    "url": req.get("url", "")
                })

            # Детект exfiltration (большие POST запросы)
            if method == "POST" and req.get("body_size", 0) > 1024 * 100:  # > 100KB
                results["data_exfiltration"].append({
                    "url": req.get("url", ""),
                    "size_kb": req.get("body_size", 0) // 1024,
                    "timestamp": req.get("timestamp", "")
                })

        return results

    def _is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Проверка подозрительного User-Agent"""
        suspicious_patterns = [
            "python",
            "curl",
            "wget",
            "powershell",
            "scanner",
            "bot"
        ]

        ua_lower = user_agent.lower()
        return any(pattern in ua_lower for pattern in suspicious_patterns)

    def _calculate_std_dev(self, values: List[float], mean: float) -> float:
        """Вычисление стандартного отклонения"""
        if not values:
            return 0.0

        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance ** 0.5


def analyze_pcap_file(pcap_path: str) -> Dict[str, Any]:
    """Parse a PCAP file and return the enriched ThreatInquisitor analysis."""
    analyzer = NetworkAnalyzer()
    parsed = analyzer.parse_pcap(pcap_path)
    return {
        "connections": analyzer.analyze_connections(parsed.get("connections", [])),
        "dns": analyzer.analyze_dns(parsed.get("dns", [])),
        "http": analyzer.analyze_http_traffic(parsed.get("http", [])),
    }

def analyze_network_traffic(connections: List[Dict[str, Any]],
                            dns_queries: List[Dict[str, Any]] = None,
                            http_requests: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Быстрая функция для сетевого анализа"""
    analyzer = NetworkAnalyzer()

    results = {
        "connections": analyzer.analyze_connections(connections),
        "dns": {},
        "http": {}
    }

    if dns_queries:
        results["dns"] = analyzer.analyze_dns(dns_queries)

    if http_requests:
        results["http"] = analyzer.analyze_http_traffic(http_requests)

    return results


if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO)

    # Тестовые данные
    test_connections = [
        {"remote_ip": "192.168.1.100", "remote_port": 4444, "protocol": "TCP", "timestamp": "2025-01-01T10:00:00"},
        {"remote_ip": "192.168.1.100", "remote_port": 4444, "protocol": "TCP", "timestamp": "2025-01-01T10:01:00"},
        {"remote_ip": "192.168.1.100", "remote_port": 4444, "protocol": "TCP", "timestamp": "2025-01-01T10:02:00"}
    ]

    test_dns = [
        {"domain": "xjkdfjkdfjkd.com", "type": "A"},
        {"domain": "verylongsubdomainthatislongerthan50charactersforsureabc123.evil.com", "type": "TXT"}
    ]

    print("=== Network Analysis ===")
    results = analyze_network_traffic(test_connections, test_dns)
    print(json.dumps(results, indent=2, default=list))
