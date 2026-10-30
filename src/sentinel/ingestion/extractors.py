"""IOC extraction from alert fields and free text."""

from __future__ import annotations

import ipaddress
import re

from sentinel.core.models import Alert, Observable, ObservableType

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")

# Explicit public-TLD allowlist: avoids matching file names like "report.pdf" or ".local" hosts.
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|xyz|top|info|biz|co|tk|onion|dev|app|shop|live|nz)\b"
)
URL_RE = re.compile(r"https?://[^\s\"'<>\\]{4,2048}")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


# ---  this is for ipv6 (not used yet for the futur)
def _ip_type(value: str) -> ObservableType:
    ip = ipaddress.ip_address(value)
    return ObservableType.IPV6 if ip.version == 6 else ObservableType.IPV4


def _canonical_ip(value: str) -> str:
    return str(ipaddress.ip_address(value))


# ---


def extract_from_text(text: str) -> set[Observable]:
    found: set[Observable] = set()
    for m in IPV4_RE.findall(text):
        if is_public_ip(m):
            found.add(Observable(type=ObservableType.IPV4, value=m))
    for m in IPV6_RE.findall(text):
        if is_public_ip(m):
            found.add(Observable(type=ObservableType.IPV6, value=m))
    for m in URL_RE.findall(text):
        found.add(Observable(type=ObservableType.URL, value=m.rstrip(".,);'")))
    for m in DOMAIN_RE.findall(text):
        found.add(Observable(type=ObservableType.DOMAIN, value=m.lower()))
    for m in SHA256_RE.findall(text):
        found.add(Observable(type=ObservableType.SHA256, value=m.lower()))
    for m in MD5_RE.findall(text):
        found.add(Observable(type=ObservableType.MD5, value=m.lower()))
    for m in EMAIL_RE.findall(text):
        found.add(Observable(type=ObservableType.EMAIL, value=m.lower()))
    return found


def enrich_observables(alert: Alert) -> Alert:
    """Fill alert.observables from structured fields + free text."""
    obs: set[Observable] = set(alert.observables)
    net, proc = alert.network, alert.process

    # --- replacing these two conditions with one loop for both ipv4 and ipv6
    # if net.source_ip and is_public_ip(net.source_ip):
    #     obs.add(Observable(type=ObservableType.IPV4, value=net.source_ip, role="source"))
    # if net.destination_ip and is_public_ip(net.destination_ip):
    #   obs.add(Observable(type=ObservableType.IPV4, value=net.destination_ip, role="destination"))
    for ip, role in ((net.source_ip, "source"), (net.destination_ip, "destination")):
        if ip and is_public_ip(ip):
            obs.add(Observable(type=_ip_type(ip), value=_canonical_ip(ip), role=role))
    # ---

    if net.domain:
        obs.add(
            Observable(type=ObservableType.DOMAIN, value=net.domain.lower(), role="destination")
        )
    if net.url:
        obs.add(Observable(type=ObservableType.URL, value=net.url, role="destination"))
    if proc.hash_sha256:
        obs.add(
            Observable(type=ObservableType.SHA256, value=proc.hash_sha256.lower(), role="subject")
        )
    if alert.user.username:
        obs.add(Observable(type=ObservableType.USERNAME, value=alert.user.username, role="subject"))
    if alert.host.hostname:
        obs.add(Observable(type=ObservableType.HOSTNAME, value=alert.host.hostname, role="subject"))

    blob = " ".join(filter(None, [alert.description, proc.command_line, proc.parent_command_line]))
    obs |= extract_from_text(blob)
    alert.observables = sorted(obs, key=lambda o: (o.type, o.value))
    return alert
