from __future__ import annotations

from abc import ABC, abstractmethod

from src.core.http_models import DetectionAlert, HTTPLogEvent

_STATIC_METHODS = frozenset({"GET", "HEAD"})
_STATIC_DIRECTORIES = frozenset(
    {"assets", "static", "media", "uploads", "images", "img", "css", "js", "fonts", "vendor"}
)
_STATIC_EXTENSIONS = frozenset(
    {
        ".css",
        ".js",
        ".mjs",
        ".cjs",
        ".map",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".webp",
        ".avif",
        ".ico",
        ".bmp",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".mp4",
        ".webm",
        ".ogg",
        ".mp3",
        ".wav",
        ".pdf",
    }
)
_STATIC_ROOT_FILES = frozenset(
    {
        "/favicon.ico",
        "/robots.txt",
        "/sitemap.xml",
        "/manifest.webmanifest",
        "/site.webmanifest",
        "/browserconfig.xml",
        "/apple-touch-icon.png",
    }
)
_DYNAMIC_PREFIXES = frozenset({"api", "auth", "login", "logout", "ingest-event"})
_MOUNT_PREFIXES = frozenset({"siem"})


def is_static_asset(event: HTTPLogEvent) -> bool:
    """True only for browser asset GETs. Anything ambiguous counts as dynamic."""
    if event.method.upper() not in _STATIC_METHODS:
        return False

    segments = [segment.lower() for segment in event.endpoint.split("/") if segment]
    if not segments:
        return False
    if any(segment in {".", ".."} or "%2e" in segment for segment in segments):
        return False
    if segments[0] in _MOUNT_PREFIXES and len(segments) > 1:
        segments = segments[1:]
    if segments[0] in _DYNAMIC_PREFIXES:
        return False
    if len(segments) == 1:
        return f"/{segments[0]}" in _STATIC_ROOT_FILES
    if segments[0] not in _STATIC_DIRECTORIES:
        return False

    filename = segments[-1]
    extension_at = filename.rfind(".")
    return extension_at > 0 and filename[extension_at:] in _STATIC_EXTENSIONS


class Detector(ABC):
    @abstractmethod
    def evaluate(self, event: HTTPLogEvent) -> list[DetectionAlert]:
        raise NotImplementedError
