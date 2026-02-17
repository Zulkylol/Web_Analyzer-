from typing import Tuple


def map_http_version(version_number: int) -> Tuple[str, str]:
    versions = {
        9 : ("HTTP/0.9", "Obsolete"), 
        10: ("HTTP/1.0", "Obsolete"),
        11: ("HTTP/1.1", "Standard"),
        20: ("HTTP/2", "Modern & performant"),
    }
    return versions.get(version_number, (f"Unknown ({version_number})", "❓ Inconnu"))