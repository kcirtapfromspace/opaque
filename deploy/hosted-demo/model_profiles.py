"""Fixed operator-owned model destinations; aliases are not arbitrary URLs.

Catalog membership does not imply deployment or qualification. The Worker owns
which catalog entries may be admitted. Legacy leases always mean Gemma.
"""
from types import MappingProxyType
from typing import NamedTuple
from urllib.parse import urlsplit

LEGACY_PROFILE_ID = "gemma4-e2b"


class ModelProfile(NamedTuple):
    profile_id: str
    url: str
    model: str


PROFILES = MappingProxyType({
    "gemma4-e2b": ModelProfile("gemma4-e2b", "http://llama-server.gemma4.svc.cluster.local:8080/",
                               "gemma-4-E2B-it-Q3_K_M.gguf"),
    "qwen35-4b": ModelProfile("qwen35-4b", "http://llama-server-qwen35.opaque-models.svc.cluster.local:8080/",
                              "Qwen3.5-4B-Q4_K_M.gguf"),
    "qwen3-14b": ModelProfile("qwen3-14b", "http://llamacpp-head.nvidia-system.svc.cluster.local:8080/",
                              "Qwen3-14B-Q4_K_M.gguf"),
})


def profile(profile_id):
    if not isinstance(profile_id, str) or profile_id not in PROFILES:
        raise ValueError("unapproved demo model profile")
    return PROFILES[profile_id]


def runtime_binding(profile_id, model_url, model_name, test_origin=None):
    """Validate exact production pair or an explicitly selected local test hop.

    The test override must be absent from admitted production Pod environments.
    Even a test hop may not change the profile's actual model identifier.
    """
    selected = profile(profile_id)
    if model_name != selected.model:
        raise ValueError("demo model profile/name mismatch")
    if test_origin is None:
        if model_url != selected.url:
            raise ValueError("demo model profile/destination mismatch")
    else:
        if not isinstance(test_origin, str) or model_url != test_origin:
            raise ValueError("invalid model test origin")
        try:
            origin = urlsplit(test_origin)
            if (origin.scheme != "http" or origin.hostname not in {"127.0.0.1", "host.docker.internal"}
                    or origin.username or origin.password or origin.query or origin.fragment
                    or origin.port is None or not 1024 <= origin.port <= 65535
                    or test_origin != f"http://{origin.hostname}:{origin.port}/"):
                raise ValueError()
        except ValueError:
            raise ValueError("invalid model test origin") from None
    return selected, urlsplit(model_url)
