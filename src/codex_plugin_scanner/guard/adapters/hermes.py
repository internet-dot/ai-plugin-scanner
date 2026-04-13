"""Hermes harness adapter.

Discovers Hermes skills (SKILL.md + subdirectory files) and MCP servers
configured in ~/.hermes/config.yaml or ~/.hermes/mcp_servers.json.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from ..models import GuardArtifact, HarnessDetection
from .base import HarnessAdapter, HarnessContext, _command_available, _json_payload

# Optional: PyYAML is preferred when available for robust YAML parsing.
# The adapter works without it via a line-based fallback parser.
try:
    import yaml as _yaml  # type: ignore[import-untyped]

    _HAS_PYYAML = True
except ImportError:
    _yaml = None  # type: ignore[assignment]
    _HAS_PYYAML = False

# Subdirectories within a skill that may contain executable or injectable content.
_SKILL_SUBDIRS = ("references", "templates", "scripts", "assets")

# File extensions whose content is scanned for risk signals.
_SCANNABLE_EXTENSIONS = {
    ".md",
    ".txt",
    ".py",
    ".sh",
    ".bash",
    ".js",
    ".ts",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".cfg",
    ".ini",
    ".env",
}

# Filenames (no extension) that should be scanned in skill subdirectories.
_SCANNABLE_NAMES = {".env", "Makefile", "Dockerfile", "Procfile"}

# Maximum bytes read from any single file for risk analysis.
_MAX_FILE_READ = 64 * 1024


class HermesHarnessAdapter(HarnessAdapter):
    """Discover Hermes skills and MCP servers."""

    harness = "hermes"
    executable = "hermes"
    approval_tier = "approval-center"
    approval_summary = (
        "Guard can scan Hermes skills before execution and hand blocked artifacts to the local approval center."
    )
    fallback_hint = "Configure Hermes to use Guard-launched sessions for skill execution."

    def detect(self, context: HarnessContext) -> HarnessDetection:
        hermes_home = context.home_dir / ".hermes"
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []

        # Detect Hermes installation signals.
        for config_name in ("config.yaml", "config.toml"):
            config_path = hermes_home / config_name
            if config_path.is_file():
                found_paths.append(str(config_path))

        # Discover skills in ~/.hermes/skills/<category>/<skill>/
        skills_dir = hermes_home / "skills"
        if skills_dir.is_dir():
            try:
                category_dirs = sorted(skills_dir.iterdir())
            except (PermissionError, OSError):
                category_dirs = []
            for category_dir in category_dirs:
                if not category_dir.is_dir():
                    continue
                try:
                    skill_dirs = sorted(category_dir.iterdir())
                except (PermissionError, OSError):
                    continue
                for skill_dir in skill_dirs:
                    if not skill_dir.is_dir():
                        continue
                    skill_md = skill_dir / "SKILL.md"
                    if not skill_md.is_file():
                        continue
                    found_paths.append(str(skill_md))
                    artifacts.extend(self._scan_skill(category_dir, skill_dir, skill_md))

        # Discover MCP servers from both config.yaml and mcp_servers.json.
        artifacts.extend(self._scan_mcp_servers(hermes_home, found_paths))

        return HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or _command_available(self.executable),
            command_available=_command_available(self.executable),
            artifacts=tuple(artifacts),
            config_paths=tuple(found_paths),
        )

    # ------------------------------------------------------------------
    # Skill scanning
    # ------------------------------------------------------------------

    def _scan_skill(
        self,
        category_dir: Path,
        skill_dir: Path,
        skill_md: Path,
    ) -> list[GuardArtifact]:
        """Produce artifacts for SKILL.md and any scannable subdirectory files."""
        artifacts: list[GuardArtifact] = []

        content = _safe_read(skill_md)
        frontmatter = _parse_frontmatter(content)
        code_blocks = _extract_code_blocks(content)

        skill_name = frontmatter.get("name") or skill_dir.name
        description = frontmatter.get("description", "")
        related = frontmatter.get("related_skills", "")

        content_hash = _content_hash(content)
        env_mentions = _extract_env_mentions(content)

        metadata: dict[str, object] = {
            "category": category_dir.name,
            "description": description[:200] if description else "",
            "content_hash": content_hash,
            "has_code_blocks": bool(code_blocks),
            "related_skills": related,
            "env_mentions": sorted(env_mentions),
        }

        # Include non-fenced SKILL.md content in args for risk analysis
        # when no code blocks are present.  Many skills embed instructions
        # or inline commands in plain markdown rather than fenced blocks.
        risk_args = tuple(code_blocks) if code_blocks else ()
        if not risk_args and content.strip():
            risk_args = (content.strip()[:2048],)

        artifacts.append(
            GuardArtifact(
                artifact_id=f"hermes:skill:{category_dir.name}:{skill_dir.name}",
                name=skill_name,
                harness=self.harness,
                artifact_type="skill",
                source_scope="global",
                config_path=str(skill_md),
                command=str(skill_md),
                url=None,
                transport=None,
                args=risk_args,
                metadata=metadata,
            )
        )

        # Scan subdirectory files (references, templates, scripts, assets).
        for subdir_name in _SKILL_SUBDIRS:
            subdir = skill_dir / subdir_name
            if not subdir.is_dir():
                continue
            try:
                sub_files = sorted(subdir.rglob("*"))
            except (PermissionError, OSError):
                continue
            for file_path in sub_files:
                if not file_path.is_file():
                    continue
                if not _is_scannable(file_path):
                    continue
                file_content = _safe_read(file_path)
                if not file_content:
                    continue
                file_blocks = _extract_code_blocks(file_content)
                file_env = _extract_env_mentions(file_content)
                rel_path = file_path.relative_to(skill_dir)

                # Include raw file content in args when no fenced code blocks
                # exist, so that plain .sh/.py scripts are visible to risk
                # signal analysis.  Truncate to avoid oversized artifacts.
                file_risk_args = tuple(file_blocks) if file_blocks else ()
                if not file_risk_args and file_content.strip():
                    file_risk_args = (file_content.strip()[:2048],)

                artifacts.append(
                    GuardArtifact(
                        artifact_id=(f"hermes:skill:{category_dir.name}:{skill_dir.name}:{rel_path}"),
                        name=f"{skill_name}/{rel_path}",
                        harness=self.harness,
                        artifact_type="skill_file",
                        source_scope="global",
                        config_path=str(file_path),
                        command=str(file_path),
                        url=None,
                        transport=None,
                        args=file_risk_args,
                        metadata={
                            "parent_skill": skill_name,
                            "subdir": subdir_name,
                            "content_hash": _content_hash(file_content),
                            "has_code_blocks": bool(file_blocks),
                            "env_mentions": sorted(file_env),
                        },
                    )
                )

        return artifacts

    # ------------------------------------------------------------------
    # MCP server scanning
    # ------------------------------------------------------------------

    def _scan_mcp_servers(
        self,
        hermes_home: Path,
        found_paths: list[str],
    ) -> list[GuardArtifact]:
        """Read MCP server configs from config.yaml and mcp_servers.json."""
        artifacts: list[GuardArtifact] = []

        # Source 1: config.yaml (primary Hermes config).
        yaml_path = hermes_home / "config.yaml"
        if yaml_path.is_file():
            found_paths.append(str(yaml_path))
            yaml_servers = _parse_mcp_from_yaml(yaml_path)
            artifacts.extend(self._mcp_artifacts(yaml_servers, str(yaml_path), source="yaml"))

        # Source 2: mcp_servers.json (legacy / alternative).
        json_path = hermes_home / "mcp_servers.json"
        if json_path.is_file():
            found_paths.append(str(json_path))
            json_servers = _parse_mcp_from_json(json_path)
            artifacts.extend(self._mcp_artifacts(json_servers, str(json_path), source="json"))

        return artifacts

    def _mcp_artifacts(
        self,
        servers: dict[str, dict[str, object]],
        config_path: str,
        *,
        source: str,
    ) -> list[GuardArtifact]:
        """Convert parsed MCP server dicts into GuardArtifacts."""
        artifacts: list[GuardArtifact] = []
        for name, server_config in servers.items():
            if not isinstance(name, str) or not isinstance(server_config, dict):
                continue

            # Skip disabled MCP servers unless explicitly enabled (default True).
            enabled = server_config.get("enabled", True)
            if enabled is False:
                continue

            command = server_config.get("command")
            url = server_config.get("url")
            args = server_config.get("args", [])
            env = server_config.get("env", {})
            headers = server_config.get("headers", {})
            sampling = server_config.get("sampling")

            if not isinstance(args, list):
                args = []
            if not isinstance(env, dict):
                env = {}
            if not isinstance(headers, dict):
                headers = {}

            args_tuple = tuple(str(a) for a in args if isinstance(a, str))
            transport = "http" if isinstance(url, str) else "stdio"

            # Filter non-string keys before sorting to avoid TypeError.
            header_keys = [k for k in headers if isinstance(k, str)]
            auth_header_keys = [
                k for k in header_keys if any(t in k.lower() for t in ("auth", "token", "key", "secret", "bearer"))
            ]

            sampling_enabled = None
            sampling_model = None
            if isinstance(sampling, dict):
                sampling_enabled = sampling.get("enabled", True)
                sampling_model = sampling.get("model")

            # Filter env keys to strings before sorting.
            env_str_keys = sorted(k for k in env if isinstance(k, str))

            metadata: dict[str, object] = {
                "source": source,
                "env_keys": env_str_keys,
                "header_keys": sorted(header_keys),
                "auth_header_keys": sorted(auth_header_keys),
                "sampling_enabled": sampling_enabled,
                "sampling_model": sampling_model,
                "has_env_secrets": bool(env),
                "has_auth_headers": bool(auth_header_keys),
            }

            env_value_hints = [
                k for k, v in env.items() if isinstance(k, str) and isinstance(v, str) and _looks_like_secret(v)
            ]
            if env_value_hints:
                metadata["env_value_secret_keys"] = sorted(env_value_hints)

            header_value_hints = [
                k for k, v in headers.items() if isinstance(k, str) and isinstance(v, str) and _looks_like_secret(v)
            ]
            if header_value_hints:
                metadata["header_value_secret_keys"] = sorted(header_value_hints)

            # Include source in artifact_id to prevent collisions when the
            # same server name appears in both config.yaml and mcp_servers.json.
            artifacts.append(
                GuardArtifact(
                    artifact_id=f"hermes:mcp:{source}:{name}",
                    name=name,
                    harness=self.harness,
                    artifact_type="mcp_server",
                    source_scope="global",
                    config_path=config_path,
                    command=command if isinstance(command, str) else None,
                    url=url if isinstance(url, str) else None,
                    transport=transport,
                    args=args_tuple,
                    metadata=metadata,
                )
            )

        return artifacts


# ------------------------------------------------------------------
# Module-level helpers (no dependency on adapter instance)
# ------------------------------------------------------------------


def _is_scannable(file_path: Path) -> bool:
    """Check whether a file should be scanned based on extension or name."""
    if file_path.suffix.lower() in _SCANNABLE_EXTENSIONS:
        return True
    # Extensionless files with known names (e.g. .env, Makefile, deploy).
    if not file_path.suffix:
        name = file_path.name
        if name in _SCANNABLE_NAMES:
            return True
        # Files in scripts/ subdirs without extension are likely shell scripts.
        for subdir in ("scripts",):
            if subdir in file_path.parts:
                return True
    return False


def _parse_frontmatter(content: str) -> dict[str, object]:
    """Parse YAML frontmatter from SKILL.md content.

    Prefers PyYAML when available for correct nested-structure handling.
    Falls back to a simple line-based parser that extracts top-level keys.
    """
    if not content.startswith("---"):
        return {}
    parts = content[3:].split("---", 1)
    if len(parts) != 2:
        return {}
    raw = parts[0].strip()

    # Try PyYAML first for robust nested-structure support.
    if _HAS_PYYAML:
        try:
            parsed = _yaml.safe_load(raw)  # type: ignore[union-attr]
            if isinstance(parsed, dict):
                # Flatten values to strings for consistent downstream handling.
                return {k: _flatten_yaml_value(v) for k, v in parsed.items()}
        except Exception:
            pass

    # Fallback: simple line-based parser for top-level keys only.
    frontmatter: dict[str, object] = {}
    for line in raw.split("\n"):
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        frontmatter[key.strip()] = value.strip()
    return frontmatter


def _flatten_yaml_value(value: object) -> str:
    """Convert a parsed YAML value to a flat string for frontmatter metadata."""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    if isinstance(value, dict):
        return str(value)
    return str(value)


def _extract_code_blocks(content: str) -> list[str]:
    """Extract code blocks from markdown for risk analysis."""
    blocks: list[str] = []
    pattern = r"```[^\n]*\n(.*?)\n?```"
    for match in re.finditer(pattern, content, re.DOTALL):
        code = match.group(1).strip()
        if code:
            blocks.append(code)
    return blocks


def _extract_env_mentions(content: str) -> list[str]:
    """Find environment variable references like ${VAR}, os.environ['VAR'], process.env.VAR."""
    mentions: set[str] = set()
    for m in re.finditer(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", content):
        mentions.add(m.group(1))
    # os.environ.get('VAR') and os.getenv('VAR')
    for m in re.finditer(r"os\.(?:environ(?:\.get)?|getenv)\(['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\)", content):
        mentions.add(m.group(1))
    # os.environ['VAR'] and os.environ["VAR"]
    for m in re.finditer(r"os\.environ\[(['\"])([A-Za-z_][A-Za-z0-9_]*)\1\]", content):
        mentions.add(m.group(2))
    for m in re.finditer(r"process\.env\.([A-Za-z_][A-Za-z0-9_]*)", content):
        mentions.add(m.group(1))
    return sorted(mentions)


def _content_hash(content: str) -> str:
    """Deterministic hash for change detection (truncated SHA-256)."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def _safe_read(path: Path) -> str:
    """Read file content with error handling."""
    try:
        return path.read_text(encoding="utf-8")[:_MAX_FILE_READ]
    except (OSError, UnicodeDecodeError):
        return ""


def _looks_like_secret(value: str) -> bool:
    """Heuristic: does this value look like a secret/token?"""
    if len(value) < 8:
        return False
    lower = value.lower()
    secret_prefixes = (
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "sk-",
        "sk_",
        "xai-",
        "key-",
        "key_",
        "tok_",
        "token_",
    )
    return bool(
        any(lower.startswith(p) for p in secret_prefixes)
        or lower.startswith("bearer ")
        or re.fullmatch(r"[A-Za-z0-9+/=_-]{20,}", value)
    )


def _unquote(value: str) -> str:
    """Remove surrounding quotes from a YAML value."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        return value[1:-1]
    return value


def _parse_mcp_from_yaml(yaml_path: Path) -> dict[str, dict[str, object]]:
    """Extract mcp_servers entries from config.yaml.

    Uses PyYAML when available for full nested-structure support.
    Falls back to a line-based indent parser that handles env/headers
    blocks by tracking nesting depth.
    """
    # Try PyYAML first for robust parsing.
    if _HAS_PYYAML:
        try:
            content = _safe_read(yaml_path)
            if not content:
                return {}
            parsed = _yaml.safe_load(content)  # type: ignore[union-attr]
            if not isinstance(parsed, dict):
                return {}
            mcp = parsed.get("mcp_servers")
            if not isinstance(mcp, dict):
                return {}
            # Normalise to plain dicts with string keys.
            servers: dict[str, dict[str, object]] = {}
            for name, config in mcp.items():
                if isinstance(name, str) and isinstance(config, dict):
                    servers[name] = config
            return servers
        except Exception:
            pass

    # Fallback: indent-aware line-based parser.
    return _parse_mcp_yaml_fallback(yaml_path)


def _parse_mcp_yaml_fallback(yaml_path: Path) -> dict[str, dict[str, object]]:
    """Line-based YAML parser with indent tracking for nested env/headers blocks."""
    content = _safe_read(yaml_path)
    if not content:
        return {}

    servers: dict[str, dict[str, object]] = {}
    lines = content.splitlines()
    in_mcp_section = False
    current_server: str | None = None
    server_indent = 0
    # Track which nested block we are inside (e.g. "env", "headers", "sampling").
    nested_block: str | None = None
    nested_indent = 0
    # Track block-style args list (args:\n  - value1\n  - value2).
    in_args_block = False
    args_indent = 0

    for line in lines:
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(stripped)

        if stripped.startswith("mcp_servers:") and indent == 0:
            in_mcp_section = True
            current_server = None
            nested_block = None
            in_args_block = False
            continue

        if indent == 0 and in_mcp_section:
            in_mcp_section = False
            current_server = None
            nested_block = None
            in_args_block = False
            continue

        if not in_mcp_section:
            continue

        # Server name line: any key ending with ":" that is deeper than
        # the mcp_servers: line but shallower than server properties.
        if (
            stripped.endswith(":")
            and not stripped.startswith("-")
            and (current_server is None or indent <= server_indent)
        ):
            server_name = stripped.rstrip(":").strip()
            if server_name and server_name not in ("mcp_servers",):
                current_server = server_name
                server_indent = indent
                servers[server_name] = {}
                nested_block = None
                in_args_block = False
                continue

        if not current_server or indent <= server_indent:
            nested_block = None
            in_args_block = False
            continue

        # Check for nested block headers (env:, headers:, sampling:).
        if stripped.endswith(":") and stripped.count(":") == 1:
            block_name = stripped.rstrip(":").strip()
            if block_name in ("env", "headers", "sampling"):
                nested_block = block_name
                nested_indent = indent
                servers[current_server].setdefault(block_name, {})
                in_args_block = False
                continue
            # args: without inline value starts a block-style list.
            if block_name == "args":
                in_args_block = True
                args_indent = indent
                servers[current_server].setdefault("args", [])
                nested_block = None
                continue

        # Inside a block-style args list (  - value1).
        if in_args_block and indent > args_indent and stripped.startswith("- "):
            arg_val = _unquote(stripped[2:].strip())
            servers[current_server].setdefault("args", []).append(arg_val)
            continue

        # Inside a nested block (env/headers key: value pairs).
        if nested_block and indent > nested_indent:
            if nested_block in ("env", "headers"):
                if ":" in stripped:
                    k, _, v = stripped.partition(":")
                    servers[current_server].setdefault(nested_block, {})[k.strip()] = _unquote(v.strip())
                continue
            if nested_block == "sampling":
                if ":" in stripped:
                    k, _, v = stripped.partition(":")
                    servers[current_server].setdefault("sampling", {})[k.strip()] = _unquote(v.strip())
                continue

        # Exit nested block if indent drops back.
        if nested_block and indent <= nested_indent:
            nested_block = None
        if in_args_block and indent <= args_indent:
            in_args_block = False

        # Top-level server property.
        _parse_yaml_property(stripped, servers[current_server])

    return servers


def _parse_yaml_property(line: str, target: dict[str, object]) -> None:
    """Parse a single YAML key: value property into target dict."""
    if ":" not in line:
        return
    key, _, value = line.partition(":")
    key = key.strip()
    value = value.strip()

    if key in ("command", "url"):
        target[key] = _unquote(value)
    elif key in ("enabled",):
        # Coerce common boolean representations.
        if value.lower() in ("false", "no", "off"):
            target[key] = False
        elif value.lower() in ("true", "yes", "on"):
            target[key] = True
        else:
            target[key] = _unquote(value)
    elif key == "args" and value.startswith("["):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                target[key] = parsed
        except json.JSONDecodeError:
            pass


def _parse_mcp_from_json(json_path: Path) -> dict[str, dict[str, object]]:
    """Parse MCP servers from mcp_servers.json."""
    payload = _json_payload(json_path)
    if not isinstance(payload, dict):
        return {}
    return {name: config for name, config in payload.items() if isinstance(name, str) and isinstance(config, dict)}
