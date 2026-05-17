"""Project configuration loading.

The standalone schema is target-oriented, but this module also understands the
legacy verification.json shape used by the initial extraction source. That keeps
the first migration incremental: projects can adopt the package before moving
their config files.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_CONFIG_PATH = "binary-comp.json"


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class BuildConfig:
    clean: str | None = None
    build: str | None = None
    jobs: int = 1


@dataclass(frozen=True)
class ProjectTarget:
    name: str
    original_exe: str
    rebuilt_exe: str
    map_path: str
    source_dirs: tuple[str, ...]
    globals_source: str | None = None
    code_dir: str | None = None
    map_skip: str | None = None
    build: BuildConfig = BuildConfig()
    values_policy: str | None = None


def load_json(path: str | os.PathLike[str] | None) -> dict[str, Any]:
    if not path:
        return {}
    if not os.path.exists(path):
        raise ConfigError(f"config file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ConfigError(f"config root must be an object: {path}")
    return data


def parse_int(value: Any, label: str) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            pass
    raise ConfigError(f"{label} must be an integer or integer string")


def require_string(config: dict[str, Any], key: str, label: str) -> str:
    value = config.get(key)
    if not isinstance(value, str) or not value:
        raise ConfigError(f"missing required configuration value: {label}")
    return value


def optional_string(config: dict[str, Any], key: str) -> str | None:
    value = config.get(key)
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ConfigError(f"{key} must be a string")
    return value


def _source_dirs(value: Any, label: str) -> tuple[str, ...]:
    if isinstance(value, str) and value:
        return (value,)
    if isinstance(value, list) and value and all(isinstance(item, str) and item for item in value):
        return tuple(value)
    raise ConfigError(f"{label} must be a non-empty string or list of strings")


def _resolve_standalone_path(value: str | None, base: Path) -> str | None:
    if value is None:
        return None
    path = Path(value)
    if path.is_absolute():
        return str(path)
    return str(base / path)


def _resolve_standalone_paths(values: tuple[str, ...], base: Path) -> tuple[str, ...]:
    return tuple(_resolve_standalone_path(value, base) or value for value in values)


def _build_config(config: dict[str, Any], inherited_jobs: int = 1) -> BuildConfig:
    build = config.get("build", {})
    if build is None:
        build = {}
    if not isinstance(build, dict):
        raise ConfigError("build must be an object")
    jobs = build.get("jobs", inherited_jobs)
    return BuildConfig(
        clean=optional_string(build, "clean"),
        build=optional_string(build, "build"),
        jobs=parse_int(jobs, "build.jobs"),
    )


def _target_from_standalone(config: dict[str, Any], target: str, base: Path) -> ProjectTarget:
    targets = config.get("targets")
    if not isinstance(targets, dict):
        raise ConfigError("targets must be an object")
    target_cfg = targets.get(target)
    if not isinstance(target_cfg, dict):
        raise ConfigError(f"missing target: {target}")

    project_build = _build_config(config)
    target_build = _build_config(target_cfg, inherited_jobs=project_build.jobs)
    build = BuildConfig(
        clean=target_build.clean or project_build.clean,
        build=target_build.build or project_build.build,
        jobs=target_build.jobs,
    )

    policies = config.get("policies", {})
    if policies is None:
        policies = {}
    if not isinstance(policies, dict):
        raise ConfigError("policies must be an object")

    values = target_cfg.get("values", {})
    if values is None:
        values = {}
    if not isinstance(values, dict):
        raise ConfigError(f"targets.{target}.values must be an object")

    policy = optional_string(values, "policy") or optional_string(policies, "values")
    source_dirs = _source_dirs(
        target_cfg.get("source_dirs") or target_cfg.get("source_dir"),
        f"targets.{target}.source_dirs",
    )
    return ProjectTarget(
        name=target,
        original_exe=_resolve_standalone_path(
            require_string(target_cfg, "original_exe", f"targets.{target}.original_exe"),
            base,
        ) or "",
        rebuilt_exe=_resolve_standalone_path(
            require_string(target_cfg, "rebuilt_exe", f"targets.{target}.rebuilt_exe"),
            base,
        ) or "",
        map_path=_resolve_standalone_path(require_string(target_cfg, "map", f"targets.{target}.map"), base) or "",
        source_dirs=_resolve_standalone_paths(source_dirs, base),
        globals_source=_resolve_standalone_path(optional_string(target_cfg, "globals_source"), base),
        code_dir=_resolve_standalone_path(
            optional_string(target_cfg, "code_export_dir") or optional_string(target_cfg, "code_dir"),
            base,
        ),
        map_skip=optional_string(target_cfg, "map_skip"),
        build=build,
        values_policy=policy,
    )


def _target_from_legacy(config: dict[str, Any], target: str) -> ProjectTarget:
    paths = config.get("paths", {})
    if not isinstance(paths, dict):
        raise ConfigError("paths must be an object")
    path_cfg = paths.get(target, {})
    if not isinstance(path_cfg, dict):
        raise ConfigError(f"paths.{target} must be an object")

    values = config.get("values_capstone", {})
    if values is None:
        values = {}
    if not isinstance(values, dict):
        raise ConfigError("values_capstone must be an object")
    value_target = values.get(target, {})
    if value_target is None:
        value_target = {}
    if not isinstance(value_target, dict):
        raise ConfigError(f"values_capstone.{target} must be an object")

    build = config.get("build", {})
    if build is None:
        build = {}
    if not isinstance(build, dict):
        raise ConfigError("build must be an object")
    jobs = parse_int(build.get("jobs", 1), "build.jobs")

    source_dir = require_string(path_cfg, "src_dir", f"paths.{target}.src_dir")
    return ProjectTarget(
        name=target,
        original_exe=require_string(path_cfg, "exe", f"paths.{target}.exe"),
        rebuilt_exe=require_string(value_target, "recompiled_exe", f"values_capstone.{target}.recompiled_exe"),
        map_path=require_string(value_target, "map", f"values_capstone.{target}.map"),
        source_dirs=(source_dir,),
        globals_source=optional_string(path_cfg, "globals_source"),
        code_dir=optional_string(path_cfg, "code_dir"),
        map_skip=optional_string(path_cfg, "map_skip"),
        build=BuildConfig(
            clean=f"make {optional_string(path_cfg, 'clean_target')}" if optional_string(path_cfg, "clean_target") else None,
            build=(
                f"make {optional_string(value_target, 'build_target') or optional_string(path_cfg, 'build_target')}"
                if (optional_string(value_target, "build_target") or optional_string(path_cfg, "build_target"))
                else None
            ),
            jobs=jobs,
        ),
        values_policy=optional_string(values, "config"),
    )


def load_project_target(config_path: str | os.PathLike[str], target: str) -> tuple[dict[str, Any], ProjectTarget]:
    config = load_json(config_path)
    if "targets" in config:
        base = Path(config_path).resolve().parent
        return config, _target_from_standalone(config, target, base)
    return config, _target_from_legacy(config, target)


def resolve_path(path: str | None, base: str | os.PathLike[str] | None = None) -> str | None:
    if path is None:
        return None
    candidate = Path(path)
    if candidate.is_absolute() or base is None:
        return str(candidate)
    return str(Path(base) / candidate)
