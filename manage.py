#!/usr/bin/env python3
"""MCP Privacy Proxy — CLI management tool.

Reads and writes the same configuration files as the proxy,
no running server required.

Usage:
    manage.py servers list
    manage.py servers add NAME TARGET
    manage.py servers remove NAME
    manage.py servers enable NAME
    manage.py servers disable NAME

    manage.py policy show
    manage.py policy edit
    manage.py policy set-operator TYPE OPERATOR

    manage.py mappings show
    manage.py mappings show --reveal
    manage.py mappings clear

    manage.py status
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from config import load_policy, save_policy, EntityPolicy
from mapping_store import MappingStore, default_mapping_path
from server_registry import ServerRegistry


def _resolve_paths() -> tuple[str, str, str]:
    """Resolve config/servers/mapping paths from env or defaults."""
    config_path = os.environ.get(
        "CONFIG_PATH",
        str(Path(__file__).parent / "default_policy.yaml"),
    )
    servers_path = os.environ.get("SERVERS_PATH", "servers.yaml")
    mapping_path = os.environ.get("MAPPING_STORE_PATH", str(default_mapping_path()))
    return config_path, servers_path, mapping_path


# ── Servers ───────────────────────────────────────────────────────────────

def cmd_servers_list(args: argparse.Namespace) -> None:
    _, servers_path, _ = _resolve_paths()
    registry = ServerRegistry(path=servers_path)

    servers = registry.all_servers()
    if not servers:
        print("No servers registered.")
        return

    print(f"{'Name':<20} {'Status':<10} {'Target'}")
    print("-" * 70)
    for name, entry in servers.items():
        status = "enabled" if entry.enabled else "disabled"
        print(f"{name:<20} {status:<10} {entry.target}")


def cmd_servers_add(args: argparse.Namespace) -> None:
    _, servers_path, _ = _resolve_paths()
    registry = ServerRegistry(path=Path(servers_path))
    if registry.get(args.name):
        # If loading from empty file, ensure we have the path set
        pass
    try:
        registry.add(args.name, args.target)
        print(f"Added server '{args.name}' -> {args.target}")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_servers_remove(args: argparse.Namespace) -> None:
    _, servers_path, _ = _resolve_paths()
    registry = ServerRegistry(path=servers_path)
    try:
        registry.remove(args.name)
        print(f"Removed server '{args.name}'")
    except KeyError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_servers_enable(args: argparse.Namespace) -> None:
    _, servers_path, _ = _resolve_paths()
    registry = ServerRegistry(path=servers_path)
    try:
        registry.enable(args.name)
        print(f"Enabled server '{args.name}'")
    except KeyError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_servers_disable(args: argparse.Namespace) -> None:
    _, servers_path, _ = _resolve_paths()
    registry = ServerRegistry(path=servers_path)
    try:
        registry.disable(args.name)
        print(f"Disabled server '{args.name}'")
    except KeyError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


# ── Policy ────────────────────────────────────────────────────────────────

def cmd_policy_show(args: argparse.Namespace) -> None:
    config_path, _, _ = _resolve_paths()
    p = Path(config_path)
    if not p.exists():
        print(f"Policy file not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    print(p.read_text())


def cmd_policy_edit(args: argparse.Namespace) -> None:
    config_path, _, _ = _resolve_paths()
    editor = os.environ.get("EDITOR", "vi")
    subprocess.call([editor, config_path])
    # Validate after editing
    try:
        load_policy(config_path)
        print("Policy is valid.")
    except Exception as e:
        print(f"Warning: Policy may be invalid: {e}", file=sys.stderr)


def cmd_policy_set_operator(args: argparse.Namespace) -> None:
    config_path, _, _ = _resolve_paths()
    policy = load_policy(config_path)
    entity_type = args.type.upper()

    existing = policy.entities.get(entity_type)
    if existing:
        existing.operator = args.operator
    else:
        policy.entities[entity_type] = EntityPolicy(operator=args.operator)

    save_policy(policy, config_path)
    print(f"Set {entity_type} operator to '{args.operator}'")


# ── Mappings ──────────────────────────────────────────────────────────────

def cmd_mappings_show(args: argparse.Namespace) -> None:
    _, _, mapping_path = _resolve_paths()
    store = MappingStore(path=mapping_path)
    data = store.dump()

    if not data:
        print("No mappings stored.")
        return

    for entity_type, mappings in data.items():
        print(f"\n{entity_type}:")
        for real_val, surrogate in mappings.items():
            if args.reveal:
                print(f"  {real_val} -> {surrogate}")
            else:
                masked = real_val[:2] + "*" * max(0, len(real_val) - 4) + real_val[-2:] if len(real_val) > 4 else "****"
                print(f"  {masked} -> {surrogate}")


def cmd_mappings_clear(args: argparse.Namespace) -> None:
    _, _, mapping_path = _resolve_paths()
    p = Path(mapping_path)
    if p.exists():
        p.write_text(json.dumps({"forward": {}}, indent=2))
        print("Mappings cleared.")
    else:
        print("No mapping file found.")


# ── Status ────────────────────────────────────────────────────────────────

def cmd_status(args: argparse.Namespace) -> None:
    config_path, servers_path, mapping_path = _resolve_paths()

    print("MCP Privacy Proxy — Status")
    print("=" * 40)

    # Policy
    p = Path(config_path)
    if p.exists():
        policy = load_policy(config_path)
        print(f"\nPolicy: {config_path}")
        print(f"  Entity types: {len(policy.entities)}")
        print(f"  Custom recognizers: {len(policy.custom_recognizers)}")
    else:
        print(f"\nPolicy: NOT FOUND ({config_path})")

    # Servers
    sp = Path(servers_path)
    if sp.exists():
        registry = ServerRegistry(path=servers_path)
        servers = registry.all_servers()
        enabled = sum(1 for s in servers.values() if s.enabled)
        print(f"\nServers: {servers_path}")
        print(f"  Total: {len(servers)}, Enabled: {enabled}")
        for name, entry in servers.items():
            status = "ON" if entry.enabled else "OFF"
            print(f"  [{status}] {name}: {entry.target}")
    else:
        print(f"\nServers: NOT FOUND ({servers_path})")

    # Mappings
    mp = Path(mapping_path)
    if mp.exists():
        store = MappingStore(path=mapping_path)
        data = store.dump()
        total = sum(len(v) for v in data.values())
        print(f"\nMappings: {mapping_path}")
        print(f"  Total: {total}")
        for et, m in data.items():
            print(f"  {et}: {len(m)} entries")
    else:
        print(f"\nMappings: no file yet ({mapping_path})")


# ── Argument parser ───────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="manage.py",
        description="MCP Privacy Proxy management CLI",
    )
    sub = parser.add_subparsers(dest="command")

    # servers
    servers = sub.add_parser("servers", help="Manage backend MCP servers")
    servers_sub = servers.add_subparsers(dest="servers_action")

    servers_sub.add_parser("list", help="List all servers")

    add = servers_sub.add_parser("add", help="Add a server")
    add.add_argument("name", help="Server name")
    add.add_argument("target", help="Server target (URL or command)")

    remove = servers_sub.add_parser("remove", help="Remove a server")
    remove.add_argument("name", help="Server name")

    enable = servers_sub.add_parser("enable", help="Enable a server")
    enable.add_argument("name", help="Server name")

    disable = servers_sub.add_parser("disable", help="Disable a server")
    disable.add_argument("name", help="Server name")

    # policy
    policy = sub.add_parser("policy", help="View/edit privacy policy")
    policy_sub = policy.add_subparsers(dest="policy_action")

    policy_sub.add_parser("show", help="Show current policy")
    policy_sub.add_parser("edit", help="Edit policy in $EDITOR")

    set_op = policy_sub.add_parser("set-operator", help="Set operator for entity type")
    set_op.add_argument("type", help="Entity type (e.g. PERSON)")
    set_op.add_argument("operator", help="Operator (fpe, deterministic_faker, replace)")

    # mappings
    mappings = sub.add_parser("mappings", help="View/manage PII mappings")
    mappings_sub = mappings.add_subparsers(dest="mappings_action")

    show = mappings_sub.add_parser("show", help="Show current mappings")
    show.add_argument("--reveal", action="store_true", help="Show real PII values")

    mappings_sub.add_parser("clear", help="Clear all mappings")

    # status
    sub.add_parser("status", help="Show overall status summary")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        ("servers", "list"): cmd_servers_list,
        ("servers", "add"): cmd_servers_add,
        ("servers", "remove"): cmd_servers_remove,
        ("servers", "enable"): cmd_servers_enable,
        ("servers", "disable"): cmd_servers_disable,
        ("policy", "show"): cmd_policy_show,
        ("policy", "edit"): cmd_policy_edit,
        ("policy", "set-operator"): cmd_policy_set_operator,
        ("mappings", "show"): cmd_mappings_show,
        ("mappings", "clear"): cmd_mappings_clear,
        ("status", None): cmd_status,
    }

    if args.command == "status":
        cmd_status(args)
        return

    action_key = None
    if args.command == "servers":
        action_key = ("servers", getattr(args, "servers_action", None))
    elif args.command == "policy":
        action_key = ("policy", getattr(args, "policy_action", None))
    elif args.command == "mappings":
        action_key = ("mappings", getattr(args, "mappings_action", None))

    if action_key and action_key in dispatch:
        dispatch[action_key](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
