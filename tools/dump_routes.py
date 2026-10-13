"""Dump API routes, auth decorators, and roles."""

import inspect
import os
import sys

# Ensure venuedesk-backend is in sys.path
backend_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "venuedesk-backend"
)
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from app import create_app


def inspect_endpoint_auth(func):
    """Inspect view function to determine auth decorator and allowed roles."""
    code = getattr(func, "__code__", None)
    if not code:
        return "none", "none"

    filename = os.path.normpath(code.co_filename)
    cv = inspect.getclosurevars(func)
    nonlocals = cv.nonlocals

    # Policy enforcement decorator (Phase 2+)
    if (
        "policy" in filename
        or "enforce_policy" in code.co_name
        or "policy" in nonlocals
    ):
        policy = nonlocals.get("policy")
        if policy:
            auth_kind = getattr(policy, "auth", str(policy))
            states = getattr(policy, "states", None)
            roles = getattr(policy, "roles", None)
            detail = ""
            if states:
                detail = f"states: {','.join(s.value if hasattr(s, 'value') else str(s) for s in states)}"
            elif roles:
                detail = f"roles: {','.join(r.value if hasattr(r, 'value') else str(r) for r in roles)}"
            return "enforce_policy", f"{auth_kind} ({detail})" if detail else auth_kind
        return "enforce_policy", "policy-defined"

    # require_role / require_ui_role / rbac.py
    if "rbac.py" in filename or "allowed_roles" in nonlocals:
        roles = nonlocals.get("allowed_roles")
        role_names = (
            [r.value if hasattr(r, "value") else str(r) for r in roles]
            if roles
            else ["all"]
        )
        inner = nonlocals.get("f")
        mod = (
            getattr(inner, "__module__", "")
            if inner
            else getattr(func, "__module__", "")
        )
        if "admin_infra" in mod:
            return "require_ui_role", ", ".join(role_names)
        return "require_role", ", ".join(role_names)

    # signatures.py / require_device_auth
    if "signatures.py" in filename:
        return "require_device_auth", "device"

    # Specific endpoints without decorators
    if "csrf.py" in filename:
        return "csrf_protect", "session"

    return "none", "none"


def dump_routes(output_file=None):
    app = create_app("testing")
    rows = []
    headers = ["Method", "Path", "Endpoint", "Auth Decorator Found?", "Roles / States"]

    rules = sorted(app.url_map.iter_rules(), key=lambda r: r.rule)

    for rule in rules:
        methods = [m for m in sorted(rule.methods) if m not in ("HEAD", "OPTIONS")]
        if not methods:
            continue
        method_str = ",".join(methods)
        func = app.view_functions[rule.endpoint]
        auth_dec, roles = inspect_endpoint_auth(func)
        rows.append([method_str, rule.rule, rule.endpoint, auth_dec, roles])

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(val)))

    header_line = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    sep_line = "-+-".join("-" * col_widths[i] for i in range(len(headers)))
    content_lines = [header_line, sep_line]
    for row in rows:
        content_lines.append(
            " | ".join(str(row[i]).ljust(col_widths[i]) for i in range(len(headers)))
        )

    output = "\n".join(content_lines)
    print(output)

    if output_file:
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(output + "\n")

    return rows


if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else None
    dump_routes(out_file)
