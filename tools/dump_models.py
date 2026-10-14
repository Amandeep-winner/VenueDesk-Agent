"""Dump SQLAlchemy DB models, tables, columns, foreign keys, unique constraints, and indexes."""

import os
import sys

# Ensure venuedesk-backend is in sys.path
backend_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "venuedesk-backend"
)
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

import app.models  # noqa: F401
from app import create_app
from app.extensions import db
from sqlalchemy import inspect


def dump_models(output_file=None):
    app = create_app("testing")
    with app.app_context():
        # Ensure all tables are created in testing memory/db
        db.create_all()
        inspector = inspect(db.engine)
        table_names = sorted(inspector.get_table_names())

        lines = []
        lines.append(f"# Database Models and Schema Dump ({len(table_names)} tables)\n")

        for table in table_names:
            lines.append(f"## Table: `{table}`")

            # Columns
            cols = inspector.get_columns(table)
            lines.append("### Columns:")
            for c in cols:
                pk_mark = " [PK]" if c.get("primary_key") else ""
                nullable_mark = " NULL" if c.get("nullable") else " NOT NULL"
                default_val = (
                    f" DEFAULT {c.get('default')}"
                    if c.get("default") is not None
                    else ""
                )
                lines.append(
                    f"  - `{c['name']}`: {c['type']}{pk_mark}{nullable_mark}{default_val}"
                )

            # Foreign Keys
            fks = inspector.get_foreign_keys(table)
            if fks:
                lines.append("### Foreign Keys:")
                for fk in fks:
                    lines.append(
                        f"  - `{fk['constrained_columns']}` -> `{fk['referred_table']}.{fk['referred_columns']}`"
                    )

            # Unique Constraints
            uqs = inspector.get_unique_constraints(table)
            if uqs:
                lines.append("### Unique Constraints:")
                for uq in uqs:
                    lines.append(f"  - `{uq['name']}`: {uq['column_names']}")

            # Indexes
            indexes = inspector.get_indexes(table)
            if indexes:
                lines.append("### Indexes:")
                for idx in indexes:
                    unique_mark = " (UNIQUE)" if idx.get("unique") else ""
                    lines.append(
                        f"  - `{idx['name']}`: {idx['column_names']}{unique_mark}"
                    )

            lines.append("")

        output = "\n".join(lines)
        print(output)

        if output_file:
            os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(output + "\n")

        return output


if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else None
    dump_models(out_file)
