# app/schemas/enums.py

from enum import Enum

# ─────────────────────────────
# 🔐 Login Mode Enum
# ─────────────────────────────
class LoginMode(str, Enum):
    """
    Defines the mode of login: personal or via organization context.
    """
    PERSONAL = "personal"
    ORGANIZATION = "organization"


# ─────────────────────────────
# 🧑‍💼 Org Role Enum
# ─────────────────────────────
class OrgRole(str, Enum):
    """
    Defines all user roles across the platform within an organization.
    Supports learning, company, and hiring use-cases.
    """
    ADMIN = "ADMIN"
    USER = "USER"


class ExportFormat(str, Enum):
    csv = "csv"
    xlsx = "xlsx"
