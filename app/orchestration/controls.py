"""Control and playbook identifiers the report writer is allowed to emit.

The REPORT schema lets the model name failed controls and recommended playbooks. Code keeps only ids found here, so a
control or playbook that does not exist can never reach the investigator.
"""

# The nine control ids of the validated catalog in neu-frontend/src/data/controls.json. The report may only name
# ids found here. Clause text lives in the catalog, not in the model's output.
CONTROL_IDS: tuple[str, ...] = (
    "C-AUDIT",      # tamper-proof audit trail of every decision and action
    "C-CERTIN",     # report a cyber incident to CERT-In within 6 hours of detection
    "C-DPDP72",     # detailed personal data breach report within 72 hours (readiness)
    "C-AGENTS",     # the insurer polices agent and POSP access (outside the IRDAI cyber guideline scope)
    "C-PORTFOLIO",  # agents access only policyholders in their own portfolio
    "C-INACTIVE",   # terminated or suspended identities cannot access data
    "C-EXPORT",     # bulk exports are detected and reviewed
    "C-HUMAN",      # a human approves containment before it runs
    "C-PII",        # customer names are tokenised before AI processing
)

# PB5 (quarantine export) is dropped from the build plan.
PLAYBOOK_IDS: tuple[str, ...] = ("PB1", "PB2", "PB6", "PB7")
