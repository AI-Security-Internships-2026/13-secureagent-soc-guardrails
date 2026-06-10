"""
SecureAgent-SOC: Guardrails and SOC Copilot for Trustworthy AI Agents
CNIT/PNTLab Pisa — AI Security Internship 2026
Student: Emaan Afroz Khuram (@emaankhuram)
"""


PROJECT_NAME = "SecureAgent-SOC: Guardrails and SOC Copilot for Trustworthy AI Agents"
STUDENT     = "Emaan Afroz Khuram (@emaankhuram)"
STATUS      = "Initialised — ready for development"


def main() -> None:
    print("=" * 65)
    print(f"Project : {PROJECT_NAME}")
    print(f"Student : {STUDENT}")
    print(f"Status  : {STATUS}")
    print("=" * 65)
    print()
    print("Architecture:")
    print("  [Alert Input] → [Input Guardrail] → [SOC Agent]")
    print("               → [Output Guardrail] → [Analyst Report]")
    print()
    print("See docs/proposal.md for research objectives.")
    print("See tasks/week-01.md for your first tasks.")


if __name__ == "__main__":
    main()
