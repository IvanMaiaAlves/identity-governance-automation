# Identity Governance and Administration (IGA) Audit Automation with Python

This project simulates a lightweight IGA (Identity Governance and Administration) tool using Python and the Pandas library. The primary goal is to automate the access review process and ensure security compliance by reconciling raw cloud infrastructure data with the official HR employee database.

## 🛡️ Automated Security Features

* **Ghost Accounts Detection:** Automatically identifies active cloud accounts belonging to employees who have already been terminated in the HR system (mitigating critical unauthorized access risks).
* **Access Review (Stale Keys):** Filters and flags access keys or credentials that haven't been rotated in over 90 days, violating standard corporate security compliance.
* **Segregation of Duties (SoD) Analysis:** Detects users with conflicting high-privilege roles (e.g., holding both `Admin` and `Auditor` permissions simultaneously) to mitigate internal fraud risks.

## 📊 Tech Stack & Tools

* **Python 3**
* **Pandas Library:** Used for advanced data manipulation, filtering, and table merging (`pd.merge`).
* **Structured Data:** Handles `JSON` (Cloud data), `CSV` (HR data), and automatically exports audit evidence to `Excel (.xlsx)`.

## 🚀 How to Run

1. Clone this repository:
   ```bash
   git clone [https://github.com/IvanMaiaAlves/identity-governance-automation.git] 

Install the required dependencies:

Bash
pip install pandas openpyxl
Run the audit script:

Bash
python auditoria.py
📁 Generated Evidence & Reports
Upon execution, the script generates a real-time terminal log (log_auditoria.txt) and outputs three specialized Excel spreadsheets for compliance teams:

relatorio_contas_fantasma.xlsx (Action item: Immediate account deprovisioning)

relatorio_chaves_obsoletas.xlsx (Action item: Enforce credential rotation)

relatorio_violacao_sod.xlsx (Action item: Privilege reduction / Risk mitigation)
