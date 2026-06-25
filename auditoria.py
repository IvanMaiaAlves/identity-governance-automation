import pandas as pd
from datetime import datetime

# Function to record logs in a text file and print to the terminal
def record_log(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_line = f"[{timestamp}] {message}\n"
    print(f"[{timestamp}] {message}")
    with open("audit_log.txt", "a", encoding="utf-8") as f:
        f.write(log_line)

record_log("=" * 50)
record_log("       STARTING IDENTITY AUDIT (IGA)       ")
record_log("=" * 50)

# 1. LOAD DATASETS
try:
    df_rh = pd.read_csv("hr_data.csv")
    record_log("[INFO] HR data loaded successfully.")
except Exception as e:
    record_log(f"🚨 [ERROR] Failed to load HR data (hr_data.csv): {e}")
    exit()

try:
    df_cloud = pd.read_json("cloud_data.json")
    record_log("[INFO] Cloud data loaded successfully.")
except Exception as e:
    record_log(f"🚨 [ERROR] Failed to load Cloud data (cloud_data.json): {e}")
    exit()

# 2. DATA RECONCILIATION AND ANOMALY DETECTION
try:
    # Standardize IDs to avoid mismatching due to whitespaces
    df_cloud["id_usuario"] = df_cloud["id_usuario"].astype(str).str.strip()
    df_rh["id"] = df_rh["id"].astype(str).str.strip()

    # Merge datasets based on IDs
    df_consolidated = pd.merge(df_cloud, df_rh, left_on="id_usuario", right_on="id")
    
    # --- FILTER 1: GHOST ACCOUNTS (Terminated employees with active access) ---
    ghost_accounts = df_consolidated[df_consolidated["status"].str.strip() == "Demitido"]
    
    if not ghost_accounts.empty:
        record_log(f"🚨 [CRITICAL ALERT] {len(ghost_accounts)} GHOST ACCOUNTS DETECTED!")
        report_ghost = ghost_accounts[['id_usuario', 'email', 'permissao', 'status']].copy()
        report_ghost.to_excel("ghost_accounts_report.xlsx", index=False)
        record_log("✅ 'ghost_accounts_report.xlsx' generated with data.")
    else:
        record_log("✅ No ghost accounts detected.")

    # --- FILTER 2: ACCESS KEY AGE REVIEW (Credential Compliance) ---
    record_log("[INFO] Analyzing access key age compliance (Limit: 90 days)...")
    
    current_date = datetime.now()
    expired_keys = []

    for index, row in df_consolidated.iterrows():
        try:
            key_date = datetime.strptime(str(row["data_criacao_chave"]).strip(), "%Y-%m-%d")
            age_days = (current_date - key_date).days
            
            if age_days > 90:
                record_log(f"⚠️ [VULNERABILITY] User {row['email']} is using a stale key ({age_days} days old)!")
                expired_keys.append({
                    "user_id": row["id_usuario"],
                    "email": row["email"],
                    "key_age_days": age_days,
                    "permission": row["permissao"]
                })
        except Exception as e:
            pass

    if expired_keys:
        df_expired = pd.DataFrame(expired_keys)
        df_expired.to_excel("stale_keys_report.xlsx", index=False)
        record_log(f"🚨 [ALERT] {len(expired_keys)} stale keys saved to 'stale_keys_report.xlsx'.")
    else:
        record_log("✅ 100% of access keys are compliant.")

    # --- FILTER 3: SEGREGATION OF DUTIES (SoD) ANALYSIS ---
    record_log("[INFO] Checking for Segregation of Duties (SoD) conflicts...")
    
    sod_conflicts = []
    
    for index, row in df_consolidated.iterrows():
        user_permissions = str(row["permissao"])
        
        if "Admin" in user_permissions and "Auditor" in user_permissions:
            record_log(f"🚨 [SoD VIOLATION] User {row['email']} has conflicting privileges: {user_permissions}!")
            sod_conflicts.append({
                "user_id": row["id_usuario"],
                "email": row["email"],
                "conflict_detected": "Admin + Auditor (Fraud / Concealment Risk)",
                "current_permissions": user_permissions
            })
            
    if sod_conflicts:
        df_sod = pd.DataFrame(sod_conflicts)
        df_sod.to_excel("sod_violations_report.xlsx", index=False)
        record_log(f"🚨 [ALERT] {len(sod_conflicts)} SoD violations saved to 'sod_violations_report.xlsx'.")
    else:
        record_log("✅ No Segregation of Duties (SoD) conflicts found.")

except Exception as e:
    record_log(f"🚨 [ERROR] Unexpected data processing failure: {e}")

record_log("================ AUDIT PROCESS FINISHED ================")
