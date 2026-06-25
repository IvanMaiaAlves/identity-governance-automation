import pandas as pd
from datetime import datetime
import os

# Função para registrar os logs com carimbo de data/hora
def registrar_log(mensagem):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    texto_log = f"[{timestamp}] {mensagem}"
    print(texto_log)
    with open("log_auditoria.txt", "a", encoding="utf-8") as f:
        f.write(texto_log + "\n")

# ==================================================
#          INICIALIZAÇÃO DO SCRIPT
# ==================================================
registrar_log("==================================================")
registrar_log("      INICIANDO AUDITORIA DE SEGURANÇA (IGA)      ")
registrar_log("==================================================")

# 1. CARREGAR DADOS DO RH (CSV)
try:
    df_rh = pd.read_csv("rh_funcionarios.csv")
    registrar_log("[INFO] Dados do RH carregados com sucesso.")
except Exception as e:
    registrar_log(f"🚨 [ERRO CRÍTICO] Falha ao carregar rh_funcionarios.csv: {e}")
    exit()

# 2. CARREGAR DADOS DA NUVEM (JSON)
try:
    df_nuvem = pd.read_json("nuvem_teste.json")
    registrar_log("[INFO] Dados da Nuvem carregados com sucesso.")
except Exception as e:
    registrar_log(f"🚨 [ERRO CRÍTICO] Falha ao carregar nuvem_teste.json: {e}")
    exit()

# 3. CRUZAR OS DADOS (CONCILIAÇÃO) E PROCURAR ANOMALIAS
try:
    # Garante que os IDs sejam lidos como texto e sem espaços para não falhar no cruzamento
    df_nuvem["id_usuario"] = df_nuvem["id_usuario"].astype(str).str.strip()
    df_rh["id"] = df_rh["id"].astype(str).str.strip()

    # Junta as tabelas
    df_consolidado = pd.merge(df_nuvem, df_rh, left_on="id_usuario", right_on="id")
    
    # --- FILTRO 1: CONTAS FANTASMA (Demitidos com acesso ativo) ---
    contas_fantasma = df_consolidado[df_consolidado["status"].str.strip() == "Demitido"]
    
    if not contas_fantasma.empty:
        registrar_log(f"🚨 [ALERTA CRÍTICO] {len(contas_fantasma)} CONTAS FANTASMA DETECTADAS!")
        # Criando uma cópia limpa para o Excel
        relatorio_fantasma = contas_fantasma[['id_usuario', 'email', 'permissao', 'status']].copy()
        relatorio_fantasma.to_excel("relatorio_contas_fantasma.xlsx", index=False)
        registrar_log("✅ Relatório 'relatorio_contas_fantasma.xlsx' gerado com dados.")
    else:
        registrar_log("✅ Nenhuma conta fantasma detectada.")

    # --- FILTRO 2: AUDITORIA DE IDADE DE CHAVES (Access Review) ---
    registrar_log("[INFO] Analisando conformidade de tempo das chaves de acesso (Limite: 90 dias)...")
    
    data_atual = datetime.now()
    chaves_expiradas = []

    for index, linha in df_consolidado.iterrows():
        try:
            data_chave = datetime.strptime(str(linha["data_criacao_chave"]).strip(), "%Y-%m-%d")
            idade_dias = (data_atual - data_chave).days
            
            if idade_dias > 90:
                registrar_log(f"⚠️ [VULNERABILIDADE] Usuário {linha['email']} usando chave antiga há {idade_dias} dias!")
                chaves_expiradas.append({
                    "id_usuario": linha["id_usuario"],
                    "email": linha["email"],
                    "idade_chave_dias": idade_dias,
                    "permissao": linha["permissao"]
                })
        except Exception as e:
            pass

    if chaves_expiradas:
        df_expiradas = pd.DataFrame(chaves_expiradas)
        df_expiradas.to_excel("relatorio_chaves_obsoletas.xlsx", index=False)
        registrar_log(f"🚨 [ALERTA] {len(chaves_expiradas)} chaves obsoletas salvas em 'relatorio_chaves_obsoletas.xlsx'.")
    else:
        registrar_log("✅ 100% das chaves de acesso estão dentro do prazo.")

    # --- FILTRO 3: ANÁLISE DE SEGREGAÇÃO DE FUNÇÕES (SoD) ---
    registrar_log("[INFO] Verificando conflitos de Segregação de Funções (SoD)...")
    
    conflitos_sod = []
    
    for index, linha in df_consolidado.iterrows():
        permissoes_usuario = str(linha["permissao"])
        
        if "Admin" in permissoes_usuario and "Auditor" in permissoes_usuario:
            registrar_log(f"🚨 [VIOLAÇÃO DE SOD] Usuário {linha['email']} possui acessos conflitantes: {permissoes_usuario}!")
            conflitos_sod.append({
                "id_usuario": linha["id_usuario"],
                "email": linha["email"],
                "conflito_detectado": "Admin + Auditor (Risco de Fraude/Ocultação)",
                "permissoes_atuais": permissoes_usuario
            })
            
    if __name__ == '__main__' or True: # Força a execução segura
        if conflitos_sod:
            df_sod = pd.DataFrame(conflitos_sod)
            df_sod.to_excel("relatorio_violacao_sod.xlsx", index=False)
            registrar_log(f"🚨 [ALERTA] {len(conflitos_sod)} violações de SoD salvas em 'relatorio_violacao_sod.xlsx'.")
        else:
            registrar_log("✅ Nenhum conflito de SoD encontrado.")

except Exception as e:
    registrar_log(f"🚨 [ERRO] Falha inesperada no processamento dos dados: {e}")

registrar_log("================ AUDITORIA FINALIZADA ================")
