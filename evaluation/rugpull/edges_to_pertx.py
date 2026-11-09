"""
edges_to_pertx.py
실데이터(_edges.csv) → 온톨로지 추론기가 읽는 per-tx CSV 로 변환.

입력 : evaluation/hoplaundering/data/logs_v2/{address}_edges.csv
        컬럼: block,timestamp,from,to,amount_eth,direction,kind,hash
출력 : evaluation/rugpull/logs/{name}_log.csv
        컬럼: block,timestamp,from,to,action,amount_eth,contract_balance_eth,participant_count
        (= analysis/logs/rugpull_log.csv 와 완전히 동일한 형식)

사용 : python3 evaluation/rugpull/edges_to_pertx.py <edges.csv> <출력이름>
"""
import sys, os
import pandas as pd

def convert(edges_path, out_name, out_dir="evaluation/rugpull/logs"):
    df = pd.read_csv(edges_path)
    df = df.sort_values(["block", "timestamp"]).reset_index(drop=True)

    os.makedirs(out_dir, exist_ok=True)
    rows, bal, participants = [], 0.0, set()

    # 최대 출금 1건을 미리 찾아둔다 (owner_withdraw_all 판정용)
    wd = df[df["direction"] == "withdrawal"]
    max_wd_idx = wd["amount_eth"].astype(float).idxmax() if len(wd) else None

    for i, r in df.iterrows():
        amt = float(r["amount_eth"])
        if r["direction"] == "deposit":
            action = "deposit"
            bal += amt
            participants.add(str(r["from"]).lower())
        else:
            # 최대 인출 1건만 owner_withdraw_all 로 표기. 나머지는 일반 withdraw.
            action = "owner_withdraw_all" if i == max_wd_idx else "withdraw"
            bal -= amt
            bal = max(bal, 0.0)
        rows.append({
            "block": int(r["block"]),
            "timestamp": int(r["timestamp"]),
            "from": str(r["from"]).lower(),
            "to": str(r["to"]).lower(),
            "action": action,
            "amount_eth": f"{amt:.8f}",
            "contract_balance_eth": f"{bal:.8f}",
            "participant_count": len(participants),
        })

    out_path = os.path.join(out_dir, f"{out_name}_log.csv")
    pd.DataFrame(rows).to_csv(out_path, index=False)
    print(f"저장 완료: {out_path}  ({len(rows)}건, peak≈{max(float(x['contract_balance_eth']) for x in rows):.4f} ETH)")
    return out_path

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("사용법: python3 edges_to_pertx.py <edges.csv> <출력이름>")
        sys.exit(1)
    convert(sys.argv[1], sys.argv[2])
