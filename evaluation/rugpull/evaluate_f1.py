"""
evaluate_f1.py
러그풀 탐지 성능 평가 — Precision / Recall / F1

기본: JS 레이어 (analysis/dynamic_analyzer.js) — 실제 탐지 파이프라인
옵션: --owl  OWL 레이어 (ontology/fraud_reasoned_real.owl) — 동일 지식의 표준 표현 검증

[정답 라벨] 로그 파일 이름으로 구분
    rug_*, *_rug   → 러그풀 (positive)
    normal_*       → 정상   (negative)

[판정불가] 입금이 0건이거나, 실제 금액이 나간 출금이 0건인 로그.
    러그풀은 "돈이 들어왔다가 빠져나가는" 사기라서, 둘 중 하나라도 관측되지
    않으면 맞다/틀리다를 따질 수 없다. (대부분 토큰으로만 거래한 컨트랙트라
    ETH 장부에 흐름이 남지 않은 경우) 레이어와 무관하게 데이터만 보고 정하므로
    JS/OWL 두 레이어가 항상 같은 평가 대상으로 비교된다.
    --include-empty 를 주면 판정불가도 포함해서 계산한다.

사용법 (저장소 최상위에서):
    python evaluation/rugpull/evaluate_f1.py                 # JS 레이어
    python evaluation/rugpull/evaluate_f1.py --owl           # OWL 레이어
    python evaluation/rugpull/evaluate_f1.py --compare       # 두 레이어 비교
    python evaluation/rugpull/evaluate_f1.py --include-empty # 판정불가 포함
    python evaluation/rugpull/evaluate_f1.py --logs 다른폴더  # 로그 폴더 지정

    --owl / --compare 는 먼저 아래 두 줄을 실행해서 OWL 결과를 만들어 둬야 한다.
      python ontology/load_instances_real.py evaluation/rugpull/logs
      python ontology/run_reasoner_real.py
"""
import sys, os, glob, json, subprocess
import pandas as pd

ARGS = sys.argv[1:]
INCLUDE_EMPTY = "--include-empty" in ARGS
MODE_OWL = "--owl" in ARGS
MODE_COMPARE = "--compare" in ARGS
LOG_DIR = ARGS[ARGS.index("--logs") + 1] if "--logs" in ARGS else "evaluation/rugpull/logs"
JS_ANALYZER = "analysis/dynamic_analyzer.js"
OWL_PATH = "ontology/fraud_reasoned_real.owl"


# ── 정답 라벨 ─────────────────────────────────────────────────────────────────
def truth_label(name):
    n = name.lower()
    if n.startswith("normal"):
        return False
    if n.startswith("rug") or n.endswith("_rug"):
        return True
    return None


# ── 판정 가능 여부 (데이터 기준) ──────────────────────────────────────────────
def is_decidable(csv_path):
    df = pd.read_csv(csv_path)
    n_dep = int((df["action"] == "deposit").sum())
    n_out = int(((df["action"] != "deposit") & (df["amount_eth"].astype(float) > 0)).sum())
    return n_dep > 0 and n_out > 0, n_dep, n_out


# ── 레이어별 예측 ─────────────────────────────────────────────────────────────
def predict_js(csv_path):
    """dynamic_analyzer.js 실행 → fraud_type_hint 가 rug_pull 이면 러그풀 예측"""
    out = subprocess.run(["node", JS_ANALYZER, csv_path],
                         capture_output=True, text=True, encoding="utf-8")
    if out.returncode != 0:
        raise RuntimeError(f"JS 실행 실패 ({csv_path}): {out.stderr.strip()[:200]}")
    hint = json.loads(out.stdout).get("fraud_type_hint", "unknown")
    return hint == "rug_pull", hint


def load_owl_predictions():
    from owlready2 import get_ontology
    onto = get_ontology(OWL_PATH).load()
    preds = {}
    for ind in onto.individuals():
        if not ind.name.startswith("contract_"):
            continue
        name = ind.name.replace("contract_", "")
        types = [c.name for c in ind.is_a if hasattr(c, "name")]
        fraud = [t for t in types if t != "FraudContract"]
        preds[name] = (any(t == "RugPull" or t.startswith("RugPull_") for t in types),
                       "+".join(fraud) if fraud else "none")
    return preds


# ── 채점 ──────────────────────────────────────────────────────────────────────
def score(rows):
    scored = rows if INCLUDE_EMPTY else [r for r in rows if r["decidable"]]
    TP = sum(r["actual"] and r["pred"] for r in scored)
    FP = sum((not r["actual"]) and r["pred"] for r in scored)
    FN = sum(r["actual"] and not r["pred"] for r in scored)
    TN = sum((not r["actual"]) and not r["pred"] for r in scored)
    P = TP / (TP + FP) if TP + FP else 0.0
    R = TP / (TP + FN) if TP + FN else 0.0
    F1 = 2 * P * R / (P + R) if P + R else 0.0
    ACC = (TP + TN) / len(scored) if scored else 0.0
    return dict(TP=TP, FP=FP, FN=FN, TN=TN, P=P, R=R, F1=F1, ACC=ACC, n=len(scored))


def verdict(r):
    if not r["decidable"] and not INCLUDE_EMPTY:
        return "판정불가"
    return {(True, True): "TP ✅", (False, False): "TN ✅",
            (True, False): "FN ❌ 미탐", (False, True): "FP ❌ 오탐"}[(r["actual"], r["pred"])]


def print_report(title, rows):
    m = score(rows)
    print("\n" + "=" * 70)
    print(f"{title} — 개별 판정")
    print("=" * 70)
    print(f"{'이름':<14}{'정답':<8}{'판정 결과':<20}{'채점'}")
    print("-" * 70)
    for r in rows:
        a = "러그풀" if r["actual"] else "정상"
        note = "" if r["decidable"] else f"  (입금 {r['n_dep']}건 / 출금 {r['n_out']}건)"
        h = r["hint"] if len(r["hint"]) <= 19 else r["hint"][:17] + ".."
        print(f"{r['name']:<14}{a:<8}{h:<20}{verdict(r)}{note}")

    print("\n혼동 행렬")
    print(f"                  예측: 러그풀   예측: 아님")
    print(f"  실제: 러그풀    TP = {m['TP']:<9} FN = {m['FN']}")
    print(f"  실제: 정상      FP = {m['FP']:<9} TN = {m['TN']}")
    print(f"\n  Precision = {m['P']:.4f}   (러그풀이라고 한 것 중 진짜 러그풀)")
    print(f"  Recall    = {m['R']:.4f}   (진짜 러그풀 중 잡아낸 것)")
    print(f"  F1 Score  = {m['F1']:.4f}")
    print(f"  Accuracy  = {m['ACC']:.4f}")
    und = [r["name"] for r in rows if not r["decidable"]]
    print(f"\n  평가 대상 {m['n']}건", end="")
    if und and not INCLUDE_EMPTY:
        print(f" / 판정불가 제외 {len(und)}건: {', '.join(und)}")
        print(f"  → 전체 {len(rows)}건 중 {len(und) / len(rows) * 100:.0f}%가 "
              f"ETH 장부에 입출금 흐름이 없음 (ETH 전용 수집의 한계)")
    else:
        print()
    return m


# ── 메인 ──────────────────────────────────────────────────────────────────────
def main():
    paths = sorted(glob.glob(os.path.join(LOG_DIR, "*_log.csv")))
    if not paths:
        print(f"[오류] {LOG_DIR} 에 *_log.csv 가 없습니다.")
        sys.exit(1)

    base = []
    for p in paths:
        name = os.path.basename(p)[:-len("_log.csv")]
        actual = truth_label(name)
        if actual is None:
            print(f"[경고] {name}: 이름으로 정답을 알 수 없어 제외 (rug_/normal_ 로 시작해야 함)")
            continue
        dec, n_dep, n_out = is_decidable(p)
        base.append(dict(name=name, path=p, actual=actual, decidable=dec, n_dep=n_dep, n_out=n_out))

    results = {}
    if not MODE_OWL or MODE_COMPARE:
        rows = []
        for b in base:
            pred, hint = predict_js(b["path"])
            rows.append({**b, "pred": pred, "hint": hint})
        results["JS"] = print_report("JS 레이어 (dynamic_analyzer.js)", rows)
        js_rows = rows

    if MODE_OWL or MODE_COMPARE:
        if not os.path.exists(OWL_PATH):
            print(f"[오류] {OWL_PATH} 가 없습니다. load_instances_real.py → run_reasoner_real.py 를 먼저 실행하세요.")
            sys.exit(1)
        owl = load_owl_predictions()
        rows = []
        for b in base:
            if b["name"] not in owl:
                print(f"[경고] {b['name']}: OWL 결과에 없음 (추론기를 다시 돌리세요)")
                continue
            pred, hint = owl[b["name"]]
            rows.append({**b, "pred": pred, "hint": hint})
        results["OWL"] = print_report("OWL 레이어 (fraud_reasoned_real.owl)", rows)
        owl_rows = rows

    if MODE_COMPARE:
        print("\n" + "=" * 70)
        print("레이어 비교")
        print("=" * 70)
        print(f"{'':<8}{'Precision':>11}{'Recall':>9}{'F1':>9}")
        for k, m in results.items():
            print(f"{k:<8}{m['P']:>11.4f}{m['R']:>9.4f}{m['F1']:>9.4f}")
        owl_map = {r["name"]: r["pred"] for r in owl_rows}
        diff = [r["name"] for r in js_rows if r["name"] in owl_map and r["pred"] != owl_map[r["name"]]]
        print(f"\n러그풀 여부 판정이 다른 건: {', '.join(diff) if diff else '없음 (두 레이어 일치)'}")
    print()


if __name__ == "__main__":
    main()