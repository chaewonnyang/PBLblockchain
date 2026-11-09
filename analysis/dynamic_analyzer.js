import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DEPOSIT_ACTIONS   = new Set(["deposit", "stake", "fund_reward_pool"]);
const WITHDRAW_ACTIONS  = new Set(["withdraw", "unstake", "owner_withdraw_all"]);
const HIGH_RISK_ACTIONS = new Set(["owner_withdraw_all"]);

// HopLaundering bothSides 판정에서 제외할 범용 DEX 라우터/애그리게이터.
// EthereumHeist 파일럿(n=8, evaluation/hoplaundering/)에서 BELLE Honeypot Rug Pull
// 케이스의 bothSides 3개 중 2개가 아래 주소로 확인됨 — 활성 지갑이면 거의 누구나
// 상호작용하는 범용 인프라라 "양방향 주소"로 잡히는 게 세탁 의도가 아니라 정상
// 스왑의 부산물일 가능성이 큼. 범위는 이번에 실증된 주소로 한정(과확장 방지) —
// 새 주소 추가 시 실제로 bothSides에 걸린 사례를 근거로만 추가할 것.
const DEX_WHITELIST = new Set([
  "0x7a250d5630b4cf539739df2c5dacb4c659f2488d", // Uniswap V2: Router 2
  "0xdef1c0ded9bec7f1a1670819833240f027b25eff", // 0x: Exchange Proxy
]);

function parseCSV(csvPath) {
  if (!fs.existsSync(csvPath)) return [];
  const lines = fs.readFileSync(csvPath, "utf8").trim().split("\n");
  const headers = lines[0].split(",");
  return lines.slice(1).map(line => {
    const vals = line.split(",");
    return Object.fromEntries(headers.map((h, i) => [h, vals[i]]));
  });
}

function detectContractAddress(rows) {
  const depositRow = rows.find(r => DEPOSIT_ACTIONS.has(r.action));
  return depositRow ? depositRow.to : null;
}

function clamp(x, lo, hi) {
  return Math.max(lo, Math.min(hi, x));
}

// EVASION_ANALYSIS.md 권고 2/6/7 적용 후 신설/변경되는 "얼마나/언제" 계열 규칙
// (BALANCE_DROP, FLOW_SPIKE, TEMPORAL_PATTERN, BALANCE_TIMESERIES_DRAIN)의 공용
// 억제 게이트. 기존에는 detectInflowStop() 내부에만 지역적으로 존재하던
// isNormalUnstake 판정을 이 함수로 추출·확장했다 — 단일 로직으로 통합해
// 두 군데서 조건이 미묘하게 갈리는 것을 방지한다.
//
// 확장한 조건 (기존: uniqueWithdrawers>=3, 금액 균등, 성공률>=80%):
//   - HIGH_RISK_ACTIONS(owner_withdraw_all)가 전혀 없을 것
//   - 출금액의 90% 이상이 원래 예치자 본인에게 돌아갈 것 (자금이 시스템 밖으로
//     나가지 않고 예치자에게 환급되는 패턴인지 확인)
//   - 금액 균등 조건의 경계값을 매우 근소한 차이로 비켜가는 것을 막기 위해
//     strict(<) 대신 <=로 완화 (flashloan_log에서 maxW(20)가 minW(8)*2.5와
//     정확히 같아 strict 비교로는 조직적 패턴이 누락되는 경계 버그 발견·수정)
function computeIsOrganicUnstake(rows, depositorMap, totalOut) {
  const withdrawals = rows.filter(r => WITHDRAW_ACTIONS.has(r.action));
  if (withdrawals.length === 0) return false;
  if (rows.some(r => HIGH_RISK_ACTIONS.has(r.action))) return false;

  const uniqueWithdrawers = new Set(withdrawals.map(r => r.to)).size;
  if (uniqueWithdrawers < 3) return false;

  const withdrawAmounts = withdrawals.map(r => parseFloat(r.amount_eth) || 0).filter(a => a > 0);
  if (withdrawAmounts.length === 0) return false;
  const successRatio = withdrawAmounts.length / withdrawals.length;
  if (successRatio < 0.8) return false;

  const maxW = Math.max(...withdrawAmounts);
  const minW = Math.min(...withdrawAmounts);
  if (maxW > minW * 2.5) return false;

  if (totalOut < 0.01) return false;
  let toDepositors = 0;
  for (const r of withdrawals) {
    if (depositorMap.has(r.to)) toDepositors += parseFloat(r.amount_eth) || 0;
  }
  return (toDepositors / totalOut) >= 0.9;
}

// 권고 7: action 문자열과 무관하게 잔고 시계열만으로 급락 구간을 탐지.
// maxBlockSpan 블록 이내에서 발생한 최대 상대 하락폭을 반환.
function maxWindowedDrawdown(rows, maxBlockSpan) {
  let maxDrop = 0;
  for (let i = 0; i < rows.length; i++) {
    const blockI = parseInt(rows[i].block);
    const balI = parseFloat(rows[i].contract_balance_eth) || 0;
    if (balI <= 0) continue;
    for (let j = i + 1; j < rows.length; j++) {
      const blockJ = parseInt(rows[j].block);
      if (blockJ - blockI > maxBlockSpan) break;
      const balJ = parseFloat(rows[j].contract_balance_eth) || 0;
      const drop = (balI - balJ) / balI;
      if (drop > maxDrop) maxDrop = drop;
    }
  }
  return maxDrop;
}

function checkOscillating(rows) {
  let nearZero = false;
  let recovered = false;
  let cycles = 0;
  for (const row of rows) {
    const bal = parseFloat(row.contract_balance_eth);
    if (bal < 0.01) {
      if (recovered) cycles++;
      nearZero = true;
      recovered = false;
    } else if (nearZero && bal > 0.5) {
      recovered = true;
    }
  }
  return cycles >= 2;
}

const RULES = [
  {
    id: "BALANCE_DROP",
    // EVASION_ANALYSIS.md 권고 2/3: hasOwnerDrain 게이트를 WITHDRAW_ACTIONS 전체로
    // 확장하고, peak*0.1(90%) 바이너리 클리프 대신 (1 - finalBal/peak) 기반 연속
    // 가중치로 전환. 50% 미만 하락은 0점, 100% 하락(완전 탈취)에서 만점.
    description: "출금 발생 후 잔고 급락 — 하락폭에 비례한 연속 점수 (러그풀/폰지 탈출)",
    detect: (ctx) => {
      if (ctx.isOrganicUnstake) return 0;
      const hasWithdrawal = ctx.rows.some(r => WITHDRAW_ACTIONS.has(r.action));
      if (!(ctx.peak > 0 && hasWithdrawal)) return 0;
      const drop = 1 - ctx.finalBal / ctx.peak;
      return clamp((drop - 0.5) / 0.5, 0, 1);
    },
    weight: 40
  },
  {
    id: "FLOW_SPIKE",
    // 권고 1: 단일-최대 출금(maxSingleWithdraw) 대신 누적 유출 비율(totalOut/totalIn)로
    // 교체 — 동일 금액을 여러 건으로 분산 인출해도 정확히 포착됨.
    description: "누적 출금이 총 입금의 50% 이상 (분산 인출 포함, 일거에 자금 흡수)",
    detect: (ctx) => {
      if (ctx.isOrganicUnstake) return false;
      return ctx.totalIn > 0 && (ctx.totalOut / ctx.totalIn) >= 0.5;
    },
    weight: 30
  },
  {
    id: "CONCENTRATION_DRAIN",
    // 권고 4: top3/totalOut >= 0.8 클리프 대신 허핀달-허쉬만 지수(HHI) 기반 연속 점수.
    description: "출금 수령 집중도(HHI) — 소수 지갑에 집중될수록 높은 연속 점수",
    detect: ({ totalOut, recipientMap }) => {
      if (totalOut < 0.01) return 0;
      const hhi = [...recipientMap.values()]
        .map(v => v / totalOut)
        .reduce((s, share) => s + share * share, 0);
      return clamp((hhi - 0.2) / 0.6, 0, 1);
    },
    weight: 35
  },
  {
    id: "PROFIT_EXTRACTION",
    description: "입금 대비 130% 이상 수령한 지갑 존재 (부당 수익 탈취)",
    detect: ({ depositorMap, recipientMap }) => {
      for (const [addr, deposited] of depositorMap.entries()) {
        if (deposited <= 0) continue;
        const received = recipientMap.get(addr) || 0;
        if (received / deposited > 1.3) return true;
      }
      return false;
    },
    weight: 35
  },
  {
    id: "OSCILLATING_BALANCE",
    description: "잔고 0 → 복구 → 0 반복 (플래시론 순환 패턴)",
    detect: ({ rows }) => checkOscillating(rows),
    weight: 30
  },
  {
    id: "TEMPORAL_PATTERN",
    // 권고 6: 시간 지표 신설. (a) 입금 종료 후 출금 시작까지의 대기(dormancy)
    // 구간이 전체 수명의 20%+인 경우, 또는 (b) 출금 구간의 ETH/block 속도가
    // peak 대비 15%+로 급격한 경우 중 더 높은 쪽을 채택.
    description: "입금 종료 후 장기 대기 뒤 인출 또는 급격한 인출 속도 (시간 패턴 이상)",
    detect: (ctx) => {
      if (ctx.isOrganicUnstake) return 0;
      const withdrawals = ctx.rows.filter(r => WITHDRAW_ACTIONS.has(r.action));
      const deposits = ctx.rows.filter(r => DEPOSIT_ACTIONS.has(r.action));
      if (withdrawals.length === 0 || deposits.length === 0) return 0;

      const lastDepositBlock = Math.max(...deposits.map(r => parseInt(r.block)));
      const wBlocks = withdrawals.map(r => parseInt(r.block));
      const firstWithdrawBlock = Math.min(...wBlocks);
      const lastWithdrawBlock = Math.max(...wBlocks);
      const firstBlock = parseInt(ctx.rows[0].block);
      const lastBlock = parseInt(ctx.rows[ctx.rows.length - 1].block);
      const totalBlocks = Math.max(1, lastBlock - firstBlock);

      const gapRatio = Math.max(0, firstWithdrawBlock - lastDepositBlock) / totalBlocks;
      const withdrawSpan = Math.max(1, lastWithdrawBlock - firstWithdrawBlock);
      const velocityRatio = ctx.peak > 0 ? (ctx.totalOut / withdrawSpan) / ctx.peak : 0;

      const fractionDormancy = clamp((gapRatio - 0.2) / 0.3, 0, 1);
      const fractionVelocity = clamp((velocityRatio - 0.15) / 0.35, 0, 1);
      return Math.max(fractionDormancy, fractionVelocity);
    },
    weight: 20
  },
  {
    id: "BALANCE_TIMESERIES_DRAIN",
    // 권고 7: action 문자열과 무관하게 잔고 시계열만으로 급락 탐지 (안전망 규칙).
    // 15블록 이내 구간에서 50% 이상 상대 하락이 있으면 연속 점수 부여.
    description: "action 종류와 무관하게 15블록 이내 잔고 50%+ 급락 탐지",
    detect: (ctx) => {
      if (ctx.isOrganicUnstake) return 0;
      const maxDrop = maxWindowedDrawdown(ctx.rows, 15);
      return clamp((maxDrop - 0.5) / 0.4, 0, 1);
    },
    weight: 20
  }
];

const VERDICT_THRESHOLDS = [
  { min: 65, label: "HIGH_RISK" },
  { min: 25, label: "MEDIUM_RISK" },
  { min: 0,  label: "LOW_RISK" }
];

// ── Cross-type disambiguation ─────────────────────────────────────────────────

function hintFraudType(rows, triggered) {
  const ids = new Set(triggered.map(r => r.id));
  const steps = [];

  const deposits    = rows.filter(r => DEPOSIT_ACTIONS.has(r.action));
  const withdrawals = rows.filter(r => WITHDRAW_ACTIONS.has(r.action));

  const peak = Math.max(0, ...rows.map(r => parseFloat(r.contract_balance_eth) || 0));
  const maxSingleWithdraw = Math.max(0, ...withdrawals.map(r => parseFloat(r.amount_eth) || 0));

  // Shared pre-computed conditions
  const depositFromAddrs    = new Set(deposits.map(r => r.from));
  const uniqueDepositorCount = depositFromAddrs.size;

  // singleLargeOutflow: largest withdrawal >= 70% of peak balance
  const singleLargeOutflow = peak > 0 && maxSingleWithdraw >= peak * 0.70;
  steps.push(
    `singleLargeOutflow: ${singleLargeOutflow}` +
    ` (${maxSingleWithdraw.toFixed(3)} / peak ${peak.toFixed(3)} = ` +
    `${peak > 0 ? (maxSingleWithdraw / peak * 100).toFixed(0) : 0}%)`
  );

  // distributedInflow: >= 5 unique depositor addresses
  const distributedInflow = uniqueDepositorCount >= 5;
  steps.push(`distributedInflow: ${distributedInflow} (${uniqueDepositorCount} unique depositors)`);

  // ownerWithdrawAll: recipient of the largest withdrawal is NOT a known depositor
  // (the deployer/owner never participated as a depositor)
  const largestW = withdrawals.reduce((best, r) => {
    return (parseFloat(r.amount_eth) || 0) > (parseFloat(best?.amount_eth) || 0) ? r : best;
  }, null);
  const ownerWithdrawAll = largestW ? !depositFromAddrs.has(largestW.to) : false;
  steps.push(
    `ownerWithdrawAll: ${ownerWithdrawAll}` +
    ` (recipient ${largestW?.to?.slice(0, 10) ?? "n/a"}... ` +
    `${ownerWithdrawAll ? "not in" : "found in"} depositor list)`
  );

  // participantMidExit: non-owner-withdraw withdrawals with amount > 0 before last block
  const lastBlock = parseInt(rows[rows.length - 1]?.block) || 0;
  const midExits  = withdrawals.filter(r =>
    r.action !== "owner_withdraw_all" &&
    (parseFloat(r.amount_eth) || 0) > 0 &&
    parseInt(r.block) < lastBlock
  );
  const participantMidExit = midExits.length > 0;
  steps.push(`participantMidExit: ${participantMidExit} (${midExits.length} mid-exit withdrawals)`);

  // pump-and-dump conditions
  const someWithdrawalsSucceed = withdrawals.some(r => (parseFloat(r.amount_eth) || 0) > 0);
  const someWithdrawalsFail    = withdrawals.some(r => (parseFloat(r.amount_eth) || 0) === 0);

  // depositor amount map for insider-exit check
  const depositorAmtMap = new Map();
  for (const r of deposits) {
    depositorAmtMap.set(r.from, (depositorAmtMap.get(r.from) || 0) + (parseFloat(r.amount_eth) || 0));
  }
  const insiderExitDetected = withdrawals.some(r => {
    const received = parseFloat(r.amount_eth) || 0;
    if (received === 0) return false;
    const deposited = depositorAmtMap.get(r.to) || 0;
    return received > deposited;
  });

  // ── 러그풀 교차공리 최종안 (2026-10-14): 사실값 계산 ──
  // 모든 값은 지갑별 "낸 돈(deposited)"과 "받은 돈(received)"에서 나온다.
  // hasRealAddresses: N=272 XBlock 평가처럼 주소가 합성(0x000...)된 데이터에서는
  //   지갑별 계산이 의미가 없으므로 기존 규칙을 그대로 쓴다 (팀원 폰지 평가 보존).
  const hasRealAddresses =
    deposits.length > 0 && !deposits.every(r => /^0x0{30,}/i.test(r.from || ""));
  steps.push(`hasRealAddresses: ${hasRealAddresses}`);

  const receivedByAddr = new Map();
  for (const r of withdrawals) {
    const amt = parseFloat(r.amount_eth) || 0;
    if (amt > 0) receivedByAddr.set(r.to, (receivedByAddr.get(r.to) || 0) + amt);
  }

  // [기본 공리] NetDrain ≡ Σ_a max(0, received(a) − deposited(a)) ≥ 0.7 × peak
  //   입금 이력 없는 운영자는 받은 돈 전부, 입금자로 위장한 운영자(evasive_C)는 순수익이 잡힌다.
  let netDrainAmount = 0;
  for (const [addr, got] of receivedByAddr.entries()) {
    netDrainAmount += Math.max(0, got - (depositorAmtMap.get(addr) || 0));
  }
  const netDrainRatio = peak > 0 ? netDrainAmount / peak : 0;
  const netDrain = peak > 0 && netDrainAmount >= peak * 0.70;
  steps.push(
    `netDrain: ${netDrain} (순수익 합 ${netDrainAmount.toFixed(3)} / peak ${peak.toFixed(3)} = ` +
    `${(netDrainRatio * 100).toFixed(0)}%, 기준 70%)`
  );

  // [교차 공리] SharedProfit ≡ |{a : deposited(a) > 0 ∧ received(a) ≥ 1.05 × deposited(a)}| ≥ 2
  //   러그풀은 ¬SharedProfit, 폰지·펌프앤덤프는 SharedProfit → 판정 순서와 무관하게 배타.
  let profitSharerCount = 0;
  for (const [addr, got] of receivedByAddr.entries()) {
    const dep = depositorAmtMap.get(addr) || 0;
    if (dep > 0 && got >= dep * 1.05) profitSharerCount++;
  }
  const sharedProfit = profitSharerCount >= 2;
  steps.push(`sharedProfit: ${sharedProfit} (105% 이상 회수한 입금자 ${profitSharerCount}명, 기준 2명)`);

  // [적용 범위] T (반복 중계): 실제 출금 5건 이상이고, 그 과반이 직전 입금과 같은 금액.
  //   돈이 쌓이지 않으므로 "쌓인 돈을 빼간다"가 성립하지 않는다 → 러그풀 판정 대상 아님.
  const posWithdrawals = withdrawals.filter(r => (parseFloat(r.amount_eth) || 0) > 0);
  let passThrough = false;
  if (posWithdrawals.length >= 5) {
    let matched = 0;
    for (let i = 1; i < rows.length; i++) {
      const cur = rows[i];
      if (!WITHDRAW_ACTIONS.has(cur.action)) continue;
      const curAmt = parseFloat(cur.amount_eth) || 0;
      if (curAmt <= 0) continue;
      const prev = rows[i - 1];
      const prevAmt = parseFloat(prev.amount_eth) || 0;
      if (DEPOSIT_ACTIONS.has(prev.action) && prevAmt > 0 && prevAmt === curAmt) matched++;
    }
    passThrough = matched / posWithdrawals.length >= 0.50;
    steps.push(`passThrough(T): ${passThrough} (직전 입금과 같은 금액 ${matched}/${posWithdrawals.length}건, 기준 과반)`);
  } else {
    steps.push(`passThrough(T): false (실제 출금 ${posWithdrawals.length}건 < 5)`);
  }

  // ── 출금 차단 경고(ZeroWithdrawBlock)·PumpAndDump 판정용 데이터 속성 ──
  // 오너 판별 1안: 배포자/ownerClient 주소를 상수로 식별한다.
  // scripts/simulate_*.js가 공통으로 hardhat 기본 니모닉의 계정 0을
  // ownerClient로 사용하므로(예: ponzi_log.csv의 owner_withdraw_all 수신자와 동일
  // 주소) 이 주소는 시뮬레이션 전반에서 고정값이다.
  const OWNER_ADDRESS = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

  // 출금 차단 경고(오너 외 출금이 거의 전부 실패) 판정 임계값. "거의 없음"을 5%로 잡은 근거는
  // 아직 실증 데이터 기반 튜닝이 아니라 잠정값이다 — 실제 사례가 쌓이면 재검토.
  const NON_PRIVILEGED_SUCCESS_EPSILON = 0.05;

  // PumpAndDump 판정용 "실패 시점 잔고 ≈ 0" 임계값.
  // TODO(ε 미정): 지금은 임의의 0.01 ETH 같은 숫자를 넣지 않고 엄격한 0
  // 비교만 적용한다 — 실제 PumpDump 시뮬레이션(analysis/logs/pumpdump_log.csv)의
  // balanceAtFailure는 정확히 0이라 이 값으로는 영향 없음. SelectiveTrap의
  // balanceAtFailure(예: 9.0 ETH)와는 이미 크게 벌어져 있어 엡실론을 늦게
  // 정해도 당장 오분류로 이어지지 않는다. 부동소수점 반올림 오차가 있는
  // 실데이터가 들어오면 이 값을 다시 정해야 한다.
  const PUMPDUMP_BALANCE_AT_FAILURE_EPSILON = 0; // TODO: 실증 데이터로 확정 필요

  const withdrawSuccessRate = withdrawals.length > 0
    ? withdrawals.filter(r => (parseFloat(r.amount_eth) || 0) > 0).length / withdrawals.length
    : 0;

  const nonPrivilegedWithdrawals = withdrawals.filter(
    r => (r.to || "").toLowerCase() !== OWNER_ADDRESS
  );
  const nonPrivilegedSuccessRate = nonPrivilegedWithdrawals.length > 0
    ? nonPrivilegedWithdrawals.filter(r => (parseFloat(r.amount_eth) || 0) > 0).length
        / nonPrivilegedWithdrawals.length
    : 0;

  // balanceAtFailure: someWithdrawalsFail과 동일한 필터(amount_eth === 0인 withdraw 행)에
  // contract_balance_eth 필드만 얹는다 — "실패"를 새로 재정의하지 않는다.
  // 평균이 아닌 최댓값을 채택: 오너가 일부만 먼저 인출하고 실패 시점들이 드레인
  // 전/후에 걸쳐 섞이면 평균은 드레인 이후의 낮은 잔고 쪽으로 끌려 내려가 "실패
  // 시점에도 자금이 남아있었다"는 증거가 희석된다. 최댓값은 단 한 번의 실패라도
  // 잔고가 유의미하게 남아있었다는 사실을 보존해 PumpDump(=항상 0)와 더 선명하게
  // 갈린다.
  const failedWithdrawBalances = withdrawals
    .filter(r => (parseFloat(r.amount_eth) || 0) === 0)
    .map(r => parseFloat(r.contract_balance_eth) || 0);
  const balanceAtFailure = failedWithdrawBalances.length > 0
    ? Math.max(...failedWithdrawBalances)
    : 0;

  steps.push(
    `withdrawSuccessRate: ${(withdrawSuccessRate * 100).toFixed(1)}% ` +
    `(${withdrawals.filter(r => (parseFloat(r.amount_eth) || 0) > 0).length}/${withdrawals.length} succeeded)`
  );
  steps.push(
    `nonPrivilegedSuccessRate: ${(nonPrivilegedSuccessRate * 100).toFixed(1)}% ` +
    `(owner ${OWNER_ADDRESS.slice(0, 10)}... 제외 ${nonPrivilegedWithdrawals.length}건 중 성공)`
  );
  steps.push(
    `balanceAtFailure: ${balanceAtFailure.toFixed(3)} ETH ` +
    `(amount_eth=0 시점 잔고 최댓값, n=${failedWithdrawBalances.length})`
  );

  // ── 출금 차단 신호 ZeroWithdrawBlock (2026-10, 허니팟 사기 유형 삭제) ──
  // 기존 honeypot 분기 조건에서 inflowContinues만 뺀 것: 오너 외 출금 시도가 있고, 그 성공률이
  // ε 이하이며, 실패 시점에도 잔고가 남아 있음. 오너만 인출하는 선택적 차단도 걸린다.
  // nonPrivilegedWithdrawals.length>0 가드: 비-오너 출금 시도가 한 건도 없으면(증거 부재)
  // nonPrivilegedSuccessRate가 0/0→0으로 계산돼 근거 없이 경고가 나지 않게 한다.
  // 사기 유형이 아니라 경고 신호다 — 아래 사기 조건이 모두 불일치일 때만 unclassified_warning을
  // 내고(Normal 대신), dynamic_risk_score에는 더하지 않는다.
  // 분류 체인과 무관하게 항상 계산해 withdraw_block_warning으로 병기한다(유형이 확정돼도 출력, b안).
  const zeroWithdrawBlock =
    nonPrivilegedWithdrawals.length > 0 &&
    nonPrivilegedSuccessRate <= NON_PRIVILEGED_SUCCESS_EPSILON &&
    balanceAtFailure > 0;
  const withdrawBlockWarning = {
    detected: zeroWithdrawBlock,
    reason: nonPrivilegedWithdrawals.length === 0
      ? "비오너 출금 시도 없음"
      : `비오너 출금 ${nonPrivilegedWithdrawals.length}건 중 성공률 ` +
        `${(nonPrivilegedSuccessRate * 100).toFixed(1)}% ` +
        `${nonPrivilegedSuccessRate <= NON_PRIVILEGED_SUCCESS_EPSILON ? "<=" : ">"} ` +
        `${(NON_PRIVILEGED_SUCCESS_EPSILON * 100).toFixed(0)}%, ` +
        `실패 시점 잔고 ${balanceAtFailure.toFixed(3)} ETH${balanceAtFailure > 0 ? " > 0" : ""}`
  };

  // (Flash Loan 분기 삭제 — 시스템 범위에서 제외. OSCILLATING_BALANCE 신호 계산은 그대로 둔다)

  // ── Priority 2: PumpAndDump ──
  // balanceAtFailure ≈ 0 조건을 추가로 요구한다(엡실론 값 자체는 위 TODO 참고,
  // 지금은 엄격한 0 비교). 오너만 인출하고 잔고가 남은 채 나머지 출금이 실패하는
  // 경우(balanceAtFailure > 0)는 이 조건으로 PumpAndDump에서 빠지고, 다른 사기 조건도
  // 불일치이면 아래 출금 차단 경고로 간다.
  // 교차 공리: 실주소 데이터에서는 SharedProfit(내부자 여럿이 이익 실현)을 요구한다.
  if (someWithdrawalsSucceed && someWithdrawalsFail && insiderExitDetected &&
      (!hasRealAddresses || sharedProfit) &&
      balanceAtFailure <= PUMPDUMP_BALANCE_AT_FAILURE_EPSILON) {
    steps.push(
      "→ pump_and_dump (mixed withdrawal outcomes + insider profit extraction, " +
      `balanceAtFailure ${balanceAtFailure.toFixed(3)} ETH <= ε)`
    );
    return { hint: "pump_and_dump", reasoning_steps: steps,
             withdrawSuccessRate, nonPrivilegedSuccessRate, balanceAtFailure, withdrawBlockWarning };
  }

  // ── Priority 3: MoneyLaundering ──
  // Single large outflow + distributed inflow + recipient IS a known depositor
  if (singleLargeOutflow && distributedInflow && !ownerWithdrawAll) {
    steps.push(
      `→ money_laundering (large outflow + ${uniqueDepositorCount} distributed depositors` +
      ` + collector is a known depositor)`
    );
    return { hint: "money_laundering", reasoning_steps: steps,
             withdrawSuccessRate, nonPrivilegedSuccessRate, balanceAtFailure, withdrawBlockWarning };
  }

  // ── Priority 4: RugPull ──
  // 최종안: RugPull ← [범위] ¬T ∧ [기본] NetDrain ∧ [교차] ¬SharedProfit
  // 주소가 합성된 데이터(hasRealAddresses=false)는 지갑별 계산이 불가능해 기존 규칙을 쓴다.
  const rugPull = hasRealAddresses
    ? (!passThrough && netDrain && !sharedProfit)
    : (singleLargeOutflow && ownerWithdrawAll && !participantMidExit);
  if (rugPull) {
    steps.push(hasRealAddresses
      ? `→ rug_pull (¬T ∧ NetDrain ${(netDrainRatio * 100).toFixed(0)}% ∧ ¬SharedProfit ${profitSharerCount}명)`
      : "→ rug_pull (legacy: large outflow to non-depositor address, no participant mid-exits)");
    return { hint: "rug_pull", reasoning_steps: steps,
             withdrawSuccessRate, nonPrivilegedSuccessRate, balanceAtFailure, withdrawBlockWarning };
  }

  // ── Priority 5: PonziScheme ──
  // 교차 공리: 실주소 데이터에서는 SharedProfit(수익을 2명 이상이 나눠 가짐)을 요구한다.
  if (ids.has("BALANCE_DROP") && ids.has("FLOW_SPIKE") && participantMidExit &&
      (!hasRealAddresses || sharedProfit)) {
    steps.push(
      `→ ponzi_scheme (balance drop + flow spike + ${midExits.length} participant mid-exits)`
    );
    return { hint: "ponzi_scheme", reasoning_steps: steps,
             withdrawSuccessRate, nonPrivilegedSuccessRate, balanceAtFailure, withdrawBlockWarning };
  }

  // ── Priority 6: 유형 미확정 + 출금 차단 경고 ──
  if (zeroWithdrawBlock) {
    steps.push(
      `→ unclassified_warning: 유형 미확정, 출금 차단 경고 (ZeroWithdrawBlock: ` +
      `nonPrivilegedSuccessRate ${(nonPrivilegedSuccessRate * 100).toFixed(1)}% ` +
      `<= ${(NON_PRIVILEGED_SUCCESS_EPSILON * 100).toFixed(0)}%, ` +
      `balanceAtFailure ${balanceAtFailure.toFixed(3)} ETH > 0, 사기 유형 조건 불일치)`
    );
    return { hint: "unclassified_warning", reasoning_steps: steps,
             withdrawSuccessRate, nonPrivilegedSuccessRate, balanceAtFailure, withdrawBlockWarning };
  }

  // ── Priority 7: Normal (사기 조건 불일치 AND NOT ZeroWithdrawBlock) ──
  if (!zeroWithdrawBlock && rows.some(r => r.action === "stake" || r.action === "unstake")) {
    steps.push("→ normal_staking (stake/unstake pattern, no fraud signals)");
    return { hint: "normal_staking", reasoning_steps: steps,
             withdrawSuccessRate, nonPrivilegedSuccessRate, balanceAtFailure, withdrawBlockWarning };
  }

  steps.push("→ unknown (no rules matched)");
  return { hint: "unknown", reasoning_steps: steps,
           withdrawSuccessRate, nonPrivilegedSuccessRate, balanceAtFailure, withdrawBlockWarning };
}

// ── InflowStop signal ─────────────────────────────────────────────────────────

function detectInflowStop(rows, isOrganicUnstake) {
  const deposits = rows.filter(r => DEPOSIT_ACTIONS.has(r.action));
  if (deposits.length === 0) {
    return { detected: false, stop_ratio: 0, last_deposit_block: null, last_block: null };
  }

  const lastDepositBlock = Math.max(...deposits.map(r => parseInt(r.block) || 0));
  const firstBlock  = parseInt(rows[0]?.block) || 0;
  const lastBlock   = parseInt(rows[rows.length - 1]?.block) || 0;
  const totalBlocks = lastBlock - firstBlock || 1;

  const stopRatio = (lastBlock - lastDepositBlock) / totalBlocks;
  const balanceAfterStop = rows
    .filter(r => parseInt(r.block) > lastDepositBlock)
    .some(r => parseFloat(r.contract_balance_eth) > 0);

  // Guard: normal unstaking (many unique recipients, roughly equal amounts, high success
  // rate, funds returning to depositors). Uses the shared computeIsOrganicUnstake() —
  // previously this guard was computed locally here only; it is now a single shared
  // gate also used by the RULES (BALANCE_DROP/FLOW_SPIKE/TEMPORAL_PATTERN/
  // BALANCE_TIMESERIES_DRAIN) so the two never drift apart.
  if (isOrganicUnstake) {
    return {
      detected: false,
      stop_ratio: +stopRatio.toFixed(3),
      suppressed_reason: "normal_unstake_pattern",
      last_deposit_block: lastDepositBlock,
      last_block: lastBlock
    };
  }

  return {
    detected: stopRatio >= 0.30 && balanceAfterStop,
    stop_ratio: +stopRatio.toFixed(3),
    last_deposit_block: lastDepositBlock,
    last_block: lastBlock
  };
}

// ── Evasion subclass scoring ──────────────────────────────────────────────────

function detectEvasionSubclass(rows, baseFraudType) {
  const THRESHOLD = 30;

  // Skip evasion check for non-fraud types (unclassified_warning maps to Unknown)
  if (baseFraudType === "Normal" || baseFraudType === "Unknown") return null;

  const withdrawals = rows.filter(r => WITHDRAW_ACTIONS.has(r.action));
  if (withdrawals.length === 0) return null;

  const peakBalance = Math.max(0, ...rows.map(r => parseFloat(r.contract_balance_eth) || 0));
  const maxSingleW  = Math.max(0, ...withdrawals.map(r => parseFloat(r.amount_eth) || 0));
  const maxRatio    = peakBalance > 0 ? maxSingleW / peakBalance : 0;

  const wBlocks    = withdrawals.map(r => parseInt(r.block) || 0);
  const firstBlock = parseInt(rows[0]?.block) || 0;
  const lastBlock  = parseInt(rows[rows.length - 1]?.block) || 0;
  const totalBlocks = lastBlock - firstBlock || 1;
  const wSpan      = wBlocks.length > 0
    ? Math.max(...wBlocks) - Math.min(...wBlocks)
    : 0;
  const spanRatio  = wSpan / totalBlocks;

  const scores = {
    BalanceDropEvasion: 0,
    MaxTxEvasion:       0,
    SlowDrain:          0,
    HopLaundering:      0,
    DistributedDump:    0
  };

  // BalanceDropEvasion: single withdrawal < 80% of peak
  if (maxRatio < 0.80) {
    scores.BalanceDropEvasion = Math.round((0.80 - maxRatio) / 0.80 * 100);
  }

  // MaxTxEvasion: repeated withdrawals, each < 90% of peak
  if (withdrawals.length >= 3 && maxRatio < 0.90) {
    scores.MaxTxEvasion = Math.min(100,
      Math.round(withdrawals.length / 3 * 50 + (0.90 - maxRatio) * 50)
    );
  }

  // SlowDrain: withdrawal span covers > 30% of contract lifespan
  if (spanRatio > 0.30) {
    scores.SlowDrain = Math.round((spanRatio - 0.30) / 0.70 * 100);
  }

  // HopLaundering (MoneyLaundering only): some withdrawal-side addresses never deposited
  if (baseFraudType === "MoneyLaundering") {
    const depositAddrs = new Set(
      rows.filter(r => DEPOSIT_ACTIONS.has(r.action)).map(r => r.from)
    );
    const withdrawAddrs = [...new Set(withdrawals.map(r => r.from))];
    const hopAddrs  = withdrawAddrs.filter(a => !depositAddrs.has(a));
    const bothSides = withdrawAddrs.filter(a => depositAddrs.has(a) && !DEX_WHITELIST.has(a));
    const whitelistedHits = withdrawAddrs.filter(a => depositAddrs.has(a) && DEX_WHITELIST.has(a));
    if (whitelistedHits.length > 0) {
      console.log(`[DEX_WHITELIST] MoneyLaundering 판정에서 제외된 주소: ${whitelistedHits.join(', ')}`);
    }
    if (hopAddrs.length >= 1 && bothSides.length >= 2) {
      scores.HopLaundering = Math.min(100, hopAddrs.length * 30 + bothSides.length * 20);
    }
  }

  // DistributedDump (PumpDump only): withdrawal-side addresses that never deposited
  if (baseFraudType === "PumpDump") {
    const depositAddrs = new Set(
      rows.filter(r => DEPOSIT_ACTIONS.has(r.action)).map(r => r.from)
    );
    const withdrawOnlyAddrs = [...new Set(withdrawals.map(r => r.from))]
      .filter(a => !depositAddrs.has(a));
    if (withdrawOnlyAddrs.length >= 2) {
      scores.DistributedDump = Math.min(100, withdrawOnlyAddrs.length * 25);
    }
  }

  // Select candidates relevant to the fraud type
  const relevant = ["BalanceDropEvasion", "MaxTxEvasion", "SlowDrain"];
  if (baseFraudType === "MoneyLaundering") relevant.push("HopLaundering");
  if (baseFraudType === "PumpDump")        relevant.push("DistributedDump");

  const candidates = relevant
    .filter(k => scores[k] >= THRESHOLD)
    .sort((a, b) => scores[b] - scores[a]);

  if (candidates.length === 0) return null;

  return {
    subclass:   `${baseFraudType}_${candidates[0]}`,
    confidence: scores[candidates[0]],
    all_scores: Object.fromEntries(
      relevant.map(k => [`${baseFraudType}_${k}`, scores[k]])
    )
  };
}

// ── Main export ───────────────────────────────────────────────────────────────

const FRAUD_TYPE_MAP = {
  "money_laundering":    "MoneyLaundering",
  "pump_and_dump":       "PumpDump",
  "rug_pull":            "RugPull",
  "ponzi_scheme":        "PonziScheme",
  "ponzi_or_laundering": "PonziScheme",
  "flash_loan":          "FlashLoan",
  "normal_staking":      "Normal"
};

export function analyzeDynamic(csvPath) {
  const rows = parseCSV(csvPath);

  if (rows.length === 0) {
    return {
      csv:               path.basename(csvPath),
      error:             "CSV 없음 — 시뮬레이션을 먼저 실행하세요",
      triggered_rules:   [],
      dynamic_risk_score: 0,
      verdict:           "UNKNOWN",
      fraud_type_hint:   "unknown",
      reasoning_steps:   [],
      withdraw_success_rate:       0,
      non_privileged_success_rate: 0,
      balance_at_failure_eth:      0,
      withdraw_block_warning:      { detected: false, reason: "CSV 없음" },
      anomaly_signals:   {},
      evasion_detected:  false,
      evasion_subclass:  null,
      evasion_confidence: 0,
      evasion_consequence: null,
      evasion_all_scores: {},
      counter_detection: null
    };
  }

  const contractAddr = detectContractAddress(rows);  // eslint-disable-line no-unused-vars
  let totalIn = 0, totalOut = 0, peak = 0, maxSingleWithdraw = 0;
  const depositorMap = new Map();
  const recipientMap = new Map();

  for (const row of rows) {
    const amount = parseFloat(row.amount_eth) || 0;
    const bal    = parseFloat(row.contract_balance_eth) || 0;
    if (bal > peak) peak = bal;

    if (DEPOSIT_ACTIONS.has(row.action)) {
      totalIn += amount;
      depositorMap.set(row.from, (depositorMap.get(row.from) || 0) + amount);
    }
    if (WITHDRAW_ACTIONS.has(row.action)) {
      totalOut += amount;
      if (amount > maxSingleWithdraw) maxSingleWithdraw = amount;
      recipientMap.set(row.to, (recipientMap.get(row.to) || 0) + amount);
    }
  }

  const finalBal = parseFloat(rows[rows.length - 1].contract_balance_eth) || 0;
  const isOrganicUnstake = computeIsOrganicUnstake(rows, depositorMap, totalOut);
  const ctx = { totalIn, totalOut, peak, finalBal, maxSingleWithdraw,
                depositorMap, recipientMap, rows, isOrganicUnstake };

  // Anomaly rule scoring. rule.detect()는 boolean(기존 규칙, true=1/false=0) 또는
  // 0~1 사이의 연속 fraction(BALANCE_DROP/CONCENTRATION_DRAIN 등)을 반환할 수 있다.
  // 획득 점수 = weight * fraction (반올림), fraction<=0이면 트리거되지 않은 것으로 간주.
  const triggered = [];
  let rawScore = 0;
  for (const rule of RULES) {
    const result = rule.detect(ctx);
    const fraction = typeof result === "boolean" ? (result ? 1 : 0) : clamp(result, 0, 1);
    if (fraction > 0) {
      const earned = Math.round(rule.weight * fraction);
      if (earned > 0) {
        triggered.push({
          id: rule.id,
          description: rule.description,
          weight: earned,
          weight_max: rule.weight,
          fraction: +fraction.toFixed(2)
        });
        rawScore += earned;
      }
    }
  }

  const dynamic_risk_score = Math.min(100, rawScore);
  const verdict = VERDICT_THRESHOLDS.find(t => dynamic_risk_score >= t.min).label;

  // Classification with reasoning
  const hintResult      = hintFraudType(rows, triggered);
  const fraud_type_hint = hintResult.hint;
  const reasoning_steps = hintResult.reasoning_steps;
  const withdraw_block_warning = hintResult.withdrawBlockWarning;
  if (withdraw_block_warning.detected && fraud_type_hint !== "unclassified_warning") {
    reasoning_steps.push(`유형은 ${fraud_type_hint}으로 확정, 별도로 출금 차단 경고 병기 (${withdraw_block_warning.reason})`);
  }

  // InflowStop signal
  const inflowStop = detectInflowStop(rows, isOrganicUnstake);
  if (fraud_type_hint === "ponzi_scheme" && inflowStop.detected) {
    reasoning_steps.push(
      `PONZI_COLLAPSE_CONFIRMED: inflow stopped at block ${inflowStop.last_deposit_block}` +
      ` (${(inflowStop.stop_ratio * 100).toFixed(0)}% of lifespan without new deposits)`
    );
  }

  // Evasion subclass scoring
  const baseFraudType  = FRAUD_TYPE_MAP[fraud_type_hint] ?? "Unknown";
  const evasionResult  = detectEvasionSubclass(rows, baseFraudType);

  return {
    csv:              path.basename(csvPath),
    rows_analyzed:    rows.length,
    metrics: {
      total_in_eth:            +totalIn.toFixed(4),
      total_out_eth:           +totalOut.toFixed(4),
      net_flow_eth:            +(totalIn - totalOut).toFixed(4),
      peak_balance_eth:        +peak.toFixed(4),
      final_balance_eth:       +finalBal.toFixed(4),
      max_single_withdraw_eth: +maxSingleWithdraw.toFixed(4)
    },
    triggered_rules:   triggered,
    dynamic_risk_score,
    verdict,
    fraud_type_hint,
    reasoning_steps,
    withdraw_success_rate:       +hintResult.withdrawSuccessRate.toFixed(3),
    non_privileged_success_rate: +hintResult.nonPrivilegedSuccessRate.toFixed(3),
    balance_at_failure_eth:      +hintResult.balanceAtFailure.toFixed(4),
    withdraw_block_warning,
    anomaly_signals: {
      INFLOW_STOP: inflowStop
    },
    evasion_detected:    evasionResult !== null,
    evasion_subclass:    evasionResult?.subclass    ?? null,
    evasion_confidence:  evasionResult?.confidence  ?? 0,
    evasion_consequence: evasionResult
      ? `Detected evasion pattern: ${evasionResult.subclass} (confidence ${evasionResult.confidence})`
      : null,
    evasion_all_scores:  evasionResult?.all_scores  ?? {},
    counter_detection:   null
  };
}

// CLI
if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  const csvArg = process.argv[2];
  if (!csvArg) {
    console.error("사용법: node analysis/dynamic_analyzer.js analysis/logs/ponzi_log.csv");
    process.exit(1);
  }
  const result = analyzeDynamic(path.resolve(csvArg));
  console.log(JSON.stringify(result, null, 2));
}