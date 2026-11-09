/**
 * filter_eth_addresses.js
 *
 * 목적: 주소 목록을 받아서, 각 주소에 "실제 ETH가 오간 거래(value > 0)"가
 *       있는지 가볍게 미리 확인한다. fetch_and_convert_v2.js 를 돌리기 전에
 *       skipped 될 주소를 걸러내서 시간 낭비를 막는다.
 *
 * 판정 기준은 fetch_and_convert_v2.js 와 동일하다:
 *   normal/internal 거래 중 value(wei) > 0 인 게 하나라도 있으면 → OK
 *   전부 0(토큰만 오간 경우 등) 이면 → SKIP
 *
 * 속도를 위해 각 주소당 첫 페이지(최대 10000건)만 확인한다. 러그풀 판정에
 * 필요한 초기 자금 유입은 거의 항상 첫 페이지 안에 있으므로 충분하다.
 *
 * 사용법:
 *   1) 확인할 주소를 addresses_to_check.txt 에 한 줄에 하나씩 적는다.
 *   2) 환경변수 키 설정 후 실행:
 *        $env:ETHERSCAN_API_KEY="당신의키"      (PowerShell)
 *        node evaluation/rugpull/filter_eth_addresses.js addresses_to_check.txt
 *   3) 결과:
 *        - 화면에 OK / SKIP 이 주소별로 출력됨
 *        - eth_ok_addresses.txt  ← OK 주소만 저장 (이걸로 fetch 돌리면 됨)
 *        - 마지막에 OK 주소들을 한 줄 명령어로 붙여서 출력해줌
 */

import fs   from 'fs';
import https from 'https';

const API_KEY  = process.env.ETHERSCAN_API_KEY;
const BASE_URL = 'https://api.etherscan.io/v2/api';
const CHAIN_ID = 1;
const RATE_MS  = 250;   // 초당 4회 이하 (무료 티어 안전선)
const PAGE_SIZE = 10000;

if (!API_KEY) {
  console.error('[오류] ETHERSCAN_API_KEY 가 설정되지 않았습니다.');
  console.error('  PowerShell:  $env:ETHERSCAN_API_KEY="당신의키"');
  process.exit(1);
}

const inputFile = process.argv[2];
if (!inputFile) {
  console.error('[사용법] node filter_eth_addresses.js <주소목록.txt>');
  process.exit(1);
}

// ── 유틸 ────────────────────────────────────────────────────────────────────
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function httpGet(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end',  () => resolve(Buffer.concat(chunks).toString('utf8')));
    });
    req.on('error', reject);
    req.setTimeout(30000, () => { req.destroy(); reject(new Error('timeout')); });
  });
}

function weiToEth(weiStr) {
  if (!weiStr || weiStr === '0') return 0;
  try   { return Number(BigInt(weiStr)) / 1e18; }
  catch { return parseFloat(weiStr) / 1e18; }
}

let _last = 0;
async function slot() {
  const gap = RATE_MS - (Date.now() - _last);
  if (gap > 0) await sleep(gap);
  _last = Date.now();
}

async function apiGet(params) {
  const qs = Object.entries({ chainid: CHAIN_ID, ...params, apikey: API_KEY })
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
  await slot();
  const text = await httpGet(`${BASE_URL}?${qs}`);
  try { return JSON.parse(text); } catch { return { result: [] }; }
}

// 첫 페이지에서 value>0 인 거래가 있는지 확인
async function hasEthValue(address, action) {
  const resp = await apiGet({
    module: 'account', action,
    address, startblock: 0, endblock: 99999999,
    page: 1, offset: PAGE_SIZE, sort: 'asc',
  });
  if (!Array.isArray(resp.result)) return false;
  return resp.result.some(tx => weiToEth(tx.value) > 0);
}

// ── 메인 ────────────────────────────────────────────────────────────────────
const addresses = fs.readFileSync(inputFile, 'utf8')
  .split(/\r?\n/)
  .map(s => s.trim().toLowerCase())
  .filter(s => /^0x[0-9a-f]{40}$/.test(s));

console.log(`확인할 주소: ${addresses.length}개\n`);

const okList = [];
for (let i = 0; i < addresses.length; i++) {
  const addr = addresses[i];
  process.stdout.write(`[${i + 1}/${addresses.length}] ${addr} ... `);
  try {
    // normal 거래 먼저 확인, 없으면 internal 확인
    let ok = await hasEthValue(addr, 'txlist');
    if (!ok) ok = await hasEthValue(addr, 'txlistinternal');
    if (ok) { console.log('OK  ✅'); okList.push(addr); }
    else    { console.log('SKIP (ETH 거래 없음)'); }
  } catch (e) {
    console.log(`오류: ${e.message}`);
  }
}

fs.writeFileSync('eth_ok_addresses.txt', okList.join('\n') + '\n', 'utf8');

console.log(`\n${'='.repeat(50)}`);
console.log(`OK ${okList.length}개 / 전체 ${addresses.length}개`);
console.log(`→ eth_ok_addresses.txt 에 저장했습니다.\n`);

if (okList.length > 0) {
  console.log('아래를 복사해서 바로 fetch 하세요 (한 번에 여러 개):\n');
  // 5개씩 묶어서 명령어 출력 (너무 길면 나눠서)
  for (let i = 0; i < okList.length; i += 5) {
    const chunk = okList.slice(i, i + 5).join(' ');
    console.log(`node evaluation/hoplaundering/fetch_and_convert_v2.js ${chunk}\n`);
  }
}
