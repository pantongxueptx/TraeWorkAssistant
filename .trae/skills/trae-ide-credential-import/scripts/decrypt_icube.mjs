import { readFileSync, existsSync } from "fs";
import { join } from "path";

// ── 参数与自动探测 ─────────────────────────────────────────────────────────
// 用法: node decrypt_icube.mjs [storage.json] [main.js]
let storagePath = process.argv[2] || "";
let mainJsPath = process.argv[3] || "";

const appData = process.env.APPDATA || "";
const storageCandidates = [
  join(appData, "Trae CN", "User", "globalStorage", "storage.json"),
  join(appData, "TRAE SOLO CN", "User", "globalStorage", "storage.json"),
];
if (!storagePath) {
  storagePath = storageCandidates.find((p) => existsSync(p)) || "";
  if (!storagePath) {
    console.error("未找到 storage.json，请显式传入: %APPDATA%\\Trae CN\\User\\globalStorage\\storage.json");
    process.exit(1);
  }
}
const mainJsCandidates = [
  "D:\\Application\\Trae CN\\resources\\app\\out\\main.js",
  join(appData, "..", "Local", "Programs", "Trae CN", "resources", "app", "out", "main.js"),
  join(appData, "..", "Local", "Programs", "TRAE SOLO CN", "resources", "app", "out", "main.js"),
];
if (!mainJsPath) {
  mainJsPath = mainJsCandidates.find((p) => existsSync(p)) || "";
  if (!mainJsPath) {
    console.error("未找到 IDE main.js，请显式传入 <IDE安装目录>\\resources\\app\\out\\main.js");
    process.exit(1);
  }
}
console.log("storage:", storagePath);
console.log("main.js:", mainJsPath);

// ── 从 IDE 代码提取替换表 ule/dle（64 字节，AES 变体密钥派生材料）──────────
const mainJs = readFileSync(mainJsPath, "utf-8");
function getTable(name) {
  const marker = name + "=Uint8Array.from([";
  const idx = mainJs.indexOf(marker);
  if (idx < 0) throw new Error("在 main.js 中未找到替换表 " + name);
  const close = mainJs.indexOf("])", idx);
  const slice = mainJs.slice(idx + marker.length, close);
  return Uint8Array.from(slice.split(",").map((s) => parseInt(s.trim(), 10)));
}
const ule = getTable("ule");
const dle = getTable("dle");
console.log("tables:", ule.length, dle.length);

// ── byteCrypto 解密实现（与 IDE out-build/vs/base/common/byteCrypto.js 一致）─
const sO = 16, nO = 16, Hh = 64, ny = 32, oO = 64, Eg = 6;
const M7 = { AES128: 16 };

async function O7(t) {
  const e = await crypto.subtle.digest("SHA-512", t);
  return new Uint8Array(e);
}
async function tle(keyMat) {
  const n = new Uint8Array(Hh + oO);
  n.set(await O7(keyMat), 0);          // n[0..64) = SHA512(keyMat)
  const a = new Uint8Array(oO);
  for (let r = 0; r < oO; r++) a[r] = ule[r] ^ dle[r];
  n.set(a, Hh);                        // n[64..128) = ule^dle
  n.set(await O7(n), 0);               // n[0..64) = SHA512(n)（覆盖前 64 字节）
  return { aesKey: n.slice(0, M7.AES128), iv: n.slice(M7.AES128, M7.AES128 + nO) };
}
async function WHe(key, iv, ct) {
  if (ct.length % sO !== 0) return new Uint8Array(0);
  try {
    const k = await crypto.subtle.importKey("raw", key, { name: "AES-CBC" }, false, ["decrypt"]);
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-CBC", iv }, k, ct));
  } catch {
    return new Uint8Array(0);
  }
}
// blob 布局: [0..6) 头 74 63 05 10 00 00 | [6..38) 密钥材料 | [38..) AES-CBC 密文
// 密文 = SHA512(明文)[0..64) 前缀 + 明文，PKCS7 填充
async function qHe(t) {
  const keyMat = t.slice(Eg, Eg + ny);
  if (keyMat.length !== ny) return new Uint8Array(0);
  const { aesKey, iv } = await tle(keyMat);
  const padded = await WHe(aesKey, iv, t.slice(ny + Eg));
  if (padded.length === 0) return new Uint8Array(0);
  const digest = await O7(padded.slice(Hh));
  for (let d = 0; d < Hh; d++) if (digest[d] !== padded[d]) return new Uint8Array(0);
  return padded.slice(Hh);
}

// ── 遍历 iCubeAuthInfo 键并解密输出 ────────────────────────────────────────
const json = JSON.parse(readFileSync(storagePath, "utf-8"));
for (const [k, v] of Object.entries(json)) {
  if (!k.startsWith("iCubeAuthInfo")) continue;
  console.log("\n=== key:", k, "===");
  const bin = Buffer.from(v, "base64");
  const header = Array.from(bin.slice(0, 6)).map((b) => b.toString(16).padStart(2, "0")).join(" ");
  console.log("blob len:", bin.length, "header:", header);
  if (header !== "74 63 05 10 00 00") { console.log("非 AES 变体头部，跳过"); continue; }
  const plain = await qHe(new Uint8Array(bin));
  if (plain.length === 0) { console.log("解密失败"); continue; }
  const text = new TextDecoder().decode(plain);
  console.log("decrypted len:", text.length);
  console.log(text);
}
