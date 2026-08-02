import wordlistSource from "./english.txt?raw";
import {
  bytesToBigInt,
  optionForEntropyBits,
  toFixedBigEndian,
  type EntropyBits,
} from "./diceSampler";

export const BIP39_WORDLIST_SHA256 =
  "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

export const BIP39_WORDLIST = Object.freeze(wordlistSource.trimEnd().split("\n"));

function assertWordlistShape(): void {
  if (BIP39_WORDLIST.length !== 2048) {
    throw new Error("The embedded BIP39 English wordlist does not contain 2,048 words");
  }
  if (new Set(BIP39_WORDLIST).size !== BIP39_WORDLIST.length) {
    throw new Error("The embedded BIP39 English wordlist contains duplicate words");
  }
  if (
    BIP39_WORDLIST[0] !== "abandon" ||
    BIP39_WORDLIST[2047] !== "zoo" ||
    BIP39_WORDLIST.some((word) => !/^[a-z]+$/.test(word))
  ) {
    throw new Error("The embedded BIP39 English wordlist has an invalid shape or ordering");
  }
}

assertWordlistShape();

function cryptoProvider(): Crypto {
  const provider = globalThis.crypto;
  if (!provider?.subtle) {
    throw new Error("Required Web Crypto SHA-256 support is unavailable");
  }
  return provider;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const input = new Uint8Array(bytes);
  const digest = await cryptoProvider().subtle.digest("SHA-256", input);
  input.fill(0);
  return new Uint8Array(digest);
}

export async function verifyWordlistIntegrity(): Promise<boolean> {
  const sourceBytes = new TextEncoder().encode(wordlistSource);
  const digest = await sha256(sourceBytes);
  sourceBytes.fill(0);
  const matches = toHex(digest) === BIP39_WORDLIST_SHA256;
  digest.fill(0);
  return matches;
}

export async function entropyToMnemonic(
  entropyValue: bigint,
  entropyBits: EntropyBits,
): Promise<readonly string[]> {
  const option = optionForEntropyBits(entropyBits);
  const target = 1n << BigInt(entropyBits);
  if (entropyValue < 0n || entropyValue >= target) {
    throw new RangeError(`Entropy must fit in exactly ${entropyBits} bits`);
  }

  const entropyBytes = toFixedBigEndian(entropyValue, entropyBits / 8);
  const digest = await sha256(entropyBytes);
  const checksum = BigInt(digest[0] as number) >> BigInt(8 - option.checksumBits);
  let combined = (entropyValue << BigInt(option.checksumBits)) | checksum;
  const words = new Array<string>(option.words);

  for (let index = option.words - 1; index >= 0; index -= 1) {
    const wordIndex = Number(combined & 0x7ffn);
    const word = BIP39_WORDLIST[wordIndex];
    if (!word) {
      entropyBytes.fill(0);
      digest.fill(0);
      throw new Error("BIP39 word index was outside the embedded wordlist");
    }
    words[index] = word;
    combined >>= 11n;
  }

  entropyBytes.fill(0);
  digest.fill(0);
  return Object.freeze(words);
}

export interface DecodedMnemonic {
  readonly entropyBits: EntropyBits;
  readonly entropyValue: bigint;
  readonly checksumValid: boolean;
}

export async function decodeMnemonic(words: readonly string[]): Promise<DecodedMnemonic> {
  const entropyBits = ((words.length * 11 * 32) / 33) as EntropyBits;
  const option = optionForEntropyBits(entropyBits);
  if (option.words !== words.length) {
    throw new RangeError("Mnemonic must contain 12, 15, 18, 21, or 24 words");
  }

  let combined = 0n;
  for (const word of words) {
    const index = BIP39_WORDLIST.indexOf(word);
    if (index < 0) {
      throw new RangeError(`“${word}” is not in the BIP39 English wordlist`);
    }
    combined = (combined << 11n) | BigInt(index);
  }

  const checksumMask = (1n << BigInt(option.checksumBits)) - 1n;
  const suppliedChecksum = combined & checksumMask;
  const entropyValue = combined >> BigInt(option.checksumBits);
  const entropyBytes = toFixedBigEndian(entropyValue, entropyBits / 8);
  const digest = await sha256(entropyBytes);
  const expectedChecksum = BigInt(digest[0] as number) >> BigInt(8 - option.checksumBits);
  entropyBytes.fill(0);
  digest.fill(0);

  return {
    entropyBits,
    entropyValue,
    checksumValid: suppliedChecksum === expectedChecksum,
  };
}

export async function validateMnemonic(words: readonly string[]): Promise<boolean> {
  try {
    return (await decodeMnemonic(words)).checksumValid;
  } catch {
    return false;
  }
}

export async function runCryptographicSelfTests(): Promise<void> {
  if (!(await verifyWordlistIntegrity())) {
    throw new Error("BIP39 wordlist integrity check failed");
  }

  const zero128 = await entropyToMnemonic(0n, 128);
  if (
    zero128.length !== 12 ||
    zero128.slice(0, 11).some((word) => word !== "abandon") ||
    zero128[11] !== "about"
  ) {
    throw new Error("BIP39 128-bit self-test failed");
  }

  const zero256 = await entropyToMnemonic(0n, 256);
  if (
    zero256.length !== 24 ||
    zero256.slice(0, 23).some((word) => word !== "abandon") ||
    zero256[23] !== "art"
  ) {
    throw new Error("BIP39 256-bit self-test failed");
  }

  const roundTrip = await decodeMnemonic(zero256);
  if (!roundTrip.checksumValid || roundTrip.entropyValue !== 0n) {
    throw new Error("BIP39 round-trip self-test failed");
  }
}

export function entropyBytesToBigInt(bytes: Uint8Array): bigint {
  return bytesToBigInt(bytes);
}
