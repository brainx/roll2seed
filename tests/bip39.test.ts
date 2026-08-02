import { describe, expect, it } from "vitest";
import {
  BIP39_WORDLIST,
  decodeMnemonic,
  entropyToMnemonic,
  runCryptographicSelfTests,
  validateMnemonic,
  verifyWordlistIntegrity,
} from "../src/entropy/bip39";
import { sampleRolls } from "../src/entropy/diceSampler";

function parseRolls(value: string): number[] {
  return Array.from(value, (digit) => Number(digit));
}

describe("BIP39 conversion", () => {
  it("uses the pinned official English wordlist", async () => {
    expect(BIP39_WORDLIST).toHaveLength(2048);
    expect(new Set(BIP39_WORDLIST).size).toBe(2048);
    expect(BIP39_WORDLIST[0]).toBe("abandon");
    expect(BIP39_WORDLIST[2047]).toBe("zoo");
    await expect(verifyWordlistIntegrity()).resolves.toBe(true);
  });

  it.each([
    {
      bits: 128 as const,
      entropy: 0n,
      expected: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    },
    {
      bits: 128 as const,
      entropy: (1n << 128n) - 1n,
      expected: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    },
    {
      bits: 160 as const,
      entropy: 0n,
      expected:
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address",
    },
    {
      bits: 192 as const,
      entropy: 0n,
      expected:
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
    },
    {
      bits: 224 as const,
      entropy: 0n,
      expected:
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon admit",
    },
    {
      bits: 256 as const,
      entropy: 0n,
      expected:
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
    },
    {
      bits: 256 as const,
      entropy: (1n << 256n) - 1n,
      expected:
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
    },
  ])("matches the official $bits-bit boundary vector", async ({ bits, entropy, expected }) => {
    const mnemonic = await entropyToMnemonic(entropy, bits);
    expect(mnemonic.join(" ")).toBe(expected);
    await expect(validateMnemonic(mnemonic)).resolves.toBe(true);
    const decoded = await decodeMnemonic(mnemonic);
    expect(decoded.entropyValue).toBe(entropy);
    expect(decoded.checksumValid).toBe(true);
  });

  it("maps the nontrivial 12-word dice vector", async () => {
    const sample = sampleRolls(parseRolls("123456".repeat(8) + "12"), 128);
    const mnemonic = await entropyToMnemonic(sample.acceptedValue as bigint, 128);
    expect(mnemonic.join(" ")).toBe(
      "blue involve cook print twist crystal razor february caution private slim medal",
    );
  });

  it("maps the nontrivial 24-word dice vector", async () => {
    const sample = sampleRolls(parseRolls("123456".repeat(16) + "1234"), 256);
    const mnemonic = await entropyToMnemonic(sample.acceptedValue as bigint, 256);
    expect(mnemonic.join(" ")).toBe(
      "defy trip fatal jaguar mean rack rifle survey satisfy drift twist champion steel wife state furnace night consider glove olympic oblige donor novel left",
    );
  });

  it("rejects altered checksums and unknown words", async () => {
    const valid = await entropyToMnemonic(0n, 128);
    const altered = [...valid.slice(0, -1), "ability"];
    await expect(validateMnemonic(altered)).resolves.toBe(false);
    await expect(validateMnemonic([...valid.slice(0, -1), "notaword"])).resolves.toBe(false);
  });

  it("rejects out-of-range entropy and invalid mnemonic lengths", async () => {
    await expect(entropyToMnemonic(-1n, 128)).rejects.toThrow(/fit in exactly 128 bits/);
    await expect(entropyToMnemonic(1n << 128n, 128)).rejects.toThrow(/fit in exactly 128 bits/);
    await expect(decodeMnemonic(["abandon"])).rejects.toThrow(/128, 160, 192, 224, or 256 bits/);
  });

  it("passes the startup self-tests", async () => {
    await expect(runCryptographicSelfTests()).resolves.toBeUndefined();
  });
});
