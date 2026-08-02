import { describe, expect, it } from "vitest";
import {
  PHRASE_OPTIONS,
  addRoll,
  createSampler,
  createSamplerForTarget,
  firstAcceptedRollCount,
  sampleRolls,
  toFixedBigEndian,
} from "../src/entropy/diceSampler";

function parseRolls(value: string): number[] {
  return Array.from(value, (digit) => Number(digit));
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function valueToFixedRolls(value: bigint, length: number): number[] {
  const rolls = new Array<number>(length).fill(1);
  let remaining = value;
  for (let index = length - 1; index >= 0; index -= 1) {
    rolls[index] = Number(remaining % 6n) + 1;
    remaining /= 6n;
  }
  expect(remaining).toBe(0n);
  return rolls;
}

describe("dice entropy sampler", () => {
  it.each(PHRASE_OPTIONS)(
    "does not accept $entropyBits-bit entropy before $minimumRolls rolls",
    ({ entropyBits, minimumRolls }) => {
      const result = sampleRolls(new Array<number>(minimumRolls - 1).fill(1), entropyBits);
      expect(result.accepted).toBe(false);
      expect(result.acceptedValue).toBeNull();
    },
  );

  it("reproduces the nontrivial 128-bit dice vector", () => {
    const rolls = parseRolls("123456".repeat(8) + "12");
    const result = sampleRolls(rolls, 128);

    expect(result.accepted).toBe(true);
    expect(result.acceptedAt).toBe(50);
    expect(bytesToHex(toFixedBigEndian(result.acceptedValue as bigint, 16))).toBe(
      "184ec4bed56eb86aacaaa224b5672f45",
    );
  });

  it("reproduces the nontrivial 256-bit dice vector", () => {
    const rolls = parseRolls("123456".repeat(16) + "1234");
    const result = sampleRolls(rolls, 256);

    expect(result.accepted).toBe(true);
    expect(result.acceptedAt).toBe(100);
    expect(bytesToHex(toFixedBigEndian(result.acceptedValue as bigint, 32))).toBe(
      "39bd194e3b989d612e6ed5bf485bae130d53f5f532f29585e98ecd298282a5c3",
    );
  });

  it("recycles the first rejected 128-bit boundary without modulo bias", () => {
    const largestAccepted = parseRolls(
      "61262262611466652634263242642635642166662444332122",
    );
    const smallestRejected = parseRolls(
      "61262262611466652634263242642635642166662444332123",
    );

    const accepted = sampleRolls(largestAccepted, 128);
    expect(accepted.acceptedValue).toBe((1n << 128n) - 1n);

    const rejected = sampleRolls(smallestRejected, 128);
    expect(rejected.accepted).toBe(false);
    expect(rejected.state.range).toBeLessThan(rejected.state.target);

    const recycled = sampleRolls([...smallestRejected, 1], 128);
    expect(recycled.accepted).toBe(true);
    expect(recycled.acceptedAt).toBe(51);
    expect(recycled.acceptedValue).toBe(0n);
  });

  it("finds the earliest accepted prefix after a roll correction", () => {
    const rejectedAt50 = parseRolls(
      "61262262611466652634263242642635642166662444332123",
    );
    const acceptedAt51 = [...rejectedAt50, 1];
    expect(firstAcceptedRollCount(acceptedAt51, 128)).toBe(51);

    const correctedToAcceptAt50 = [...acceptedAt51];
    correctedToAcceptAt50[49] = 2;
    expect(firstAcceptedRollCount(correctedToAcceptAt50, 128)).toBe(50);

    correctedToAcceptAt50[49] = 3;
    expect(firstAcceptedRollCount(correctedToAcceptAt50.slice(0, 50), 128)).toBeNull();
  });

  it.each(PHRASE_OPTIONS)(
    "accepts and rejects the exact $entropyBits-bit threshold boundaries",
    ({ entropyBits, minimumRolls }) => {
      const target = 1n << BigInt(entropyBits);
      const range = 6n ** BigInt(minimumRolls);
      const usable = range - (range % target);

      const largestAccepted = sampleRolls(valueToFixedRolls(usable - 1n, minimumRolls), entropyBits);
      expect(largestAccepted.acceptedValue).toBe(target - 1n);

      const smallestRejected = sampleRolls(valueToFixedRolls(usable, minimumRolls), entropyBits);
      expect(smallestRejected.accepted).toBe(false);
      expect(smallestRejected.state.value).toBe(0n);
      expect(smallestRejected.state.range).toBe(range - usable);
    },
  );

  it("is exactly uniform in an exhaustive toy target", () => {
    const counts = new Array<number>(8).fill(0);

    for (let first = 1; first <= 6; first += 1) {
      for (let second = 1; second <= 6; second += 1) {
        for (let third = 1; third <= 6; third += 1) {
          let state = createSamplerForTarget(8n);
          for (const face of [first, second, third]) {
            if (state.acceptedValue === null) {
              state = addRoll(state, face);
            }
          }
          expect(state.acceptedValue).not.toBeNull();
          const outcome = Number(state.acceptedValue);
          counts[outcome] = (counts[outcome] ?? 0) + 1;
        }
      }
    }

    expect(counts).toEqual(new Array<number>(8).fill(27));
  });

  it("rejects invalid faces, targets, and trailing rolls", () => {
    const initial = createSampler(128);
    expect(() => addRoll(initial, 0)).toThrow(/1 through 6/);
    expect(() => addRoll(initial, 1.5)).toThrow(/1 through 6/);
    expect(() => createSamplerForTarget(1n)).toThrow(/at least two outcomes/);
    expect(() => sampleRolls(new Array<number>(51).fill(1), 128)).toThrow(
      /after entropy had already been accepted/,
    );
  });

  it("preserves leading zero bytes and refuses overflow", () => {
    expect(bytesToHex(toFixedBigEndian(1n, 4))).toBe("00000001");
    expect(() => toFixedBigEndian(256n, 1)).toThrow(/does not fit/);
  });
});
