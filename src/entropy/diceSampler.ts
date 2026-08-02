export const PHRASE_OPTIONS = [
  { words: 12, entropyBits: 128, checksumBits: 4, minimumRolls: 50 },
  { words: 15, entropyBits: 160, checksumBits: 5, minimumRolls: 62 },
  { words: 18, entropyBits: 192, checksumBits: 6, minimumRolls: 75 },
  { words: 21, entropyBits: 224, checksumBits: 7, minimumRolls: 87 },
  { words: 24, entropyBits: 256, checksumBits: 8, minimumRolls: 100 },
] as const;

export type PhraseOption = (typeof PHRASE_OPTIONS)[number];
export type EntropyBits = PhraseOption["entropyBits"];
export type DieFace = 1 | 2 | 3 | 4 | 5 | 6;

export interface DiceSamplerState {
  readonly target: bigint;
  readonly value: bigint;
  readonly range: bigint;
  readonly rollCount: number;
  readonly acceptedValue: bigint | null;
}

export interface DiceSample {
  readonly accepted: boolean;
  readonly acceptedValue: bigint | null;
  readonly acceptedAt: number | null;
  readonly state: DiceSamplerState;
}

export function isDieFace(value: number): value is DieFace {
  return Number.isInteger(value) && value >= 1 && value <= 6;
}

export function optionForWords(words: number): PhraseOption {
  const option = PHRASE_OPTIONS.find((candidate) => candidate.words === words);
  if (!option) {
    throw new RangeError("BIP39 phrase length must be 12, 15, 18, 21, or 24 words");
  }
  return option;
}

export function optionForEntropyBits(entropyBits: number): PhraseOption {
  const option = PHRASE_OPTIONS.find((candidate) => candidate.entropyBits === entropyBits);
  if (!option) {
    throw new RangeError("BIP39 entropy must be 128, 160, 192, 224, or 256 bits");
  }
  return option;
}

export function createSampler(entropyBits: EntropyBits): DiceSamplerState {
  optionForEntropyBits(entropyBits);
  return createSamplerForTarget(1n << BigInt(entropyBits));
}

export function createSamplerForTarget(target: bigint): DiceSamplerState {
  if (target < 2n) {
    throw new RangeError("Sampler target must contain at least two outcomes");
  }

  return {
    target,
    value: 0n,
    range: 1n,
    rollCount: 0,
    acceptedValue: null,
  };
}

/**
 * Adds one physical d6 roll using an exact entropy-recycling rejection sampler.
 *
 * `value` is uniform in [0, range). Once `range` can cover the target, only the
 * largest evenly divisible prefix is accepted. A rejected tail remains uniform,
 * so it can safely be retained and extended by the next roll.
 */
export function addRoll(state: DiceSamplerState, face: number): DiceSamplerState {
  if (state.acceptedValue !== null) {
    throw new Error("The sampler has already accepted an entropy value");
  }
  if (!isDieFace(face)) {
    throw new RangeError("A die roll must be an integer from 1 through 6");
  }

  let value = state.value * 6n + BigInt(face - 1);
  let range = state.range * 6n;
  let acceptedValue: bigint | null = null;

  if (range >= state.target) {
    const usableRange = range - (range % state.target);

    if (value < usableRange) {
      acceptedValue = value % state.target;
    } else {
      value -= usableRange;
      range -= usableRange;
    }
  }

  return {
    target: state.target,
    value,
    range,
    rollCount: state.rollCount + 1,
    acceptedValue,
  };
}

export function sampleRolls(rolls: readonly number[], entropyBits: EntropyBits): DiceSample {
  let state = createSampler(entropyBits);

  for (let index = 0; index < rolls.length; index += 1) {
    if (state.acceptedValue !== null) {
      throw new Error(`Roll ${index + 1} was supplied after entropy had already been accepted`);
    }
    state = addRoll(state, rolls[index] as number);
  }

  return {
    accepted: state.acceptedValue !== null,
    acceptedValue: state.acceptedValue,
    acceptedAt: state.acceptedValue === null ? null : state.rollCount,
    state,
  };
}

/** Returns the first accepted prefix length, or null when more rolls are required. */
export function firstAcceptedRollCount(
  rolls: readonly number[],
  entropyBits: EntropyBits,
): number | null {
  let state = createSampler(entropyBits);

  for (let index = 0; index < rolls.length; index += 1) {
    state = addRoll(state, rolls[index] as number);
    if (state.acceptedValue !== null) {
      return index + 1;
    }
  }

  return null;
}

export function toFixedBigEndian(value: bigint, byteLength: number): Uint8Array {
  if (value < 0n || !Number.isInteger(byteLength) || byteLength < 1) {
    throw new RangeError("A non-negative value and positive byte length are required");
  }

  const bytes = new Uint8Array(byteLength);
  let remaining = value;

  for (let index = byteLength - 1; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }

  if (remaining !== 0n) {
    bytes.fill(0);
    throw new RangeError("Entropy value does not fit in the requested byte length");
  }

  return bytes;
}

export function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}
