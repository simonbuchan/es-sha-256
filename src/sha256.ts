// Clean-room implemented from https://en.wikipedia.org/wiki/SHA-2 pseudocode to avoid BSD license encumbrance
// of other pure-js SHA packages.
// Also allows possibly more JIT-friendly interface and typing.

const k = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

/**
 * Internal state of this package. Details subject to change, for example sharing working and buffered data.
 */
export interface Sha256State {
  /**
   * @private
   * Current SHA-256 hash value.
   */
  readonly hash: Uint32Array;

  /**
   * @private
   * Working buffer, cleared on each update.
   */
  readonly working: Uint32Array;

  /**
   * @private
   * A DataView over the same ArrayBuffer as buffered.
   * Required due to the definition of SHA-256 being operations on big-endian data
   * in the raw chunk.
   */
  readonly bufferedView: DataView;

  /**
   * @private
   * A buffer for the data not yet hashed from the last update call.
   */
  readonly buffered: Uint8Array;

  /**
   * @private
   * The number of bytes of data not yet hashed from the last update call.
   * Should always be less than the chunk byte length, 64.
   */
  bufferedByteLength: number;

  /**
   * @private
   * The number of bits written using update().
   */
  messageBitLength: number;
}

const chunkByteLength = 64; // 512 bits / 8 bits per byte
const workingElementLength = 64;

/**
 * Creates a new SHA-256 internal state object, representing empty input.
 */
export function create(): Sha256State {
  const buffer = new ArrayBuffer(chunkByteLength);
  return {
    hash: new Uint32Array([
      0x6a09e667,
      0xbb67ae85,
      0x3c6ef372,
      0xa54ff53a,
      0x510e527f,
      0x9b05688c,
      0x1f83d9ab,
      0x5be0cd19,
    ]),
    working: new Uint32Array(workingElementLength),
    bufferedView: new DataView(buffer, 0, chunkByteLength),
    buffered: new Uint8Array(buffer),
    bufferedByteLength: 0,
    messageBitLength: 0,
  };
}

/**
 * Updates the internal state with new data, as if it were appended to the previous update data.
 * @param state SHA-256 internal state, returned by {@link create()}
 * @param data Bytes to update as if appending. Use {@link Uint8Array#slice()} if only part of the data is wanted.
 */
export function update(state: Sha256State, data: Uint8Array) {
  const dataLength = data.byteLength;
  const { hash, working, buffered, bufferedView, bufferedByteLength } = state;

  state.messageBitLength += dataLength * 8;

  // If we don't yet have enough data for a 512-bit chunk, just store all of the data in the buffer.
  if (bufferedByteLength + dataLength < chunkByteLength) {
    buffered.set(data, bufferedByteLength);
    state.bufferedByteLength += dataLength;
    return;
  }

  let dataOffset = 0;
  if (bufferedByteLength) {
    // Fill the rest of the buffer, then update using the DataView on the underlying buffer
    dataOffset = chunkByteLength - bufferedByteLength;
    buffered.set(data.slice(0, dataOffset), bufferedByteLength);
    updateChunk(hash, working, bufferedView);
  }

  // Repeat for each full chunkByteLength slice of data, still copying through the buffer
  // so we don't need to allocate a new DataView on the data - that is within a standard
  // deviation of this, but is slightly more complicated.
  while (dataOffset + chunkByteLength <= dataLength) {
    buffered.set(data.slice(dataOffset, dataOffset + chunkByteLength));
    updateChunk(hash, working, bufferedView);
    dataOffset += chunkByteLength;
  }

  buffered.fill(0);

  // Skip the slice cost if we're already aligned
  if (dataOffset < dataLength) {
    // Copy any final data to the buffer for the next update or finish.
    buffered.set(data.slice(dataOffset));
    state.bufferedByteLength = dataLength - dataOffset;
  } else {
    state.bufferedByteLength = 0;
  }
}

export function finish(state: Sha256State) {
  // Note that bufferedByteLength must always be less than bufferedLength.
  state.buffered[state.bufferedByteLength] = 0x80;
  if (state.bufferedByteLength > chunkByteLength - 9) {
    updateChunk(state.hash, state.working, state.bufferedView);
    state.buffered.fill(0);
  }
  // High bits, for updates over 2**32 bytes / 8 bits = 512MB
  state.bufferedView.setUint32(chunkByteLength - 8, state.messageBitLength / 0x1_0000_0000, false);
  state.bufferedView.setUint32(chunkByteLength - 4, state.messageBitLength, false);
  updateChunk(state.hash, state.working, state.bufferedView);
  return state.hash;
}

export function digest(state: Sha256State) {
  const hash = finish(state);
  let result = "";
  for (let i = 0; i !== hash.length; i++) {
    const hex = hash[i].toString(16);
    // result += hex.padStart(8, "0"), but that would be an es2017 dependency.
    result += "00000000".substring(hex.length) + hex;
  }
  return result;
}

function updateChunk(hash: Uint32Array, w: Uint32Array, chunkView: DataView) {
  for (let i = 0; i !== 16; i++) {
    w[i] = chunkView.getUint32(i * 4, false);
  }
  for (let i = 16; i !== workingElementLength; i++) {
    const w0 = w[i - 15];
    const s0 = rotate32(w0, 7) ^ rotate32(w0, 18) ^ (w0 >>> 3);
    const w1 = w[i - 2];
    const s1 = rotate32(w1, 17) ^ rotate32(w1, 19) ^ (w1 >>> 10);
    w[i] = w[i - 16] + (s0 >>> 0) + w[i - 7] + (s1 >>> 0);
  }

  let a = hash[0];
  let b = hash[1];
  let c = hash[2];
  let d = hash[3];
  let e = hash[4];
  let f = hash[5];
  let g = hash[6];
  let h = hash[7];

  for (let i = 0; i !== 64; i++) {
    const s1 = (rotate32(e, 6) ^ rotate32(e, 11) ^ rotate32(e, 25)) >>> 0;
    const ch = ((e & f) ^ (~e & g)) >>> 0;
    const temp1 = h + s1 + ch + k[i] + w[i];
    const s0 = (rotate32(a, 2) ^ rotate32(a, 13) ^ rotate32(a, 22)) >>> 0;
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const temp2 = s0 + maj;

    h = g;
    g = f;
    f = e;
    e = (d + temp1) >>> 0;
    d = c;
    c = b;
    b = a;
    a = (temp1 + temp2) >>> 0;
  }

  hash[0] += a;
  hash[1] += b;
  hash[2] += c;
  hash[3] += d;
  hash[4] += e;
  hash[5] += f;
  hash[6] += g;
  hash[7] += h;
}

export function rotate32(word: number, shift: number) {
  return ((word >>> shift) | (word << (32 - shift))) >>> 0;
}
