const sha256 = require("../");

const expected = "987523e7780392e283b404990c4e84e580bc75c451138b0c86c4f81c296eeebe";
const data = new Uint8Array(4096);
const state = sha256.create();
for (let i = 0; i < 150 * 1024; i++) {
  sha256.update(state, data);
}
const actual = sha256.digest(state);
if (actual !== expected) {
  throw new Error(`unexpected digest: ${actual}`);
}
