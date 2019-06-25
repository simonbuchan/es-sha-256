import { strict as assert } from "assert";

import * as sha256 from "../src/sha256";

function testBody(expected: string, ...chunks: Uint8Array[]) {
  return () => {
    const state = sha256.create();
    for (const chunk of chunks) {
      sha256.update(state, chunk);
    }
    const actual = sha256.digest(state);
    assert.equal(actual, expected);
  };
}

const expected0 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const expected5 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
const expected54 = "e961ecdc61c754885765dac0997c2b7d0cfa1e6bfeea3faa81406d8725289e72";
const expected55 = "65bdf22e790590424e6fb0d5cf439a21be15c4021c55e51b7b001a0f12afd81a";
const expected56 = "1a7f34cac2d5dda2ae5cb43c5498a38c15bc409c65581c0026efc2bbc99c6f14";
const expected63 = "26b03a4a28d042fc7c700b066f79c7cc0bc859a0054e11a1fbd71928cbf95148";
const expected64 = "be874cd84bbc0f1025265b4c242806e7c4e7c69ac710278e7d317f57ae661fc9";
const expected100 = "4e4ba7e5b2223cfbbd7cd1937cdde31663a1d9dd58c35a48c2658f884d562102";
const expected200 = "d5ce6a23da7585701e0b8d32ee986fed6511eba4e1d2aed3670550508f8f431a";

describe("sha256", () => {
  it("no update", testBody(expected0));
  it("empty update", testBody(expected0, Uint8Array.of()));
  it("small update", testBody(expected5, Buffer.from("hello")));
  it("two small updates", testBody(expected5, Buffer.from("hel"), Buffer.from("lo")));
  // 64 bytes per chunk, 9 bytes of final padding = edge case at 55 bytes
  it("chunk with final padding - 1 byte", testBody(expected54, Buffer.from("hello".repeat(11).slice(0, 54))));
  it("chunk with final padding exactly", testBody(expected55, Buffer.from("hello".repeat(11))));
  it("chunk with final padding + 1 byte", testBody(expected56, Buffer.from("hello".repeat(12).slice(0, 56))));
  it("chunk size update - 1 byte", testBody(expected63, Buffer.from("hello".repeat(13).slice(0, 63))));
  it("chunk size update exactly", testBody(expected64, Buffer.from("hello".repeat(13).slice(0, 64))));
  it("split chunk update: 'hello' * 20", testBody(expected100, Buffer.from("hello".repeat(20))));
  it("split chunk update with buffered: 'hello' + 'hello' * 19",
     testBody(expected100, Buffer.from("hello"), Buffer.from("hello".repeat(19))));
  it("multiple chunk small updates", testBody(expected100, ...repeated(20, () => Buffer.from("hello"))));
  it("multiple full chunk updates: 'hello' * 40", testBody(expected200, Buffer.from("hello".repeat(40))));
  it("multiple full chunk updates with buffered: 'hello' + 'hello' * 39",
     testBody(expected200, Buffer.from("hello"), Buffer.from("hello".repeat(39))));
});

function* repeated<T>(count: number, factory: () => T) {
  for (let i = 0; i < count; i++) {
    yield factory();
  }
}
