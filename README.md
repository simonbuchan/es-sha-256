# NPM `@simonbuchan/sha-256`

SHA-256 core implementation in pure ECMAScript, for node or browser,
in a functional-ish style, copyright free. Use however you want.

Has somewhat decent functional tests, if I do say so my self, and in
my performance tests gets a little over 120MiB/s (hashing the same
in-memory data), in comparison to Ubuntu's `sha256sum` getting over
300MiB/s on a (sparse) 600MiB file. I have not yet compared to the
performance of the existing npm packages.

Will run into float64 precision errors past 2**50 byte files, but that would
take over 100 days to run on my machine, so I'm not too concerned!

## API

### `create(): Sha256State`

Returns an opaque state object, representing an empty byte stream.

### `update(state: Sha256State, data: Uint8Array): void`

Given a hash state object and some data, updates the state in-place 

### `digest(state: Sha256State): string`

Finishes the state, making it unusable, and formats the final hash as
a 64 character hexadecimal digest (64 chars * 4 bits per hex char = 256 bits).

### `finish(state: Sha256State): Uint32Array`

Finishes the state, making it unusable, and returns the raw final hash as
an 8 element `Uint32Array`. Note that this is *not* a Uint8Array or Buffer,
and the underlying `ArrayBuffer` stores the bytes in a machine-dependent endian
order.

This is intended for lower-level usages.

## Example

A CLI wrapper for this might look like:

```js
const fs = require("fs");
const sha256 = require("@simonbuchan/sha-256");

async function main() {
  const state = sha256.create();
  for await (const chunk of fs.createReadStream(process.argv[2])) {
    sha256.update(state, chunk);
  }
  const hex = sha256.digest(state);
  console.log(hex);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
```
