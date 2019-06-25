const assert = require("assert").strict;
const { performance, PerformanceObserver } = require("perf_hooks");

const sha256 = require("../");

const expected = "987523e7780392e283b404990c4e84e580bc75c451138b0c86c4f81c296eeebe";
const data = new Uint8Array(4096);

new PerformanceObserver((list, observer) => {
  const durations = list.getEntries().map(e => e.duration);
  const sum = durations.reduce((a, d) => a + d, 0);
  const average = sum / durations.length;
  const absDev = durations.reduce((a, d) => a + (d - average) ** 2, 0);
  const stdDev = Math.sqrt(absDev / durations.length);
  console.log("count: %O", durations.length);
  console.log("min: %O", Math.min(...durations));
  console.log("max: %O", Math.max(...durations));
  console.log("avg: %O", average);
  console.log("std.dev.: %O", stdDev);
  console.log("durations: %O", durations);
  observer.disconnect();
}).observe({
  entryTypes: ["function"],
  buffered: true,
});

const iteration = performance.timerify(function iteration() {
  const state = sha256.create();
  for (let i = 0; i < 150 * 1024; i++) {
    sha256.update(state, data);
  }
  const actual = sha256.digest(state);

  assert.equal(actual, expected);
});

for (let i = 0; i !== 20; i++) {
  iteration();
}
