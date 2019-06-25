require("ts-node").register({
  project: `${__dirname}/tsconfig.json`,
});
require("source-map-support").install({
  environment: "node",
});
