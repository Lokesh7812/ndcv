// src/fetcher/fetcherRunner.js
const run = require('./fetcher');
module.exports = async (opts = {}) => {
  // run the fetcher and return a short summary
  return run(opts);
};
