'use strict';

// temp@0.9.4 still calls rimraf with callbacks; keep that contract over rimraf 6.
const modern = require('rimraf-modern');

function modernOptions(options = {}) {
  const { maxBusyTries, ...rest } = options;
  return maxBusyTries === undefined ? rest : { ...rest, maxRetries: maxBusyTries };
}

function rimraf(path, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }

  modern.rimraf(path, modernOptions(options)).then(
    () => callback(null),
    (error) => callback(error),
  );
}

rimraf.sync = (path, options) => modern.rimrafSync(path, modernOptions(options));

module.exports = rimraf;
