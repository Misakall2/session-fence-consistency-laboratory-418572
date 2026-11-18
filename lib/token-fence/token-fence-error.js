'use strict';

/**
 * Module dependencies.
 */

var util = require('util');

/**
 * Constructor.
 *
 * Thrown by the token-family fence whenever a token cannot be used because
 * its family has been revoked, or because the revocation marker could not be
 * read (which is treated exactly like a revocation).
 *
 * Every rejection produced by the centralized revocation decision carries the
 * same stable `reason`. That makes an old token that is retried after a
 * revocation and a freshly derived token rejected by the same revocation
 * indistinguishable to callers: one family revocation has one answer.
 */

function TokenFenceError(message, properties) {
  properties = properties || {};

  Error.call(this);
  Error.captureStackTrace(this, TokenFenceError);

  this.name = 'TokenFenceError';
  this.message = message || 'Token family has been revoked';
  this.reason = properties.reason || 'token_family_revoked';
  this.familyId = properties.familyId || null;
  this.code = properties.code || 401;
}

/**
 * Inherit from `Error`.
 */

util.inherits(TokenFenceError, Error);

/**
 * Export constructor.
 */

module.exports = TokenFenceError;
