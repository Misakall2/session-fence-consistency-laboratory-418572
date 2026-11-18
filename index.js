'use strict';

/**
 * Expose server and request/response classes.
 */

exports = module.exports = require('./lib/server');
exports.Request = require('./lib/request');
exports.Response = require('./lib/response');

/**
 * Export helpers for extension grants.
 */

exports.AbstractGrantType = require('./lib/grant-types/abstract-grant-type');

/**
 * Export error classes.
 */

exports.AccessDeniedError = require('./lib/errors/access-denied-error');
exports.InsufficientScopeError = require('./lib/errors/insufficient-scope-error');
exports.InvalidArgumentError = require('./lib/errors/invalid-argument-error');
exports.InvalidClientError = require('./lib/errors/invalid-client-error');
exports.InvalidGrantError = require('./lib/errors/invalid-grant-error');
exports.InvalidRequestError = require('./lib/errors/invalid-request-error');
exports.InvalidScopeError = require('./lib/errors/invalid-scope-error');
exports.InvalidTokenError = require('./lib/errors/invalid-token-error');
exports.OAuthError = require('./lib/errors/oauth-error');
exports.ServerError = require('./lib/errors/server-error');
exports.UnauthorizedClientError = require('./lib/errors/unauthorized-client-error');
exports.UnauthorizedRequestError = require('./lib/errors/unauthorized-request-error');
exports.UnsupportedGrantTypeError = require('./lib/errors/unsupported-grant-type-error');
exports.UnsupportedResponseTypeError = require('./lib/errors/unsupported-response-type-error');

/**
 * Export the token-family fence subsystem: the single authoritative store for
 * tokens and their revocation markers, the centralized revocation decision,
 * and a model adapter that routes refresh exchange and access token
 * validation through it.
 */

exports.TokenFence = require('./lib/token-fence');
exports.TokenFenceStore = require('./lib/token-fence/token-fence-store');
exports.TokenFenceError = require('./lib/token-fence/token-fence-error');
exports.FenceModelAdapter = require('./lib/token-fence/fence-model-adapter');
exports.tokenRevocation = require('./lib/utils/token-revocation');

