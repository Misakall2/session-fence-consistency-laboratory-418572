'use strict';

/**
 * Module dependencies.
 */

var InvalidGrantError = require('../errors/invalid-grant-error');
var InvalidTokenError = require('../errors/invalid-token-error');
var Promise = require('bluebird');
var TokenFenceError = require('./token-fence-error');

/**
 * Attach live revocation markers to a token record handed to the framework.
 *
 * The framework (the grant type and the authenticate handler) reads
 * `revoked` / `familyRevoked` / the family fence on the record
 * it received. If those were snapshots, a revocation committing after the
 * store's decision but before the framework's check could go unnoticed.
 * Defining them as getters that read the single authoritative family record
 * means the framework's check always sees the current marker, with no second
 * copy to drift.
 *
 * `readState()` treats a throwing property read as revoked, so a store read
 * failure captured here fails closed just like any other unreadable marker.
 */

function attachLiveMarkers(store, familyId, record) {
  function define(name, read) {
    Object.defineProperty(record, name, {
      enumerable: true,
      configurable: true,
      get: read
    });
  }

  define('revoked', function() {
    return store.getFamilyState(familyId).revoked;
  });

  define('familyRevoked', function() {
    return store.getFamilyState(familyId).revoked;
  });

  define('familyFence', function() {
    return store.getFamilyState(familyId).fence;
  });

  return record;
}

/**
 * OAuth2 model adapter backed by the token-family fence store.
 *
 * The framework talks to a "model" made of callback-style functions. This
 * adapter exposes exactly that surface while routing every token read and
 * write through the fence store, so the centralized revocation decision sits
 * in front of both paths:
 *
 *   - refresh path:  getRefreshToken() -> revokeToken() -> saveToken()
 *   - auth path:     getAccessToken()
 *
 * Both paths hand the framework a token record whose revocation markers are
 * *live*: they are getters that read the family state from the store at the
 * moment the framework asks. There is no snapshot for the framework's own
 * revocation check to consult, so a revocation that commits between the
 * store's decision and the framework's check is still observed - the check
 * reads the same single marker, freshly.
 *
 * The refresh path is split across three model calls, but the store keeps it
 * atomic:
 *
 *   1. `getRefreshToken()` runs `beginExchange()`: under the family lock it
 *      reads the revocation marker and decides. The returned record carries
 *      the family marker so the grant type's own validation reads the very
 *      same state.
 *   2. `revokeToken()` confirms the exchange. Consumption is atomic in step 3,
 *      so there is nothing left to race on here.
 *   3. `saveToken()` runs `commitExchange()`: the marker is read *again*
 *      under the same lock, the presented token is consumed, and the pair is
 *      written - or the request is rejected if the family was revoked in
 *      between. No token is ever issued into a revoked family.
 *
 * Correlation between steps 1 and 3 uses the `user` object handed to
 * `saveToken()` by the grant type. Each `getRefreshToken()` call returns a
 * distinct view object, and the exchange is recorded against that view's
 * `user` in a `WeakMap`. Concurrent refresh requests therefore never see each
 * other's exchanges, and nothing is retained once the objects are garbage
 * collected.
 */

function FenceModelAdapter(store, options) {
  if (!store) {
    throw new Error('FenceModelAdapter requires a TokenFenceStore instance');
  }

  options = options || {};

  this.store = store;
  this.clients = options.clients || {};
  this._exchanges = new WeakMap();
}

/**
 * Refresh path, step 1: check the presented refresh token.
 *
 * `beginExchange()` performs the centralized revocation decision first; only
 * a live token in a live family is described back. Revocation failures are
 * mapped to `invalid_grant` while preserving the stable `reason`.
 */

FenceModelAdapter.prototype.getRefreshToken = function(refreshToken) {
  var self = this;

  return this.store.beginExchange(refreshToken)
    .then(function(record) {
      var user = {id: record.userId};

      // Bind the exchange to this request's `user` view. The grant type
      // passes `token.user` straight into `saveToken()`, which lets us find
      // the exact exchange without a shared mutable slot.
      self._exchanges.set(user, record);

      return attachLiveMarkers(self.store, record.familyId, {
        refreshToken: refreshToken,
        refreshTokenExpiresAt: record.refreshTokenExpiresAt,
        scope: record.scope,
        client: {id: record.clientId},
        user: user,
        familyId: record.familyId,
        fenceAtIssuance: record.tokenFence
      });
    })
    .catch(function(err) {
      throw self._toInvalidGrant(err);
    });
};

/**
 * Refresh path, step 2: retire the presented refresh token.
 *
 * Rotation consumes the token atomically inside `commitExchange()`, so this
 * only confirms success. Reporting `false` here would be treated as an
 * invalid grant and would wrongly reject a request that has already passed
 * the centralized revocation check.
 */

FenceModelAdapter.prototype.revokeToken = function() {
  return true;
};

/**
 * Refresh path, step 3: commit the generated token values.
 *
 * `tokenData` holds the values produced by the grant type. The exchange is
 * looked up through the `user` view passed as the third argument, then
 * `commitExchange()` re-reads the revocation marker, consumes the presented
 * token and writes the pair - or rejects if the family was revoked in the
 * meantime.
 *
 * Declared with three parameters on purpose: the grant type promisifies this
 * with `numArgs = 3`, and a longer parameter list would be mistaken for a
 * node-style callback function.
 */

FenceModelAdapter.prototype.saveToken = function(tokenData, client, user) {
  var self = this;
  var record = user && typeof user === 'object' ? this._exchanges.get(user) : null;

  if (!record) {
    // No exchange means this model call did not start from a fenced refresh
    // request. Fail closed instead of silently minting an unfenced token.
    return Promise.reject(new InvalidGrantError('Invalid grant: refresh token is invalid'));
  }

  this._exchanges.delete(user);

  var keepRefreshToken = !tokenData.refreshToken;

  return this.store.commitExchange(record, {
    accessToken: tokenData.accessToken,
    accessTokenExpiresAt: tokenData.accessTokenExpiresAt,
    refreshToken: keepRefreshToken ? null : tokenData.refreshToken,
    refreshTokenExpiresAt: tokenData.refreshTokenExpiresAt,
    keepRefreshToken: keepRefreshToken,
    scope: tokenData.scope
  })
    .then(function(pair) {
      // Return a complete token record so the framework can build its
      // response. When the refresh token is reused, the pair already points
      // at the same value.
      return {
        accessToken: pair.accessToken,
        accessTokenExpiresAt: pair.accessTokenExpiresAt,
        refreshToken: pair.refreshToken,
        refreshTokenExpiresAt: pair.refreshTokenExpiresAt,
        scope: pair.scope,
        client: client,
        user: user
      };
    })
    .catch(function(err) {
      throw self._toInvalidGrant(err);
    });
};

/**
 * Authentication path: resolve and validate an access token.
 *
 * `store.validate()` runs the same centralized revocation decision as the
 * exchange path. The returned record still carries the family marker so the
 * authenticate handler's own validation (`tokenRevocation.readState`) reads
 * the same state rather than a separate copy.
 */

FenceModelAdapter.prototype.getAccessToken = function(accessToken) {
  var self = this;

  return this.store.validate(accessToken)
    .then(function(record) {
      // Hand the framework a record whose revocation markers are live reads of
      // the single authoritative family state, so its own check cannot be
      // fooled by a revocation that commits after this decision.
      return attachLiveMarkers(self.store, record.familyId, record);
    })
    .catch(function(err) {
      throw self._toInvalidToken(err);
    });
};

/**
 * Minimal `getClient()` so the adapter can drive the framework's token
 * endpoint. Clients are registered up front in `options.clients`.
 */

FenceModelAdapter.prototype.getClient = function(clientId, clientSecret) {
  var client = this.clients[clientId];

  if (!client) {
    return null;
  }

  if (client.clientSecret !== undefined && client.clientSecret !== clientSecret) {
    return null;
  }

  return client;
};

/**
 * Scope verification used by the authenticate handler when a scope is
 * requested. Revocation is already enforced by `getAccessToken()`; this only
 * confirms the token carries the required scope.
 */

FenceModelAdapter.prototype.verifyScope = function(token, scope) {
  if (!scope) {
    return true;
  }

  var granted = (token.scope || '').split(' ');
  var required = scope.split(' ');

  return required.every(function(s) {
    return granted.indexOf(s) >= 0;
  });
};

/**
 * Map a fence rejection to `invalid_grant`, preserving the stable reason and
 * family id for callers that inspect the cause.
 */

FenceModelAdapter.prototype._toInvalidGrant = function(err) {
  if (err instanceof TokenFenceError) {
    var grantError = new InvalidGrantError('Invalid grant: refresh token is invalid or revoked');

    grantError.reason = err.reason;
    grantError.familyId = err.familyId;

    return grantError;
  }

  return err;
};

/**
 * Map a fence rejection to `invalid_token`, preserving the stable reason.
 */

FenceModelAdapter.prototype._toInvalidToken = function(err) {
  if (err instanceof TokenFenceError) {
    var tokenError = new InvalidTokenError('Invalid token: access token is invalid or revoked');

    tokenError.reason = err.reason;
    tokenError.familyId = err.familyId;

    return tokenError;
  }

  return err;
};

/**
 * Export constructor.
 */

module.exports = FenceModelAdapter;
