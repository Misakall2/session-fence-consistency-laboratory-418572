'use strict';

/**
 * Module dependencies.
 */

var FamilyMutex = require('./family-mutex');
var Promise = require('bluebird');
var TokenFenceError = require('./token-fence-error');
var tokenRevocation = require('../utils/token-revocation');

/**
 * Stable rejection reason shared by every path that loses against a
 * revocation. Both the exchange path and the validation path report this
 * value, so a retried old token and a freshly derived token rejected by the
 * same revocation are indistinguishable to a caller.
 */

var REVOKED_REASON = tokenRevocation.REVOKED_REASON;

/**
 * Token-family fence store.
 *
 * This store is the single authoritative location for three things at once:
 *
 *   1. every issued token (access and refresh), in `_tokens`;
 *   2. every token family, including its monotonic `fence` and the revocation
 *      marker, in `_families`;
 *   3. the append-only audit trail, in `_audit` / `_auditByFamily`.
 *
 * The revocation marker therefore lives in the same place as the tokens it
 * governs. There is deliberately no second, separately-synchronised copy of
 * the marker and no read-through cache: every mutating or validating
 * operation reads the family record freshly, inside the per-family lock,
 * through the one decision point (`tokenRevocation.readState()` on the token
 * view of the family state).
 *
 * A family carries a monotonic `fence`. Issuing a token records the fence it
 * was issued under. Revoking the family raises the fence and flips `revoked`.
 * A token whose recorded fence is below the current fence is stale, so once a
 * family is revoked every token ever issued under it - and every token
 * derived afterwards - fails the same check.
 *
 * The store exposes two exchange steps (`beginExchange` / `commitExchange`)
 * so the framework can generate token values in between, plus `exchange()`
 * which performs both atomically for direct use. The revocation decision is
 * taken at `beginExchange` (before any token work) *and* re-taken at
 * `commitExchange` (before any token is written), so a revocation landing in
 * that window still wins and no token is ever issued into a revoked family.
 */

function TokenFenceStore(options) {
  options = options || {};

  this._tokens = Object.create(null);
  this._families = Object.create(null);
  this._audit = [];
  // Per-family archive index: familyId -> ordered audit entries. Keeping this
  // index next to the marker and tokens guarantees the three cannot drift.
  this._auditByFamily = Object.create(null);
  this._mutex = new FamilyMutex();
  this._sequence = 0;

  // Clock and identifier generation are injectable so tests can drive expiry
  // and concurrency deterministically.
  this._now = typeof options.now === 'function' ? options.now : defaultNow;
  this._generateId = typeof options.generateId === 'function' ?
    options.generateId : defaultIdGenerator;

  // Optional failure injection: `options.failRead(familyId)` returning a
  // truthy value makes the next family read for that id fail. Used by tests
  // to prove that an unreadable marker is treated exactly like a revocation.
  this._failRead = typeof options.failRead === 'function' ? options.failRead : null;
}

/**
 * Issue the very first token pair for a new family.
 *
 * Initial issuance is not an exchange of an existing token and therefore does
 * not perform - nor need - a revocation check for a *new* family: the family
 * is created in the same write with fence 0 and `revoked = false`.
 *
 * Issuing into a family id that already exists is different. If that family
 * was revoked, issuing would silently revive it by replacing the marker, so it
 * is rejected with the same canonical error as every other path. An existing
 * live family is reused as-is, keeping its fence and marker - there is never a
 * second copy of either.
 *
 * All later refresh activity for this family flows through
 * `beginExchange()`, which always consults the marker first.
 */

TokenFenceStore.prototype.issue = function(attributes) {
  attributes = attributes || {};

  var familyId = attributes.familyId || this._generateId('family');
  var read = this._safeReadFamily(familyId);
  var family;

  if (read.ok) {
    // An existing revocation marker is authoritative: never replace it.
    if (read.family.revoked) {
      this._appendAudit(familyId, 'issue_rejected', {
        familyId: familyId,
        reason: REVOKED_REASON
      });
      throw this._revocationError(familyId, REVOKED_REASON);
    }

    family = read.family;
  } else if (read.unreadable) {
    // The marker could not be read. Treat it as revoked rather than creating
    // a fresh, unrevoked family over whatever is really stored.
    throw this._revocationError(familyId, REVOKED_REASON);
  } else {
    family = this._families[familyId] = {
      familyId: familyId,
      fence: 0,
      revoked: false,
      revokedAt: null,
      clientId: attributes.clientId || null,
      userId: attributes.userId || null,
      scope: attributes.scope || null
    };
  }

  var pair = this._writeTokenPair(family, {}, attributes);

  this._appendAudit(familyId, 'issued', {
    familyId: familyId,
    fence: family.fence,
    refreshToken: pair.refreshToken,
    accessToken: pair.accessToken
  });

  return pair;
};

/**
 * Exchange a refresh token for a new token pair, atomically.
 *
 * Convenience wrapper around `beginExchange()` + `commitExchange()` for
 * callers that do not need to generate token values in between.
 */

TokenFenceStore.prototype.exchange = function(refreshToken) {
  var self = this;

  return this.beginExchange(refreshToken)
    .then(function(record) {
      return self.commitExchange(record, {});
    });
};

/**
 * First half of a refresh exchange: read the revocation marker and confirm
 * the presented refresh token may be exchanged.
 *
 * Everything runs under the family lock, and the very first action is the
 * centralized revocation decision applied to a freshly read family record.
 * Only a token that passes is described back to the caller, and a retry
 * cannot bypass the check because every call re-enters it and re-reads the
 * marker.
 *
 * The token is *not* consumed here: the framework runs its own checks
 * (client binding, for instance) between this call and the commit, and a
 * failure there must not silently burn a still-valid refresh token. The
 * atomic consumption happens in `commitExchange()`, which re-decides under
 * the same lock before writing anything.
 */

TokenFenceStore.prototype.beginExchange = function(refreshTokenValue) {
  var self = this;
  var located = this._locateToken(refreshTokenValue);

  // An unknown refresh token has no family whose marker we could read. Per
  // the failure policy, "marker unreadable" is treated exactly as revoked.
  if (!located) {
    return Promise.reject(this._revocationError(null, REVOKED_REASON));
  }

  var familyId = located.familyId;

  return this._mutex.runExclusive(familyId, function() {
    var read = self._safeReadFamily(familyId);
    var tokenRecord = self._tokens[located.value];

    var decision = self._decide(read, tokenRecord);

    if (!decision.allowed) {
      self._appendAudit(familyId, 'exchange_rejected', {
        familyId: familyId,
        refreshToken: located.value,
        reason: decision.reason
      });
      throw self._revocationError(familyId, decision.reason);
    }

    var family = read.family;

    self._appendAudit(familyId, 'exchange_started', {
      familyId: familyId,
      fence: family.fence,
      refreshToken: located.value
    });

    return {
      familyId: familyId,
      refreshToken: located.value,
      refreshTokenExpiresAt: tokenRecord.expiresAt,
      tokenFence: tokenRecord.fenceAtIssuance,
      familyFence: family.fence,
      clientId: family.clientId,
      userId: family.userId,
      scope: family.scope,
      accessTokenTtl: tokenRecord.accessTokenTtl,
      refreshTokenTtl: tokenRecord.refreshTokenTtl
    };
  });
};

/**
 * Second half of a refresh exchange: persist the generated token values into
 * the family.
 *
 * The marker is read again, under the same lock, immediately before any write.
 * A revocation that landed between the two steps therefore still wins: the
 * exchange is rejected and no token is written.
 *
 * The presented refresh token is consumed in this same atomic step, so of
 * several concurrent exchanges of the same token at most one can commit: the
 * others find the token record gone and are rejected by the same decision
 * point, never by a second, parallel rule.
 */

TokenFenceStore.prototype.commitExchange = function(record, attributes) {
  var self = this;

  if (!record || !record.familyId) {
    return Promise.reject(this._revocationError(null, REVOKED_REASON));
  }

  attributes = attributes || {};

  return this._mutex.runExclusive(record.familyId, function() {
    var read = self._safeReadFamily(record.familyId);
    var presentedRecord = self._tokens[record.refreshToken];

    // Re-decide against the freshly read marker. The presented token's own
    // record is used, so a token consumed by a competing commit in between
    // is rejected here even though `beginExchange()` saw it live. Its fence
    // is the fence it was issued under, so a fence raised in between makes it
    // stale; a flipped marker makes it revoked outright.
    var decision = self._decide(read, presentedRecord);

    if (!decision.allowed) {
      self._appendAudit(record.familyId, 'exchange_rejected', {
        familyId: record.familyId,
        refreshToken: record.refreshToken,
        reason: decision.reason
      });
      throw self._revocationError(record.familyId, decision.reason);
    }

    // Consume the presented token and write the new pair in the same atomic
    // step, under the same lock that guards the marker.
    if (!attributes.keepRefreshToken) {
      delete self._tokens[record.refreshToken];
    }

    var pair = self._writeTokenPair(read.family, record, attributes);

    self._appendAudit(record.familyId, 'exchanged', {
      familyId: record.familyId,
      fence: read.family.fence,
      consumedRefreshToken: record.refreshToken,
      refreshToken: pair.refreshToken,
      accessToken: pair.accessToken
    });

    return pair;
  });
};

/**
 * Validate an access token (the authentication path).
 *
 * Uses the same `_decide` entry point as the exchange path. Both paths thus
 * share one revocation judgement and one rejection reason; there is no
 * parallel revocation logic that could drift out of sync.
 */

TokenFenceStore.prototype.validate = function(accessTokenValue) {
  var self = this;
  var located = this._locateToken(accessTokenValue);

  if (!located) {
    return Promise.reject(this._revocationError(null, REVOKED_REASON));
  }

  var familyId = located.familyId;

  return this._mutex.runExclusive(familyId, function() {
    var read = self._safeReadFamily(familyId);
    var tokenRecord = self._tokens[located.value];

    var decision = self._decide(read, tokenRecord);

    if (!decision.allowed) {
      self._appendAudit(familyId, 'access_rejected', {
        familyId: familyId,
        accessToken: located.value,
        reason: decision.reason
      });
      throw self._revocationError(familyId, decision.reason);
    }

    self._appendAudit(familyId, 'access_accepted', {
      familyId: familyId,
      fence: read.family.fence,
      accessToken: located.value
    });

    return {
      accessToken: tokenRecord.value,
      accessTokenExpiresAt: tokenRecord.expiresAt,
      familyId: familyId,
      fence: tokenRecord.fenceAtIssuance,
      fenceAtIssuance: tokenRecord.fenceAtIssuance,
      familyFence: read.family.fence,
      client: {id: read.family.clientId},
      scope: read.family.scope,
      user: {id: read.family.userId}
    };
  });
};

/**
 * Revoke an entire token family.
 *
 * Runs under the same per-family lock as exchange and validate, so a
 * revocation and a competing exchange are serialized against one shared
 * state. The family fence is raised and the marker flipped; every token of
 * the family - old and future - then fails `_decide`.
 *
 * After the write, the family state is read back from the store and only that
 * freshly-read record is returned. A stale cached value can therefore never
 * mask or overwrite a just-completed revocation.
 */

TokenFenceStore.prototype.revokeFamily = function(familyId) {
  var self = this;

  return this._mutex.runExclusive(familyId, function() {
    var before = self._safeReadFamily(familyId);

    if (before.unreadable) {
      // The existing marker cannot be read, so its fence cannot be preserved.
      // Overwriting it with a fresh record could lower the fence and revive
      // tokens; refuse instead. The marker on disk is left untouched.
      throw new TokenFenceError('Token family state could not be read before revocation', {
        familyId: familyId,
        reason: 'family_state_unreadable',
        code: 500
      });
    }

    var family = before.family;
    var alreadyRevoked = !!(family && family.revoked);
    var fenceBefore = family ? family.fence : 0;

    if (!family) {
      // Even an unknown family gets a tombstone marker so the decision is
      // durable and readable for any token that claims this family later.
      family = self._families[familyId] = {
        familyId: familyId,
        fence: 0,
        revoked: false,
        revokedAt: null,
        clientId: null,
        userId: null,
        scope: null
      };
    }

    // Repeated revocation is idempotent. The marker stays in this one place;
    // a second call never creates a divergent copy and cannot un-revoke.
    if (!family.revoked) {
      family.fence += 1;
      family.revoked = true;
      family.revokedAt = self._now();
    }

    // Read the committed state back from the store. This is the value that is
    // returned - never a value captured before the write - so the response
    // always agrees with what a concurrent exchange would now read.
    var readBack = self._safeReadFamily(familyId);

    if (!readBack.ok) {
      // The write succeeded but the authoritative state cannot be read back.
      // Refuse to report success; the marker stays in place (fail closed).
      throw new TokenFenceError('Token family state could not be read after revocation', {
        familyId: familyId,
        reason: 'family_state_unreadable',
        code: 500
      });
    }

    var state = readBack.family;

    self._appendAudit(familyId, alreadyRevoked ? 'revoke_repeated' : 'revoked', {
      familyId: familyId,
      fenceBefore: fenceBefore,
      fenceAfter: state.fence,
      revoked: state.revoked
    });

    return copyFamilyState(state);
  });
};

/**
 * Read the current state of a family directly from the store.
 *
 * The read is fresh every time - there is no cache to go stale. A missing
 * family is reported as revoked, because the absence of a readable marker is
 * indistinguishable from a revoked one for security purposes.
 */

TokenFenceStore.prototype.getFamilyState = function(familyId) {
  var read = this._safeReadFamily(familyId);

  if (!read.ok) {
    return {
      familyId: familyId,
      fence: 0,
      revoked: true,
      revokedAt: null,
      unreadable: true
    };
  }

  return copyFamilyState(read.family);
};

/**
 * Return the audit entries archived for one family, in append order.
 *
 * Entries form a chain within the family (`prevEntryId`), so the revocation
 * action and every subsequent rejection can be replayed in order without
 * crossing into another family's history.
 */

TokenFenceStore.prototype.getAuditTrail = function(familyId) {
  // Return a copy so callers cannot mutate the archived chain.
  return (this._auditByFamily[familyId] || []).slice();
};

/**
 * Return the complete audit log in global append order.
 */

TokenFenceStore.prototype.getAuditLog = function() {
  return this._audit.slice();
};

/**
 * Resolve the family a token value belongs to, or null.
 */

TokenFenceStore.prototype.familyIdFor = function(tokenValue) {
  var located = this._locateToken(tokenValue);

  return located ? located.familyId : null;
};

/**
 * The single, centralized revocation decision.
 *
 * Both the exchange path and the validation path must call this - never
 * inline their own checks - so there is exactly one revocation judgement in
 * the codebase. It delegates the marker interpretation to
 * `tokenRevocation.readState()`, passing a token view that carries the
 * family's marker and fence. The rule is fail-closed:
 *
 *   - unreadable family record                -> denied;
 *   - missing family marker                   -> denied;
 *   - family.revoked                          -> denied;
 *   - token issued under an older fence       -> denied (stale);
 *   - unknown/consumed/malformed token record -> denied;
 *   - expired token                           -> denied;
 *   - otherwise                               -> allowed.
 */

TokenFenceStore.prototype._decide = function(read, tokenRecord) {
  if (!read || !read.ok || !read.family) {
    return {allowed: false, reason: REVOKED_REASON};
  }

  if (!tokenRecord || typeof tokenRecord !== 'object') {
    return {allowed: false, reason: REVOKED_REASON};
  }

  var family = read.family;

  // Hand the canonical marker to the shared decision helper. `readState()`
  // fails closed on any unreadable/odd marker, so the two paths can never
  // disagree about what "revoked" means.
  var state = tokenRevocation.readState({
    revocationState: 'readable',
    revoked: false,
    familyRevoked: family.revoked,
    family: family,
    fenceAtIssuance: tokenRecord.fenceAtIssuance,
    familyFence: family.fence
  });

  if (state.revoked) {
    return {allowed: false, reason: state.reason};
  }

  if (tokenRecord.expiresAt && tokenRecord.expiresAt.getTime() <= this._now().getTime()) {
    return {allowed: false, reason: 'token_expired'};
  }

  return {allowed: true, reason: null};
};

/**
 * Write a fresh access/refresh pair under the family's current fence.
 * Called with the family lock held.
 */

TokenFenceStore.prototype._writeTokenPair = function(family, defaults, attributes) {
  attributes = attributes || {};

  var now = this._now();
  var accessTokenTtl = attributes.accessTokenTtl || defaults.accessTokenTtl || 3600;
  var refreshTokenTtl = attributes.refreshTokenTtl || defaults.refreshTokenTtl || 1209600;

  var accessToken = attributes.accessToken || this._generateId('access');

  var accessExpiresAt = attributes.accessTokenExpiresAt ||
    new Date(now.getTime() + accessTokenTtl * 1000);

  this._tokens[accessToken] = {
    value: accessToken,
    kind: 'access',
    familyId: family.familyId,
    fenceAtIssuance: family.fence,
    expiresAt: accessExpiresAt,
    accessTokenTtl: accessTokenTtl,
    refreshTokenTtl: refreshTokenTtl
  };

  var refreshToken;
  var refreshExpiresAt;

  if (attributes.keepRefreshToken) {
    // Rotation disabled: the presented refresh token stays the family's
    // refresh token. Its record was left untouched by the commit, so it stays
    // usable, and there is still only one copy of it.
    var retained = this._tokens[defaults.refreshToken];

    if (retained) {
      refreshToken = defaults.refreshToken;
      refreshExpiresAt = retained.expiresAt;
    }
  } else if (attributes.refreshToken === null) {
    refreshToken = null;
    refreshExpiresAt = null;
  } else {
    refreshToken = attributes.refreshToken || this._generateId('refresh');
    refreshExpiresAt = attributes.refreshTokenExpiresAt ||
      new Date(now.getTime() + refreshTokenTtl * 1000);

    this._tokens[refreshToken] = {
      value: refreshToken,
      kind: 'refresh',
      familyId: family.familyId,
      fenceAtIssuance: family.fence,
      expiresAt: refreshExpiresAt,
      accessTokenTtl: accessTokenTtl,
      refreshTokenTtl: refreshTokenTtl
    };
  }

  return {
    familyId: family.familyId,
    fence: family.fence,
    accessToken: accessToken,
    accessTokenExpiresAt: accessExpiresAt,
    refreshToken: refreshToken,
    refreshTokenExpiresAt: refreshExpiresAt,
    client: {id: family.clientId},
    user: {id: family.userId},
    scope: family.scope,
    revoked: false
  };
};

/**
 * Find a token's raw value and the family it belongs to. Returns null when
 * the value is not a known token (treated as revoked by callers).
 */

TokenFenceStore.prototype._locateToken = function(value) {
  if (!value || typeof value !== 'string') {
    return null;
  }

  var record = this._tokens[value];

  if (!record) {
    return null;
  }

  return {value: value, familyId: record.familyId, kind: record.kind};
};

/**
 * Read a family record straight from the store, translating a store read
 * failure into an explicit result. Callers treat a failed read as revoked;
 * nothing is cached, so the next call attempts a fresh read.
 *
 * The result distinguishes a *missing* family (`missing: true`) from a family
 * whose marker could not be read at all (`unreadable: true`), because the two
 * need different handling when creating a marker.
 */

TokenFenceStore.prototype._safeReadFamily = function(familyId) {
  try {
    if (this._failRead && this._failRead(familyId)) {
      return {ok: false, missing: false, unreadable: true, family: null};
    }

    var family = this._families[familyId];

    if (!family) {
      return {ok: false, missing: true, unreadable: false, family: null};
    }

    return {ok: true, missing: false, unreadable: false, family: family};
  } catch (e) {
    return {ok: false, missing: false, unreadable: true, family: null};
  }
};

/**
 * Append one audit entry for a family.
 *
 * Entries are archived per family and form a chain *within that family*:
 * `prevEntryId` always points at the family's previous entry (null for its
 * first), so the revocation action and every later denial can be replayed in
 * order without crossing into another family's history. A global sequence
 * number preserves cross-family ordering when needed.
 */

TokenFenceStore.prototype._appendAudit = function(familyId, action, details) {
  var familyTrail = this._auditByFamily[familyId];
  var previous = familyTrail && familyTrail.length ?
    familyTrail[familyTrail.length - 1].entryId : null;

  var entry = {
    entryId: 'audit-' + (++this._sequence),
    prevEntryId: previous,
    familyId: familyId,
    action: action,
    at: this._now(),
    details: details || {}
  };

  this._audit.push(entry);

  if (!this._auditByFamily[familyId]) {
    this._auditByFamily[familyId] = [];
  }

  this._auditByFamily[familyId].push(entry);

  return entry;
};

/**
 * Build the canonical fence error.
 */

TokenFenceStore.prototype._revocationError = function(familyId, reason) {
  return new TokenFenceError('Token family has been revoked', {
    familyId: familyId,
    reason: reason || REVOKED_REASON,
    code: 401
  });
};

/**
 * Snapshot a family record into a plain, caller-owned object so outside code
 * cannot mutate the authoritative state.
 */

function copyFamilyState(family) {
  return {
    familyId: family.familyId,
    fence: family.fence,
    revoked: family.revoked,
    revokedAt: family.revokedAt,
    clientId: family.clientId,
    userId: family.userId,
    scope: family.scope,
    unreadable: false
  };
}

/**
 * Default clock.
 */

function defaultNow() {
  return new Date();
}

/**
 * Default identifier generator. Uses the platform RNG and is only used when
 * no generator is injected.
 */

function defaultIdGenerator(kind) {
  var random = Math.random().toString(36).slice(2);
  var time = Date.now().toString(36);

  return kind + '_' + time + random;
}

/**
 * Export constructor.
 */

module.exports = TokenFenceStore;
