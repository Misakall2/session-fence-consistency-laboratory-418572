'use strict';

/**
 * Centralized revocation decision.
 *
 * OAuth tokens are grouped into token families: the first access/refresh pair
 * starts a family and every refresh rotation derives a new pair into the same
 * family. Revoking a family must therefore invalidate every token ever issued
 * under it, before and after the revocation.
 *
 * The revocation marker lives next to the token it governs - inside the token
 * record (or its family record) returned by the model - and nowhere else. This
 * module is the *only* place that interprets that marker: both the refresh
 * exchange path (`RefreshTokenGrantType`) and the access token validation path
 * (`AuthenticateHandler`) call `readState()` so they share one judgment and one
 * rejection reason. Keeping a separate revocation list or a cached decision
 * would create a second copy of the marker that could drift out of sync with
 * the token store; neither exists here.
 *
 * The decision is fail-closed. Anything that prevents a positive "still live"
 * reading - a missing record, a malformed marker, a throwing getter, an
 * explicitly unreadable marker, a token issued under an older family fence -
 * is treated exactly like a revoked token.
 */

/**
 * The single, stable reason reported for every revocation-caused denial. An
 * old token retried after a revocation and a freshly derived token rejected by
 * the same revocation therefore produce the identical reason.
 */

var REVOKED_REASON = 'token_family_revoked';

/**
 * Build a revoked decision.
 */

function denied() {
  return {revoked: true, reason: REVOKED_REASON};
}

/**
 * Build an allowed decision.
 */

function allowed() {
  return {revoked: false, reason: null};
}

/**
 * Read the revocation state of a token record.
 *
 * Returns `{revoked: Boolean, reason: String}`. All property access happens
 * inside the guard, so a model that computes a marker lazily - including a
 * getter that reads the store and throws when the store is unavailable - can
 * never turn a failed read into an "allowed" decision.
 *
 * Recognized marker shapes (one canonical location, no copies):
 *
 *   - `revocationState === 'unreadable'` - the store could not answer;
 *   - `revoked === true` - the token itself was revoked;
 *   - `familyRevoked === true` - the token family was revoked;
 *   - `family.revoked === true` - the attached family record was revoked;
 *   - `fenceAtIssuance < familyFence` - the token predates a revocation.
 *
 * A token with none of these markers is allowed. That keeps plain model
 * records (which do not implement families at all) working unchanged.
 */

function readState(token) {
  try {
    if (!token || typeof token !== 'object') {
      return denied();
    }

    if (token.revocationState === 'unreadable') {
      return denied();
    }

    if (token.revoked === true) {
      return denied();
    }

    if (token.familyRevoked === true) {
      return denied();
    }

    var family = token.family;

    if (family && family.revoked === true) {
      return denied();
    }

    var fenceAtIssuance = token.fenceAtIssuance;
    var familyFence = token.familyFence;

    if (typeof fenceAtIssuance === 'number' && typeof familyFence === 'number' && fenceAtIssuance < familyFence) {
      return denied();
    }

    return allowed();
  } catch (e) {
    // An unreadable marker is indistinguishable from a revoked one and must
    // never be treated as permission to proceed.
    return denied();
  }
}

/**
 * Convenience predicate.
 */

function isRevoked(token) {
  return readState(token).revoked;
}

/**
 * Export helpers.
 */

exports.REVOKED_REASON = REVOKED_REASON;
exports.readState = readState;
exports.isRevoked = isRevoked;
