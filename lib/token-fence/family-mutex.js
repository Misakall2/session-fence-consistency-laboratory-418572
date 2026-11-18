'use strict';

/**
 * Module dependencies.
 */

var Promise = require('bluebird');

/**
 * Per-family FIFO mutex.
 *
 * Revocation, token exchange and token validation all have to decide against
 * the same family state. This lock makes that possible without introducing a
 * second copy of the state: every operation that touches a family is queued
 * behind the previous one for that same family, in arrival order.
 *
 * FIFO ordering is what makes the concurrent cases deterministic:
 *
 *   - a revocation that arrives before an exchange is decided (and committed)
 *     first, so the exchange afterwards reads the revoked state and loses;
 *   - an exchange that arrives before a revocation completes against the live
 *     state, and the revocation that follows still fences the token it
 *     produced - the later exchange never "wins" over the earlier revocation
 *     because the fence is raised before any later exchange can run;
 *   - both paths observe exactly one shared decision result per family state,
 *     because the state cannot change while the lock is held.
 *
 * The lock is deliberately in-process and promise-based. The store it guards
 * is the single authoritative location for tokens and their revocation
 * marker, so keeping the atomicity reasoning local to that data is enough.
 */

function FamilyMutex() {
  // family id -> tail of the promise chain for that family.
  this._tails = Object.create(null);
}

/**
 * Run `fn` exclusively for `key`, in arrival order.
 *
 * The promise returned to the caller reflects the outcome of `fn`; the chain
 * tail stored for the key never rejects, otherwise one failed operation would
 * permanently break the queue for that family.
 */

FamilyMutex.prototype.runExclusive = function(key, fn) {
  var self = this;
  var previous = this._tails[key] || Promise.resolve();

  var result = previous.then(function() {
    return fn();
  });

  var tail = result.then(noop, noop);

  this._tails[key] = tail;

  // Only remove the key if nobody queued behind us in the meantime.
  tail.then(function() {
    if (self._tails[key] === tail) {
      delete self._tails[key];
    }
  });

  return result;
};

/**
 * Swallow a value/reason so the internal chain tail is always fulfilled.
 */

function noop() {}

/**
 * Export constructor.
 */

module.exports = FamilyMutex;
