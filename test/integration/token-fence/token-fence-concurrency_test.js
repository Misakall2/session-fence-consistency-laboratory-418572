'use strict';

/**
 * Module dependencies.
 */

var FenceModelAdapter = require('../../../lib/token-fence/fence-model-adapter');
var Promise = require('bluebird');
var should = require('should');
var TokenFenceError = require('../../../lib/token-fence/token-fence-error');
var TokenFenceStore = require('../../../lib/token-fence/token-fence-store');

/**
 * Manual promise gate, giving tests deterministic control over interleaving.
 */

function gate() {
  var held = {release: null, promise: null};

  held.promise = new Promise(function(resolve) {
    held.release = resolve;
  });

  return held;
}

/**
 * Deterministic store: fixed clock and sequential ids.
 */

function createStore(options) {
  var sequence = 0;
  var settings = {
    now: function() { return new Date('2026-06-01T00:00:00Z'); },
    generateId: function(kind) {
      sequence += 1;
      return kind + '-' + sequence;
    }
  };

  if (options) {
    Object.keys(options).forEach(function(key) {
      settings[key] = options[key];
    });
  }

  return new TokenFenceStore(settings);
}

/**
 * Test `TokenFenceStore` under concurrent revocation and exchange.
 */

describe('TokenFenceStore concurrency', function() {
  it('should let an earlier revocation beat a later exchange', function() {
    var store = createStore();
    var pair = store.issue({familyId: 'race-revoke-first'});

    return store.revokeFamily('race-revoke-first')
      .then(function() {
        return store.exchange(pair.refreshToken);
      })
      .then(should.fail)
      .catch(function(err) {
        err.should.be.an.instanceOf(TokenFenceError);
        err.reason.should.equal('token_family_revoked');

        store.getAuditTrail('race-revoke-first')
          .filter(function(entry) { return entry.action === 'exchanged'; })
          .should.have.length(0);
      });
  });

  it('should decouple a queued revocation from a completed exchange but still fence its output', function() {
    var store = createStore();
    var pair = store.issue({familyId: 'race-exchange-first'});

    var exchangePromise = store.exchange(pair.refreshToken);
    var revokePromise = store.revokeFamily('race-exchange-first');

    // Both operations race on the same family lock. Whichever is decided
    // first, the family ends revoked and the exchange outcome is one of the
    // two deterministic answers, never a token that outlives the revocation.
    return Promise.all([
      exchangePromise.then(function(result) { return {outcome: 'issued', result: result}; },
                           function(err) { return {outcome: 'rejected', err: err}; }),
      revokePromise
    ])
      .then(function(results) {
        var exchangeResult = results[0];
        var state = results[1];

        state.revoked.should.be.true;
        store.getFamilyState('race-exchange-first').revoked.should.be.true;

        if (exchangeResult.outcome === 'issued') {
          // The exchange won the lock; its token must now be dead.
          return store.validate(exchangeResult.result.accessToken)
            .then(should.fail)
            .catch(function(err) {
              err.reason.should.equal('token_family_revoked');
            });
        }

        exchangeResult.err.reason.should.equal('token_family_revoked');
      });
  });

  it('should give one shared decision to revocation and exchange when they interleave', function() {
    var store = createStore();
    var pair = store.issue({familyId: 'race-interleaved'});

    // Pause the exchange while it holds the family lock, launch the
    // revocation on the same lock, then release. The revocation is decided
    // against the state the exchange leaves behind - never against a stale
    // pre-exchange copy.
    var insideExchange = gate();
    var releaseExchange = gate();
    var original = store._mutex.runExclusive.bind(store._mutex);
    var paused = false;

    store._mutex.runExclusive = function(key, fn) {
      if (key === 'race-interleaved' && !paused && !store._armed) {
        store._armed = true;
        return original(key, function() {
          insideExchange.release();

          return releaseExchange.promise.then(fn);
        });
      }

      return original(key, fn);
    };

    var exchangePromise = store.exchange(pair.refreshToken)
      .then(function(result) { return {outcome: 'issued', result: result}; },
            function(err) { return {outcome: 'rejected', err: err}; });

    return insideExchange.promise.then(function() {
      var revokePromise = store.revokeFamily('race-interleaved');

      releaseExchange.release();

      return Promise.all([exchangePromise, revokePromise]);
    })
      .then(function(results) {
        var exchangeResult = results[0];
        var state = results[1];

        state.revoked.should.be.true;
        store.getFamilyState('race-interleaved').revoked.should.be.true;

        if (exchangeResult.outcome === 'issued') {
          return store.validate(exchangeResult.result.accessToken)
            .then(should.fail)
            .catch(function(err) {
              err.reason.should.equal('token_family_revoked');
            });
        }

        exchangeResult.err.reason.should.equal('token_family_revoked');
      });
  });

  it('should not let a later exchange re-issue a token from a stale allowance', function() {
    var store = createStore();
    var pair = store.issue({familyId: 'race-stale'});

    // Warm any decision the store might be tempted to remember.
    return store.validate(pair.accessToken)
      .then(function() {
        return store.revokeFamily('race-stale');
      })
      .then(function() {
        // Repeat the same read several times; every attempt must re-decide
        // against the revoked marker rather than reuse the earlier allowance.
        return Promise.all([
          store.validate(pair.accessToken).then(should.fail, function(err) {
            err.reason.should.equal('token_family_revoked');
          }),
          store.validate(pair.accessToken).then(should.fail, function(err) {
            err.reason.should.equal('token_family_revoked');
          }),
          store.exchange(pair.refreshToken).then(should.fail, function(err) {
            err.reason.should.equal('token_family_revoked');
          })
        ]);
      });
  });

  it('should let at most one of many concurrent exchanges of the same token succeed', function() {
    var store = createStore();
    var pair = store.issue({familyId: 'race-burst'});

    var jobs = [];

    for (var i = 0; i < 8; i += 1) {
      jobs.push(store.exchange(pair.refreshToken).then(function() { return 'issued'; }, function() { return 'rejected'; }));
    }

    return Promise.all(jobs)
      .then(function(results) {
        results.filter(function(result) { return result === 'issued'; }).should.have.length(1);
        store.getFamilyState('race-burst').revoked.should.be.false;
      });
  });

  it('should let at most one of many concurrent begin/commit exchanges of the same token commit', function() {
    var store = createStore();
    var pair = store.issue({familyId: 'race-split'});

    // All eight requests pass the begin step while the token is still live...
    var begins = [];

    for (var i = 0; i < 8; i += 1) {
      begins.push(store.beginExchange(pair.refreshToken));
    }

    return Promise.all(begins)
      .then(function(records) {
        // ...then all commit. Exactly one may consume the token and write;
        // the rest are rejected by the same decision point.
        return Promise.all(records.map(function(record) {
          return store.commitExchange(record, {}).then(function() { return 'issued'; }, function() { return 'rejected'; });
        }));
      })
      .then(function(results) {
        results.filter(function(result) { return result === 'issued'; }).should.have.length(1);
        store.getAuditTrail('race-split')
          .filter(function(entry) { return entry.action === 'exchanged'; })
          .should.have.length(1);
      });
  });

  it('should reject every concurrent exchange when a revocation commits first', function() {
    var store = createStore();
    var pair = store.issue({familyId: 'race-begins-then-revoke'});

    // Simulate several requests that all passed their begin step before the
    // revocation, then commit afterwards. None may succeed.
    return Promise.all([
      store.beginExchange(pair.refreshToken),
      store.beginExchange(pair.refreshToken)
    ])
      .then(function(records) {
        return store.revokeFamily('race-begins-then-revoke').then(function() {
          return Promise.all(records.map(function(record) {
            return store.commitExchange(record, {}).then(function() { return 'issued'; }, function() { return 'rejected'; });
          }));
        });
      })
      .then(function(results) {
        results.forEach(function(result) {
          result.should.equal('rejected');
        });
        store.getAuditTrail('race-begins-then-revoke')
          .filter(function(entry) { return entry.action === 'exchanged'; })
          .should.have.length(0);
      });
  });

  it('should settle a burst of exchanges mixed with a revocation on one consistent state', function() {
    var store = createStore();
    var pair = store.issue({familyId: 'race-mixed'});

    var jobs = [];

    for (var i = 0; i < 6; i += 1) {
      jobs.push(store.exchange(pair.refreshToken).then(function() { return 'issued'; }, function() { return 'rejected'; }));
    }

    jobs.push(store.revokeFamily('race-mixed').then(function() { return 'revoked'; }));

    return Promise.all(jobs)
      .then(function(results) {
        results.filter(function(result) { return result === 'revoked'; }).should.have.length(1);
        store.getFamilyState('race-mixed').revoked.should.be.true;

        // Whatever was issued is dead, and no further derivation succeeds.
        var issued = results.filter(function(result) { return result === 'issued'; }).length;

        // At most the single exchange that held the token can have succeeded.
        issued.should.be.lessThanOrEqual(1);

        return store.exchange(pair.refreshToken).then(should.fail, function(err) {
          err.reason.should.equal('token_family_revoked');
        });
      });
  });

  it('should reject retries after revocation without ever bypassing the check', function() {
    var store = createStore();
    var pair = store.issue({familyId: 'race-retry'});

    return store.revokeFamily('race-retry')
      .then(function() {
        function attempt(remaining) {
          if (remaining === 0) {
            return Promise.resolve();
          }

          return store.exchange(pair.refreshToken)
            .then(should.fail, function(err) {
              err.reason.should.equal('token_family_revoked');
              return attempt(remaining - 1);
            });
        }

        return attempt(5);
      })
      .then(function() {
        store.getAuditTrail('race-retry')
          .filter(function(entry) { return entry.action === 'exchanged'; })
          .should.have.length(0);
      });
  });
});

/**
 * Test the adapter's split refresh path under revocation competition.
 */

describe('FenceModelAdapter revocation races', function() {
  function createAdapter(store) {
    return new FenceModelAdapter(store, {
      clients: {
        client: {id: 'client', clientSecret: 'secret', grants: ['refresh_token', 'password']}
      }
    });
  }

  it('should expose live markers, so a revocation after the decision is still seen by the framework check', function() {
    var store = createStore();
    var adapter = createAdapter(store);
    var pair = store.issue({familyId: 'adapter-live', clientId: 'client', userId: 'user'});

    return adapter.getAccessToken(pair.accessToken)
      .then(function(record) {
        // The store's decision has already allowed this token.
        record.revoked.should.be.false;

        // A revocation now commits; the framework's later check reads the
        // same marker and must observe it, not a snapshot taken earlier.
        return store.revokeFamily('adapter-live').then(function() {
          record.revoked.should.be.true;
          store.getFamilyState('adapter-live').revoked.should.be.true;
        });
      })
      .catch(should.fail);
  });

  it('should fetch fresh markers for refresh tokens across begin and revoke', function() {
    var store = createStore();
    var adapter = createAdapter(store);
    var pair = store.issue({familyId: 'adapter-live-refresh', clientId: 'client', userId: 'user'});

    return adapter.getRefreshToken(pair.refreshToken)
      .then(function(token) {
        token.revoked.should.be.false;

        return store.revokeFamily('adapter-live-refresh').then(function() {
          token.revoked.should.be.true;
        });
      })
      .catch(should.fail);
  });

  it('should reject the commit when the family is revoked between begin and commit', function() {
    var store = createStore();
    var adapter = createAdapter(store);
    var pair = store.issue({familyId: 'adapter-between', clientId: 'client', userId: 'user'});

    return adapter.getRefreshToken(pair.refreshToken)
      .then(function(token) {
        return store.revokeFamily('adapter-between').then(function() {
          return adapter.revokeToken(token);
        }).then(function() {
          return adapter.saveToken({
            accessToken: 'forced-access',
            accessTokenExpiresAt: new Date(Date.now() + 10000),
            refreshToken: 'forced-refresh',
            refreshTokenExpiresAt: new Date(Date.now() + 10000),
            scope: null
          }, {id: 'client'}, token.user);
        });
      })
      .then(should.fail)
      .catch(function(err) {
        err.name.should.equal('invalid_grant');
        err.reason.should.equal('token_family_revoked');
        should(store._tokens['forced-access']).be.undefined;
        should(store._tokens['forced-refresh']).be.undefined;
      });
  });

  it('should reject a refresh token that was already revoked before the request', function() {
    var store = createStore();
    var adapter = createAdapter(store);
    var pair = store.issue({familyId: 'adapter-pre', clientId: 'client', userId: 'user'});

    return store.revokeFamily('adapter-pre')
      .then(function() {
        return adapter.getRefreshToken(pair.refreshToken);
      })
      .then(should.fail)
      .catch(function(err) {
        err.name.should.equal('invalid_grant');
        err.reason.should.equal('token_family_revoked');
      });
  });

  it('should reject the stale token of one request without affecting the live one\'s commit', function() {
    var store = createStore();
    var adapter = createAdapter(store);
    var first = store.issue({familyId: 'adapter-concurrent', clientId: 'client', userId: 'user'});

    // Rotate once so the family holds a live refresh token and a consumed one.
    return store.exchange(first.refreshToken)
      .then(function(second) {
        return Promise.all([
          adapter.getRefreshToken(second.refreshToken),
          adapter.getRefreshToken(first.refreshToken).then(function() { return null; }, function() { return 'rejected'; })
        ]).then(function(results) {
          var live = results[0];

          // The consumed token was rejected at the begin step, so its
          // exchange was never bound and cannot be mixed up with the live
          // one.
          results[1].should.equal('rejected');

          return adapter.saveToken({
            accessToken: 'new-access',
            accessTokenExpiresAt: new Date(Date.now() + 10000),
            refreshToken: 'new-refresh',
            refreshTokenExpiresAt: new Date(Date.now() + 10000),
            scope: null
          }, {id: 'client'}, live.user);
        });
      })
      .then(function(saved) {
        saved.accessToken.should.equal('new-access');
        store.getFamilyState('adapter-concurrent').revoked.should.be.false;
      })
      .catch(should.fail);
  });

  it('should keep two distinct families independent under concurrent revocation', function() {
    var store = createStore();
    var adapter = createAdapter(store);
    var a = store.issue({familyId: 'adapter-fam-a', clientId: 'client', userId: 'user'});
    var b = store.issue({familyId: 'adapter-fam-b', clientId: 'client', userId: 'user'});

    return store.revokeFamily('adapter-fam-a')
      .then(function() {
        return Promise.all([
          adapter.getAccessToken(a.accessToken).then(function() { return 'accepted'; }, function(err) { return err.name; }),
          adapter.getAccessToken(b.accessToken).then(function() { return 'accepted'; }, function(err) { return err.name; })
        ]);
      })
      .then(function(results) {
        results[0].should.equal('invalid_token');
        results[1].should.equal('accepted');
      })
      .catch(should.fail);
  });

  it('should preserve the refresh token when rotation is disabled', function() {
    var store = createStore();
    var adapter = createAdapter(store);
    var pair = store.issue({familyId: 'adapter-no-rotate', clientId: 'client', userId: 'user'});

    return adapter.getRefreshToken(pair.refreshToken)
      .then(function(token) {
        return adapter.saveToken({
          accessToken: 'next-access',
          accessTokenExpiresAt: new Date(Date.now() + 10000),
          scope: null
        }, {id: 'client'}, token.user).then(function(saved) {
          return {saved: saved, token: token};
        });
      })
      .then(function(result) {
        result.saved.refreshToken.should.equal(pair.refreshToken);

        // The retained refresh token remains usable for the next rotation.
        return adapter.getRefreshToken(pair.refreshToken);
      })
      .then(function(token) {
        token.refreshToken.should.equal(pair.refreshToken);
      })
      .catch(should.fail);
  });
});
