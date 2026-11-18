'use strict';

/**
 * Module dependencies.
 */

var Promise = require('bluebird');
var should = require('should');
var TokenFenceError = require('../../../lib/token-fence/token-fence-error');
var TokenFenceStore = require('../../../lib/token-fence/token-fence-store');

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
 * Test `TokenFenceStore`.
 */

describe('TokenFenceStore', function() {
  describe('issue()', function() {
    it('should issue a live access/refresh pair in a new family', function() {
      var store = createStore();
      var pair = store.issue({familyId: 'fam-1', clientId: 'client', userId: 'user', scope: 'foo'});

      pair.familyId.should.equal('fam-1');
      pair.fence.should.equal(0);
      pair.revoked.should.be.false;
      pair.accessToken.should.be.a.String();
      pair.refreshToken.should.be.a.String();
      store.getFamilyState('fam-1').revoked.should.be.false;
    });

    it('should archive an issuance audit entry under the family', function() {
      var store = createStore();

      store.issue({familyId: 'fam-audit'});

      var trail = store.getAuditTrail('fam-audit');

      trail.should.have.length(1);
      trail[0].action.should.equal('issued');
      trail[0].familyId.should.equal('fam-audit');
    });
    it('should not revive a revoked family by issuing into it again', function() {
      var store = createStore();

      store.issue({familyId: 'fam-reissue'});

      return store.revokeFamily('fam-reissue')
        .then(function() {
          try {
            store.issue({familyId: 'fam-reissue'});

            should.fail();
          } catch (err) {
            err.should.be.an.instanceOf(TokenFenceError);
            err.reason.should.equal('token_family_revoked');
          }

          // The original marker is still the one in force.
          store.getFamilyState('fam-reissue').revoked.should.be.true;
          store.getFamilyState('fam-reissue').fence.should.equal(1);
          store.getAuditTrail('fam-reissue')
            .filter(function(entry) { return entry.action === 'issued'; })
            .should.have.length(1);
        })
        .catch(should.fail);
    });

    it('should not create a fresh family over an unreadable marker', function() {
      var store = createStore();

      store._failRead = function() { return true; };

      try {
        store.issue({familyId: 'fam-issue-unreadable'});

        should.fail();
      } catch (err) {
        err.should.be.an.instanceOf(TokenFenceError);
      }

      store._failRead = null;
      should(store._families['fam-issue-unreadable']).be.undefined;
    });
  });

  describe('exchange()', function() {
    it('should rotate a refresh token into a new pair in the same family', function() {
      var store = createStore();
      var first = store.issue({familyId: 'fam-exchange'});

      return store.exchange(first.refreshToken)
        .then(function(second) {
          second.familyId.should.equal('fam-exchange');
          second.accessToken.should.not.equal(first.accessToken);
          second.refreshToken.should.not.equal(first.refreshToken);
          second.fence.should.equal(0);
        })
        .catch(should.fail);
    });

    it('should reject an unknown refresh token as revoked', function() {
      var store = createStore();

      return store.exchange('does-not-exist')
        .then(should.fail)
        .catch(function(err) {
          err.should.be.an.instanceOf(TokenFenceError);
          err.reason.should.equal('token_family_revoked');
        });
    });

    it('should reject reuse of an already exchanged refresh token', function() {
      var store = createStore();
      var first = store.issue({familyId: 'fam-reuse'});

      return store.exchange(first.refreshToken)
        .then(function() {
          return store.exchange(first.refreshToken);
        })
        .then(should.fail)
        .catch(function(err) {
          err.should.be.an.instanceOf(TokenFenceError);
        });
    });

    it('should reject an expired refresh token', function() {
      var clock = new Date('2026-06-01T00:00:00Z');
      var sequence = 0;
      var store = new TokenFenceStore({
        now: function() { return clock; },
        generateId: function(kind) {
          sequence += 1;
          return kind + '-' + sequence;
        }
      });
      var pair = store.issue({familyId: 'fam-expired'});

      // Advance past the default refresh token lifetime.
      clock = new Date('2030-01-01T00:00:00Z');

      return store.exchange(pair.refreshToken)
        .then(should.fail)
        .catch(function(err) {
          err.reason.should.equal('token_expired');
        });
    });
  });

  describe('beginExchange()/commitExchange()', function() {
    it('should let a revocation between the two steps win', function() {
      var store = createStore();
      var first = store.issue({familyId: 'fam-between'});

      return store.beginExchange(first.refreshToken)
        .then(function(record) {
          return store.revokeFamily('fam-between')
            .then(function() {
              return store.commitExchange(record, {
                accessToken: 'access-forced',
                refreshToken: 'refresh-forced'
              });
            });
        })
        .then(should.fail)
        .catch(function(err) {
          err.should.be.an.instanceOf(TokenFenceError);
          err.reason.should.equal('token_family_revoked');
          should(store._tokens['access-forced']).be.undefined;
          should(store._tokens['refresh-forced']).be.undefined;
        });
    });

    it('should record the rejection in the family audit trail', function() {
      var store = createStore();
      var first = store.issue({familyId: 'fam-between-audit'});

      return store.beginExchange(first.refreshToken)
        .then(function(record) {
          return store.revokeFamily('fam-between-audit').then(function() {
            return store.commitExchange(record, {accessToken: 'a', refreshToken: 'r'});
          });
        })
        .then(should.fail)
        .catch(function() {
          var actions = store.getAuditTrail('fam-between-audit').map(function(e) { return e.action; });
          actions.should.containEql('revoked');
          actions.should.containEql('exchange_rejected');
        });
    });
  });

  describe('validate()', function() {
    it('should accept a live access token', function() {
      var store = createStore();
      var pair = store.issue({familyId: 'fam-valid', clientId: 'c', userId: 'u', scope: 'foo'});

      return store.validate(pair.accessToken)
        .then(function(record) {
          record.familyId.should.equal('fam-valid');
          record.client.id.should.equal('c');
          record.user.id.should.equal('u');
          record.accessTokenExpiresAt.should.be.a.Date();
        })
        .catch(should.fail);
    });

    it('should reject an unknown access token', function() {
      var store = createStore();

      return store.validate('nope')
        .then(should.fail)
        .catch(function(err) {
          err.reason.should.equal('token_family_revoked');
        });
    });

    it('should reject a revoked access token with the same reason as the exchange path', function() {
      var store = createStore();
      var pair = store.issue({familyId: 'fam-revoked'});

      return store.revokeFamily('fam-revoked').then(function() {
        return store.validate(pair.accessToken);
      })
        .then(should.fail)
        .catch(function(err) {
          err.reason.should.equal('token_family_revoked');
        });
    });
  });

  describe('revokeFamily()', function() {
    it('should invalidate every token issued in the family', function() {
      var store = createStore();
      var first = store.issue({familyId: 'fam-all'});

      return store.exchange(first.refreshToken)
        .then(function(second) {
          return store.revokeFamily('fam-all').then(function(state) {
            return {
              second: second,
              state: state
            };
          });
        })
        .then(function(result) {
          result.state.revoked.should.be.true;
          result.state.fence.should.equal(1);

          return Promise.all([
            store.validate(first.accessToken).then(should.fail, function(err) {
              err.reason.should.equal('token_family_revoked');
            }),
            store.validate(result.second.accessToken).then(should.fail, function(err) {
              err.reason.should.equal('token_family_revoked');
            }),
            store.exchange(result.second.refreshToken).then(should.fail, function(err) {
              err.reason.should.equal('token_family_revoked');
            })
          ]);
        });
    });

    it('should invalidate tokens derived after the revocation by refusing to derive them', function() {
      var store = createStore();
      var first = store.issue({familyId: 'fam-derive'});

      return store.revokeFamily('fam-derive').then(function() {
        return store.exchange(first.refreshToken);
      })
        .then(should.fail)
        .catch(function(err) {
          err.reason.should.equal('token_family_revoked');
        });
    });

    it('should be idempotent for repeated revocation', function() {
      var store = createStore();

      store.issue({familyId: 'fam-repeat'});

      return store.revokeFamily('fam-repeat')
        .then(function(first) {
          return store.revokeFamily('fam-repeat').then(function(second) {
            second.revoked.should.be.true;
            second.fence.should.equal(first.fence);
            second.revokedAt.getTime().should.equal(first.revokedAt.getTime());
          });
        })
        .catch(should.fail);
    });

    it('should record repeated revocation distinctly in the audit trail', function() {
      var store = createStore();

      store.issue({familyId: 'fam-repeat-audit'});

      return store.revokeFamily('fam-repeat-audit')
        .then(function() {
          return store.revokeFamily('fam-repeat-audit');
        })
        .then(function() {
          var actions = store.getAuditTrail('fam-repeat-audit').map(function(e) { return e.action; });
          actions.should.containEql('revoked');
          actions.should.containEql('revoke_repeated');
        })
        .catch(should.fail);
    });

    it('should create a readable tombstone for an unknown family', function() {
      var store = createStore();

      return store.revokeFamily('fam-unknown')
        .then(function(state) {
          state.revoked.should.be.true;
          store.getFamilyState('fam-unknown').revoked.should.be.true;
        })
        .catch(should.fail);
    });

    it('should refuse to revoke when the existing marker cannot be read', function() {
      var store = createStore();

      store.issue({familyId: 'fam-revoke-unreadable'});

      store._failRead = function(familyId) { return familyId === 'fam-revoke-unreadable'; };

      return store.revokeFamily('fam-revoke-unreadable')
        .then(should.fail)
        .catch(function(err) {
          err.should.be.an.instanceOf(TokenFenceError);
          err.reason.should.equal('family_state_unreadable');

          // The stored state was never overwritten or lowered.
          store._failRead = null;
          store.getFamilyState('fam-revoke-unreadable').revoked.should.be.false;
          store.getFamilyState('fam-revoke-unreadable').fence.should.equal(0);
        });
    });

    it('should return the state read back after the write, ignoring any stale snapshot', function() {
      var store = createStore();

      store.issue({familyId: 'fam-readback'});

      // Hold a pre-revocation snapshot: a "cache hit" from before the
      // revocation. It must never be able to override or mask the committed
      // state.
      var staleSnapshot = store.getFamilyState('fam-readback');

      staleSnapshot.revoked.should.be.false;

      return store.revokeFamily('fam-readback')
        .then(function(state) {
          state.revoked.should.be.true;
          state.fence.should.equal(1);

          // The stale snapshot is inert, and every fresh read agrees with the
          // revocation that was just committed.
          store.getFamilyState('fam-readback').revoked.should.be.true;
          store.getFamilyState('fam-readback').fence.should.equal(1);

          staleSnapshot.revoked = false;
          store.getFamilyState('fam-readback').revoked.should.be.true;
        })
        .catch(should.fail);
    });

    it('should fail closed if the family state cannot be read back after the write', function() {
      var store = createStore();

      store.issue({familyId: 'fam-readback-fail'});

      var readCalls = 0;

      store._failRead = function(familyId) {
        if (familyId !== 'fam-readback-fail') {
          return false;
        }

        readCalls += 1;

        // Let the first read (state before the write) succeed, then make the
        // read-back fail.
        return readCalls > 1;
      };

      return store.revokeFamily('fam-readback-fail')
        .then(should.fail)
        .catch(function(err) {
          err.should.be.an.instanceOf(TokenFenceError);
          err.reason.should.equal('family_state_unreadable');

          // The marker was still committed, so the family is not revived.
          store._failRead = null;
          store.getFamilyState('fam-readback-fail').revoked.should.be.true;
        });
    });
  });

  describe('getFamilyState()', function() {
    it('should report a missing family as revoked', function() {
      var store = createStore();
      var state = store.getFamilyState('fam-missing');

      state.revoked.should.be.true;
      state.unreadable.should.be.true;
    });

    it('should report an unreadable family as revoked', function() {
      var store = createStore();

      store.issue({familyId: 'fam-unreadable'});

      store._failRead = function() { return true; };

      var state = store.getFamilyState('fam-unreadable');

      state.revoked.should.be.true;
      state.unreadable.should.be.true;
    });

    it('should return a snapshot that cannot mutate the store', function() {
      var store = createStore();

      store.issue({familyId: 'fam-snapshot'});

      var snapshot = store.getFamilyState('fam-snapshot');
      snapshot.revoked = true;

      store.getFamilyState('fam-snapshot').revoked.should.be.false;
    });
  });

  describe('read failures', function() {
    it('should treat an unreadable marker as revoked on exchange', function() {
      var store = createStore();
      var pair = store.issue({familyId: 'fam-fail-exchange'});

      store._failRead = function(familyId) { return familyId === 'fam-fail-exchange'; };

      return store.exchange(pair.refreshToken)
        .then(should.fail)
        .catch(function(err) {
          err.reason.should.equal('token_family_revoked');
        });
    });

    it('should treat an unreadable marker as revoked on validation', function() {
      var store = createStore();
      var pair = store.issue({familyId: 'fam-fail-validate'});

      store._failRead = function(familyId) { return familyId === 'fam-fail-validate'; };

      return store.validate(pair.accessToken)
        .then(should.fail)
        .catch(function(err) {
          err.reason.should.equal('token_family_revoked');
        });
    });

    it('should not leave a cached allowed decision behind after a failed read', function() {
      var store = createStore();
      var pair = store.issue({familyId: 'fam-fail-cache'});

      store._failRead = function() { return true; };

      return store.validate(pair.accessToken)
        .then(should.fail)
        .catch(function(err) {
          err.reason.should.equal('token_family_revoked');

          // The read recovers; there is no cached denial, and no cached
          // allowance either. The next call reads the live state.
          store._failRead = null;

          return store.validate(pair.accessToken);
        })
        .then(function(record) {
          record.familyId.should.equal('fam-fail-cache');
        })
        .catch(should.fail);
    });
  });

  describe('audit trail', function() {
    it('should chain entries within a family and link revocation to later rejections', function() {
      var store = createStore();
      var pair = store.issue({familyId: 'fam-chain'});

      return store.revokeFamily('fam-chain')
        .then(function() {
          return store.validate(pair.accessToken).then(should.fail, function() {});
        })
        .then(function() {
          var trail = store.getAuditTrail('fam-chain');
          var actions = trail.map(function(e) { return e.action; });

          actions.slice(0, 3).should.eql(['issued', 'revoked', 'access_rejected']);
          should(trail[0].prevEntryId).be.null;

          for (var i = 1; i < trail.length; i += 1) {
            trail[i].prevEntryId.should.equal(trail[i - 1].entryId);
            trail[i].familyId.should.equal('fam-chain');
          }
        })
        .catch(should.fail);
    });

    it('should archive entries per family without crossing families', function() {
      var store = createStore();

      store.issue({familyId: 'fam-x'});
      store.issue({familyId: 'fam-y'});

      return store.revokeFamily('fam-x')
        .then(function() {
          store.getAuditTrail('fam-x').forEach(function(entry) {
            entry.familyId.should.equal('fam-x');
          });
          store.getAuditTrail('fam-y').forEach(function(entry) {
            entry.familyId.should.equal('fam-y');
          });

          var actions = store.getAuditTrail('fam-y').map(function(e) { return e.action; });
          actions.should.not.containEql('revoked');
        })
        .catch(should.fail);
    });

    it('should return a copy so callers cannot mutate the archive', function() {
      var store = createStore();

      store.issue({familyId: 'fam-copy'});

      var trail = store.getAuditTrail('fam-copy');
      trail.length = 0;

      store.getAuditTrail('fam-copy').should.have.length(1);
    });
  });
});
