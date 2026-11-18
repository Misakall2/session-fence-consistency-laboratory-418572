'use strict';

/**
 * Module dependencies.
 */

var FenceModelAdapter = require('../../../lib/token-fence/fence-model-adapter');
var OAuth2Server = require('../../../index');
var Promise = require('bluebird');
var Request = require('../../../lib/request');
var Response = require('../../../lib/response');
var should = require('should');
var TokenFenceStore = require('../../../lib/token-fence/token-fence-store');

/**
 * Build a server wired to the fence store through the model adapter.
 */

function createServer(store) {
  var adapter = new FenceModelAdapter(store, {
    clients: {
      client: {id: 'client', clientSecret: 'secret', grants: ['refresh_token']},
      other: {id: 'other', clientSecret: 'other-secret', grants: ['refresh_token']}
    }
  });
  var server = new OAuth2Server({
    model: adapter
  });

  return {server: server, adapter: adapter};
}

/**
 * Build a refresh token request.
 */

function refreshRequest(refreshToken) {
  return new Request({
    body: {
      client_id: 'client',
      client_secret: 'secret',
      grant_type: 'refresh_token',
      refresh_token: refreshToken
    },
    headers: {'content-type': 'application/x-www-form-urlencoded', 'transfer-encoding': 'chunked'},
    method: 'POST',
    query: {}
  });
}

/**
 * Build an authenticate request.
 */

function authenticateRequest(accessToken) {
  return new Request({
    body: {},
    headers: {authorization: 'Bearer ' + accessToken},
    method: 'GET',
    query: {}
  });
}

/**
 * Deterministic store: only the identifier sequence is fixed; the clock is
 * the real one so the framework's own expiry checks see live timestamps.
 */

function createStore() {
  var sequence = 0;

  return new TokenFenceStore({
    generateId: function(kind) {
      sequence += 1;
      return kind + '-' + sequence;
    }
  });
}

/**
 * Test the framework end-to-end through the fence adapter.
 */

describe('Token fence integration', function() {
  describe('refresh flow', function() {
    it('should exchange a live refresh token for a new pair in the same family', function() {
      var store = createStore();
      var pair = store.issue({familyId: 'fam-refresh', clientId: 'client', userId: 'user', scope: 'foo'});
      var built = createServer(store);
      var response = new Response({body: {}, headers: {}});

      return built.server.token(refreshRequest(pair.refreshToken), response)
        .then(function() {
          response.body.access_token.should.be.a.String();
          response.body.refresh_token.should.be.a.String();
          response.body.refresh_token.should.not.equal(pair.refreshToken);
          store.familyIdFor(response.body.access_token).should.equal('fam-refresh');
          store.familyIdFor(response.body.refresh_token).should.equal('fam-refresh');
        })
        .catch(should.fail);
    });

    it('should reject a revoked refresh token from the token endpoint', function() {
      var store = createStore();
      var pair = store.issue({familyId: 'fam-refresh-revoked', clientId: 'client', userId: 'user'});
      var built = createServer(store);
      var response = new Response({body: {}, headers: {}});

      return store.revokeFamily('fam-refresh-revoked')
        .then(function() {
          return built.server.token(refreshRequest(pair.refreshToken), response);
        })
        .then(should.fail)
        .catch(function(err) {
          err.name.should.equal('invalid_grant');
          err.reason.should.equal('token_family_revoked');
          response.status.should.equal(400);
          response.body.error.should.equal('invalid_grant');
        });
    });

    it('should reject a refresh token revoked immediately before the request', function() {
      var store = createStore();
      var pair = store.issue({familyId: 'fam-immediate', clientId: 'client', userId: 'user'});
      var built = createServer(store);
      var response = new Response({body: {}, headers: {}});
      var rotated;

      return built.server.token(refreshRequest(pair.refreshToken), response)
        .then(function() {
          // Rotation succeeded once; revoke the family and retry the *new*
          // refresh token immediately.
          rotated = response.body.refresh_token;

          return store.revokeFamily('fam-immediate');
        })
        .then(function() {
          return built.server.token(refreshRequest(rotated), new Response({body: {}, headers: {}}));
        })
        .then(should.fail)
        .catch(function(err) {
          err.reason.should.equal('token_family_revoked');
        });
    });

    it('should not issue a token when the revocation races the exchange', function() {
      var store = createStore();
      var pair = store.issue({familyId: 'fam-race', clientId: 'client', userId: 'user'});
      var built = createServer(store);
      var response = new Response({body: {}, headers: {}});

      // Start the exchange and revoke on the same tick, then let the family
      // lock serialize them in arrival order.
      var exchange = built.server.token(refreshRequest(pair.refreshToken), response)
        .then(function() { return 'issued'; }, function(err) { return err.reason || err.name; });
      var revoke = store.revokeFamily('fam-race');

      return Promise.all([exchange, revoke])
        .then(function(results) {
          store.getFamilyState('fam-race').revoked.should.be.true;

          if (results[0] === 'issued') {
            // The exchange won; its access token must still be dead.
            return built.server.authenticate(
              authenticateRequest(response.body.access_token),
              new Response({body: {}, headers: {}})
            ).then(should.fail, function(err) {
              err.reason.should.equal('token_family_revoked');
            });
          }

          results[0].should.equal('token_family_revoked');
        });
    });
  });

  describe('authenticate flow', function() {
    it('should keep the same refresh token when rotation is disabled', function() {
      var store = createStore();
      var pair = store.issue({familyId: 'fam-no-rotate', clientId: 'client', userId: 'user'});
      var built = createServer(store);
      var response = new Response({body: {}, headers: {}});

      return built.server.token(refreshRequest(pair.refreshToken), response, {alwaysIssueNewRefreshToken: false})
        .then(function() {
          response.body.refresh_token.should.equal(pair.refreshToken);

          // The retained token still belongs to the same family and is still
          // usable, but a later family revocation fences it like any other.
          return built.server.token(refreshRequest(pair.refreshToken), new Response({body: {}, headers: {}}), {alwaysIssueNewRefreshToken: false});
        })
        .then(function() {
          return store.revokeFamily('fam-no-rotate');
        })
        .then(function() {
          return built.server.token(refreshRequest(pair.refreshToken), new Response({body: {}, headers: {}}), {alwaysIssueNewRefreshToken: false});
        })
        .then(should.fail)
        .catch(function(err) {
          err.reason.should.equal('token_family_revoked');
        });
    });

    it('should authenticate a live access token', function() {
      var store = createStore();
      var pair = store.issue({familyId: 'fam-auth', clientId: 'client', userId: 'user', scope: 'foo'});
      var built = createServer(store);

      return built.server.authenticate(authenticateRequest(pair.accessToken), new Response({body: {}, headers: {}}))
        .then(function(token) {
          token.accessToken.should.equal(pair.accessToken);
          token.user.id.should.equal('user');
        })
        .catch(should.fail);
    });

    it('should reject a revoked access token with the same reason as the exchange path', function() {
      var store = createStore();
      var pair = store.issue({familyId: 'fam-auth-revoked', clientId: 'client', userId: 'user'});
      var built = createServer(store);

      return store.revokeFamily('fam-auth-revoked')
        .then(function() {
          return built.server.authenticate(authenticateRequest(pair.accessToken), new Response({body: {}, headers: {}}));
        })
        .then(should.fail)
        .catch(function(err) {
          err.name.should.equal('invalid_token');

          // The reason must match the one the exchange path reports for the
          // same family revocation.
          return built.server.token(refreshRequest(pair.refreshToken), new Response({body: {}, headers: {}}))
            .then(should.fail, function(grantErr) {
              err.reason.should.equal(grantErr.reason);
              err.reason.should.equal('token_family_revoked');
            });
        });
    });
  });

  describe('family-wide revocation', function() {
    it('should invalidate the old token and the newly derived token after revoking the family', function() {
      var store = createStore();
      var first = store.issue({familyId: 'fam-derive', clientId: 'client', userId: 'user'});
      var built = createServer(store);
      var response = new Response({body: {}, headers: {}});

      return built.server.token(refreshRequest(first.refreshToken), response)
        .then(function() {
          var derivedAccessToken = response.body.access_token;
          var derivedRefreshToken = response.body.refresh_token;

          return store.revokeFamily('fam-derive')
            .then(function() {
              return Promise.all([
                // The old token, tried once more.
                built.server.token(refreshRequest(first.refreshToken), new Response({body: {}, headers: {}}))
                  .then(should.fail, function(err) { return err.reason; }),
                // The newly derived token, tried once more.
                built.server.token(refreshRequest(derivedRefreshToken), new Response({body: {}, headers: {}}))
                  .then(should.fail, function(err) { return err.reason; }),
                built.server.authenticate(authenticateRequest(derivedAccessToken), new Response({body: {}, headers: {}}))
                  .then(should.fail, function(err) { return err.reason; })
              ]);
            });
        })
        .then(function(reasons) {
          reasons.forEach(function(reason) {
            reason.should.equal('token_family_revoked');
          });
        })
        .catch(should.fail);
    });

    it('should not consume the refresh token when the request fails the client check', function() {
      var store = createStore();
      var pair = store.issue({familyId: 'fam-client-check', clientId: 'client', userId: 'user'});
      var built = createServer(store);

      // The presented refresh token is valid and live, but the request is
      // made by a different client. That is rejected by the framework after
      // the fence's begin step; the token itself must stay usable.
      var request = new Request({
        body: {
          client_id: 'other',
          client_secret: 'other-secret',
          grant_type: 'refresh_token',
          refresh_token: pair.refreshToken
        },
        headers: {'content-type': 'application/x-www-form-urlencoded', 'transfer-encoding': 'chunked'},
        method: 'POST',
        query: {}
      });

      return built.server.token(request, new Response({body: {}, headers: {}}))
        .then(should.fail)
        .catch(function(err) {
          err.name.should.equal('invalid_grant');

          // The legitimate owner can still use the token afterwards.
          return built.server.token(refreshRequest(pair.refreshToken), new Response({body: {}, headers: {}}));
        })
        .then(function() {
          store.getFamilyState('fam-client-check').revoked.should.be.false;
        })
        .catch(should.fail);
    });

    it('should not affect other families', function() {
      var store = createStore();
      var revoked = store.issue({familyId: 'fam-one', clientId: 'client', userId: 'user'});
      var kept = store.issue({familyId: 'fam-two', clientId: 'client', userId: 'user'});
      var built = createServer(store);

      return store.revokeFamily(revoked.familyId)
        .then(function() {
          return built.server.authenticate(authenticateRequest(kept.accessToken), new Response({body: {}, headers: {}}));
        })
        .then(function(token) {
          token.familyId.should.equal('fam-two');
        })
        .then(function() {
          return built.server.token(refreshRequest(kept.refreshToken), new Response({body: {}, headers: {}}));
        })
        .then(function() {
          store.getFamilyState('fam-two').revoked.should.be.false;
        })
        .catch(should.fail);
    });
  });

  describe('audit trail', function() {
    it('should link the revocation action to every subsequent rejection for the family', function() {
      var store = createStore();
      var pair = store.issue({familyId: 'fam-audit', clientId: 'client', userId: 'user'});
      var built = createServer(store);

      return store.revokeFamily('fam-audit')
        .then(function() {
          return built.server.token(refreshRequest(pair.refreshToken), new Response({body: {}, headers: {}}));
        })
        .then(should.fail, function() {
          return built.server.authenticate(authenticateRequest(pair.accessToken), new Response({body: {}, headers: {}}));
        })
        .then(should.fail, function() {
          var trail = store.getAuditTrail('fam-audit');
          var actions = trail.map(function(entry) { return entry.action; });

          actions.should.containEql('issued');
          actions.should.containEql('revoked');
          actions.should.containEql('exchange_rejected');
          actions.should.containEql('access_rejected');

          var revokeIndex = actions.indexOf('revoked');

          actions.slice(revokeIndex + 1).forEach(function(action) {
            action.should.match(/_rejected$/);
          });

          for (var i = 1; i < trail.length; i += 1) {
            trail[i].prevEntryId.should.equal(trail[i - 1].entryId);
          }
        })
        .catch(should.fail);
    });
  });
});
