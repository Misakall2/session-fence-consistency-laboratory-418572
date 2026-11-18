'use strict';

/**
 * Module dependencies.
 */

var should = require('should');
var tokenRevocation = require('../../../lib/utils/token-revocation');

/**
 * Test `tokenRevocation`.
 *
 * These tests pin down the one centralized revocation judgement that both the
 * refresh exchange path and the access token validation path rely on.
 */

describe('tokenRevocation', function() {
  describe('readState()', function() {
    it('should allow a plain token record with no revocation marker', function() {
      var state = tokenRevocation.readState({accessToken: 'foo'});

      state.revoked.should.be.false;
      should(state.reason).be.null;
    });

    it('should treat a missing token record as revoked', function() {
      tokenRevocation.readState().revoked.should.be.true;
      tokenRevocation.readState(null).revoked.should.be.true;
      tokenRevocation.readState('foo').revoked.should.be.true;
    });

    it('should treat a revoked token as revoked', function() {
      var state = tokenRevocation.readState({revoked: true});

      state.revoked.should.be.true;
      state.reason.should.equal('token_family_revoked');
    });

    it('should treat a revoked family as revoked', function() {
      var state = tokenRevocation.readState({familyRevoked: true});

      state.revoked.should.be.true;
      state.reason.should.equal('token_family_revoked');
    });

    it('should treat an attached revoked family record as revoked', function() {
      var state = tokenRevocation.readState({family: {revoked: true}});

      state.revoked.should.be.true;
      state.reason.should.equal('token_family_revoked');
    });

    it('should treat a token issued under an older family fence as revoked', function() {
      var state = tokenRevocation.readState({fenceAtIssuance: 0, familyFence: 1});

      state.revoked.should.be.true;
      state.reason.should.equal('token_family_revoked');
    });

    it('should allow a token issued under the current family fence', function() {
      tokenRevocation.readState({fenceAtIssuance: 2, familyFence: 2}).revoked.should.be.false;
    });

    it('should treat an explicitly unreadable marker as revoked', function() {
      var state = tokenRevocation.readState({revocationState: 'unreadable'});

      state.revoked.should.be.true;
      state.reason.should.equal('token_family_revoked');
    });

    it('should treat a throwing marker read as revoked', function() {
      var token = {};

      Object.defineProperty(token, 'revoked', {
        enumerable: true,
        get: function() {
          throw new Error('store unavailable');
        }
      });

      var state = tokenRevocation.readState(token);

      state.revoked.should.be.true;
      state.reason.should.equal('token_family_revoked');
    });

    it('should treat a throwing family read as revoked', function() {
      var token = {};

      Object.defineProperty(token, 'family', {
        enumerable: true,
        get: function() {
          throw new Error('store unavailable');
        }
      });

      tokenRevocation.readState(token).revoked.should.be.true;
    });

    it('should report one stable reason for every revocation cause', function() {
      var causes = [
        {revoked: true},
        {familyRevoked: true},
        {family: {revoked: true}},
        {fenceAtIssuance: 0, familyFence: 1},
        {revocationState: 'unreadable'}
      ];

      causes.forEach(function(token) {
        tokenRevocation.readState(token).reason.should.equal(tokenRevocation.REVOKED_REASON);
      });
    });
  });

  describe('isRevoked()', function() {
    it('should return true for a revoked marker', function() {
      tokenRevocation.isRevoked({revoked: true}).should.be.true;
    });

    it('should return false for a live marker', function() {
      tokenRevocation.isRevoked({revoked: false}).should.be.false;
    });
  });
});
