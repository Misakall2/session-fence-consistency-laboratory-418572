.. _token-fences:

=================
 Token families
=================

A *token family* is the chain of tokens derived from one another by refresh
token rotation: the initial access/refresh pair starts the family, and every
refresh exchange derives a new pair into the same family.

Revoking a family must fence **every** token in it - the tokens issued before
the revocation as well as any token a racing exchange is about to derive. The
``TokenFenceStore`` and ``FenceModelAdapter`` provided by *oauth2-server* make
that the default behaviour. They are optional: models that do not use them keep
working, because a token without a revocation marker is treated as live.

Why a single store
==================

A revocation marker kept in a second place (a separate revocation list, a
per-token boolean copied around, or a read-through cache of decisions) can drift
out of sync with the tokens it governs. That drift is exactly what lets a
revoked token be exchanged through another code path, or lets a stale cache hit
mask a revocation that has already committed.

The fence store therefore keeps three things in **one** place and reads them
freshly on every operation:

- the issued tokens;
- each family's monotonic ``fence`` and its revocation marker;
- the append-only audit trail, archived per family.

There is no cache of decisions anywhere in the subsystem.

The single decision point
=========================

``lib/utils/token-revocation.js`` holds the one judgement both paths use:

- the refresh exchange path (``RefreshTokenGrantType.getRefreshToken()``);
- the access token validation path
  (``AuthenticateHandler.validateAccessToken()``).

Both call ``readState()`` and report the same stable ``token_family_revoked``
reason, so an old token retried after a revocation and a freshly derived token
rejected by that revocation are indistinguishable to a caller.

``readState()`` fails closed: a missing record, a malformed marker, a throwing
getter, an explicitly unreadable marker, and a token issued under an older
family fence are all treated as revoked.

Concurrency
===========

All operations that touch one family are serialized behind a per-family FIFO
lock (``FamilyMutex``), so a revocation and an exchange are decided against the
same family state:

- a revocation that arrives first is committed first; the exchange that
  follows reads the revoked marker and loses;
- an exchange that arrives first completes, and the revocation that follows
  raises the fence - the token it produced is immediately stale;
- an exchange re-reads the marker at commit time, under the same lock, so a
  revocation landing between the check and the write still wins and no token
  is issued.

``revokeFamily()`` reads the family state back from the store after writing the
marker and returns that freshly-read value. A stale snapshot held by a caller
cannot mask or undo the committed revocation.

Audit trail
===========

``getAuditTrail(familyId)`` returns the entries archived for one family, in
append order. Each entry links to the previous entry of the same family
(``prevEntryId``), so the revocation action and every subsequent rejection are
replayable as one chain.

Usage
=====

::

  const OAuth2Server = require('oauth2-server');
  const TokenFenceStore = OAuth2Server.TokenFenceStore;
  const FenceModelAdapter = OAuth2Server.FenceModelAdapter;

  const store = new TokenFenceStore();
  const model = new FenceModelAdapter(store, {
    clients: {
      myClient: {id: 'myClient', clientSecret: 'secret', grants: ['refresh_token']}
    }
  });

  const oauth = new OAuth2Server({model: model});

  // Issue the first pair of a family (your own issuance path).
  const pair = store.issue({
    familyId: 'session-123',
    clientId: 'myClient',
    userId: 'user-1',
    scope: 'read'
  });

  // Revoke every token in the family. The returned state is read back from
  // the store after the marker was written.
  store.revokeFamily('session-123').then(function(state) {
    state.revoked.should.be.true; // (illustrative)
  });

If you already have your own storage, you do not need the store: return the
revocation markers described in the :ref:`model specification <Model#getAccessToken>`
from ``getAccessToken()`` and ``getRefreshToken()`` instead.
