'use strict';

/**
 * Token-family fence subsystem.
 *
 * Provides a single authoritative store for tokens, token families, their
 * revocation markers and the audit trail, plus a model adapter that routes
 * both the refresh exchange path and the access token validation path through
 * that one store's centralized revocation decision.
 */

exports.TokenFenceStore = require('./token-fence-store');
exports.TokenFenceError = require('./token-fence-error');
exports.FamilyMutex = require('./family-mutex');
exports.FenceModelAdapter = require('./fence-model-adapter');
