// Counterparty-verifiable grant tokens (D-DC3, docs/grant-token-design.md). A broker-local grant id is
// SYMMETRIC — only the broker that minted it can check it. A grant TOKEN is the vault's Ed25519
// identity signature over the grant's claims, so ANY counterparty (the app itself, a payment processor
// receiving a tier-3 borrow) can verify it against the vault's PINNED public key — no DEK, no broker
// round-trip. It reuses the audited attestation primitive (docs/vault-signing-design.md); no new
// crypto. This is exactly the custody-v1 proto `Grant`: `claims` = the canonical claim below, `proof` =
// the Ed25519 signature (upgraded from the "DEK-MAC now" placeholder the proto noted).

const te = (s) => new TextEncoder().encode(s);

/** The canonical, deterministic claim the vault signs and any verifier recomputes from a token's
 *  structured fields. Scopes are sorted; a fixed-key JSON layout means arbitrary `purpose` text cannot
 *  smuggle a delimiter or reorder fields. Bumped label ⇒ never collides with a tier-2 attestation. */
export function canonicalGrantClaim(g) {
  return JSON.stringify({
    v: 'freehold-grant-v1',
    grantId: String(g.grantId),
    appId: String(g.appId),
    tier: g.tier | 0,
    scopes: (g.scopes || []).slice().sort(),
    purpose: String(g.purpose || ''),
    issuedAt: g.issuedAt | 0,
    expiry: g.expiry | 0,
  });
}

/** Broker/vault side: mint a signed grant token bound to the app it is for. `vault` is the open vault
 *  (only it can sign with the DEK-derived identity key). `ttlSeconds` bounds validity. */
export async function issueGrantToken(vault, g, ttlSeconds = 3600) {
  const issuedAt = Math.floor(Date.now() / 1000);
  const expiry = issuedAt + Math.max(1, Math.floor(ttlSeconds));
  const grant = {
    grantId: g.grantId, appId: g.appId, tier: g.tier | 0,
    scopes: (g.scopes || []).slice(), purpose: g.purpose || '', issuedAt, expiry,
  };
  const claim = canonicalGrantClaim(grant);
  // audience binds the token to the (verified) app_id it was granted to.
  const attestation = await vault.attest(claim, { audience: te(g.appId), ttlSeconds });
  return { v: 1, ...grant, attestation };
}

/** Counterparty side: verify a grant token with ONLY the pinned vault public key + the pure
 *  `verifyAttestation` reference — no DEK, no broker. Checks, in order: the signed claim equals the
 *  claim recomputed from the presented fields (a valid signature cannot be paired with different
 *  claims), the requested `scope` is in the grant, the audience binds the app, the signer is the pinned
 *  vault key, the signature verifies, and it isn't expired. `deps.verifyAttestation` is the reference
 *  pure verify (a real remote party may use any Ed25519 lib on the documented canonical message). */
export async function verifyGrantToken(deps, token, expect = {}) {
  if (!token || token.v !== 1 || !token.attestation) return { ok: false, reason: 'not a v1 grant token' };
  const claim = canonicalGrantClaim(token);
  if (token.attestation.claim !== claim) return { ok: false, reason: 'claim does not match token fields (tampered)' };
  if (expect.scope != null && !(token.scopes || []).includes(expect.scope)) return { ok: false, reason: 'requested scope not in grant' };
  const r = await deps.verifyAttestation(token.attestation, {
    claim, audience: te(token.appId), publicKey: deps.vaultPublicKey, now: expect.now,
  });
  return r.ok
    ? { ok: true, grantId: token.grantId, appId: token.appId, scopes: token.scopes, tier: token.tier }
    : { ok: false, reason: r.reason };
}
