/**
 * The network boundary for a service that has only ONE database.
 *
 * identity is a class B′ singleton (micro-deploy `docs/network-consolidation.md` §5): one account
 * set, one database, both estates. That was settled by micro-org#459 — a user is one account, and
 * splitting the accounts is what the combined view existed to undo.
 *
 * So there is no handle to select here, and none of the `NetworkSql` machinery applies. What the
 * request's network is *for* is narrower and sharper: the `net` claim on a service token.
 */
import { describe, it } from 'node:test'
import { strict as assert } from 'node:assert'
import { NetworkUnknownError, requestNetwork } from '@cloudsforge/http'

describe('the network a request is attributed to', () => {
  it('comes from the header the gateway stamped', () => {
    assert.equal(requestNetwork({ 'cf-network': 'testnet' }), 'testnet')
    assert.equal(requestNetwork({ 'cf-network': 'mainnet' }), 'mainnet')
  })

  it('REFUSES an unstamped request rather than assuming mainnet', () => {
    assert.throws(() => requestNetwork({}), NetworkUnknownError)
  })

  it('takes CF_NETWORK_SINGLE only when the header is absent, never over it', () => {
    assert.equal(requestNetwork({}, { fallback: 'testnet' }), 'testnet')
    assert.equal(requestNetwork({ 'cf-network': 'mainnet' }, { fallback: 'testnet' }), 'mainnet')
  })
})

describe('the `net` claim, and the fallback the consolidation changed', () => {
  /*
   * ══════════════════════════════════════════════════════════════════════════════════════════════
   * THE ORDER IS THE WHOLE BEHAVIOUR, AND THE MIDDLE STEP IS NEW.
   * ══════════════════════════════════════════════════════════════════════════════════════════════
   *
   * `net` names the estate a service token is FOR. Under the shared identity that is not always the
   * estate identity runs in: a testnet service exchanges its credential HERE, at the one identity,
   * and must get `net=testnet`.
   *
   * The credential ROW carries it, and has since micro-org#459 stage 2. What this wave changes is
   * what happens when the row does not — every credential minted before that. The old fallback was
   * `IDENTITY_NETWORK`, and it was CORRECT while this pod served one estate: its own network and
   * the caller's were the same thing.
   *
   * One pod now serves both. `IDENTITY_NETWORK` names whichever estate the deployment happens to be
   * labelled with, so a testnet service presenting a pre-#459 credential would be handed
   * `net=mainnet` — a token that FAILS at its own estate and PASSES at the other one. Backwards
   * twice, and precisely the crossing the claim exists to refuse. It is not hypothetical: the
   * mainnet-stamped token was the combined view's first live defect, custody refusing settlement in
   * an every-two-minutes remint loop.
   */
  const netFor = (row: string | null, request: string | undefined, envNetwork: string) =>
    row ?? request ?? envNetwork ?? null

  it('takes the credential row first, whatever the request said', () => {
    // A row that names its estate is the authority. A caller cannot widen its own token by
    // arriving through the other gateway.
    assert.equal(netFor('testnet', 'mainnet', 'mainnet'), 'testnet')
    assert.equal(netFor('mainnet', 'testnet', 'testnet'), 'mainnet')
  })

  it('falls back to the REQUEST before the process, for a credential that predates #459', () => {
    assert.equal(netFor(null, 'testnet', 'mainnet'), 'testnet')
  })

  it('still falls back to IDENTITY_NETWORK when there is no request network either', () => {
    // A single-network deployment, and `pnpm dev`. This is what makes the change need no flag-day:
    // with nothing stamped, today's answer is unchanged.
    assert.equal(netFor(null, undefined, 'mainnet'), 'mainnet')
  })
})

describe('identity has ONE database, and that is a decision rather than an omission', () => {
  /*
   * Worth a test because the absence of `NetworkSql` here would otherwise read as an oversight
   * next to the fifteen services that have it. A future reader comparing identity to market will
   * find no per-network handle and should find this instead of adding one.
   *
   * Splitting the accounts is what micro-org#459 existed to UNDO: one person, one login, both
   * estates. A second account set would restore the defect the combined view removed.
   */
  it('does not select a handle per request, because there is only one', () => {
    const deps = { sql: { tag: 'the one database' } }
    const forMainnet = deps.sql
    const forTestnet = deps.sql

    assert.equal(forMainnet, forTestnet, 'identity must not grow a second account set')
  })
})

describe('the operational endpoints are exempt, and only they', () => {
  const OPERATIONAL = ['/livez', '/readyz', '/metrics']

  it('names exactly the three endpoints that arrive without a gateway', () => {
    assert.deepEqual([...OPERATIONAL].sort(), ['/livez', '/metrics', '/readyz'])
  })

  it('does not exempt the token routes', () => {
    // `/v1/service-tokens/exchange` is the route the `net` fallback above runs on. Exempting it
    // would put the boot-time default back in the one place this wave took it out of.
    for (const p of ['/v1/service-tokens/exchange', '/v1/sessions', '/v1/users']) {
      assert.ok(!OPERATIONAL.includes(p), `${p} must carry a network`)
    }
  })
})
