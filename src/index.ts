/**
 * The composition root.
 *
 * Everything this service is made of is constructed here, once, in an order that is not arbitrary.
 * Each step carries the reason it must precede the next; the ordering is the substance of this file.
 *
 * What this file deliberately does NOT do: run migrations. That is `src/migrator.ts`, a separate
 * one-shot process — rule 7.
 *
 * **Identity has no JWKS probe, and that is the one place it departs from the template.** Every
 * other service adds a soft `httpProbe('identity-jwks', ...)` because it verifies against this
 * service's document. This service IS the issuer: it verifies its own tokens against its own table,
 * over the pool the Postgres probe already covers. Probing itself over a socket would make readiness
 * depend on the listener that readiness gates, which is a deadlock on a bad day and a lie on a good
 * one.
 *
 * Traces are exported by the OpenTelemetry SDK loaded ahead of this module —
 * `NODE_OPTIONS=--import @opentelemetry/auto-instrumentations-node/register` in the deploy, which
 * reads `OTEL_EXPORTER_OTLP_ENDPOINT` and friends from the environment itself. That is why no
 * `OTEL_*` variable appears in `src/env.ts`: the service does not read them, so under rule 9 it must
 * not declare them.
 */

import postgres from 'postgres'
import { assertSchemaAtLeast, type Sql as DbSql } from '@cloudsforge/db'
import { JobQueue, JobRunner, type Sql as JobsSql } from '@cloudsforge/jobs'
import { Lifecycle, installSignalHandlers, postgresProbe } from '@cloudsforge/lifecycle'
import { Logger, Metrics, registerHttpMetrics, registerJobMetrics } from '@cloudsforge/telemetry'
import { SERVICE, env } from './env.ts'
import { SCHEMA_VERSION } from './migrations.ts'
import { createServer, registerServiceMetrics } from './server.ts'
import { registerHandlers, rescheduleRecurring, seedRecurring } from './jobs.ts'
import { logKeyState } from './keys.ts'
import type { Db } from './outbox.ts'

// 1. Environment. Importing `./env.ts` validated it; a missing or placeholder secret has already
//    exited with a structured line naming the variable. Nothing below may run first, because every
//    step after this reads configuration and a half-built service that then exits is harder to
//    diagnose than one that never started.

// 2. Telemetry, before anything that can fail. A logger that exists before the pool means the
//    pool's failure is a structured, searchable, redacted line rather than a bare V8 stack the
//    collector drops.
const logger = new Logger({
  service: SERVICE,
  level: env.logLevel,
  version: env.version,
  env: env.env,
})
const metrics = registerServiceMetrics(registerJobMetrics(registerHttpMetrics(new Metrics())))
logger.info('starting', { version: env.version, schemaVersion: SCHEMA_VERSION, issuer: env.issuer })

// 3. The database pool. Opened before the schema assertion for the obvious reason that the
//    assertion is a query, and before the Lifecycle because the readiness probe closes over it.
const sql = postgres(env.databaseUrl, {
  max: env.databasePoolMax,
  // postgres.js writes notices to stderr as unstructured text by default, which is how a connection
  // string ends up in a log the collector cannot parse.
  onnotice: () => {},
})

// 4. Assert the schema. This does NOT migrate — the migrator job does, and it has already run by
//    the time a container starts. Failing here rather than serving is the point: a replica of the
//    new code answering requests against the old schema corrupts data quietly, whereas a container
//    that refuses to start is a deploy that visibly stops.
try {
  await assertSchemaAtLeast(sql as unknown as DbSql, SCHEMA_VERSION)
} catch (err) {
  logger.fatal('schema assertion failed', { err, required: SCHEMA_VERSION })
  await sql.end({ timeout: 5 }).catch(() => {})
  process.exit(1)
}

// 5. The signing key, before the socket opens.
//
//    Bootstrapping it here rather than lazily on the first sign-in means the twenty-second RSA
//    keypair generation on a cold database happens while the balancer still believes this replica
//    is starting, instead of inside somebody's login. It also puts the key state in the boot log,
//    which is the first thing anyone reads when the estate starts rejecting tokens.
try {
  await logKeyState(sql as unknown as Db, logger)
} catch (err) {
  // Fatal, and it has to be. A service that cannot read or create a signing key cannot mint a
  // token, so every route that matters would answer 500 — and it would do so while reporting ready.
  logger.fatal('could not establish a signing key', { err })
  await sql.end({ timeout: 5 }).catch(() => {})
  process.exit(1)
}

// 6. The Lifecycle and its probes, before the routes, because `/readyz` is a route and it needs
//    something to report. The service is `starting` from here until `markReady()`, so a balancer
//    that probes during boot is told the truth rather than a static `{ok:true}`.
const lifecycle = new Lifecycle({
  // Must exceed one load-balancer probe interval, or the balancer is still sending traffic when the
  // process stops accepting it.
  drainDelayMs: 5_000,
  drainTimeoutMs: 25_000,
  onStateChange: (state) => logger.info('lifecycle state', { state }),
})

lifecycle.addProbe(
  postgresProbe('postgres', (signal) =>
    // The probe deadline is enforced by the Lifecycle's AbortSignal, but a driver that ignores the
    // signal would hang `/readyz` for ever. Racing the signal here is what turns "the database is
    // not answering" into a fail rather than a hung readiness endpoint.
    //
    // HARD, not soft. Every route on this service reads or writes Postgres — a replica that cannot
    // reach it cannot verify a token, let alone mint one, so there is nothing left to serve.
    Promise.race([
      sql`select 1`,
      new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(new Error('probe aborted')), { once: true })
      }),
    ]),
  ),
)

// 7. Routes. Constructed after the Lifecycle so the health handlers report real state, and after the
//    pool so nothing is a lazily-connected surprise on the first request.
const server = createServer({
  lifecycle,
  logger,
  metrics,
  sql: sql as unknown as Db,
  deletionGraceDays: env.deletionGraceDays,
  // `null` on any deployment without a Turnstile account, which is every developer machine and
  // every micro network — `parseTurnstile` refuses the half-configured middle, so this is either
  // the whole feature or none of it. `turnstileFetch` is left unset: the global `fetch` is the
  // right one everywhere except the suite, which injects its own.
  turnstile: env.turnstile,
  // Queue depth is sampled at scrape time rather than on a timer. There is no `setInterval` in this
  // repository, and CI greps for one — rule 8.
  beforeScrape: async () => {
    const stats = await queue.stats()
    metrics.set('jobs_pending', stats.pending)
    metrics.set('jobs_overdue', stats.overdue)
  },
})

// 8. The job runner, started before `listen()`. Background work is claimed under a lease, so a
//    replica that is draining stops claiming before it stops serving — `shouldClaim` is wired to the
//    Lifecycle for exactly that.
const queue = new JobQueue(sql as unknown as JobsSql, { owner: env.instanceId })
const reschedule = rescheduleRecurring(queue, logger)
const runner = new JobRunner({
  queue,
  concurrency: 4,
  pollMs: 1_000,
  shouldClaim: () => lifecycle.claimingJobs,
  onEvent: (event) => {
    if (event.kind) {
      if (event.type === 'claimed') metrics.increment('jobs_claimed_total', { kind: event.kind })
      if (event.type === 'completed') metrics.increment('jobs_completed_total', { kind: event.kind })
      if (event.type === 'failed') metrics.increment('jobs_failed_total', { kind: event.kind })
      if (event.type === 'dead') metrics.increment('jobs_dead_total', { kind: event.kind })
      if (event.durationMs !== undefined) {
        metrics.observe('jobs_duration_ms', event.durationMs, { kind: event.kind })
      }
    }
    if (event.type === 'failed' || event.type === 'dead' || event.type === 'error') {
      logger.error('job failure', { ...event })
    }
    reschedule(event)
  },
})

registerHandlers(runner, {
  sql: sql as unknown as Db,
  logger,
  signingSecret: env.outboxSigningSecret,
  deletionGraceDays: env.deletionGraceDays,
})
await seedRecurring(queue)
runner.start()

// 9. Listen. Last of the construction steps, because a socket that accepts before its dependencies
//    exist is a socket that answers 500.
await new Promise<void>((resolve, reject) => {
  server.once('error', reject)
  server.listen(env.port, () => resolve())
})
logger.info('listening', { port: env.port })

// 10. Ready. Only now: the state moves `starting → ready`, `/readyz` starts answering 200, and the
//     balancer is allowed to send traffic. Flipping this before `listen()` would advertise a replica
//     that has no socket.
lifecycle.markReady()

// 11. Signal handlers, last of all. Installing them earlier means a SIGTERM arriving mid-boot drains
//     a service that was never ready, and the drain races the construction above. Hooks run in
//     reverse registration order, so the server closes first, then the runner stops claiming and
//     drains, then the pool closes with nothing left to use it.
lifecycle.onShutdown(async () => {
  await sql.end({ timeout: 5 })
  logger.info('database pool closed')
})
lifecycle.onShutdown(async () => {
  const clean = await runner.stop(20_000)
  logger.info('job runner stopped', { clean })
})
lifecycle.onShutdown(
  () =>
    new Promise<void>((resolve) => {
      server.close(() => resolve())
      // Idle keep-alive sockets hold the server open past the drain budget. Closing them is what
      // makes `server.close()` a bounded operation rather than a wait on the slowest client.
      server.closeIdleConnections()
    }),
)

installSignalHandlers(lifecycle)
