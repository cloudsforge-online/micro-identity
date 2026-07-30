/**
 * The one-shot migrator.
 *
 * A separate process, run as an init container or a Kubernetes Job, and **never** called from
 * `index.ts`. Three reasons, in increasing order of seriousness:
 *
 *   1. A slow migration would stall every service that waits on this one's health — and every
 *      service in the estate waits on this one, because nothing can verify a token without it.
 *   2. Two replicas booting together race on `pg_type`, one raises 23505 and crash-loops, which is
 *      why the estate cannot scale a service past one replica today.
 *   3. Migrating from inside the service means the service decides when the schema changes, so a
 *      rollback of the image is not a rollback of the database.
 *
 * Safe to run concurrently from N processes: `@cloudsforge/db` serialises them on an advisory lock
 * derived from the service name, and the losers observe an empty pending set.
 */

import postgres from 'postgres'
import { migrate, type Sql } from '@cloudsforge/db'
import { Logger } from '@cloudsforge/telemetry'
import { SERVICE, env } from './env.ts'
import { BASELINE_VERSION, MIGRATIONS } from './migrations.ts'

const log = new Logger({
  service: SERVICE,
  level: env.logLevel,
  version: env.version,
  env: env.env,
}).child({ step: 'migrate' })

// A tiny pool: the whole run happens on one reserved connection, and a wide pool here only makes a
// migration that has to wait for a lock hold more of the database's connection budget.
const sql = postgres(env.databaseUrl, { max: 2, onnotice: () => {} })

try {
  const result = await migrate(sql as unknown as Sql, MIGRATIONS, {
    service: SERVICE,
    baselineVersion: BASELINE_VERSION,
    onLog: (message, fields) => log.info(message, fields),
  })
  log.info('migrations complete', {
    from: result.alreadyAt,
    to: result.nowAt,
    applied: result.applied.map((a) => `${a.version}:${a.name}`),
  })
  await sql.end({ timeout: 5 })
  process.exit(0)
} catch (err) {
  // Exit non-zero and loudly. The deploy must stop here.
  //
  // Migration 10 is the one most likely to land here on a real database: it puts a unique index on
  // `lower(email)`, and two accounts differing only by case make it fail. That is deliberate — the
  // alternative is guessing which of two people's accounts to destroy. The operator resolves the
  // collision by hand and runs this again.
  log.fatal('migration failed', { err })
  await sql.end({ timeout: 5 }).catch(() => {})
  process.exit(1)
}
