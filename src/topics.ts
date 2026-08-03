/**
 * What identity puts on the bus, and the two-sided agreement with the shared registry.
 *
 * ## The defect this file exists to close
 *
 * Every consumer in the estate is already pinned to `@cloudsforge/contracts-events`. `activity`
 * declares its table `satisfies Readonly<Record<TopicName, TopicClassifier>>`, so a registry topic
 * it has not classified fails to compile. `notify` asserts `unmappedRegistryTopics()` is empty, so
 * a registry topic it has no rule for fails its suite.
 *
 * **The producer was pinned to nothing at all.** `DomainEvent.topic` was `string`, so identity
 * could emit any name it liked and nothing anywhere would notice. It did, and three facts were
 * lost for the whole life of the service:
 *
 *   - `identity.mfa.changed` was emitted; the registry, `notify`, `activity` and `analytics` all
 *     say `identity.mfa.removed`. Every MFA change was delivered to a topic no consumer classifies
 *     and dropped on the floor.
 *   - `identity.session.revoked` was emitted and is in no registry, so no consumer can classify it.
 *   - `identity.user.registered` is in the registry and all three consumers classify it, and
 *     identity never emitted it. "Your account was created" could not appear in anyone's feed,
 *     because the fact never left this service.
 *
 * A rename alone would fix the three names and leave the hole open for the fourth. What actually
 * closes it is that the producer and the registry must now agree **in both directions**, checked
 * two ways:
 *
 *   1. **At compile time.** `Emit` takes `IdentityTopic`, not `string`. A misspelled or invented
 *      topic is a type error, which is `pnpm typecheck` in CI, which is the build.
 *   2. **At test time, against the source rather than against this list.** `topics.test.ts` reads
 *      every `topic: '...'` literal out of `src/` and compares that set with the registry. A
 *      constant that claims a topic no emit site emits fails, and an emit site whose topic is in no
 *      registry fails. The list below cannot lie about the code, because the code is what is read.
 *
 * ## Why the emit sites still spell the string out
 *
 * They could reference a constant. They deliberately do not: `grep -rn 'identity.mfa.removed'`
 * across the estate is how a topic's producer and its consumers are found, and that grep is worth
 * more than the one-fewer-place-to-edit that a constant would buy. The union type is what stops the
 * literal being wrong; the literal is what keeps it findable.
 */

import {
  TOPICS,
  isRegisteredTopic,
  isValidTopicName,
  topicsProducedBy,
  type TopicName,
  type TopicSpec,
} from '@cloudsforge/contracts-events'

/**
 * Every topic identity emits.
 *
 * Membership is not a decision taken here — it is the union of what the registry says identity
 * produces and what `AWAITING_REGISTRATION` below records as proposed. The test asserts exactly
 * that, so this array cannot quietly gain an entry that neither justifies.
 */
export const EMITTED_TOPICS = Object.freeze([
  'identity.user.registered',
  'identity.user.deleted',
  'identity.session.created',
  'identity.session.revoked',
  'identity.device.added',
  'identity.mfa.added',
  'identity.mfa.removed',
  'identity.role.changed',
] as const)

/** The only strings `emit` will accept. Anything else is a compile error at the call site. */
export type IdentityTopic = (typeof EMITTED_TOPICS)[number]

export interface ProposedTopic {
  /** Why the fact belongs on the bus at all. Read by a human reviewing the contracts change. */
  readonly reason: string
  /** The entry to add to `TOPICS` in `@cloudsforge/contracts-events`, verbatim. */
  readonly spec: TopicSpec
}

/**
 * Topics identity emits that the shared registry does not yet name.
 *
 * This is a quarantine, not an exemption, and it has three properties that keep it honest:
 *
 *   - An entry must carry the exact `TopicSpec` it is asking for, so adopting it into
 *     `contracts/packages/events/src/index.ts` is a copy rather than a fresh design.
 *   - The test asserts every entry is **genuinely absent** from the registry. The moment contracts
 *     registers one, this file fails until the entry is deleted — so the quarantine empties itself
 *     rather than rotting into a permanent allow-list.
 *   - An emit site whose topic is in neither the registry nor here fails the test. Adding a topic
 *     still costs a decision; it just does not cost a release of `contracts` to make it visible.
 *
 * `micro-contracts` is owned by another agent at the time of writing, which is why these two are
 * described here instead of registered there.
 */
export const AWAITING_REGISTRATION: Readonly<Record<string, ProposedTopic>> = Object.freeze({
  // `identity.session.revoked` and `identity.mfa.added` were both described here because
  // micro-contracts was owned by another agent at the time. It has since adopted both —
  // contracts/packages/events/src/index.ts:263 and :291 — so `isRegisteredTopic` now answers true
  // for each, and the test that asserts every entry is GENUINELY absent from the registry failed
  // until they were deleted. That is the third property in the doc above doing exactly what it
  // promised: the quarantine empties itself rather than rotting into a permanent allow-list.
  'identity.role.changed': {
    reason:
      "A platform role was granted or withdrawn — the single most consequential write in the estate, and until migration 12 the only one with no trail at all. SD-15's Identity row asks for it and admin-api's operator log is fed by the bus (admin-api/src/server.ts:510, the audit mirror), so a promotion that never reaches a topic is a promotion the estate audit of record cannot show. Every event carries the approval id, which is two operators' signatures out of admin-api's four-eyes queue; the bootstrap grant is the one promotion that predates any queue and is emitted by nothing, because it is written by a human against the database before this service is trusted to act.",
    spec: {
      producer: 'identity',
      payloadType: 'PlatformRolesChanged',
      version: '1.0',
      // The person whose authority changed, not the approval — `activity` reads the owner straight
      // off the key for identity topics, and ordering is per key, so two changes to one account
      // must be ordered with respect to each other.
      keyedBy: 'user_id',
      description:
        "A user's platform roles changed, carrying the roles gained and lost and the approval id that authorised them.",
    },
  },
})

/**
 * Exported functions that emit, and that nothing calls.
 *
 * ## The hole this closes, which the checks above could not see
 *
 * Everything else in this file reconciles topic NAMES: the literals in `src/` against the registry,
 * in both directions. That is a check on spelling and on membership, and it is blind to the one
 * question that decides whether a fact ever reaches the bus — **is the code containing that literal
 * ever executed?**
 *
 * It was blind to it in production. `emitSessionRevoked` was written, correct, and called by
 * nothing: `revokeSession` and `revokeAllSessions` updated the session rows and emitted nothing at
 * all. Every check above passed, because the literal `identity.session.revoked` was present in
 * `src/` exactly as the registry spells it. Meanwhile `micro-notify` had landed a **critical** rule
 * on that topic — the one that tells a user their session was killed by a security event rather
 * than by their own sign-out — and it could never fire. A topic whose producer is unreachable is
 * indistinguishable, from the registry's point of view, from one that works.
 *
 * That is the same class of defect as `identity.user.registered`, which the registry named and all
 * three consumers classified while the producer never emitted it. The difference is only that this
 * one had an emitter, so a name-based check saw what it expected to see.
 *
 * ## What "reachable" means here, and what it deliberately does not
 *
 * An exported function whose body contains a `topic: '...'` literal must be referenced by name
 * somewhere in `src/` other than its own declaration. That is a cheap, purely syntactic proxy for
 * reachability and it is honest about being one:
 *
 *   - It catches the whole of the defect that actually happened — an emitter nothing calls.
 *   - It does NOT prove the caller is itself reachable, or that the branch containing the call is
 *     ever taken. A chain of dead functions calling each other would satisfy it.
 *
 * A real answer needs a call graph from the type checker, which is a great deal of machinery for a
 * service with eight emit sites. This is the ninety-percent check that costs twenty lines, and the
 * limitation is written down here rather than left for someone to discover.
 */
export function unreferencedEmitters(
  sources: ReadonlyArray<{ readonly file: string; readonly text: string }>,
): readonly string[] {
  const declaration = /^export\s+(?:async\s+)?function\s+(\w+)/gm
  const emitters: { name: string; file: string }[] = []

  /*
   * COMMENTS ARE STRIPPED FIRST, and finding out why is instructive: the first version of this
   * check passed while `emitSessionRevoked` still had no caller, because the paragraphs above
   * mention it by name and a prose mention counted as a reference. A guard that a comment about
   * the guard can satisfy is worse than no guard, because it reads as a proof.
   *
   * The same line-shape rule `emittedInSource` uses in topics.test.ts, for the same reason.
   */
  const code = sources.map((source) => ({
    file: source.file,
    text: source.text
      .split('\n')
      .map((line) => {
        const trimmed = line.trimStart()
        if (trimmed.startsWith('*') || trimmed.startsWith('//') || trimmed.startsWith('/*')) return ''
        return line.replace(/\/\/.*$/, '')
      })
      .join('\n'),
  }))

  for (const source of code) {
    for (const match of source.text.matchAll(declaration)) {
      const name = match[1]
      if (!name || match.index === undefined) continue
      // The body runs to the next closing brace in column zero, which is where this codebase puts
      // the end of every top-level function.
      const rest = source.text.slice(match.index)
      const end = rest.search(/\n\}/)
      const body = end === -1 ? rest : rest.slice(0, end)
      if (/\btopic:\s*'/.test(body)) emitters.push({ name, file: source.file })
    }
  }

  const unreferenced: string[] = []
  for (const emitter of emitters) {
    let references = 0
    for (const source of code) {
      for (const hit of source.text.matchAll(new RegExp(`\\b${emitter.name}\\b`, 'g'))) {
        // Its own `export function <name>` is not a call site. Every other mention — an import, a
        // call, a re-export — is something that could lead here.
        const preceding = source.text.slice(Math.max(0, hit.index - 40), hit.index)
        if (source.file === emitter.file && /function\s+$/.test(preceding)) continue
        references += 1
      }
    }
    if (references === 0) unreferenced.push(`${emitter.name} (${emitter.file})`)
  }
  return unreferenced.sort()
}

/** Topics identity emits that no registry names and no proposal explains — always a defect. */
export function undeclaredTopics(emitted: readonly string[]): readonly string[] {
  return emitted
    .filter((topic) => !isRegisteredTopic(topic) && !Object.hasOwn(AWAITING_REGISTRATION, topic))
    .sort()
}

/**
 * Registry topics identity owns and never emits — a feature that can never fire.
 *
 * This is the direction that is easiest to miss, because nothing breaks and nothing logs. It is
 * how `identity.user.registered` stayed unemitted while three services classified it.
 */
export function unemittedOwnedTopics(emitted: readonly string[]): readonly TopicName[] {
  const seen = new Set(emitted)
  return topicsProducedBy('identity').filter((topic) => !seen.has(topic))
}

/** Proposals the registry has since adopted. Non-empty means delete the entry from the quarantine. */
export function adoptedProposals(): readonly string[] {
  return Object.keys(AWAITING_REGISTRATION).filter(isRegisteredTopic).sort()
}

/** A proposal must describe a topic that could actually be registered. */
export function malformedProposals(): readonly string[] {
  return Object.keys(AWAITING_REGISTRATION)
    .filter((topic) => {
      const proposed = AWAITING_REGISTRATION[topic]
      if (!proposed) return true
      return (
        !isValidTopicName(topic) ||
        proposed.spec.producer !== 'identity' ||
        !topic.startsWith('identity.') ||
        proposed.spec.keyedBy === '' ||
        proposed.reason.length < 80
      )
    })
    .sort()
}

/** What the relay iterates: everything identity emits, registered or not. */
export function emittedTopicNames(): readonly string[] {
  return [...EMITTED_TOPICS]
}

/** The registry's own description, for the topics that have one. Null while a proposal is pending. */
export function describeTopic(topic: IdentityTopic): string | null {
  return isRegisteredTopic(topic) ? TOPICS[topic].description : null
}
