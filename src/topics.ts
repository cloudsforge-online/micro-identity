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
  // EMPTY, AND THAT IS THE QUARANTINE WORKING RATHER THAN A GAP.
  //
  // `identity.session.revoked` and `identity.mfa.added` were both described here because
  // micro-contracts was owned by another agent at the time. It has since adopted both —
  // contracts/packages/events/src/index.ts:263 and :291 — so `isRegisteredTopic` now answers true
  // for each, and the test that asserts every entry is GENUINELY absent from the registry failed
  // until they were deleted. That is the third property in the doc above doing exactly what it
  // promised: the quarantine empties itself rather than rotting into a permanent allow-list.
  //
  // Nothing else changes. Both topics stay in `EMITTED_TOPICS`; they are simply named by the shared
  // registry now instead of by a proposal here.
})

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
