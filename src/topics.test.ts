/**
 * The producer half of the bus contract.
 *
 * Every other check of this kind in the estate runs on the consumer side. This one runs on the
 * producer, and it is the check whose absence let `identity.mfa.changed`, `identity.session.revoked`
 * and the never-emitted `identity.user.registered` all ship at once.
 *
 * **The topics are read out of `src/`, not out of a constant.** That is the whole point. A test
 * that compared `EMITTED_TOPICS` with the registry would agree with itself forever while the emit
 * sites drifted underneath it — which is precisely the failure that happened. Reading the literals
 * back from the source means the thing being checked is the thing that runs.
 *
 * No database. This file is pure text and set arithmetic, so it runs in CI even when the
 * database-backed suite skips.
 */

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { TOPIC_NAMES, isRegisteredTopic, topicsProducedBy } from '@cloudsforge/contracts-events'
import {
  AWAITING_REGISTRATION,
  EMITTED_TOPICS,
  adoptedProposals,
  malformedProposals,
  undeclaredTopics,
  unemittedOwnedTopics,
  unreferencedEmitters,
} from './topics.ts'

const SRC = dirname(fileURLToPath(import.meta.url))

/** Every non-test source file, as text. The reachability check needs whole files, not lines. */
function sourceFiles(): ReadonlyArray<{ file: string; text: string }> {
  return readdirSync(SRC)
    .filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts') && f !== 'testsupport.ts')
    .map((file) => ({ file, text: readFileSync(join(SRC, file), 'utf8') }))
}

/**
 * Every topic literal that appears at an emit site in this service.
 *
 * `topic: '<name>'` is the shape `DomainEvent` forces, so matching it finds every emit and nothing
 * else. Test files are excluded — a fixture is allowed to name a topic that does not exist, and
 * several deliberately do, to prove the inbox refuses one.
 *
 * Comment lines are skipped, and that is load-bearing rather than tidy: `outbox.ts` carries a
 * worked `emit({ topic: 'identity.session.created' ... })` example in its header, and this file's
 * own header quotes the pattern it matches. Counting either as an emit site would mean the check
 * reports a topic that no code path can ever produce. Every continuation line of a JSDoc block
 * starts with `*`, which is what makes the cheap test sufficient here.
 */
function emittedInSource(): readonly string[] {
  const found = new Set<string>()
  for (const file of readdirSync(SRC)) {
    if (!file.endsWith('.ts') || file.endsWith('.test.ts') || file === 'testsupport.ts') continue
    for (const line of readFileSync(join(SRC, file), 'utf8').split('\n')) {
      const trimmed = line.trimStart()
      if (trimmed.startsWith('*') || trimmed.startsWith('//') || trimmed.startsWith('/*')) continue
      const match = /\btopic:\s*'([^']+)'/.exec(line)
      if (match?.[1]) found.add(match[1])
    }
  }
  return [...found].sort()
}

test('the source emits exactly the topics this service declares', () => {
  // Catches both halves of the drift: a literal at an emit site that EMITTED_TOPICS does not
  // list, and an entry in EMITTED_TOPICS that no emit site produces. The second half is what
  // stops the list being repaired by editing the list.
  assert.deepEqual(
    emittedInSource(),
    [...EMITTED_TOPICS].sort(),
    'src/ and EMITTED_TOPICS disagree about what this service puts on the bus',
  )
})

test('every topic identity emits is one the estate has a name for', () => {
  // The silently-dropped-fact direction. A topic no registry names is a topic no consumer can
  // classify, so the event is written, signed, delivered and discarded.
  assert.deepEqual(
    undeclaredTopics(emittedInSource()),
    [],
    'emitted, but in neither the registry nor AWAITING_REGISTRATION — decide which, then say so',
  )
})

test('every registry topic identity owns is actually emitted', () => {
  // The feature-that-can-never-fire direction. This is the one that fails silently in production:
  // consumers classify the topic, the code path renders it, and nothing ever arrives.
  assert.deepEqual(
    unemittedOwnedTopics(emittedInSource()),
    [],
    'the registry says identity produces these and no emit site does — the consumers of each are dead code',
  )
  // And the registry is being read rather than the check passing vacuously.
  assert.ok(topicsProducedBy('identity').length >= 5)
  assert.ok(TOPIC_NAMES.length >= 18)
})

test('every emitter is actually called by something', () => {
  // THE REACHABILITY DIRECTION, and the one the other three checks are blind to. They reconcile
  // topic NAMES; a name is present in src/ whether or not the code containing it can ever run.
  //
  // `emitSessionRevoked` was correct, spelled exactly as the registry spells it, and called by
  // nothing — so every check above passed while notify's critical rule on the topic could never
  // fire. Spelling a topic right proves nothing about whether it is ever produced.
  assert.deepEqual(
    unreferencedEmitters(sourceFiles()),
    [],
    'these functions emit and nothing calls them — every consumer downstream of them is dead code',
  )

  // And the scan is finding emitters at all rather than passing because it matched none.
  assert.ok(sourceFiles().length >= 10, 'the source scan found the service')
})

test('a pending proposal disappears once contracts adopts it', () => {
  // Without this the quarantine becomes a permanent allow-list: the topic gets registered, the
  // entry stays, and the next reader believes the topic is still unregistered.
  assert.deepEqual(
    adoptedProposals(),
    [],
    'the registry now names these — delete them from AWAITING_REGISTRATION',
  )
})

test('every pending proposal carries a spec that could be pasted into the registry', () => {
  assert.deepEqual(
    malformedProposals(),
    [],
    'a proposal needs a valid three-segment identity topic, a real ordering key, and a reason worth reading',
  )
})

test('the three topics that were wrong stay fixed', () => {
  const emitted = new Set(emittedInSource())

  // 1. The MFA split. `identity.mfa.changed` was one name over three different payload shapes;
  // the registry, notify, activity and analytics all say `removed`, and notify has carried an
  // `added` rule that could never fire.
  assert.ok(!emitted.has('identity.mfa.changed'), 'identity.mfa.changed is not a topic anyone reads')
  assert.ok(emitted.has('identity.mfa.removed'), 'the registered name for a factor being revoked')
  assert.ok(emitted.has('identity.mfa.added'), 'the other half, which notify has always expected')
  assert.equal(isRegisteredTopic('identity.mfa.removed'), true)
  // contracts has since adopted `added` too (contracts/packages/events/src/index.ts:291), so the
  // consumer rule notify has carried all along can finally fire.
  assert.equal(isRegisteredTopic('identity.mfa.added'), true)

  // 2. Session revocation is a real fact and stays emitted. It was carried as a proposal here while
  // micro-contracts belonged to another agent; that agent has now registered it, so the assertion
  // moves UP from "a proposal explains it" to "the shared registry names it" — and it must no
  // longer be in the quarantine, or `pendingProposalsNotYetRegistered` would fail.
  assert.ok(emitted.has('identity.session.revoked'))
  assert.ok(emitted.has('identity.session.created'))
  assert.equal(isRegisteredTopic('identity.session.revoked'), true)
  assert.ok(!Object.hasOwn(AWAITING_REGISTRATION, 'identity.session.revoked'))

  // 3. Registration. The registry and all three consumers named it; only the producer did not.
  assert.ok(emitted.has('identity.user.registered'), '"your account was created" starts here')
  assert.equal(isRegisteredTopic('identity.user.registered'), true)
})
