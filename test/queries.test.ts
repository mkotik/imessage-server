/**
 * Read-side behaviour backing the MCP tools, including the motivating question:
 * "What did Alex say about Yosemite last month?"
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { applyBatch } from '../src/repo/messages.js';
import * as q from '../src/repo/queries.js';
import { sandbox, makeBatch, makeMessage, makeAttachment } from './helpers.js';

const JULY = (day: number, hour = 12): string => new Date(Date.UTC(2026, 6, day, hour)).toISOString();
const JUNE = (day: number): string => new Date(Date.UTC(2026, 5, day, 12)).toISOString();

function seed(db: ReturnType<typeof sandbox>['db']): void {
  const alex = {
    chatGuid: 'chat-alex',
    chatRowId: 1,
    identifier: '+15550001111',
    isGroup: false,
    displayName: 'Alex Rivera',
    service: 'iMessage',
  };
  const group = {
    chatGuid: 'chat-hikers',
    chatRowId: 2,
    identifier: 'chat9911',
    isGroup: true,
    displayName: 'Hiking Crew',
    service: 'iMessage',
  };

  const msgs = [
    makeMessage({ chat: alex, sentAt: JULY(3), text: 'Booked the Yosemite permits for us' }),
    makeMessage({ chat: alex, sentAt: JULY(4), text: 'Half Dome cables open on the 15th' }),
    makeMessage({
      chat: alex,
      sentAt: JULY(5),
      text: 'Sent you my packing list',
      isFromMe: true,
      sender: { handle: undefined, displayName: undefined, isMe: true },
    }),
    makeMessage({ chat: alex, sentAt: JUNE(2), text: 'Yosemite is booked out in June apparently' }),
    makeMessage({
      chat: group,
      sentAt: JULY(6),
      text: 'Anyone driving up to Yosemite Friday?',
      sender: { handle: '+15550002222', displayName: 'Priya Shah', isMe: false },
      participants: [
        { handle: '+15550001111', displayName: 'Alex Rivera' },
        { handle: '+15550002222', displayName: 'Priya Shah' },
      ],
    }),
    makeMessage({ chat: alex, sentAt: JULY(7), text: 'Dinner tomorrow?' }),
  ];
  applyBatch(db, makeBatch(msgs), msgs, 0);
}

test('free-text search finds messages by content', () => {
  const s = sandbox();
  try {
    seed(s.db);
    const r = q.searchMessages(s.db, { query: 'Yosemite', limit: 50 });
    assert.equal(r.length, 3);
    assert.ok(r.every((m) => /yosemite/i.test(m.text ?? '')));
  } finally {
    s.cleanup();
  }
});

test('"what did Alex say about Yosemite last month" resolves precisely', () => {
  const s = sandbox();
  try {
    seed(s.db);
    const r = q.searchMessages(s.db, {
      query: 'Yosemite',
      contact: 'Alex',
      after: Date.UTC(2026, 6, 1),
      before: Date.UTC(2026, 6, 31),
      fromMe: false,
      limit: 50,
    });
    const texts = r.map((m) => m.text);
    assert.ok(texts.includes('Booked the Yosemite permits for us'));
    assert.ok(!texts.includes('Yosemite is booked out in June apparently'), 'June message leaked into a July window');
    assert.ok(r.every((m) => !m.isFromMe));
  } finally {
    s.cleanup();
  }
});

test('search results are newest first and respect the limit', () => {
  const s = sandbox();
  try {
    seed(s.db);
    const r = q.searchMessages(s.db, { limit: 3 });
    assert.equal(r.length, 3);
    const times = r.map((m) => Date.parse(m.sentAt!));
    assert.deepEqual(times, [...times].sort((a, b) => b - a));
  } finally {
    s.cleanup();
  }
});

test('FTS query building neutralises FTS5 syntax', () => {
  assert.equal(q.toFtsQuery('yosemite permits'), '"yosemite" AND "permits"');
  assert.equal(q.toFtsQuery('NEAR( a b'), '"NEAR(" AND "a" AND "b"');
  assert.equal(q.toFtsQuery('"quoted"'), '"quoted"');
  assert.equal(q.toFtsQuery('   '), '""');
  assert.ok(q.toFtsQuery('x '.repeat(100)).split(' AND ').length <= 20);
});

test('a hostile search string does not throw', () => {
  const s = sandbox();
  try {
    seed(s.db);
    for (const bad of ['"', 'a OR', 'NEAR(', '*', 'x AND AND y', "'; DROP TABLE messages; --"]) {
      assert.doesNotThrow(() => q.searchMessages(s.db, { query: bad, limit: 5 }), `threw on ${bad}`);
    }
    assert.equal((s.db.prepare('SELECT count(*) n FROM messages').get() as { n: number }).n, 6);
  } finally {
    s.cleanup();
  }
});

test('date filtering alone works with no query', () => {
  const s = sandbox();
  try {
    seed(s.db);
    const r = q.searchMessages(s.db, { after: Date.UTC(2026, 6, 5), limit: 50 });
    assert.equal(r.length, 3);
  } finally {
    s.cleanup();
  }
});

test('conversation retrieval is chronological and paginates backwards', () => {
  const s = sandbox();
  try {
    seed(s.db);
    const page1 = q.conversation(s.db, 'chat-alex', { limit: 2 });
    assert.equal(page1.length, 2);
    assert.ok(Date.parse(page1[0]!.sentAt!) < Date.parse(page1[1]!.sentAt!), 'not chronological');

    const page2 = q.conversation(s.db, 'chat-alex', { before: Date.parse(page1[0]!.sentAt!) - 1, limit: 2 });
    assert.ok(page2.every((m) => Date.parse(m.sentAt!) < Date.parse(page1[0]!.sentAt!)));
  } finally {
    s.cleanup();
  }
});

test('conversations resolve by name, handle, and guid', () => {
  const s = sandbox();
  try {
    seed(s.db);
    assert.ok(q.resolveChats(s.db, 'chat-alex').some((c) => c.chatGuid === 'chat-alex'));
    assert.ok(q.resolveChats(s.db, '+15550001111').length > 0);
    assert.ok(q.resolveChats(s.db, 'Hiking').some((c) => c.chatGuid === 'chat-hikers'));
    assert.equal(q.resolveChats(s.db, 'nobody-by-that-name').length, 0);
  } finally {
    s.cleanup();
  }
});

test('a group conversation reports its participants', () => {
  const s = sandbox();
  try {
    seed(s.db);
    const group = q.resolveChats(s.db, 'chat-hikers')[0]!;
    assert.equal(group.isGroup, true);
    assert.ok(group.participants.length >= 2);
  } finally {
    s.cleanup();
  }
});

test('get_messages_since pages forward by sent time and by ingestion time', () => {
  const s = sandbox();
  try {
    seed(s.db);
    const bySent = q.messagesSince(s.db, Date.UTC(2026, 6, 1), 100, false);
    assert.equal(bySent.length, 5);
    const times = bySent.map((m) => Date.parse(m.sentAt!));
    assert.deepEqual(times, [...times].sort((a, b) => a - b), 'not oldest-first');

    // Everything was ingested just now, so an ingestion-time window catches all 6.
    assert.equal(q.messagesSince(s.db, Date.now() - 60_000, 100, true).length, 6);
  } finally {
    s.cleanup();
  }
});

test('attachment metadata is attached to results but bytes are not', () => {
  const s = sandbox();
  try {
    const m = makeMessage({ text: 'here is the photo' });
    m.attachments = [makeAttachment(m.messageGuid, { filename: 'sunset.jpg' })];
    applyBatch(s.db, makeBatch([m]), [m], 0);

    const r = q.searchMessages(s.db, { query: 'photo', limit: 10 });
    q.attachAttachments(s.db, r);
    assert.equal(r[0]!.attachments?.length, 1);
    assert.equal(r[0]!.attachments![0]!.filename, 'sunset.jpg');
    assert.ok(!('data' in r[0]!.attachments![0]!));
  } finally {
    s.cleanup();
  }
});

test('stats summarise the archive', () => {
  const s = sandbox();
  try {
    seed(s.db);
    const st = q.stats(s.db);
    assert.equal(st.messages, 6);
    assert.equal(st.chats, 2);
    assert.ok(typeof st.earliest === 'string');
  } finally {
    s.cleanup();
  }
});
