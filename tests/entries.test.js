const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const request = require('supertest');

let mongod;
let app;

async function signup(email) {
  const res = await request(app)
    .post('/api/auth/signup')
    .send({ name: 'User', email, password: 'longenough' });
  return { token: res.body.data.token, userId: res.body.data.user.id };
}

beforeAll(async () => {
  mongod = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mongod.getUri();
  process.env.JWT_SECRET = 'test-secret';
  app = require('../server');
  await new Promise((resolve, reject) => {
    mongoose.connection.once('open', resolve);
    mongoose.connection.once('error', reject);
  });
});

afterEach(async () => {
  await mongoose.connection.collection('users').deleteMany({});
  await mongoose.connection.collection('entries').deleteMany({});
});

afterAll(async () => {
  await mongoose.connection.close();
  await mongod.stop();
});

describe('auth guard on /api/entries', () => {
  it('rejects requests with no token', async () => {
    const res = await request(app).get('/api/entries?date=2026-07-18');
    expect(res.status).toBe(401);
  });

  it('rejects requests with a malformed token', async () => {
    const res = await request(app)
      .get('/api/entries?date=2026-07-18')
      .set('Authorization', 'Bearer not-a-real-token');
    expect(res.status).toBe(401);
  });
});

describe('GET /api/entries', () => {
  it('requires a valid date query param', async () => {
    const { token } = await signup('date@example.com');
    const res = await request(app)
      .get('/api/entries?date=not-a-date')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(400);
  });

  it('returns only the requesting user\'s entries for that date', async () => {
    const a = await signup('a@example.com');
    const b = await signup('b@example.com');
    await request(app)
      .post('/api/entries')
      .set('Authorization', `Bearer ${a.token}`)
      .send({ task: 'A task', type: 'task', date: '2026-07-18', mins: 30 });
    await request(app)
      .post('/api/entries')
      .set('Authorization', `Bearer ${b.token}`)
      .send({ task: 'B task', type: 'task', date: '2026-07-18', mins: 45 });

    const res = await request(app)
      .get('/api/entries?date=2026-07-18')
      .set('Authorization', `Bearer ${a.token}`);
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(1);
    expect(res.body.data[0].task).toBe('A task');
  });
});

describe('POST /api/entries', () => {
  it('rejects a missing task', async () => {
    const { token } = await signup('u1@example.com');
    const res = await request(app)
      .post('/api/entries')
      .set('Authorization', `Bearer ${token}`)
      .send({ type: 'task', date: '2026-07-18', mins: 30 });
    expect(res.status).toBe(400);
  });

  it('rejects an invalid type', async () => {
    const { token } = await signup('u2@example.com');
    const res = await request(app)
      .post('/api/entries')
      .set('Authorization', `Bearer ${token}`)
      .send({ task: 'Do a thing', type: 'not-a-type', date: '2026-07-18', mins: 30 });
    expect(res.status).toBe(400);
  });

  it('rejects a malformed date', async () => {
    const { token } = await signup('u3@example.com');
    const res = await request(app)
      .post('/api/entries')
      .set('Authorization', `Bearer ${token}`)
      .send({ task: 'Do a thing', type: 'task', date: '18-07-2026', mins: 30 });
    expect(res.status).toBe(400);
  });

  it('rejects mins below 1', async () => {
    const { token } = await signup('u4@example.com');
    const res = await request(app)
      .post('/api/entries')
      .set('Authorization', `Bearer ${token}`)
      .send({ task: 'Do a thing', type: 'task', date: '2026-07-18', mins: 0 });
    expect(res.status).toBe(400);
  });

  it.each(['deployment', 'planning', 'learning', 'support', 'mentoring', 'testing'])(
    'accepts the %s type',
    async (type) => {
      const { token } = await signup(`type-${type}@example.com`);
      const res = await request(app)
        .post('/api/entries')
        .set('Authorization', `Bearer ${token}`)
        .send({ task: `Doing ${type}`, type, date: '2026-07-18', mins: 15 });
      expect(res.status).toBe(201);
      expect(res.body.data.type).toBe(type);
    }
  );

  it('creates an entry scoped to the authenticated user, ignoring a spoofed userId', async () => {
    const a = await signup('spoof-a@example.com');
    const b = await signup('spoof-b@example.com');
    const res = await request(app)
      .post('/api/entries')
      .set('Authorization', `Bearer ${a.token}`)
      .send({ task: 'Sneaky', type: 'task', date: '2026-07-18', mins: 10, userId: b.userId });
    expect(res.status).toBe(201);
    expect(res.body.data.userId).toBe(a.userId);
  });
});

describe('PUT /api/entries/:id', () => {
  it('updates an entry owned by the user', async () => {
    const { token } = await signup('put1@example.com');
    const created = await request(app)
      .post('/api/entries')
      .set('Authorization', `Bearer ${token}`)
      .send({ task: 'Original', type: 'task', date: '2026-07-18', mins: 10 });

    const res = await request(app)
      .put(`/api/entries/${created.body.data._id}`)
      .set('Authorization', `Bearer ${token}`)
      .send({ task: 'Updated', mins: 20 });
    expect(res.status).toBe(200);
    expect(res.body.data.task).toBe('Updated');
    expect(res.body.data.mins).toBe(20);
  });

  it('rejects clearing the task to empty', async () => {
    const { token } = await signup('put2@example.com');
    const created = await request(app)
      .post('/api/entries')
      .set('Authorization', `Bearer ${token}`)
      .send({ task: 'Original', type: 'task', date: '2026-07-18', mins: 10 });

    const res = await request(app)
      .put(`/api/entries/${created.body.data._id}`)
      .set('Authorization', `Bearer ${token}`)
      .send({ task: '   ' });
    expect(res.status).toBe(400);
  });

  it('returns 404 when updating another user\'s entry', async () => {
    const owner = await signup('owner1@example.com');
    const stranger = await signup('stranger1@example.com');
    const created = await request(app)
      .post('/api/entries')
      .set('Authorization', `Bearer ${owner.token}`)
      .send({ task: 'Mine', type: 'task', date: '2026-07-18', mins: 10 });

    const res = await request(app)
      .put(`/api/entries/${created.body.data._id}`)
      .set('Authorization', `Bearer ${stranger.token}`)
      .send({ task: 'Hijacked' });
    expect(res.status).toBe(404);
  });

  it('returns 400 for a malformed id', async () => {
    const { token } = await signup('put3@example.com');
    const res = await request(app)
      .put('/api/entries/not-an-object-id')
      .set('Authorization', `Bearer ${token}`)
      .send({ task: 'Updated' });
    expect(res.status).toBe(400);
  });
});

describe('DELETE /api/entries/:id', () => {
  it('deletes an entry owned by the user', async () => {
    const { token } = await signup('del1@example.com');
    const created = await request(app)
      .post('/api/entries')
      .set('Authorization', `Bearer ${token}`)
      .send({ task: 'To delete', type: 'task', date: '2026-07-18', mins: 10 });

    const res = await request(app)
      .delete(`/api/entries/${created.body.data._id}`)
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.data.deleted).toBe(true);

    const followUp = await request(app)
      .get('/api/entries?date=2026-07-18')
      .set('Authorization', `Bearer ${token}`);
    expect(followUp.body.data).toHaveLength(0);
  });

  it('returns 404 when deleting another user\'s entry', async () => {
    const owner = await signup('owner2@example.com');
    const stranger = await signup('stranger2@example.com');
    const created = await request(app)
      .post('/api/entries')
      .set('Authorization', `Bearer ${owner.token}`)
      .send({ task: 'Mine', type: 'task', date: '2026-07-18', mins: 10 });

    const res = await request(app)
      .delete(`/api/entries/${created.body.data._id}`)
      .set('Authorization', `Bearer ${stranger.token}`);
    expect(res.status).toBe(404);
  });
});

describe('GET /api/entries/range', () => {
  it('requires from and to as valid dates', async () => {
    const { token } = await signup('range1@example.com');
    const res = await request(app)
      .get('/api/entries/range?from=2026-07-01')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(400);
  });

  it('returns only entries within the date bounds', async () => {
    const { token } = await signup('range2@example.com');
    const dates = ['2026-06-30', '2026-07-10', '2026-07-31'];
    for (const date of dates) {
      await request(app)
        .post('/api/entries')
        .set('Authorization', `Bearer ${token}`)
        .send({ task: `Task ${date}`, type: 'task', date, mins: 10 });
    }

    const res = await request(app)
      .get('/api/entries/range?from=2026-07-01&to=2026-07-31')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.data.map((e) => e.date)).toEqual(['2026-07-10', '2026-07-31']);
  });
});
