const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const request = require('supertest');

let mongod;
let app;

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
});

afterAll(async () => {
  await mongoose.connection.close();
  await mongod.stop();
});

describe('POST /api/auth/signup', () => {
  it('rejects a missing field', async () => {
    const res = await request(app)
      .post('/api/auth/signup')
      .send({ name: 'Ada', email: 'ada@example.com' });
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  it('rejects a password under 8 characters', async () => {
    const res = await request(app)
      .post('/api/auth/signup')
      .send({ name: 'Ada', email: 'ada@example.com', password: 'short' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/at least 8 characters/i);
  });

  it('creates a user and returns a token', async () => {
    const res = await request(app)
      .post('/api/auth/signup')
      .send({ name: 'Ada', email: 'ada@example.com', password: 'longenough' });
    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.data.token).toEqual(expect.any(String));
    expect(res.body.data.user).toMatchObject({ name: 'Ada', email: 'ada@example.com' });
    expect(res.body.data.user.password).toBeUndefined();
  });

  it('rejects a duplicate email', async () => {
    await request(app)
      .post('/api/auth/signup')
      .send({ name: 'Ada', email: 'dup@example.com', password: 'longenough' });
    const res = await request(app)
      .post('/api/auth/signup')
      .send({ name: 'Ada2', email: 'dup@example.com', password: 'longenough' });
    expect(res.status).toBe(409);
    expect(res.body.success).toBe(false);
  });

  it('treats email as case-insensitive for uniqueness', async () => {
    await request(app)
      .post('/api/auth/signup')
      .send({ name: 'Ada', email: 'Case@Example.com', password: 'longenough' });
    const res = await request(app)
      .post('/api/auth/signup')
      .send({ name: 'Ada2', email: 'case@example.com', password: 'longenough' });
    expect(res.status).toBe(409);
  });
});

describe('POST /api/auth/login', () => {
  beforeEach(async () => {
    await request(app)
      .post('/api/auth/signup')
      .send({ name: 'Ada', email: 'ada@example.com', password: 'longenough' });
  });

  it('rejects a missing field', async () => {
    const res = await request(app).post('/api/auth/login').send({ email: 'ada@example.com' });
    expect(res.status).toBe(400);
  });

  it('rejects an unknown email with a generic message', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'nope@example.com', password: 'longenough' });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Invalid email or password');
  });

  it('rejects a wrong password with the same generic message', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'ada@example.com', password: 'wrongpassword' });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Invalid email or password');
  });

  it('logs in with correct credentials', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'ada@example.com', password: 'longenough' });
    expect(res.status).toBe(200);
    expect(res.body.data.token).toEqual(expect.any(String));
  });
});
