const test = require('node:test');
const assert = require('node:assert/strict');
const { getJwtSecret, isSafeTableName } = require('../api/src/config/securityHelpers');

test('getJwtSecret throws when JWT_SECRET is missing', () => {
    delete process.env.JWT_SECRET;
    assert.throws(() => getJwtSecret(), /JWT_SECRET must be set/);
});

test('getJwtSecret returns the configured secret', () => {
    process.env.JWT_SECRET = 'test-secret';
    assert.equal(getJwtSecret(), 'test-secret');
});

test('isSafeTableName rejects unsafe table names', () => {
    assert.equal(isSafeTableName('users'), true);
    assert.equal(isSafeTableName('DROP TABLE users'), false);
    assert.equal(isSafeTableName('users; DROP TABLE admins'), false);
});
