function getJwtSecret() {
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
        throw new Error('JWT_SECRET must be set');
    }
    return jwtSecret;
}

function isSafeTableName(tableName) {
    if (typeof tableName !== 'string') return false;
    return /^[a-zA-Z_][a-zA-Z0-9_]{0,63}$/.test(tableName);
}

module.exports = { getJwtSecret, isSafeTableName };
