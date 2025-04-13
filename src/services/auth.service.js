import redis from "../config/redis.js";
// Храним сессии в Redis: userSessions:{userId} = [token1, token2]
const SESSION_PREFIX = 'token_';
const SESSION_TTL = 60 * 60; // 1 час в секундах

export const addSession = async (userId, token) => {
  await redis.sadd(`${SESSION_PREFIX}${userId}`, token);
  await redis.expire(`${SESSION_PREFIX}${userId}`, SESSION_TTL);
};

export const removeSession = async (userId, token) => {
  await redis.srem(`${SESSION_PREFIX}${userId}`, token);
};

export const removeAllSessions = async () => {
  let cursor = '0';
  do {
    const result = await redis.scan(cursor, 'MATCH', `${SESSION_PREFIX}*`);
    cursor = result[0];
    if (result[1].length > 0) {
      await redis.del(...result[1]);
    }
  } while (cursor !== '0');
};

export const isValidSession = async (userId, token) => {
  return await redis.sismember(`${SESSION_PREFIX}${userId}`, token);
};