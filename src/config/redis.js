// import Redis from 'ioredis';

// const redis = new Redis(process.env.REDIS_URL || 'redis://:qazwsxedc@redis:6379', {
//   retryStrategy: (times) => Math.min(times * 50, 2000),
//   maxRetriesPerRequest: 3
// });

// redis.on('error', (err) => console.error('Redis error:', err));
// redis.on('connect', () => console.log('Connected to Redis'));

// export default redis;

import Redis from 'ioredis';

const redisConfig = {
  host: process.env.REDIS_HOST || 'localhost',
  port: process.env.REDIS_PORT || 6379,
  password: process.env.REDIS_PASSWORD || "qazwsxedc",
  retryStrategy: (times) => Math.min(times * 50, 2000),
  maxRetriesPerRequest: 3
};

const redis = new Redis(redisConfig);

// Проверка соединения при инициализации
redis.ping()
  .then(() => console.log('Successfully connected to Redis'))
  .catch(err => console.error('Redis connection error:', err));

export default redis;