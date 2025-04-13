import Fastify from 'fastify';
import cors from '@fastify/cors';
import cookie from '@fastify/cookie';
import fastifyJwt from '@fastify/jwt';
import { sequelize, seedDatabase } from './config/database.js';
import Character from './models/laughariki.model.js';
import  handleError  from './utils/errorHandler.js';
import { characterSchema, characterPatchSchema } from './validate/character.validator.js';
import authRoutes from './controllers/auth.controller.js';
import { createUser } from './services/user.service.js';
import fastifyRedis from '@fastify/redis';
import * as AuthService from './services/auth.service.js';
import redis from './config/redis.js';



const fastify = Fastify({
  logger: true
});

fastify.register(cors, {
  origin: process.env.CORS_ORIGIN || true,
  credentials: true
});

fastify.register(cookie);

fastify.register(fastifyJwt, {
  secret: process.env.JWT_SECRET || 'your-very-strong-secret-key-here-32-chars-min',
  cookie: {
    cookieName: 'token',
    signed: false
  }
});

fastify.register(fastifyRedis, {
  client: redis,
  name: 'redis' // для доступа через app.redis
});

// fastify.register(fastifyRedis, { host: '127.0.0.1', password: 'qazwsxedc' })

fastify.decorate('authenticate', async (request, reply) => {
  try {
    const token = request.cookies.token;
    if (!token) throw new Error('Токен отсутствует');

    const decoded = await request.jwtVerify(token);

    // Проверяем, есть ли токен в Redis
    const isValid = await AuthService.isValidSession(decoded.id, token);
    if (!isValid) {
      throw new Error('Сессия недействительна');
    }

    request.user = decoded;
  } catch (err) {
    reply.clearCookie('token');
    reply.code(401).send({ error: 'Не авторизован', message: err.message });
  }
});

fastify.decorate('verifyRole', (requiredRole) => async (request, reply) => {
  try {
    const token = request.cookies.token;
    if (!token) throw new Error('Токен отсутствует');

    await request.jwtVerify(token);

    if (request.user.role !== requiredRole) {
      throw new Error('Недостаточно прав');
    }
  } catch (err) {
    reply.code(403).send({
      error: 'Запрещено',
      message: err.message
    });
  }
});

fastify.register(authRoutes, { prefix: '/api/auth' });

fastify.post('/api/characters', {
  schema: {
    body: characterSchema,
  },
  preHandler: [fastify.authenticate, fastify.verifyRole('admin')]
}, async (request, reply) => {
  try {
    const character = await Character.create(request.body);
    return reply.status(201).send(character);
  } catch (error) {
    handleError(error, reply);
  }
});

fastify.get('/api/characters', {
  preHandler: fastify.authenticate
}, async (request, reply) => {
  try {
    const page = parseInt(request.query.page, 10) || 1;
    const limit = parseInt(request.query.limit, 10) || 5;

    if (isNaN(page) || isNaN(limit) || page < 1 || limit < 1) {
      throw { statusCode: 400, message: 'Невалидные параметры пагинации' };
    }

    const offset = (page - 1) * limit;

    const { count, rows } = await Character.findAndCountAll({
      limit,
      offset,
      order: [['id', 'ASC']],
    });

    return reply.status(200).send({
      data: rows,
      pagination: {
        totalItems: count,
        currentPage: page,
        totalPages: Math.ceil(count / limit),
        itemsPerPage: limit,
      },
    });
  } catch (error) {
    handleError(error, reply);
  }
});

fastify.put('/api/characters/:id', {
  schema: {
    body: characterSchema,
  },
  preHandler: [fastify.authenticate, fastify.verifyRole('admin')]
}, async (request, reply) => {
  try {
    const { id } = request.params;
    const [updated] = await Character.update(request.body, {
      where: { id },
    });

    if (!updated) {
      throw { statusCode: 404, message: 'Ресурс не найден' };
    }

    const updatedCharacter = await Character.findByPk(id);
    return reply.status(200).send(updatedCharacter);
  } catch (error) {
    handleError(error, reply);
  }
});

fastify.patch('/api/characters/:id', {
  schema: {
    body: characterPatchSchema,
  },
  preHandler: [fastify.authenticate, fastify.verifyRole('admin')]
}, async (request, reply) => {
  try {
    const { id } = request.params;

    if (Object.keys(request.body).length === 0) {
      throw { statusCode: 400, message: 'Необходимо указать хотя бы одно поле для обновления' };
    }

    const [updated] = await Character.update(request.body, {
      where: { id },
    });

    if (!updated) {
      throw { statusCode: 404, message: 'Ресурс не найден' };
    }

    const updatedCharacter = await Character.findByPk(id);
    return reply.status(200).send(updatedCharacter);
  } catch (error) {
    handleError(error, reply);
  }
});

fastify.delete('/api/characters/:id', {
  preHandler: [fastify.authenticate, fastify.verifyRole('admin')]
}, async (request, reply) => {
  try {
    const { id } = request.params;
    const deleted = await Character.destroy({
      where: { id },
    });

    if (!deleted) {
      throw { statusCode: 404, message: 'Ресурс не найден' };
    }

    return reply.status(204).send();
  } catch (error) {
    handleError(error, reply);
  }
});

const startServer = async () => {
  try {
    await sequelize.authenticate();
    await sequelize.sync({ force: process.env.NODE_ENV !== 'production' });

    await createUser('admin', 'admin123', 'admin');
    await createUser('user', 'user123');

    await seedDatabase(Character);

    // await fastify.redis.ping();
    //   console.log('Redis connection established');

    await fastify.listen({
      port: process.env.PORT || 8000,
      host: '0.0.0.0'
    });

    fastify.log.info(`Сервер запущен на ${fastify.server.address().port}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

startServer();
