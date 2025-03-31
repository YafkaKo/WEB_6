import Fastify from 'fastify';
import cors from '@fastify/cors';
import cookie from '@fastify/cookie'; // Добавлен плагин для работы с куками
import { sequelize, seedDatabase } from './config/database.js';
import Character from './models/laughariki.model.js';
import User from './models/user.model.js';
import fastifyJwt from '@fastify/jwt';
import bcrypt from 'bcrypt';
import { ValidationError } from 'sequelize';

const fastify = Fastify({
  logger: true
});

// Регистрация плагинов
fastify.register(cors, {
  origin: process.env.CORS_ORIGIN || true,
  credentials: true
});

fastify.register(cookie); // Регистрация плагина для работы с куками

fastify.register(fastifyJwt, {
  secret: process.env.JWT_SECRET || 'your-very-strong-secret-key-here-32-chars-min',
  cookie: {
    cookieName: 'token',
    signed: false
  }
});

// Генерация хэша с использованием соли
const generateHashWithSalt = async (password) => {
  if (!password || password.length < 6) {
    throw new Error('Пароль должен содержать минимум 6 символов');
  }
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
};

// Хелпер для создания пользователя
const createUser = async (username, password, role = 'user') => {
  if (!username || !password) {
    throw new Error('Имя пользователя и пароль обязательны');
  }
  const hashedPassword = await generateHashWithSalt(password);
  return User.create({ username, password: hashedPassword, role });
};

// Валидация пользователя
const validateUser = async (username, password) => {
  if (!username || !password) return false;

  const user = await User.findOne({ where: { username } });
  if (!user) return false;

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return false;

  return user;
};

// Декорация authenticate
fastify.decorate('authenticate', async (request, reply) => {
  try {
    await request.jwtVerify();
  } catch (err) {
    reply.clearCookie('token');
    reply.code(401).send({ error: 'Не авторизован', message: err.message });
  }
});

// Декорация verifyRole
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

// Схема для валидации персонажа
const characterSchema = {
  type: 'object',
  required: ['name', 'avatar', 'description', 'character', 'hobbies', 'favoritePhrases', 'friends'],
  properties: {
    name: {
      type: 'string',
      minLength: 2,
      maxLength: 50
    },
    avatar: {
      type: 'string',
      format: 'uri'
    },
    description: {
      type: 'string',
      minLength: 10
    },
    character: {
      type: 'string',
      minLength: 5
    },
    hobbies: {
      type: 'string',
      minLength: 5
    },
    favoritePhrases: {
      type: 'array',
      items: {
        type: 'string',
        minLength: 3
      },
    },
    friends: {
      type: 'array',
      items: {
        type: 'string',
        minLength: 2
      },
    },
  },
};

// Схема для частичной валидации персонажа
const characterPatchSchema = {
  type: 'object',
  properties: {
    name: {
      type: 'string',
      minLength: 2,
      maxLength: 50
    },
    avatar: {
      type: 'string',
      format: 'uri'
    },
    description: {
      type: 'string',
      minLength: 10
    },
    character: {
      type: 'string',
      minLength: 5
    },
    hobbies: {
      type: 'string',
      minLength: 5
    },
    favoritePhrases: {
      type: 'array',
      items: {
        type: 'string',
        minLength: 3
      },
    },
    friends: {
      type: 'array',
      items: {
        type: 'string',
        minLength: 2
      },
    },
  },
};

// Обработка ошибок
const handleError = (error, reply) => {
  fastify.log.error(error);

  if (error instanceof ValidationError) {
    return reply.status(400).send({
      error: 'Ошибка валидации',
      details: error.errors.map((err) => ({
        field: err.path,
        message: err.message,
      })),
    });
  }

  const statusCode = error.statusCode || 500;
  const message = statusCode === 500 ? 'Внутренняя ошибка сервера' : error.message;

  reply.status(statusCode).send({
    error: message,
    details: statusCode === 500 ? undefined : error.details
  });
};

// Роут для регистрации
fastify.post('/api/auth/register', async (request, reply) => {
  const { username, password } = request.body;

  try {
    if (!username || !password) {
      throw { statusCode: 400, message: 'Имя пользователя и пароль обязательны' };
    }

    const user = await createUser(username, password);
    const token = fastify.jwt.sign({
      id: user.id,
      role: user.role
    });

    reply.setCookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
      maxAge: 3600000,
    });

    return { message: 'Регистрация прошла успешно' };
  } catch (error) {
    if (error.name === 'SequelizeUniqueConstraintError') {
      return reply.status(400).send({ error: 'Имя пользователя уже занято' });
    }
    handleError(error, reply);
  }
});


// Роут для входа
fastify.post('/api/auth/login', async (request, reply) => {
  const { username, password } = request.body;

  try {
    if (!username || !password) {
      throw { statusCode: 400, message: 'Имя пользователя и пароль обязательны' };
    }

    const user = await validateUser(username, password);
    if (!user) {
      throw { statusCode: 401, message: 'Неверные учетные данные' };
    }

    const token = fastify.jwt.sign({
      id: user.id,
      role: user.role
    });

    reply.setCookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
      maxAge: 3600000,
    });

    return { message: 'Вы вошли успешно' };
  } catch (error) {
    handleError(error, reply);
  }
});

// Роут для выхода
fastify.post('/api/auth/logout', async (request, reply) => {
  reply.clearCookie('token');
  return { message: 'Вы вышли успешно' };
});

// Роут для создания персонажа (только для админов)
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

// Роут для получения списка персонажей с пагинацией
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

// Роут для полного обновления персонажа (PUT)
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

// Роут для частичного обновления персонажа (PATCH)
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

// Роут для удаления персонажа
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