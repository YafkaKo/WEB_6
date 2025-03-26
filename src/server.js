import Fastify from 'fastify'
import { sequelize, seedDatabase } from './config/database.js'
import Character from './models/laughariki.model.js';
import User from './models/user.model.js';
import fastifyJwt from '@fastify/jwt';
import bcrypt from 'bcrypt';
import { ValidationError } from 'sequelize';


const fastify = Fastify({
    logger: true
})

// Регистрируем JWT плагин
fastify.register(fastifyJwt, {
  secret: 'your-very-strong-secret-key-here-32-chars-min' // В продакшене используйте переменные окружения
});

// Хелперы для работы с пользователями
const createUser = async (username, password, role = 'user') => {
  const hashedPassword = await bcrypt.hash(password, 10);
  return User.create({ username, password: hashedPassword, role });
};

const validateUser = async (username, password) => {
  const user = await User.findOne({ where: { username } });
  if (!user) return false;

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return false;

  return user;
};

// Роуты для аутентификации
fastify.post('/api/auth/register', async (request, reply) => {
  const { username, password } = request.body;

  try {
    const user = await createUser(username, password);
    const token = fastify.jwt.sign({ id: user.id, role: user.role });
    return { token };
  } catch (error) {
    if (error.name === 'SequelizeUniqueConstraintError') {
      return reply.status(400).send({ error: 'Username already exists' });
    }
    reply.status(500).send({ error: 'Internal server error' });
  }
});

fastify.post('/api/auth/login', async (request, reply) => {
  const { username, password } = request.body;

  const user = await validateUser(username, password);
  if (!user) {
    return reply.status(401).send({ error: 'Invalid credentials' });
  }

  const token = fastify.jwt.sign({ id: user.id, role: user.role });
  return { token };
});

// Хук для проверки аутентификации
fastify.decorate('authenticate', async (request, reply) => {
  try {
    await request.jwtVerify();
  } catch (err) {
    reply.send(err);
  }
});

// Хук для проверки роли
fastify.decorate('verifyRole', (role) => async (request, reply) => {
  try {
    await request.jwtVerify();
    if (request.user.role !== role) {
      throw new Error('Unauthorized: Insufficient permissions');
    }
  } catch (err) {
    reply.code(403).send({ error: 'Forbidden', message: 'Insufficient permissions' });
  }
});

const characterSchema = {
    type: 'object',
    required: ['name', 'avatar', 'description', 'character', 'hobbies', 'favoritePhrases', 'friends'],
    properties: {
      name: { type: 'string' },
      avatar: { type: 'string', format: 'uri' },
      description: { type: 'string' },
      character: { type: 'string' },
      hobbies: { type: 'string' },
      favoritePhrases: {
        type: 'array',
        items: { type: 'string' },
      },
      friends: {
        type: 'array',
        items: { type: 'string' },
      },
    },
  };

  const characterPatchSchema = {
    type: 'object',
    properties: {
      name: { type: 'string' },
      avatar: { type: 'string', format: 'uri' },
      description: { type: 'string' },
      character: { type: 'string' },
      hobbies: { type: 'string' },
      favoritePhrases: {
        type: 'array',
        items: { type: 'string' },
      },
      friends: {
        type: 'array',
        items: { type: 'string' },
      },
    },
  };

// Обработчик ошибок
const handleError = (error, reply) => {
  if (error instanceof ValidationError) {
    // Ошибка валидации Sequelize
    return reply.status(400).send({
      error: 'Ошибка валидации',
      details: error.errors.map((err) => ({
        field: err.path,
        message: err.message,
      })),
    });
  } else if (error.name === 'SequelizeDatabaseError') {
    // Ошибка базы данных
    return reply.status(500).send({ error: 'Ошибка базы данных', details: error.message });
  } else if (error.name === 'SequelizeUniqueConstraintError') {
    // Ошибка уникальности
    return reply.status(400).send({ error: 'Нарушение уникальности', details: error.message });
  } else {
    // Общая ошибка сервера
    return reply.status(500).send({ error: 'Ошибка сервера', details: error.message });
  }
};

// Защищенные роуты с JWT аутентификацией

// Роут для создания персонажа (только для админов)
fastify.post('/api/characters', {
  schema: {
    body: characterSchema,
  },
  preHandler: [fastify.authenticate, fastify.verifyRole('admin')]
}, async (request, reply) => {
  const data = request.body;

  try {
    const character = await Character.create(data);
    return reply.status(200).send(character);
  } catch (error) {
    handleError(error, reply);
  }
});

// Роут для получения списка персонажей с пагинацией (доступно всем аутентифицированным пользователям)
fastify.get('/api/characters', {
  preHandler: fastify.authenticate
}, async (request, reply) => {
  const page = parseInt(request.query.page, 10) || 1;
  const limit = parseInt(request.query.limit, 10) || 5;

  if (isNaN(page) || isNaN(limit) || page < 1 || limit < 1) {
    return reply.status(400).send({ error: 'Невалидные параметры пагинации' });
  }

  const offset = (page - 1) * limit;

  try {
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
  const { id } = request.params;
  const data = request.body;

  try {
    const [updated] = await Character.update(data, {
      where: { id },
    });

    if (!updated) {
      return reply.status(404).send({ error: 'Ресурс не найден' });
    }

    const updatedCharacter = await Character.findByPk(id);
    return reply.status(200).send({
      message: 'Данные обновлены успешно',
      data: updatedCharacter,
    });
  } catch (error) {
    handleError(error, reply);
  }
});

// Роут для частичного обновления персонажа (PATCH) (только для админов)
fastify.patch('/api/characters/:id', {
  schema: {
    body: characterPatchSchema,
  },
  preHandler: [fastify.authenticate, fastify.verifyRole('admin')]
}, async (request, reply) => {
  const { id } = request.params;
  const data = request.body;

  if (Object.keys(data).length === 0) {
    return reply.status(400).send({ error: 'Хотя бы одно поле должно быть заполнено' });
  }

  try {
    const [updated] = await Character.update(data, {
      where: { id },
    });

    if (!updated) {
      return reply.status(404).send({ error: 'Ресурс не найден' });
    }

    const updatedCharacter = await Character.findByPk(id);
    return reply.status(200).send({
      message: 'Данные обновлены успешно',
      data: updatedCharacter,
    });
  } catch (error) {
    handleError(error, reply);
  }
});

// Роут для удаления персонажа (только для админов)
fastify.delete('/api/characters/:id', {
  preHandler: [fastify.authenticate, fastify.verifyRole('admin')]
}, async (request, reply) => {
  const { id } = request.params;

  try {
    const deleted = await Character.destroy({
      where: { id },
    });

    if (!deleted) {
      return reply.status(404).send({ error: 'Ресурс не найден' });
    }

    return reply.status(200).send({
      message: 'Ресурс успешно удален',
    });
  } catch (error) {
    handleError(error, reply);
  }
});

try {
    await sequelize.authenticate();
    await sequelize.sync({ force: true });

    // Создаем тестового пользователя (в реальном приложении это не нужно)
    await createUser('admin', 'admin123', 'admin');
    await createUser('user', 'user123');

    await seedDatabase(Character);

    await fastify.listen({ port: 8000 });
} catch (err) {
    fastify.log.error(err);
    process.exit(1);
}