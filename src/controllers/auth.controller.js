import * as UserService from '../services/user.service.js';
// import * as AuthService from '../services/auth.service.js';
import handleError from '../utils/errorHandler.js';
import * as AuthSession from '../services/auth.service.js';


const setTokenCookie = (reply, token,id) => {
  reply.setCookie(`token_${id}`, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: 60 * 60, // 1 час в секундах
  });
};

const registerHandler = async (request, reply) => {
  const { username, password } = request.body;

  try {
    if (!username || !password) {
      throw { statusCode: 400, message: 'Имя пользователя и пароль обязательны' };
    }

    const user = await UserService.createUser(username, password);
    const token = request.server.jwt.sign({
      id: user.id,
      role: user.role
    });

    // Сохраняем сессию в Redis
    await AuthSession.addSession(user.id, token);

    setTokenCookie(reply, token,user.id);
    return { message: 'Регистрация прошла успешно' };
  } catch (error) {
    if (error.name === 'SequelizeUniqueConstraintError') {
      return reply.status(400).send({ error: 'Имя пользователя уже занято' });
    }
    handleError(error, reply);
  }
};

const loginHandler = async (request, reply) => {
  const { username, password } = request.body;

  try {
    if (!username || !password) {
      throw { statusCode: 400, message: 'Имя пользователя и пароль обязательны' };
    }

    const user = await UserService.validateUser(username, password);
    if (!user) {
      throw { statusCode: 401, message: 'Неверные учетные данные' };
    }

    const token = request.server.jwt.sign({
      id: user.id,
      role: user.role
    });

    // Сохраняем сессию в Redis
    await AuthSession.addSession(user.id, token);

    setTokenCookie(reply, token,user.id);
    return { message: 'Вы вошли успешно' };
  } catch (error) {
    handleError(error, reply);
  }
};

const logoutHandler = async (request, reply) => {
  const { id } = request.params;
  const callToken = 'token_' + id
  try {
    const token = request.cookies[callToken];
    if (!token) {
      return reply.status(400).send({ error: 'Токен отсутствует' });
    }

    // Верифицируем токен и получаем userId
    const decoded = await request.server.jwt.verify(token);

    // Удаляем конкретную сессию
    await AuthSession.removeSession(decoded.id, token);

    // Очищаем куки для конкретного пользователя
    reply.clearCookie(`token_${decoded.id}`);

    return { message: 'Вы вышли успешно' };
  } catch (error) {
    handleError(error, reply);
  }
};

const logoutAllHandler = async (request, reply) => {
  try {
    // Удаляем все сессии из Redis
    await AuthSession.removeAllSessions();

    // Очищаем все куки, связанные с активными пользователями
    const cookies = request.cookies;
    const cookieNamesToClear = Object.keys(cookies).filter(name => name.startsWith('token_'));

    for (const cookieName of cookieNamesToClear) {
      reply.clearCookie(cookieName, { path: '/' });
    }

    return { message: 'Все пользователи вышли из системы' };
  } catch (error) {
    handleError(error, reply);
  }
};

export default async function authRoutes(fastify) {
  fastify.post('/register', registerHandler);
  fastify.post('/login', loginHandler);
  fastify.post('/logout/:id', logoutHandler);
  fastify.post('/logout/all', logoutAllHandler); // Новый эндпоинт
}