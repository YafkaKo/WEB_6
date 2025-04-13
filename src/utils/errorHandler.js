import { ValidationError } from 'sequelize';

/**
 * Универсальный обработчик ошибок для Fastify
 * @param {Error|Object} error - Объект ошибки
 * @param {FastifyReply} reply - Объект ответа Fastify
 * @returns {FastifyReply} Ответ с информацией об ошибке
 */
const handleError = (error, reply) => {
  // Логирование ошибки с дополнительной информацией
  console.error('Error occurred:', {
    message: error.message,
    stack: error.stack,
    originalError: error
  });

  // Обработка ошибок валидации Sequelize
  if (error instanceof ValidationError) {
    return reply.status(400).send({
      status: 'error',
      code: 'VALIDATION_ERROR',
      message: 'Ошибка валидации данных',
      errors: error.errors.map((err) => ({
        field: err.path,
        type: err.type,
        message: err.message,
      })),
      timestamp: new Date().toISOString()
    });
  }

  // Определение кода и сообщения ошибки
  const statusCode = error.statusCode || 500;
  const isServerError = statusCode >= 500;

  // Формирование ответа
  const response = {
    status: 'error',
    code: error.code || 'INTERNAL_ERROR',
    message: isServerError ? 'Внутренняя ошибка сервера' : error.message,
    timestamp: new Date().toISOString()
  };

  // Добавляем детали только для клиентских ошибок
  if (!isServerError && error.details) {
    response.details = error.details;
  }

  // Логирование серверных ошибок
  if (isServerError) {
    console.error('Server error:', {
      statusCode,
      error: error.message,
      stack: error.stack
    });
  }

  return reply.status(statusCode).send(response);
};

export default handleError;