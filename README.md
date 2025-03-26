# Лабораторная работа 5
## Построение RESTful API с использованием ORM Sequelize
### Цель работы
Реализовать хранение сущностей по тематике лабораторных работ в реляционной СУБД PostgreSQL с  использованием ORM Sequelize

### Технические требования:
- Наличие интернет-соединения
- Наличие [Postman](https://www.postman.com/downloads/) или 
- Наличие [Node](https://nodejs.org/en) [v22 и выше] или наличие [NVM](https://github.com/nvm-sh/nvm) для переключения между версиями Node
- Наличие [Docker](https://docs.docker.com/desktop/)

### Ход работы:

1. В директории с лабораторной работой выполните запуск контейнеров с PostgreSQL и PGAdmin при помощи команды `docker-compose up -d` (`docker compose up -d`)

2. В директории с лабораторной работой выполните установку зависимостей при комощи команды `npm i`

4. В директории с лабораторной работой выполните запуск проекта с помощью команды `npm start`

5. Выполните вход в PGAdmin, перейдя по [данному](http://localhost:7777) адресу, используя следующие данные для входа: email `admin@example.com`, пароль `qazwsxedc`

6. Добавьте соединение с сервером, используя кнопку `Add new server`

![Главный экран PGAdmin](https://storage.yandexcloud.net/shesterikov/WP/WP_5_1.png)

![Пример заполнения имени соединения](https://storage.yandexcloud.net/shesterikov/WP/WP_5_2.png)

![Пример заполнения данных соединения](https://storage.yandexcloud.net/shesterikov/WP/WP_5_3.png)

Обратите внимание, что при сохранении соединения в PGAdmin в качестве хоста указывается имя сервиса из `docker-compose.yml` файла (в данном случае `db`). Это связано с тем, что PGAdmin и PostgreSQL находятся в одной сети Docker'a. При инициализации подключения в Node как правило указывается `localhost` (если приложение не запускается в Docker контейнере)

7. Удостоверьтесь, что создана новая таблица `pokemons`

![Главный экран PGAdmin](https://storage.yandexcloud.net/shesterikov/WP/WP_5_4.png)

![Главный экран PGAdmin](https://storage.yandexcloud.net/shesterikov/WP/WP_5_5.png)

![Главный экран PGAdmin](https://storage.yandexcloud.net/shesterikov/WP/WP_5_6.png)

8. Выполните следующий запрос в Postman для создания новой записи

```
curl --location 'localhost:8000/api' \
--header 'accept: application/json' \
--header 'Content-Type: application/json' \
--data '{
    "name": "Snorlax",
    "pic": "https://github.com/PokeAPI/sprites/raw/master/sprites/pokemon/other/official-artwork/25.png"
}'
```

8. Убедитесь в существовании новой записи в таблице `pokemons`

![Главный экран PGAdmin](https://storage.yandexcloud.net/shesterikov/WP/WP_5_7.png)

9. Модифицируйте исходный код приложения в соответствии с тематикой вашей лабораторной работы, добавив наработки из лабораторной работы №4 и реализовав хранение данных в СУБД PostgreSQL с использованием ORM Sequilize

На выходе должно получиться RESTful API, реализующее основные операции над сущностями: чтение, создание, модификацию и удаление

Операцию удаления требуется реализовать с использованием "мягкого удаления" (soft delete). 

### Примечания

Исходная модель хранится в `src/models/pokemon.model.js`

Для процесса разработки применяется принудительная синхронизация Sequelize с флагом `force: true` [файл `src/server.js`].
```
await sequelize.sync({ force: true })
```

Это может привести к потере данных в СУБД в процессе изменения кода. Рекомендуется по окончании процесса модификации моделей убрать данный флаг

В Sequilize мягкое удаление упоминается как [paranoid](https://sequelize.org/docs/v6/core-concepts/paranoid/)

### Документация:

[Sequelize](https://sequelize.org/docs/v6/)

[Описание типов данных в СУБД PostgreSQL](https://www.postgresql.org/docs/14/datatype.html)

### Контрольные вопросы:
1. Что такое ORM? Что такое модель? Какие преимущества дает использование ORM? 
2. Какие типы данных вы использовали при создании моделей?
3. Что такое мягкое удаление (soft delete)?