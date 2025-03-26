import { Sequelize } from 'sequelize';

export const sequelize = new Sequelize('postgres://student:QrGZex@localhost:5432/lab_5_db')

export const seedDatabase = async (Character) => {
  const characters = [
    {
      name: 'Крош',
      avatar: 'https://static.wikia.nocookie.net/smeshariki/images/6/6e/Krosh.png',
      description: 'Веселый и энергичный кролик, любит приключения.',
      character: 'Энергичный, непоседливый, любопытный',
      hobbies: 'Кататься на скейтборде, придумывать новые игры',
      favoritePhrases: ["Ёлки-иголки!", "Это же просто праздник какой-то!"],
      friends: ["Ёжик", "Бараш", "Нюша"]
    },
    {
      name: 'Ёжик',
      avatar: 'https://static.wikia.nocookie.net/smeshariki/images/9/9a/EJik.png',
      description: 'Спокойный и рассудительный ёж, лучший друг Кроша.',
      character: 'Умный, осторожный, добрый',
      hobbies: 'Чтение книг, коллекционирование кактусов',
      favoritePhrases: ["Надо подумать...", "Это небезопасно!"],
      friends: ["Крош", "Бараш", "Пин"]
    },
    {
      name: 'Бараш',
      avatar: 'https://static.wikia.nocookie.net/smeshariki/images/2/2a/Barash.png',
      description: 'Поэтичная и романтичная натура, часто грустит.',
      character: 'Чувствительный, мечтательный, ранимый',
      hobbies: 'Писать стихи, любоваться природой',
      favoritePhrases: ["Как грустно...", "Осень - пора поэзии..."],
      friends: ["Крош", "Ёжик", "Нюша"]
    },
    {
      name: 'Нюша',
      avatar: 'https://static.wikia.nocookie.net/smeshariki/images/7/7a/Nysha.png',
      description: 'Модная и немного капризная свинка, мечтает о принце.',
      character: 'Кокетливая, эмоциональная, добрая',
      hobbies: 'Ухаживать за собой, читать журналы мод',
      favoritePhrases: ["Какой ужас!", "Я же девочка!"],
      friends: ["Крош", "Бараш", "Лосяш"]
    },
    {
      name: 'Пин',
      avatar: 'https://static.wikia.nocookie.net/smeshariki/images/8/8a/Pin.png',
      description: 'Гениальный изобретатель, прилетевший с далекого севера.',
      character: 'Умный, изобретательный, немного рассеянный',
      hobbies: 'Изобретать новые устройства, чинить технику',
      favoritePhrases: ["По моим расчетам...", "Это гениально!"],
      friends: ["Крош", "Ёжик", "Лосяш"]
    },
    {
      name: 'Лосяш',
      avatar: 'https://static.wikia.nocookie.net/smeshariki/images/3/3a/Losyash.png',
      description: 'Ученый-интеллектуал, знает ответы на все вопросы.',
      character: 'Умный, спокойный, иногда занудный',
      hobbies: 'Чтение научной литературы, наблюдение за звездами',
      favoritePhrases: ["С научной точки зрения...", "Это элементарно!"],
      friends: ["Пин", "Копатыч", "Совунья"]
    },
    {
      name: 'Копатыч',
      avatar: 'https://static.wikia.nocookie.net/smeshariki/images/5/5d/Kopatych.png',
      description: 'Добродушный медведь, знатный огородник.',
      character: 'Добрый, хозяйственный, мудрый',
      hobbies: 'Выращивать овощи, готовить варенье',
      favoritePhrases: ["Ох, как же я устал...", "Без труда не вытащишь и рыбку из пруда!"],
      friends: ["Лосяш", "Совунья", "Кар-Карыч"]
    },
    {
      name: 'Совунья',
      avatar: 'https://static.wikia.nocookie.net/smeshariki/images/4/4f/Sovunya.png',
      description: 'Заботливая сова, следит за здоровьем друзей.',
      character: 'Заботливая, внимательная, иногда строгая',
      hobbies: 'Готовить лекарства, заботиться о других',
      favoritePhrases: ["Надо измерять температуру!", "Это полезно для здоровья!"],
      friends: ["Копатыч", "Лосяш", "Кар-Карыч"]
    },
    {
      name: 'Кар-Карыч',
      avatar: 'https://static.wikia.nocookie.net/smeshariki/images/9/9a/Kar-Karych.png',
      description: 'Бывший цирковой артист, любит рассказывать истории.',
      character: 'Добрый, мудрый, немного хвастливый',
      hobbies: 'Рассказывать истории, петь песни',
      favoritePhrases: ["В мои годы...", "Когда я был в цирке..."],
      friends: ["Копатыч", "Совунья", "Пин"]
    },
    {
      name: 'Рома',
      avatar: 'https://static.wikia.nocookie.net/smeshariki/images/3/3f/Roma.png',
      description: 'Спокойный и добрый песик, любит порядок.',
      character: 'Аккуратный, ответственный, доброжелательный',
      hobbies: 'Наводить порядок, помогать друзьям',
      favoritePhrases: ["Всё должно быть на своих местах!", "Я помогу!"],
      friends: ["Крош", "Ёжик", "Нюша"]
    }
  ];

  await Character.bulkCreate(characters);
  console.log('База данных заполнена персонажами Смешариков');
};