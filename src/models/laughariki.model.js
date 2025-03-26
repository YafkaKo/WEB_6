import { DataTypes, Model } from 'sequelize';
import { sequelize } from '../config/database.js';

class character extends Model { }

character.init(
  {
    id: {
      type: DataTypes.INTEGER, // SERIAL в PostgreSQL
      primaryKey: true,
      autoIncrement: true, // Автоматическое увеличение для поля id
    },
    name: {
      type: DataTypes.STRING(255), // VARCHAR(255) в PostgreSQL
      allowNull: false, // Имя обязательно
    },
    avatar: {
      type: DataTypes.TEXT, // TEXT для аватара
      allowNull: false, // Аватар обязательно
    },
    description: {
      type: DataTypes.TEXT, // TEXT для описания
      allowNull: false, // Описание обязательно
    },
    character: {
      type: DataTypes.TEXT, // TEXT для характеристики
      allowNull: false, // Характеристика обязательна
    },
    hobbies: {
      type: DataTypes.TEXT, // TEXT для хобби
      allowNull: false, // Хобби обязательно
    },
    favoritePhrases: {
      type: DataTypes.ARRAY(DataTypes.TEXT), // TEXT[] для массива фраз
      allowNull: false, // Массив фраз обязателен
    },
    friends: {
      type: DataTypes.ARRAY(DataTypes.TEXT), // TEXT[] для массива друзей
      allowNull: false, // Массив друзей обязателен
    },
  },
  {
    sequelize,
    modelName: 'Character',
    timestamps: false,
  }
);

export default character;
