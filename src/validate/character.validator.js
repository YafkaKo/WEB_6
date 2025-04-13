export const characterSchema = {
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

export const characterPatchSchema = {
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