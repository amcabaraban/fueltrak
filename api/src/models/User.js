const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');
const bcrypt = require('bcryptjs');

const User = sequelize.define('User', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  email: { type: DataTypes.STRING(100), unique: true, allowNull: false },
  password: { type: DataTypes.STRING(255), allowNull: false },
  mobile: { type: DataTypes.STRING(20), allowNull: false },
  role: { type: DataTypes.ENUM('client', 'dispatcher', 'management'), defaultValue: 'client' },
  company_name: { type: DataTypes.STRING(150), allowNull: true },
  is_active: { type: DataTypes.BOOLEAN, defaultValue: true },
  is_verified: { type: DataTypes.BOOLEAN, defaultValue: false },
  last_login: { type: DataTypes.DATE, allowNull: true }
}, {
  tableName: 'users',
  timestamps: true,
  hooks: {
    beforeCreate: async (user) => {
      if (user.password && !user.password.startsWith('$2')) {
        user.password = await bcrypt.hash(user.password, 12);
      }
    },
    beforeUpdate: async (user) => {
      if (user.changed('password') && !user.password.startsWith('$2')) {
        user.password = await bcrypt.hash(user.password, 12);
      }
    }
  }
});

User.prototype.comparePassword = async function(password) {
  return await bcrypt.compare(password, this.password);
};

User.prototype.toJSON = function() {
  const values = { ...this.get() };
  delete values.password;
  return values;
};

module.exports = User;