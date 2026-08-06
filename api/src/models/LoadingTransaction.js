const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const LoadingTransaction = sequelize.define('LoadingTransaction', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  atl_id: { type: DataTypes.INTEGER, allowNull: false },
  actual_volume: { type: DataTypes.DECIMAL(10, 2), allowNull: true },
  loading_start: { type: DataTypes.DATE, allowNull: true },
  loading_end: { type: DataTypes.DATE, allowNull: true },
  status: { 
    type: DataTypes.ENUM('scheduled', 'in_progress', 'completed', 'cancelled'),
    defaultValue: 'scheduled' 
  },
  notes: { type: DataTypes.TEXT, allowNull: true }
}, { tableName: 'loading_transactions' });

module.exports = LoadingTransaction;