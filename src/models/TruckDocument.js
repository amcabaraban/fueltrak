const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const TruckDocument = sequelize.define('TruckDocument', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  truck_id: { type: DataTypes.INTEGER, allowNull: false },
  document_type: { type: DataTypes.STRING(50), allowNull: false },
  document_number: { type: DataTypes.STRING(100), allowNull: true },
  issue_date: { type: DataTypes.DATEONLY, allowNull: true },
  expiry_date: { type: DataTypes.DATEONLY, allowNull: false },
  status: { 
    type: DataTypes.ENUM('valid', 'expiring_soon', 'expired'), 
    defaultValue: 'valid' 
  },
  file_path: { type: DataTypes.STRING(255), allowNull: true },
  reminder_sent: { type: DataTypes.BOOLEAN, defaultValue: false }
}, { tableName: 'truck_documents' });

module.exports = TruckDocument;