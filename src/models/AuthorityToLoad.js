const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const AuthorityToLoad = sequelize.define('AuthorityToLoad', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  client_id: { type: DataTypes.INTEGER, allowNull: false },
  truck_id: { type: DataTypes.INTEGER, allowNull: false },
  atl_code: { type: DataTypes.STRING(15), unique: true, allowNull: true },
  company: { type: DataTypes.STRING(150), allowNull: true },
  so_number: { type: DataTypes.STRING(50), allowNull: true },
  has_si: { type: DataTypes.BOOLEAN, defaultValue: false, comment: 'With SI or No SI' },
  volume: { type: DataTypes.DECIMAL(10, 2), allowNull: true },
  actual_volume: { type: DataTypes.DECIMAL(10, 2), allowNull: true },
  date: { type: DataTypes.DATEONLY, allowNull: true },
  hauler: { type: DataTypes.STRING(100), allowNull: true },
  plate_no: { type: DataTypes.STRING(20), allowNull: true },
  driver_name: { type: DataTypes.STRING(100), allowNull: true },
  contact_number: { type: DataTypes.STRING(20), allowNull: true },
  status: { 
    type: DataTypes.ENUM('pending', 'verified', 'approved', 'rejected', 'dispatched', 'cancelled', 'completed', 'last_chance'),
    defaultValue: 'pending' 
  },
  scheduled_date: { type: DataTypes.DATEONLY, allowNull: false },
  dispatch_date: { type: DataTypes.DATE, allowNull: true },
  completed_date: { type: DataTypes.DATE, allowNull: true },
  last_chance_granted: { type: DataTypes.BOOLEAN, defaultValue: false },
  management_approval: { type: DataTypes.BOOLEAN, defaultValue: false },
  approved_by: { type: DataTypes.INTEGER, allowNull: true },
  verified_by: { type: DataTypes.INTEGER, allowNull: true },
  completed_by: { type: DataTypes.INTEGER, allowNull: true },
  remarks: { type: DataTypes.TEXT, allowNull: true },
  revision_history: { type: DataTypes.TEXT, allowNull: true }
}, { tableName: 'authority_to_load' });

module.exports = AuthorityToLoad;