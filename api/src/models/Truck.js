const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const Truck = sequelize.define('Truck', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  plate_no: { type: DataTypes.STRING(20), unique: true, allowNull: false },
  make: { type: DataTypes.STRING(50), allowNull: false },
  driver_name: { type: DataTypes.STRING(100), allowNull: true },
  hauler_name: { type: DataTypes.STRING(100), allowNull: true },
  total_capacity: { type: DataTypes.DECIMAL(10, 2), allowNull: false },
  num_tps: { type: DataTypes.INTEGER, defaultValue: 0 },
  calibration_date: { type: DataTypes.DATEONLY, allowNull: true },
  next_calibration_date: { type: DataTypes.DATEONLY, allowNull: true },
  discharge_line: { 
    type: DataTypes.ENUM('including', 'excluding'), 
    defaultValue: 'including' 
  },
  remarks: { type: DataTypes.TEXT, allowNull: true },
  is_active: { type: DataTypes.BOOLEAN, defaultValue: true }
}, { tableName: 'trucks' });

module.exports = Truck;