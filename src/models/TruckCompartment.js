const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const TruckCompartment = sequelize.define('TruckCompartment', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  truck_id: { type: DataTypes.INTEGER, allowNull: false },
  compartment_number: { type: DataTypes.INTEGER, allowNull: false },
  capacity: { type: DataTypes.DECIMAL(10, 2), allowNull: false }
}, { tableName: 'truck_compartments' });

module.exports = TruckCompartment;
