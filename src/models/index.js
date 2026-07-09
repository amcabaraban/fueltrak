const User = require('./User');
const Truck = require('./Truck');
const TruckDocument = require('./TruckDocument');
const AuthorityToLoad = require('./AuthorityToLoad');

// Define associations
User.hasMany(AuthorityToLoad, { foreignKey: 'client_id', as: 'authorities' });
AuthorityToLoad.belongsTo(User, { foreignKey: 'client_id', as: 'client' });

Truck.hasMany(TruckDocument, { foreignKey: 'truck_id', as: 'documents' });
TruckDocument.belongsTo(Truck, { foreignKey: 'truck_id' });

Truck.hasMany(AuthorityToLoad, { foreignKey: 'truck_id', as: 'authorities' });
AuthorityToLoad.belongsTo(Truck, { foreignKey: 'truck_id', as: 'truck' });

module.exports = { User, Truck, TruckDocument, AuthorityToLoad };