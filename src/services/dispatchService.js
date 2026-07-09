const { AuthorityToLoad, Truck } = require('../models'); 
const { Op } = require('sequelize'); 
 
class DispatchService { 
  async getDashboardStats() { 
    const today = new Date(); today.setHours(0,0,0,0); 
    const [loaded, pending, scheduled, recent] = await Promise.all([ 
      AuthorityToLoad.count({ where: { status: 'dispatched', dispatch_date: { [Op.gte]: today } } }), 
      AuthorityToLoad.count({ where: { status: 'pending' } }), 
      AuthorityToLoad.count({ where: { scheduled_date: today, status: ['approved','verified'] } }), 
      AuthorityToLoad.findAll({ where: { status: 'dispatched' }, include: [{ model: Truck, as: 'truck' }], order: [['dispatch_date','DESC']], limit: 5 }) 
    ]); 
    return { loadedToday: loaded, pendingCount: pending, scheduledToday: scheduled, recentDispatches: recent }; 
  } 
} 
module.exports = new DispatchService(); 
