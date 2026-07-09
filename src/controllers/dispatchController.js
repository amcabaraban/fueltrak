const dispatchService = require('../services/dispatchService'); 
const { AuthorityToLoad, Truck, User } = require('../models'); 
 
class DispatchController { 
  async dashboard(req, res) { 
    try { const stats = await dispatchService.getDashboardStats(); res.json({ status: 'success', data: stats }); } 
    catch (error) { res.status(500).json({ status: 'error', message: error.message }); } 
  } 
  async pendingVerifications(req, res) { 
    try { 
      const pending = await AuthorityToLoad.findAll({ 
        where: { status: ['pending','verified'] }, 
        include: [ 
          { model: Truck, as: 'truck' }, 
          { model: User, as: 'client', attributes: ['id','email','company_name'] } 
        ], 
        order: [['created_at','DESC']] 
      }); 
      res.json({ status: 'success', data: pending }); 
    } catch (error) { res.status(500).json({ status: 'error', message: error.message }); } 
  } 
  async verifyATL(req, res) { 
    try { 
      const { id } = req.params; const { action, remarks } = req.body; 
      const atl = await AuthorityToLoad.findByPk(id); 
      if (!atl) return res.status(404).json({ status: 'error', message: 'ATL not found' }); 
      atl.status = action === 'approve' ? 'approved' : action === 'reject' ? 'rejected' : 'last_chance'; 
      atl.verified_by = req.user.id; if (remarks) atl.remarks = remarks; 
      await atl.save(); 
      res.json({ status: 'success', message: 'ATL ' + atl.status, data: atl }); 
    } catch (error) { res.status(400).json({ status: 'error', message: error.message }); } 
  } 
  async dispatch(req, res) { 
    try { 
      const { id } = req.params; const atl = await AuthorityToLoad.findByPk(id); 
      if (!atl || atl.status !== 'approved') return res.status(400).json({ status: 'error', message: 'ATL must be approved first' }); 
      atl.status = 'dispatched'; atl.dispatch_date = new Date(); await atl.save(); 
      res.json({ status: 'success', message: 'Truck dispatched', data: atl }); 
    } catch (error) { res.status(400).json({ status: 'error', message: error.message }); } 
  } 
} 
module.exports = new DispatchController(); 
