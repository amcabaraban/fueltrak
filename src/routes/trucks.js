const express = require('express'); 
const router = express.Router(); 
const { authenticate } = require('../middleware/auth'); 
const { Truck } = require('../models'); 
router.use(authenticate); 
router.get('/', async (req, res) => { 
  try { const trucks = await Truck.findAll({ where: { is_active: true } }); res.json({ status: 'success', data: trucks }); } 
  catch (error) { res.status(500).json({ status: 'error', message: error.message }); } 
}); 
router.post('/', async (req, res) => { 
  try { const truck = await Truck.create(req.body); res.status(201).json({ status: 'success', data: truck }); } 
  catch (error) { res.status(400).json({ status: 'error', message: error.message }); } 
}); 
module.exports = router; 
