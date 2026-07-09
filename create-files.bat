@echo off
cd /d C:\laragon\www\fueltrak-node

echo Creating missing files...

REM Create services directory
mkdir src\services 2>nul
mkdir src\controllers 2>nul
mkdir src\middleware 2>nul
mkdir src\routes 2>nul

REM Auth Service
echo const { User } = require('../models'); > src\services\authService.js
echo const jwt = require('jsonwebtoken'); >> src\services\authService.js
echo. >> src\services\authService.js
echo class AuthService { >> src\services\authService.js
echo   async register(userData) { >> src\services\authService.js
echo     const exists = await User.findOne({ where: { email: userData.email } }); >> src\services\authService.js
echo     if (exists) throw new Error('Email already registered'); >> src\services\authService.js
echo     return await User.create(userData); >> src\services\authService.js
echo   } >> src\services\authService.js
echo. >> src\services\authService.js
echo   async login(email, password) { >> src\services\authService.js
echo     const user = await User.findOne({ where: { email } }); >> src\services\authService.js
echo     if (!user ^|^| !(await user.comparePassword(password))) throw new Error('Invalid credentials'); >> src\services\authService.js
echo     if (!user.is_active) throw new Error('Account deactivated'); >> src\services\authService.js
echo     await user.update({ last_login: new Date() }); >> src\services\authService.js
echo     const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET ^|^| 'secret', { expiresIn: '24h' }); >> src\services\authService.js
echo     return { token, user: { id: user.id, email: user.email, role: user.role, mobile: user.mobile, company_name: user.company_name } }; >> src\services\authService.js
echo   } >> src\services\authService.js
echo } >> src\services\authService.js
echo module.exports = new AuthService(); >> src\services\authService.js

echo ✅ Auth service created

REM Dispatch Service
echo const { AuthorityToLoad, Truck } = require('../models'); > src\services\dispatchService.js
echo const { Op } = require('sequelize'); >> src\services\dispatchService.js
echo. >> src\services\dispatchService.js
echo class DispatchService { >> src\services\dispatchService.js
echo   async getDashboardStats() { >> src\services\dispatchService.js
echo     const today = new Date(); today.setHours(0,0,0,0); >> src\services\dispatchService.js
echo     const [loaded, pending, scheduled, recent] = await Promise.all([ >> src\services\dispatchService.js
echo       AuthorityToLoad.count({ where: { status: 'dispatched', dispatch_date: { [Op.gte]: today } } }), >> src\services\dispatchService.js
echo       AuthorityToLoad.count({ where: { status: 'pending' } }), >> src\services\dispatchService.js
echo       AuthorityToLoad.count({ where: { scheduled_date: today, status: ['approved','verified'] } }), >> src\services\dispatchService.js
echo       AuthorityToLoad.findAll({ where: { status: 'dispatched' }, include: [{ model: Truck, as: 'truck' }], order: [['dispatch_date','DESC']], limit: 5 }) >> src\services\dispatchService.js
echo     ]); >> src\services\dispatchService.js
echo     return { loadedToday: loaded, pendingCount: pending, scheduledToday: scheduled, recentDispatches: recent }; >> src\services\dispatchService.js
echo   } >> src\services\dispatchService.js
echo } >> src\services\dispatchService.js
echo module.exports = new DispatchService(); >> src\services\dispatchService.js

echo ✅ Dispatch service created

REM Middleware
echo const jwt = require('jsonwebtoken'); > src\middleware\auth.js
echo const { User } = require('../models'); >> src\middleware\auth.js
echo. >> src\middleware\auth.js
echo const authenticate = async (req, res, next) =^> { >> src\middleware\auth.js
echo   try { >> src\middleware\auth.js
echo     const token = req.header('Authorization')?.replace('Bearer ', ''); >> src\middleware\auth.js
echo     if (!token) throw new Error(); >> src\middleware\auth.js
echo     const decoded = jwt.verify(token, process.env.JWT_SECRET ^|^| 'secret'); >> src\middleware\auth.js
echo     const user = await User.findByPk(decoded.id); >> src\middleware\auth.js
echo     if (!user ^|^| !user.is_active) throw new Error(); >> src\middleware\auth.js
echo     req.user = user; >> src\middleware\auth.js
echo     next(); >> src\middleware\auth.js
echo   } catch (error) { >> src\middleware\auth.js
echo     res.status(401).json({ status: 'error', message: 'Please authenticate' }); >> src\middleware\auth.js
echo   } >> src\middleware\auth.js
echo }; >> src\middleware\auth.js
echo. >> src\middleware\auth.js
echo const authorize = (...roles) =^> { >> src\middleware\auth.js
echo   return (req, res, next) =^> { >> src\middleware\auth.js
echo     if (!roles.includes(req.user.role)) return res.status(403).json({ status: 'error', message: 'Access denied' }); >> src\middleware\auth.js
echo     next(); >> src\middleware\auth.js
echo   }; >> src\middleware\auth.js
echo }; >> src\middleware\auth.js
echo module.exports = { authenticate, authorize }; >> src\middleware\auth.js

echo ✅ Middleware created

REM Controllers
echo const authService = require('../services/authService'); > src\controllers\authController.js
echo. >> src\controllers\authController.js
echo class AuthController { >> src\controllers\authController.js
echo   async register(req, res) { >> src\controllers\authController.js
echo     try { const user = await authService.register(req.body); res.status(201).json({ status: 'success', user }); } >> src\controllers\authController.js
echo     catch (error) { res.status(400).json({ status: 'error', message: error.message }); } >> src\controllers\authController.js
echo   } >> src\controllers\authController.js
echo   async login(req, res) { >> src\controllers\authController.js
echo     try { const result = await authService.login(req.body.email, req.body.password); res.json({ status: 'success', ...result }); } >> src\controllers\authController.js
echo     catch (error) { res.status(401).json({ status: 'error', message: error.message }); } >> src\controllers\authController.js
echo   } >> src\controllers\authController.js
echo } >> src\controllers\authController.js
echo module.exports = new AuthController(); >> src\controllers\authController.js

echo ✅ Auth controller created

echo const dispatchService = require('../services/dispatchService'); > src\controllers\dispatchController.js
echo const { AuthorityToLoad, Truck, User } = require('../models'); >> src\controllers\dispatchController.js
echo. >> src\controllers\dispatchController.js
echo class DispatchController { >> src\controllers\dispatchController.js
echo   async dashboard(req, res) { >> src\controllers\dispatchController.js
echo     try { const stats = await dispatchService.getDashboardStats(); res.json({ status: 'success', data: stats }); } >> src\controllers\dispatchController.js
echo     catch (error) { res.status(500).json({ status: 'error', message: error.message }); } >> src\controllers\dispatchController.js
echo   } >> src\controllers\dispatchController.js
echo   async pendingVerifications(req, res) { >> src\controllers\dispatchController.js
echo     try { >> src\controllers\dispatchController.js
echo       const pending = await AuthorityToLoad.findAll({ >> src\controllers\dispatchController.js
echo         where: { status: ['pending','verified'] }, >> src\controllers\dispatchController.js
echo         include: [ >> src\controllers\dispatchController.js
echo           { model: Truck, as: 'truck' }, >> src\controllers\dispatchController.js
echo           { model: User, as: 'client', attributes: ['id','email','company_name'] } >> src\controllers\dispatchController.js
echo         ], >> src\controllers\dispatchController.js
echo         order: [['created_at','DESC']] >> src\controllers\dispatchController.js
echo       }); >> src\controllers\dispatchController.js
echo       res.json({ status: 'success', data: pending }); >> src\controllers\dispatchController.js
echo     } catch (error) { res.status(500).json({ status: 'error', message: error.message }); } >> src\controllers\dispatchController.js
echo   } >> src\controllers\dispatchController.js
echo   async verifyATL(req, res) { >> src\controllers\dispatchController.js
echo     try { >> src\controllers\dispatchController.js
echo       const { id } = req.params; const { action, remarks } = req.body; >> src\controllers\dispatchController.js
echo       const atl = await AuthorityToLoad.findByPk(id); >> src\controllers\dispatchController.js
echo       if (!atl) return res.status(404).json({ status: 'error', message: 'ATL not found' }); >> src\controllers\dispatchController.js
echo       atl.status = action === 'approve' ? 'approved' : action === 'reject' ? 'rejected' : 'last_chance'; >> src\controllers\dispatchController.js
echo       atl.verified_by = req.user.id; if (remarks) atl.remarks = remarks; >> src\controllers\dispatchController.js
echo       await atl.save(); >> src\controllers\dispatchController.js
echo       res.json({ status: 'success', message: 'ATL ' + atl.status, data: atl }); >> src\controllers\dispatchController.js
echo     } catch (error) { res.status(400).json({ status: 'error', message: error.message }); } >> src\controllers\dispatchController.js
echo   } >> src\controllers\dispatchController.js
echo   async dispatch(req, res) { >> src\controllers\dispatchController.js
echo     try { >> src\controllers\dispatchController.js
echo       const { id } = req.params; const atl = await AuthorityToLoad.findByPk(id); >> src\controllers\dispatchController.js
echo       if (!atl ^|^| atl.status !== 'approved') return res.status(400).json({ status: 'error', message: 'ATL must be approved first' }); >> src\controllers\dispatchController.js
echo       atl.status = 'dispatched'; atl.dispatch_date = new Date(); await atl.save(); >> src\controllers\dispatchController.js
echo       res.json({ status: 'success', message: 'Truck dispatched', data: atl }); >> src\controllers\dispatchController.js
echo     } catch (error) { res.status(400).json({ status: 'error', message: error.message }); } >> src\controllers\dispatchController.js
echo   } >> src\controllers\dispatchController.js
echo } >> src\controllers\dispatchController.js
echo module.exports = new DispatchController(); >> src\controllers\dispatchController.js

echo ✅ Dispatch controller created

REM Routes
echo const express = require('express'); > src\routes\auth.js
echo const router = express.Router(); >> src\routes\auth.js
echo const authController = require('../controllers/authController'); >> src\routes\auth.js
echo const { authenticate } = require('../middleware/auth'); >> src\routes\auth.js
echo. >> src\routes\auth.js
echo router.post('/register', authController.register); >> src\routes\auth.js
echo router.post('/login', authController.login); >> src\routes\auth.js
echo router.get('/profile', authenticate, (req, res) =^> { res.json({ user: req.user }); }); >> src\routes\auth.js
echo module.exports = router; >> src\routes\auth.js

echo ✅ Auth routes created

echo const express = require('express'); > src\routes\trucks.js
echo const router = express.Router(); >> src\routes\trucks.js
echo const { authenticate } = require('../middleware/auth'); >> src\routes\trucks.js
echo const { Truck } = require('../models'); >> src\routes\trucks.js
echo router.use(authenticate); >> src\routes\trucks.js
echo router.get('/', async (req, res) =^> { >> src\routes\trucks.js
echo   try { const trucks = await Truck.findAll({ where: { is_active: true } }); res.json({ status: 'success', data: trucks }); } >> src\routes\trucks.js
echo   catch (error) { res.status(500).json({ status: 'error', message: error.message }); } >> src\routes\trucks.js
echo }); >> src\routes\trucks.js
echo router.post('/', async (req, res) =^> { >> src\routes\trucks.js
echo   try { const truck = await Truck.create(req.body); res.status(201).json({ status: 'success', data: truck }); } >> src\routes\trucks.js
echo   catch (error) { res.status(400).json({ status: 'error', message: error.message }); } >> src\routes\trucks.js
echo }); >> src\routes\trucks.js
echo module.exports = router; >> src\routes\trucks.js

echo ✅ Truck routes created

echo const express = require('express'); > src\routes\dispatch.js
echo const router = express.Router(); >> src\routes\dispatch.js
echo const dispatchController = require('../controllers/dispatchController'); >> src\routes\dispatch.js
echo const { authenticate, authorize } = require('../middleware/auth'); >> src\routes\dispatch.js
echo router.use(authenticate); >> src\routes\dispatch.js
echo router.get('/dashboard', dispatchController.dashboard); >> src\routes\dispatch.js
echo router.get('/pending', authorize('dispatcher', 'management'), dispatchController.pendingVerifications); >> src\routes\dispatch.js
echo router.post('/verify/:id', authorize('dispatcher', 'management'), dispatchController.verifyATL); >> src\routes\dispatch.js
echo router.post('/dispatch/:id', authorize('dispatcher', 'management'), dispatchController.dispatch); >> src\routes\dispatch.js
echo module.exports = router; >> src\routes\dispatch.js

echo ✅ Dispatch routes created

echo.
echo ========================================
echo  All files created successfully!
echo ========================================
echo.
echo Run: node server.js