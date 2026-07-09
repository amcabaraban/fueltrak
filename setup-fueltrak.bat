@echo off
setlocal enabledelayedexpansion

echo ========================================
echo  FuelTrak Logistics System Setup
echo  Node.js + MySQL on Laragon
echo ========================================
echo.

REM Set project directory
set PROJECT_DIR=C:\laragon\www\fueltrak-node

REM Check if Laragon exists
if not exist "C:\laragon" (
    echo [ERROR] Laragon not found at C:\laragon
    echo Please install Laragon first from https://laragon.org
    pause
    exit /b 1
)

REM Try to find Node.js in common locations
set NODE_FOUND=0

REM Check standard Node.js installation
where node >nul 2>nul
if %ERRORLEVEL% equ 0 (
    set NODE_FOUND=1
    goto :node_found
)

REM Check Laragon's Node.js
if exist "C:\laragon\bin\nodejs\node-v18\node.exe" (
    set "PATH=C:\laragon\bin\nodejs\node-v18;%PATH%"
    set NODE_FOUND=1
    goto :node_found
)

if exist "C:\laragon\bin\nodejs\node-v16\node.exe" (
    set "PATH=C:\laragon\bin\nodejs\node-v16;%PATH%"
    set NODE_FOUND=1
    goto :node_found
)

REM Check Program Files
if exist "C:\Program Files\nodejs\node.exe" (
    set "PATH=C:\Program Files\nodejs;%PATH%"
    set NODE_FOUND=1
    goto :node_found
)

if exist "C:\Program Files (x86)\nodejs\node.exe" (
    set "PATH=C:\Program Files (x86)\nodejs;%PATH%"
    set NODE_FOUND=1
    goto :node_found
)

:node_not_found
echo [ERROR] Node.js is not installed or not found in PATH
echo.
echo Please install Node.js:
echo 1. Download from https://nodejs.org (LTS version recommended)
echo 2. Or install via Laragon: Right-click Laragon ^> Tools ^> Quick Add ^> Node.js
echo.
echo After installation, restart this batch file.
pause
exit /b 1

:node_found
echo [INFO] Node.js found!
node --version
npm --version
echo.

REM Check MySQL access
echo [INFO] Checking MySQL connection...
mysql -u root -e "SELECT 1" >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [WARNING] Cannot connect to MySQL. Make sure Laragon MySQL is running.
    echo Starting Laragon MySQL...
    start "" "C:\laragon\laragon.exe" --start
    timeout /t 5 /nobreak >nul
)

echo [INFO] Creating project structure...
echo.

REM Create main project directory
if not exist "%PROJECT_DIR%" mkdir "%PROJECT_DIR%"
cd /d "%PROJECT_DIR%"

REM Create directory structure
echo Creating directories...
(
    mkdir src 2>nul
    mkdir src\config 2>nul
    mkdir src\models 2>nul
    mkdir src\controllers 2>nul
    mkdir src\services 2>nul
    mkdir src\middleware 2>nul
    mkdir src\routes 2>nul
    mkdir src\jobs 2>nul
    mkdir src\utils 2>nul
    mkdir src\validators 2>nul
    mkdir src\seeders 2>nul
    mkdir public 2>nul
    mkdir public\css 2>nul
    mkdir public\js 2>nul
    mkdir logs 2>nul
    mkdir uploads 2>nul
    mkdir tests 2>nul
)
echo Directories created successfully.
echo.

REM Initialize package.json
if not exist "package.json" (
    echo Creating package.json...
    call npm init -y >nul 2>nul
)

REM Install dependencies
echo.
echo ========================================
echo  Installing Dependencies
echo ========================================
echo.

echo Installing core dependencies...
call npm install express mysql2 sequelize jsonwebtoken bcryptjs cors dotenv 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to install core dependencies
    pause
    exit /b 1
)

echo Installing additional packages...
call npm install joi helmet morgan compression winston ioredis 2>nul
call npm install socket.io uuid multer 2>nul
call npm install node-cron axios 2>nul

echo Installing dev dependencies...
call npm install -D nodemon 2>nul

echo Dependencies installed successfully.
echo.

REM Create all project files
echo ========================================
echo  Creating Project Files
echo ========================================
echo.

REM .env file
echo Creating .env file...
(
echo NODE_ENV=development
echo PORT=3000
echo HOST=localhost
echo.
echo # Database Configuration (Laragon MySQL)
echo DB_HOST=localhost
echo DB_PORT=3306
echo DB_NAME=fueltrak_node
echo DB_USER=root
echo DB_PASSWORD=
echo DB_DIALECT=mysql
echo.
echo # JWT Configuration
echo JWT_SECRET=Fu3lTr4k_S3cur3_K3y_2024_NodeJS
echo JWT_EXPIRES_IN=24h
echo JWT_REFRESH_EXPIRES_IN=7d
echo.
echo # Redis Configuration
echo REDIS_HOST=localhost
echo REDIS_PORT=6379
echo.
echo # Application
echo FRONTEND_URL=http://localhost:3000
echo API_URL=http://localhost:3000/api
echo UPLOAD_PATH=./uploads
echo MAX_FILE_SIZE=10mb
) > .env

echo .env created.
echo.

REM Create .gitignore
(
echo node_modules/
echo .env
echo logs/
echo uploads/
echo *.log
echo .DS_Store
echo dist/
echo coverage/
) > .gitignore

REM Create database config
echo Creating database configuration...
(
echo const { Sequelize } = require('sequelize');
echo require('dotenv').config();
echo.
echo const sequelize = new Sequelize(
echo   process.env.DB_NAME,
echo   process.env.DB_USER,
echo   process.env.DB_PASSWORD,
echo   {
echo     host: process.env.DB_HOST,
echo     port: process.env.DB_PORT,
echo     dialect: process.env.DB_DIALECT,
echo     logging: false,
echo     pool: {
echo       max: 10,
echo       min: 0,
echo       acquire: 30000,
echo       idle: 10000
echo     }
echo   }
echo );
echo.
echo const testConnection = async () => {
echo   try {
echo     await sequelize.authenticate();
echo     console.log('✅ MySQL connected successfully');
echo   } catch (error) {
echo     console.error('❌ Unable to connect to MySQL:', error.message);
echo   }
echo };
echo.
echo module.exports = { sequelize, testConnection };
) > src\config\database.js

echo Database config created.
echo.

REM Create models
echo Creating models...
call :CreateAllModels

REM Create services
echo Creating services...
call :CreateAllServices

REM Create controllers
echo Creating controllers...
call :CreateAllControllers

REM Create middleware
echo Creating middleware...
call :CreateAllMiddleware

REM Create routes
echo Creating routes...
call :CreateAllRoutes

REM Create server.js
echo Creating server.js...
call :CreateServerFile

REM Create frontend
echo Creating frontend...
call :CreateFrontend

REM Create seeder
echo Creating database seeder...
call :CreateSeeder

REM Create nodemon.json
(
echo {
echo   "watch": ["src", "server.js"],
echo   "ext": "js,json,html",
echo   "ignore": ["node_modules", "logs", "uploads"]
echo }
) > nodemon.json

REM Update package.json scripts
echo Updating package.json scripts...
node -e "const pkg=require('./package.json');pkg.scripts={start:'node server.js',dev:'nodemon server.js',seed:'node src/seeders/seed.js'};require('fs').writeFileSync('package.json',JSON.stringify(pkg,null,2))"

echo.
echo ========================================
echo  Setting Up Database
echo ========================================
echo.

echo Creating MySQL database...
mysql -u root -e "CREATE DATABASE IF NOT EXISTS fueltrak_node CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" 2>nul
if %ERRORLEVEL% equ 0 (
    echo ✅ Database 'fueltrak_node' created successfully
) else (
    echo ⚠️  Please create database manually in HeidiSQL:
    echo     CREATE DATABASE fueltrak_node;
)

echo.
echo Running database seeder...
node src/seeders/seed.js 2>nul
if %ERRORLEVEL% neq 0 (
    echo ⚠️  Seeder had issues. You can run it manually: npm run seed
)

echo.
echo ========================================
echo  ✅ Setup Complete!
echo ========================================
echo.
echo 🚀 FuelTrak Logistics System is ready!
echo.
echo 📁 Project location: %PROJECT_DIR%
echo.
echo 🔑 Test Accounts:
echo    Management: admin@fueltrak.com / password123
echo    Dispatcher: dispatcher@fueltrak.com / password123
echo    Client:     client1@hauler.com / password123
echo.
echo 📋 Quick Start Commands:
echo    cd %PROJECT_DIR%
echo    npm run dev
echo.
echo 🌐 Access the application at:
echo    http://localhost:3000
echo.
echo ════════════════════════════════════════
echo.
echo Starting the application now...
echo.
cd /d "%PROJECT_DIR%"
npm run dev

pause
exit /b 0

REM ============================================
REM  Function: Create All Models
REM ============================================
:CreateAllModels

REM User Model
(
echo const { DataTypes } = require('sequelize');
echo const { sequelize } = require('../config/database');
echo const bcrypt = require('bcryptjs');
echo.
echo const User = sequelize.define('User', {
echo   id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
echo   email: { type: DataTypes.STRING(100), unique: true, allowNull: false },
echo   password: { type: DataTypes.STRING(255), allowNull: false },
echo   mobile: { type: DataTypes.STRING(20), allowNull: false },
echo   role: { type: DataTypes.ENUM('client', 'dispatcher', 'management'), defaultValue: 'client' },
echo   company_name: { type: DataTypes.STRING(150), allowNull: true },
echo   is_active: { type: DataTypes.BOOLEAN, defaultValue: true },
echo   last_login: { type: DataTypes.DATE, allowNull: true }
echo }, {
echo   tableName: 'users',
echo   hooks: {
echo     beforeCreate: async (user) => {
echo       user.password = await bcrypt.hash(user.password, 12);
echo     }
echo   }
echo });
echo.
echo User.prototype.comparePassword = async function(password) {
echo   return await bcrypt.compare(password, this.password);
echo };
echo.
echo User.prototype.toJSON = function() {
echo   const values = { ...this.get() };
echo   delete values.password;
echo   return values;
echo };
echo.
echo module.exports = User;
) > src\models\User.js

REM Truck Model
(
echo const { DataTypes } = require('sequelize');
echo const { sequelize } = require('../config/database');
echo.
echo const Truck = sequelize.define('Truck', {
echo   id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
echo   plate_no: { type: DataTypes.STRING(20), unique: true, allowNull: false },
echo   make: { type: DataTypes.STRING(50), allowNull: false },
echo   driver_name: { type: DataTypes.STRING(100), allowNull: true },
echo   hauler_name: { type: DataTypes.STRING(100), allowNull: true },
echo   total_capacity: { type: DataTypes.DECIMAL(10, 2), allowNull: false },
echo   num_tps: { type: DataTypes.INTEGER, defaultValue: 0 },
echo   calibration_date: { type: DataTypes.DATEONLY, allowNull: true },
echo   next_calibration_date: { type: DataTypes.DATEONLY, allowNull: true },
echo   discharge_line: { type: DataTypes.ENUM('including', 'excluding'), defaultValue: 'including' },
echo   remarks: { type: DataTypes.TEXT, allowNull: true },
echo   is_active: { type: DataTypes.BOOLEAN, defaultValue: true }
echo }, { tableName: 'trucks' });
echo.
echo module.exports = Truck;
) > src\models\Truck.js

REM Other models
(
echo const { DataTypes } = require('sequelize');
echo const { sequelize } = require('../config/database');
echo const TruckCompartment = sequelize.define('TruckCompartment', {
echo   id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
echo   truck_id: { type: DataTypes.INTEGER, allowNull: false },
echo   compartment_number: { type: DataTypes.INTEGER, allowNull: false },
echo   capacity: { type: DataTypes.DECIMAL(10, 2), allowNull: false }
echo }, { tableName: 'truck_compartments' });
echo module.exports = TruckCompartment;
) > src\models\TruckCompartment.js

(
echo const { DataTypes } = require('sequelize');
echo const { sequelize } = require('../config/database');
echo const TruckDocument = sequelize.define('TruckDocument', {
echo   id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
echo   truck_id: { type: DataTypes.INTEGER, allowNull: false },
echo   document_type: { type: DataTypes.STRING(50), allowNull: false },
echo   document_number: { type: DataTypes.STRING(100), allowNull: true },
echo   issue_date: { type: DataTypes.DATEONLY, allowNull: true },
echo   expiry_date: { type: DataTypes.DATEONLY, allowNull: false },
echo   status: { type: DataTypes.ENUM('valid', 'expiring_soon', 'expired'), defaultValue: 'valid' },
echo   file_path: { type: DataTypes.STRING(255), allowNull: true },
echo   reminder_sent: { type: DataTypes.BOOLEAN, defaultValue: false }
echo }, { tableName: 'truck_documents' });
echo module.exports = TruckDocument;
) > src\models\TruckDocument.js

(
echo const { DataTypes } = require('sequelize');
echo const { sequelize } = require('../config/database');
echo const AuthorityToLoad = sequelize.define('AuthorityToLoad', {
echo   id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
echo   client_id: { type: DataTypes.INTEGER, allowNull: false },
echo   truck_id: { type: DataTypes.INTEGER, allowNull: false },
echo   status: { 
echo     type: DataTypes.ENUM('pending', 'verified', 'approved', 'rejected', 'dispatched', 'last_chance'),
echo     defaultValue: 'pending' 
echo   },
echo   scheduled_date: { type: DataTypes.DATEONLY, allowNull: false },
echo   dispatch_date: { type: DataTypes.DATE, allowNull: true },
echo   last_chance_granted: { type: DataTypes.BOOLEAN, defaultValue: false },
echo   last_chance_reason: { type: DataTypes.TEXT, allowNull: true },
echo   management_approval: { type: DataTypes.BOOLEAN, defaultValue: false },
echo   approved_by: { type: DataTypes.INTEGER, allowNull: true },
echo   verified_by: { type: DataTypes.INTEGER, allowNull: true },
echo   remarks: { type: DataTypes.TEXT, allowNull: true }
echo }, { tableName: 'authority_to_load' });
echo module.exports = AuthorityToLoad;
) > src\models\AuthorityToLoad.js

(
echo const { DataTypes } = require('sequelize');
echo const { sequelize } = require('../config/database');
echo const LoadingTransaction = sequelize.define('LoadingTransaction', {
echo   id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
echo   atl_id: { type: DataTypes.INTEGER, allowNull: false },
echo   actual_volume: { type: DataTypes.DECIMAL(10, 2), allowNull: true },
echo   loading_start: { type: DataTypes.DATE, allowNull: true },
echo   loading_end: { type: DataTypes.DATE, allowNull: true },
echo   status: { 
echo     type: DataTypes.ENUM('scheduled', 'in_progress', 'completed', 'cancelled'),
echo     defaultValue: 'scheduled' 
echo   },
echo   notes: { type: DataTypes.TEXT, allowNull: true }
echo }, { tableName: 'loading_transactions' });
echo module.exports = LoadingTransaction;
) > src\models\LoadingTransaction.js

(
echo const { DataTypes } = require('sequelize');
echo const { sequelize } = require('../config/database');
echo const Notification = sequelize.define('Notification', {
echo   id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
echo   user_id: { type: DataTypes.INTEGER, allowNull: false },
echo   title: { type: DataTypes.STRING(200), allowNull: false },
echo   message: { type: DataTypes.TEXT, allowNull: false },
echo   type: { type: DataTypes.STRING(50), defaultValue: 'system' },
echo   data: { type: DataTypes.TEXT, allowNull: true },
echo   is_read: { type: DataTypes.BOOLEAN, defaultValue: false },
echo   read_at: { type: DataTypes.DATE, allowNull: true }
echo }, { tableName: 'notifications' });
echo module.exports = Notification;
) > src\models\Notification.js

REM Models index
(
echo const User = require('./User');
echo const Truck = require('./Truck');
echo const TruckCompartment = require('./TruckCompartment');
echo const TruckDocument = require('./TruckDocument');
echo const AuthorityToLoad = require('./AuthorityToLoad');
echo const LoadingTransaction = require('./LoadingTransaction');
echo const Notification = require('./Notification');
echo.
echo // Associations
echo User.hasMany(AuthorityToLoad, { foreignKey: 'client_id', as: 'authorities' });
echo User.hasMany(Notification, { foreignKey: 'user_id', as: 'notifications' });
echo Truck.hasMany(TruckCompartment, { foreignKey: 'truck_id', as: 'compartments' });
echo Truck.hasMany(TruckDocument, { foreignKey: 'truck_id', as: 'documents' });
echo Truck.hasMany(AuthorityToLoad, { foreignKey: 'truck_id', as: 'authorities' });
echo AuthorityToLoad.belongsTo(User, { foreignKey: 'client_id', as: 'client' });
echo AuthorityToLoad.belongsTo(Truck, { foreignKey: 'truck_id', as: 'truck' });
echo AuthorityToLoad.belongsTo(User, { foreignKey: 'approved_by', as: 'approver' });
echo AuthorityToLoad.hasOne(LoadingTransaction, { foreignKey: 'atl_id', as: 'transaction' });
echo TruckCompartment.belongsTo(Truck, { foreignKey: 'truck_id' });
echo TruckDocument.belongsTo(Truck, { foreignKey: 'truck_id' });
echo Notification.belongsTo(User, { foreignKey: 'user_id' });
echo.
echo module.exports = {
echo   User, Truck, TruckCompartment, TruckDocument,
echo   AuthorityToLoad, LoadingTransaction, Notification
echo };
) > src\models\index.js

goto :EOF

REM ============================================
REM  Function: Create All Services
REM ============================================
:CreateAllServices

(
echo const { User } = require('../models');
echo const jwt = require('jsonwebtoken');
echo.
echo class AuthService {
echo   async register(userData) {
echo     const exists = await User.findOne({ where: { email: userData.email } });
echo     if (exists) throw new Error('Email already registered');
echo     return await User.create(userData);
echo   }
echo.
echo   async login(email, password) {
echo     const user = await User.findOne({ where: { email } });
echo     if (!user || !(await user.comparePassword(password))) throw new Error('Invalid credentials');
echo     if (!user.is_active) throw new Error('Account deactivated');
echo     await user.update({ last_login: new Date() });
echo     const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
echo     return { token, user: { id: user.id, email: user.email, role: user.role, mobile: user.mobile, company_name: user.company_name } };
echo   }
echo }
echo module.exports = new AuthService();
) > src\services\authService.js

(
echo const { AuthorityToLoad, Truck, Notification } = require('../models');
echo const { Op } = require('sequelize');
echo.
echo class DispatchService {
echo   async getDashboardStats() {
echo     const today = new Date(); today.setHours(0,0,0,0);
echo     const [loaded, pending, scheduled, volume, recent] = await Promise.all([
echo       AuthorityToLoad.count({ where: { status: 'dispatched', dispatch_date: { [Op.gte]: today } } }),
echo       AuthorityToLoad.count({ where: { status: 'pending' } }),
echo       AuthorityToLoad.count({ where: { scheduled_date: today, status: ['approved','verified'] } }),
echo       AuthorityToLoad.findAll({ where: { status: 'dispatched', dispatch_date: { [Op.gte]: today } }, include: [{ model: Truck, as: 'truck', attributes: ['total_capacity'] }] }),
echo       AuthorityToLoad.findAll({ where: { status: 'dispatched' }, include: [{ model: Truck, as: 'truck', attributes: ['plate_no','total_capacity'] }], order: [['dispatch_date','DESC']], limit: 5 })
echo     ]);
echo     const totalVol = volume.reduce((sum, a) => sum + parseFloat(a.truck?.total_capacity || 0), 0);
echo     return { loadedToday: loaded, pendingCount: pending, scheduledToday: scheduled, totalVolume: totalVol, recentDispatches: recent };
echo   }
echo }
echo module.exports = new DispatchService();
) > src\services\dispatchService.js

goto :EOF

REM ============================================
REM  Function: Create All Controllers
REM ============================================
:CreateAllControllers

(
echo const authService = require('../services/authService');
echo.
echo class AuthController {
echo   async register(req, res) {
echo     try {
echo       const user = await authService.register(req.body);
echo       res.status(201).json({ status: 'success', user });
echo     } catch (error) {
echo       res.status(400).json({ status: 'error', message: error.message });
echo     }
echo   }
echo   async login(req, res) {
echo     try {
echo       const result = await authService.login(req.body.email, req.body.password);
echo       res.json({ status: 'success', ...result });
echo     } catch (error) {
echo       res.status(401).json({ status: 'error', message: error.message });
echo     }
echo   }
echo }
echo module.exports = new AuthController();
) > src\controllers\authController.js

(
echo const dispatchService = require('../services/dispatchService');
echo const { AuthorityToLoad, Truck, User } = require('../models');
echo.
echo class DispatchController {
echo   async dashboard(req, res) {
echo     try {
echo       const stats = await dispatchService.getDashboardStats();
echo       res.json({ status: 'success', data: stats });
echo     } catch (error) {
echo       res.status(500).json({ status: 'error', message: error.message });
echo     }
echo   }
echo   async pendingVerifications(req, res) {
echo     try {
echo       const pending = await AuthorityToLoad.findAll({
echo         where: { status: ['pending', 'verified'] },
echo         include: [{ model: Truck, as: 'truck' }, { model: User, as: 'client', attributes: ['id','email','company_name'] }],
echo         order: [['created_at', 'DESC']]
echo       });
echo       res.json({ status: 'success', data: pending });
echo     } catch (error) {
echo       res.status(500).json({ status: 'error', message: error.message });
echo     }
echo   }
echo   async verifyATL(req, res) {
echo     try {
echo       const { id } = req.params;
echo       const { action, remarks } = req.body;
echo       const atl = await AuthorityToLoad.findByPk(id);
echo       if (!atl) return res.status(404).json({ status: 'error', message: 'ATL not found' });
echo       atl.status = action === 'approve' ? 'approved' : action === 'reject' ? 'rejected' : 'last_chance';
echo       atl.verified_by = req.user.id;
echo       if (remarks) atl.remarks = remarks;
echo       await atl.save();
echo       res.json({ status: 'success', message: `ATL ${atl.status}`, data: atl });
echo     } catch (error) {
echo       res.status(400).json({ status: 'error', message: error.message });
echo     }
echo   }
echo   async dispatch(req, res) {
echo     try {
echo       const { id } = req.params;
echo       const atl = await AuthorityToLoad.findByPk(id);
echo       if (!atl || atl.status !== 'approved') return res.status(400).json({ status: 'error', message: 'ATL must be approved first' });
echo       atl.status = 'dispatched';
echo       atl.dispatch_date = new Date();
echo       await atl.save();
echo       res.json({ status: 'success', message: 'Truck dispatched', data: atl });
echo     } catch (error) {
echo       res.status(400).json({ status: 'error', message: error.message });
echo     }
echo   }
echo }
echo module.exports = new DispatchController();
) > src\controllers\dispatchController.js

goto :EOF

REM ============================================
REM  Function: Create Middleware
REM ============================================
:CreateAllMiddleware

(
echo const jwt = require('jsonwebtoken');
echo const { User } = require('../models');
echo.
echo const authenticate = async (req, res, next) => {
echo   try {
echo     const token = req.header('Authorization')?.replace('Bearer ', '');
echo     if (!token) throw new Error();
echo     const decoded = jwt.verify(token, process.env.JWT_SECRET);
echo     const user = await User.findByPk(decoded.id);
echo     if (!user || !user.is_active) throw new Error();
echo     req.user = user;
echo     next();
echo   } catch (error) {
echo     res.status(401).json({ status: 'error', message: 'Please authenticate' });
echo   }
echo };
echo.
echo const authorize = (...roles) => {
echo   return (req, res, next) => {
echo     if (!roles.includes(req.user.role)) {
echo       return res.status(403).json({ status: 'error', message: 'Access denied' });
echo     }
echo     next();
echo   };
echo };
echo.
echo module.exports = { authenticate, authorize };
) > src\middleware\auth.js

goto :EOF

REM ============================================
REM  Function: Create Routes
REM ============================================
:CreateAllRoutes

(
echo const express = require('express');
echo const router = express.Router();
echo const authController = require('../controllers/authController');
echo const { authenticate } = require('../middleware/auth');
echo.
echo router.post('/register', authController.register);
echo router.post('/login', authController.login);
echo router.get('/profile', authenticate, (req, res) => { res.json({ user: req.user }); });
echo.
echo module.exports = router;
) > src\routes\auth.js

(
echo const express = require('express');
echo const router = express.Router();
echo const dispatchController = require('../controllers/dispatchController');
echo const { authenticate, authorize } = require('../middleware/auth');
echo.
echo router.use(authenticate);
echo router.get('/dashboard', dispatchController.dashboard);
echo router.get('/pending', authorize('dispatcher', 'management'), dispatchController.pendingVerifications);
echo router.post('/verify/:id', authorize('dispatcher', 'management'), dispatchController.verifyATL);
echo router.post('/dispatch/:id', authorize('dispatcher', 'management'), dispatchController.dispatch);
echo.
echo module.exports = router;
) > src\routes\dispatch.js

(
echo const express = require('express');
echo const router = express.Router();
echo const { authenticate } = require('../middleware/auth');
echo const { Truck } = require('../models');
echo.
echo router.use(authenticate);
echo router.get('/', async (req, res) => {
echo   const trucks = await Truck.findAll({ where: { is_active: true } });
echo   res.json({ status: 'success', data: trucks });
echo });
echo router.post('/', async (req, res) => {
echo   try {
echo     const truck = await Truck.create(req.body);
echo     res.status(201).json({ status: 'success', data: truck });
echo   } catch (error) {
echo     res.status(400).json({ status: 'error', message: error.message });
echo   }
echo });
echo.
echo module.exports = router;
) > src\routes\trucks.js

goto :EOF

REM ============================================
REM  Function: Create Server File
REM ============================================
:CreateServerFile

(
echo require('dotenv').config();
echo const express = require('express');
echo const cors = require('cors');
echo const helmet = require('helmet');
echo const morgan = require('morgan');
echo const compression = require('compression');
echo const path = require('path');
echo const { testConnection } = require('./src/config/database');
echo.
echo const authRoutes = require('./src/routes/auth');
echo const truckRoutes = require('./src/routes/trucks');
echo const dispatchRoutes = require('./src/routes/dispatch');
echo.
echo const app = express();
echo.
echo app.use(helmet({ contentSecurityPolicy: false }));
echo app.use(cors());
echo app.use(morgan('dev'));
echo app.use(compression());
echo app.use(express.json({ limit: '10mb' }));
echo app.use(express.urlencoded({ extended: true }));
echo app.use(express.static('public'));
echo.
echo app.use('/api/auth', authRoutes);
echo app.use('/api/trucks', truckRoutes);
echo app.use('/api/dispatch', dispatchRoutes);
echo.
echo app.get('/api/health', (req, res) => {
echo   res.json({ status: 'OK', timestamp: new Date(), uptime: process.uptime() });
echo });
echo.
echo app.get('/', (req, res) => {
echo   res.sendFile(path.join(__dirname, 'public', 'index.html'));
echo });
echo.
echo app.use((err, req, res, next) => {
echo   console.error(err.stack);
echo   res.status(500).json({ status: 'error', message: 'Internal server error' });
echo });
echo.
echo const PORT = process.env.PORT || 3000;
echo.
echo const start = async () => {
echo   await testConnection();
echo   const { sequelize } = require('./src/config/database');
echo   await sequelize.sync({ alter: true });
echo   console.log('✅ Database synced');
echo   app.listen(PORT, () => {
echo     console.log(`✅ Server running on http://localhost:${PORT}`);
echo   });
echo };
echo.
echo start();
) > server.js

goto :EOF

REM ============================================
REM  Function: Create Frontend
REM ============================================
:CreateFrontend

(
echo ^<!DOCTYPE html^>
echo ^<html lang="en"^>
echo ^<head^>
echo     ^<meta charset="UTF-8"^>
echo     ^<meta name="viewport" content="width=device-width, initial-scale=1.0"^>
echo     ^<title^>FuelTrak - Truck Logistics System^</title^>
echo     ^<script src="https://cdn.tailwindcss.com"^>^</script^>
echo     ^<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css"^>
echo ^</head^>
echo ^<body class="bg-gray-100"^>
echo     ^<!-- Navigation --^>
echo     ^<nav class="bg-blue-800 text-white shadow-lg"^>
echo         ^<div class="max-w-7xl mx-auto px-4 py-3 flex justify-between items-center"^>
echo             ^<div class="flex items-center space-x-2"^>
echo                 ^<i class="fas fa-gas-pump text-2xl"^>^</i^>
echo                 ^<span class="font-bold text-xl"^>FuelTrak Logistics^</span^>
echo             ^</div^>
echo             ^<div id="userInfo" class="flex items-center space-x-4"^>
echo                 ^<button onclick="showLogin(^)" class="bg-yellow-500 text-black px-4 py-2 rounded hover:bg-yellow-400"^>Login^</button^>
echo             ^</div^>
echo         ^</div^>
echo     ^</nav^>
echo.
echo     ^<!-- Login Modal --^>
echo     ^<div id="loginModal" class="hidden fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center"^>
echo         ^<div class="bg-white p-8 rounded-lg shadow-xl w-96"^>
echo             ^<h2 class="text-2xl font-bold mb-6"^>Login^</h2^>
echo             ^<form id="loginForm" onsubmit="login(event^)"^>
echo                 ^<input type="email" id="email" placeholder="Email" class="w-full px-3 py-2 border rounded mb-3" required^>
echo                 ^<input type="password" id="password" placeholder="Password" class="w-full px-3 py-2 border rounded mb-4" required^>
echo                 ^<button type="submit" class="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700"^>Login^</button^>
echo             ^</form^>
echo             ^<p class="text-sm text-gray-600 mt-4 text-center"^>Test: admin@fueltrak.com / password123^</p^>
echo         ^</div^>
echo     ^</div^>
echo.
echo     ^<!-- Dashboard --^>
echo     ^<div id="dashboard" class="hidden max-w-7xl mx-auto px-4 py-8"^>
echo         ^<h1 class="text-3xl font-bold mb-8"^>Dispatch Dashboard^</h1^>
echo         ^<div id="stats" class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8"^>^</div^>
echo         ^<div class="bg-white rounded-lg shadow p-6"^>
echo             ^<h2 class="text-xl font-semibold mb-4"^>Recent Dispatches^</h2^>
echo             ^<div id="recentDispatches"^>^</div^>
echo         ^</div^>
echo     ^</div^>
echo.
echo     ^<script^>
echo         const API = 'http://localhost:3000/api';
echo         let token = localStorage.getItem('token');
echo.
echo         function showLogin(^) { document.getElementById('loginModal'^).classList.remove('hidden'^); }
echo.
echo         async function login(e^) {
echo             e.preventDefault(^);
echo             const res = await fetch(`${API}/auth/login`, {
echo                 method: 'POST', headers: { 'Content-Type': 'application/json' },
echo                 body: JSON.stringify({ email: document.getElementById('email'^).value, password: document.getElementById('password'^).value }^)
echo             }^);
echo             const data = await res.json(^);
echo             if (data.status === 'success'^) {
echo                 token = data.token;
echo                 localStorage.setItem('token', token^);
echo                 document.getElementById('loginModal'^).classList.add('hidden'^);
echo                 document.getElementById('userInfo'^).innerHTML = `^<span^>${data.user.email}^</span^>^<button onclick="logout(^)" class="bg-red-500 px-4 py-2 rounded"^>Logout^</button^>`;
echo                 loadDashboard(^);
echo             } else { alert(data.message^); }
echo         }
echo.
echo         function logout(^) { localStorage.removeItem('token'^); location.reload(^); }
echo.
echo         async function loadDashboard(^) {
echo             const res = await fetch(`${API}/dispatch/dashboard`, { headers: { 'Authorization': `Bearer ${token}` } }^);
echo             const data = await res.json(^);
echo             if (data.status === 'success'^) {
echo                 document.getElementById('dashboard'^).classList.remove('hidden'^);
echo                 const s = data.data;
echo                 document.getElementById('stats'^).innerHTML = `
echo                     ^<div class="bg-white p-6 rounded-lg shadow"^>^<h3 class="text-gray-500"^>Loaded Today^</h3^>^<p class="text-3xl font-bold"^>${s.loadedToday}^</p^>^</div^>
echo                     ^<div class="bg-white p-6 rounded-lg shadow"^>^<h3 class="text-gray-500"^>Pending^</h3^>^<p class="text-3xl font-bold"^>${s.pendingCount}^</p^>^</div^>
echo                     ^<div class="bg-white p-6 rounded-lg shadow"^>^<h3 class="text-gray-500"^>Scheduled Today^</h3^>^<p class="text-3xl font-bold"^>${s.scheduledToday}^</p^>^</div^>
echo                     ^<div class="bg-white p-6 rounded-lg shadow"^>^<h3 class="text-gray-500"^>Total Volume^</h3^>^<p class="text-3xl font-bold"^>${(s.totalVolume/1000^).toFixed(1^)}k L^</p^>^</div^>
echo                 `;
echo             }
echo         }
echo.
echo         if (token^) { 
echo             fetch(`${API}/auth/profile`, { headers: { 'Authorization': `Bearer ${token}` } }^)
echo                 .then(r =^> r.json(^)^)
echo                 .then(d =^> { if(d.user^) { document.getElementById('userInfo'^).innerHTML = `^<span^>${d.user.email}^</span^>^<button onclick="logout(^)" class="bg-red-500 px-4 py-2 rounded"^>Logout^</button^>`; loadDashboard(^); } }^)
echo                 .catch((^) =^> { localStorage.removeItem('token'^); showLogin(^); }^);
echo         }
echo     ^</script^>
echo ^</body^>
echo ^</html^>
) > public\index.html

goto :EOF

REM ============================================
REM  Function: Create Seeder
REM ============================================
:CreateSeeder

(
echo require('dotenv').config({ path: require('path').join(__dirname, '../../.env') });
echo const { sequelize } = require('../config/database');
echo const { User, Truck, TruckDocument } = require('../models');
echo.
echo async function seed() {
echo   try {
echo     await sequelize.sync({ force: true });
echo     console.log('Database synced');
echo.
echo     const users = await User.bulkCreate([
echo       { email: 'admin@fueltrak.com', password: 'password123', mobile: '+639171234567', role: 'management', company_name: 'FuelTrak Inc' },
echo       { email: 'dispatcher@fueltrak.com', password: 'password123', mobile: '+639172345678', role: 'dispatcher' },
echo       { email: 'client1@hauler.com', password: 'password123', mobile: '+639173456789', role: 'client', company_name: 'Fast Haulers Inc' }
echo     ]);
echo.
echo     const truck = await Truck.create({
echo       plate_no: 'ABC1234', make: 'ISUZU', driver_name: 'Juan Dela Cruz',
echo       hauler_name: 'Fast Haulers Inc', total_capacity: 40000, num_tps: 4,
echo       calibration_date: '2024-01-15', next_calibration_date: '2025-01-15'
echo     });
echo.
echo     await TruckDocument.bulkCreate([
echo       { truck_id: truck.id, document_type: 'lto_registration', document_number: 'LTO-001', expiry_date: '2025-06-30' },
echo       { truck_id: truck.id, document_type: 'fire_permit', document_number: 'FP-001', expiry_date: '2024-12-31' },
echo       { truck_id: truck.id, document_type: 'dost_calibration', document_number: 'DOST-001', expiry_date: '2025-01-15' }
echo     ]);
echo.
echo     console.log('✅ Database seeded successfully!');
echo     console.log('Test accounts:');
echo     console.log('  Management: admin@fueltrak.com / password123');
echo     console.log('  Dispatcher: dispatcher@fueltrak.com / password123');
echo     console.log('  Client: client1@hauler.com / password123');
echo     process.exit(0);
echo   } catch (error) {
echo     console.error('Seeding failed:', error);
echo     process.exit(1);
echo   }
echo }
echo.
echo seed();
) > src\seeders\seed.js

goto :EOF