require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { testConnection, sequelize } = require('./src/config/database');
const { User, Truck, TruckDocument, AuthorityToLoad } = require('./src/models');
const jwt = require('jsonwebtoken');
const NodeCache = require('node-cache');

const app = express();
const otpCache = new NodeCache({ stdTTL: 600 });

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Generate OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ============ AUTH MIDDLEWARE ============
const authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Please authenticate' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    req.user = await User.findByPk(decoded.id);
    if (!req.user || !req.user.is_active) return res.status(401).json({ error: 'Invalid token' });
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const authorize = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Access denied' });
  next();
};

// ============ AUTH ROUTES ============

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, mobile, company_name } = req.body;
    const mobileRegex = /^(09\d{9}|\+639\d{9})$/;
    if (!mobileRegex.test(mobile)) {
      return res.status(400).json({ error: 'Invalid mobile format' });
    }
    const existing = await User.findOne({ where: { email } });
    if (existing) return res.status(400).json({ error: 'Email already registered' });

    const user = await User.create({ email, password, mobile, company_name, role: 'client', is_verified: false });
    const otp = generateOTP();
    otpCache.set(email, otp);
    console.log(`📧 OTP for ${email}: ${otp}`);

    res.status(201).json({ status: 'success', message: 'Registration successful. Check console for OTP.', email, otp });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.is_verified) return res.json({ message: 'Already verified' });

    const storedOTP = otpCache.get(email);
    if (!storedOTP || storedOTP !== otp) return res.status(400).json({ error: 'Invalid OTP' });

    otpCache.del(email);
    await user.update({ is_verified: true });
    res.json({ status: 'success', message: 'Email verified. You can now login.' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/auth/resend-otp', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.is_verified) return res.json({ message: 'Already verified' });

  const otp = generateOTP();
  otpCache.set(email, otp);
  console.log(`📧 OTP for ${email}: ${otp}`);
  res.json({ message: 'OTP resent', otp });
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (!user.is_verified) return res.status(401).json({ error: 'Please verify your email first' });
    if (!user.is_active) return res.status(403).json({ error: 'Account deactivated' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

    await user.update({ last_login: new Date() });
    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET || 'secret', { expiresIn: '24h' });

    res.json({
      status: 'success',
      token,
      user: { id: user.id, email: user.email, role: user.role, mobile: user.mobile, company_name: user.company_name }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/auth/profile', authenticate, (req, res) => {
  res.json({ status: 'success', user: req.user });
});

// ============ PASSWORD RESET ROUTES ============

// Forgot password - send OTP
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ where: { email } });
    
    if (!user) {
      return res.status(404).json({ error: 'Email not found' });
    }

    // Generate OTP
    const otp = generateOTP();
    otpCache.set(`reset_${email}`, otp);
    console.log(`📧 Password reset OTP for ${email}: ${otp}`);

    res.json({ 
      status: 'success', 
      message: 'OTP sent to your email. Check console for OTP.',
      otp // Remove in production
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Verify OTP for password reset
app.post('/api/auth/verify-reset-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const storedOTP = otpCache.get(`reset_${email}`);
    
    if (!storedOTP || storedOTP !== otp) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    otpCache.del(`reset_${email}`);
    
    // Generate a reset token
    const resetToken = jwt.sign({ email, purpose: 'reset' }, process.env.JWT_SECRET || 'secret', { expiresIn: '15m' });
    
    res.json({ 
      status: 'success', 
      message: 'OTP verified. You can now reset your password.',
      resetToken
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Reset password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;
    
    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    const decoded = jwt.verify(resetToken, process.env.JWT_SECRET || 'secret');
    if (decoded.purpose !== 'reset') {
      return res.status(400).json({ error: 'Invalid reset token' });
    }

    const user = await User.findOne({ where: { email: decoded.email } });
    if (!user) return res.status(404).json({ error: 'User not found' });

    // IMPORTANT: Update password directly - the model hook will hash it
    user.password = newPassword;
    await user.save();

    // Verify the password was hashed correctly
    const verify = await user.comparePassword(newPassword);
    console.log(`Password reset for ${user.email}. Verify match: ${verify}`);

    res.json({ status: 'success', message: 'Password reset successfully. You can now login.' });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(400).json({ error: 'Reset token expired. Please request a new OTP.' });
    }
    res.status(400).json({ error: error.message });
  }
});

// ============ CLIENT ATL ROUTES ============

app.get('/api/client/dashboard', authenticate, authorize('client'), async (req, res) => {
  try {
    const atls = await AuthorityToLoad.findAll({
      where: { client_id: req.user.id },
      order: [['createdAt', 'DESC']]
    });

    const result = [];
    for (const atl of atls) {
      const truck = await Truck.findByPk(atl.truck_id);
      result.push({
        id: atl.id,
        atl_code: atl.atl_code,           // ADD THIS
        company: atl.company,
        so_number: atl.so_number,
        plate_no: atl.plate_no || truck?.plate_no,
        hauler: atl.hauler,
        driver_name: atl.driver_name || truck?.driver_name,
        contact_number: atl.contact_number,
        volume: atl.volume,                // ADD THIS
        scheduled_date: atl.scheduled_date,
        dispatch_date: atl.dispatch_date,
        status: atl.status,
        remarks: atl.remarks,
        truck_details: truck ? { plate_no: truck.plate_no, make: truck.make, capacity: truck.total_capacity } : null
      });
    }

    const stats = {
      total: atls.length,
      successful: atls.filter(a => a.status === 'completed').length,
      failed: atls.filter(a => a.status === 'rejected').length,
      pending: atls.filter(a => a.status === 'pending').length,
      approved: atls.filter(a => a.status === 'approved').length,
      cancelled: atls.filter(a => a.status === 'cancelled').length,
      dispatched: atls.filter(a => a.status === 'dispatched').length
    };

    res.json({ status: 'success', data: { stats, recentATLs: result } });
  } catch (error) {
    console.error('Client dashboard error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/client/verify-truck/:plateNo', authenticate, authorize('client'), async (req, res) => {
  try {
    const truck = await Truck.findOne({ where: { plate_no: req.params.plateNo.toUpperCase(), is_active: true } });
    if (!truck) return res.status(404).json({ error: 'Truck not found', can_proceed: false });

    const docs = await TruckDocument.findAll({ where: { truck_id: truck.id } });
    const docStatus = {};
    let allValid = true;

    ['lto_registration', 'fire_permit', 'dost_calibration'].forEach(type => {
      const doc = docs.find(d => d.document_type === type);
      const days = doc ? Math.ceil((new Date(doc.expiry_date) - new Date()) / (1000 * 60 * 60 * 24)) : -1;
      docStatus[type] = { status: days < 0 ? 'expired' : days <= 30 ? 'expiring_soon' : 'valid', valid: days >= 0, days_remaining: days };
      if (days < 0) allValid = false;
    });

    res.json({ status: 'success', data: { truck: { id: truck.id, plate_no: truck.plate_no, make: truck.make, driver_name: truck.driver_name, total_capacity: truck.total_capacity }, documents: docStatus, can_proceed: allValid } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/client/submit-atl', authenticate, authorize('client'), async (req, res) => {
  try {
    const { plate_no, scheduled_date, company, so_number, volume, hauler, driver_name, contact_number, has_si } = req.body;
    
    const truck = await Truck.findOne({ where: { plate_no: plate_no.toUpperCase(), is_active: true } });
    if (!truck) return res.status(404).json({ error: 'Truck not found' });

    if (volume && parseFloat(volume) > parseFloat(truck.total_capacity)) {
      return res.status(400).json({ error: `Volume (${volume}L) exceeds truck capacity (${truck.total_capacity}L)` });
    }

    const docs = await TruckDocument.findAll({ where: { truck_id: truck.id } });
    const hasExpired = ['lto_registration', 'fire_permit', 'dost_calibration'].some(type => {
      const doc = docs.find(d => d.document_type === type);
      return !doc || new Date(doc.expiry_date) < new Date();
    });
    if (hasExpired) return res.status(400).json({ error: 'Truck has expired documents. Cannot submit ATL.' });

    const existing = await AuthorityToLoad.findOne({ where: { client_id: req.user.id, truck_id: truck.id, status: ['pending', 'approved'] } });
    if (existing) return res.status(400).json({ error: 'You already have a pending ATL for this truck' });

    const atlCode = await generateATLCode(company || req.user.company_name);

    const atl = await AuthorityToLoad.create({
      client_id: req.user.id, 
      truck_id: truck.id,
      atl_code: atlCode,
      company: company || req.user.company_name, 
      so_number: so_number || null,
      has_si: has_si || false,
      volume: volume || null,
      hauler: hauler || truck.hauler_name, 
      plate_no: truck.plate_no,
      driver_name: driver_name || truck.driver_name, 
      contact_number: contact_number || req.user.mobile,
      scheduled_date, 
      status: 'pending'
    });

    res.status(201).json({ 
      status: 'success', 
      message: `ATL ${atlCode} submitted successfully`, 
      data: { ...atl.toJSON(), atl_code: atlCode }
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/client/cancel-atl/:id', authenticate, authorize('client'), async (req, res) => {
  try {
    const atl = await AuthorityToLoad.findOne({ where: { id: req.params.id, client_id: req.user.id, status: ['pending', 'approved'] } });
    if (!atl) return res.status(404).json({ error: 'ATL not found or cannot be cancelled' });
    atl.status = 'pending';
    atl.remarks = `Cancellation requested: ${req.body.reason || 'No reason provided'}`;
    await atl.save();
    res.json({ status: 'success', message: 'Cancellation requested. Awaiting dispatcher approval.' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/client/atl/:id', authenticate, authorize('client'), async (req, res) => {
  try {
    const atl = await AuthorityToLoad.findOne({ where: { id: req.params.id, client_id: req.user.id } });
    if (!atl) return res.status(404).json({ error: 'ATL not found' });
    const truck = await Truck.findByPk(atl.truck_id);
    res.json({ status: 'success', data: { ...atl.toJSON(), truck: truck?.toJSON() } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ATL Code Generator: First 3 letters of company + 9-digit series (global counter)
async function generateATLCode(company) {
  const prefix = (company || 'ATL').replace(/[^a-zA-Z]/g, '').substring(0, 3).toUpperCase().padEnd(3, 'X');
  
  // Count ALL ATLs (global series, not just today)
  const count = await AuthorityToLoad.count();
  
  const series = String(count + 1).padStart(9, '0');
  
  return `${prefix}-${series}`;
}

// ============ DISPATCHER/MANAGEMENT ROUTES ============

app.get('/api/dispatch/dashboard', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const loaded = await AuthorityToLoad.count({ where: { status: 'dispatched' } });
    const pending = await AuthorityToLoad.count({ where: { status: 'pending' } });
    res.json({ status: 'success', data: { loadedToday: loaded, pendingCount: pending } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/dispatch/pending', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const pending = await AuthorityToLoad.findAll({
      where: { status: ['pending', 'verified'] },
      order: [['createdAt', 'DESC']]
    });

    const result = [];
    for (const atl of pending) {
      const truck = await Truck.findByPk(atl.truck_id);
      const client = await User.findByPk(atl.client_id, { attributes: ['id', 'email', 'company_name'] });
      result.push({
        ...atl.toJSON(),
        truck: truck ? truck.toJSON() : null,
        client: client ? client.toJSON() : null
      });
    }

    res.json({ status: 'success', data: result });
  } catch (error) {
    console.error('Pending error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/dispatch/verify/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const atl = await AuthorityToLoad.findByPk(req.params.id);
    if (!atl) return res.status(404).json({ error: 'ATL not found' });
    atl.status = req.body.action === 'approve' ? 'approved' : req.body.action === 'reject' ? 'rejected' : atl.status;
    atl.verified_by = req.user.id;
    if (req.body.remarks) atl.remarks = req.body.remarks;
    await atl.save();
    res.json({ status: 'success', data: atl });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/dispatch/handle-cancellation/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const atl = await AuthorityToLoad.findByPk(req.params.id);
    if (!atl) return res.status(404).json({ error: 'ATL not found' });
    atl.status = req.body.action === 'approve_cancel' ? 'cancelled' : 'approved';
    await atl.save();
    res.json({ status: 'success', data: atl });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get truck statistics for dashboard
app.get('/api/dispatch/truck-stats', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const allTrucks = await Truck.findAll({ include: ['documents'] });
    
    const today = new Date();
    
    const stats = {
      total: allTrucks.length,
      active: allTrucks.filter(t => t.is_active).length,
      inactive: allTrucks.filter(t => !t.is_active).length,
      withExpiredDocs: 0,
      withValidDocs: 0,
      expiringSoon: 0,
      totalCapacity: 0,
      documentBreakdown: {
        lto: { valid: 0, expired: 0, missing: 0 },
        fire: { valid: 0, expired: 0, missing: 0 },
        dost: { valid: 0, expired: 0, missing: 0 }
      },
      trucksNeedingAttention: []
    };

    for (const truck of allTrucks) {
      if (truck.is_active) {
        stats.totalCapacity += parseFloat(truck.total_capacity) || 0;
      }

      const docs = truck.documents || [];
      let hasExpired = false;
      let hasExpiringSoon = false;

      // Check each document type
      ['lto_registration', 'fire_permit', 'dost_calibration'].forEach(type => {
        const doc = docs.find(d => d.document_type === type);
        const key = type === 'lto_registration' ? 'lto' : type === 'fire_permit' ? 'fire' : 'dost';
        
        if (!doc) {
          stats.documentBreakdown[key].missing++;
          if (truck.is_active) hasExpired = true;
        } else {
          const daysUntilExpiry = Math.ceil((new Date(doc.expiry_date) - today) / (1000 * 60 * 60 * 24));
          
          if (daysUntilExpiry < 0) {
            stats.documentBreakdown[key].expired++;
            if (truck.is_active) hasExpired = true;
          } else if (daysUntilExpiry <= 30) {
            stats.documentBreakdown[key].valid++;
            if (truck.is_active) hasExpiringSoon = true;
          } else {
            stats.documentBreakdown[key].valid++;
          }
        }
      });

      if (truck.is_active) {
        if (hasExpired) {
          stats.withExpiredDocs++;
          stats.trucksNeedingAttention.push({
            id: truck.id,
            plate_no: truck.plate_no,
            make: truck.make,
            driver_name: truck.driver_name,
            issue: 'Expired documents',
            documents: docs.filter(d => new Date(d.expiry_date) < today).map(d => ({
              type: d.document_type,
              expiry: d.expiry_date
            }))
          });
        } else if (hasExpiringSoon) {
          stats.expiringSoon++;
          stats.trucksNeedingAttention.push({
            id: truck.id,
            plate_no: truck.plate_no,
            make: truck.make,
            driver_name: truck.driver_name,
            issue: 'Documents expiring soon',
            documents: docs.filter(d => {
              const days = Math.ceil((new Date(d.expiry_date) - today) / (1000 * 60 * 60 * 24));
              return days > 0 && days <= 30;
            }).map(d => ({
              type: d.document_type,
              expiry: d.expiry_date
            }))
          });
        } else {
          stats.withValidDocs++;
        }
      }
    }

    res.json({ status: 'success', data: stats });
  } catch (error) {
    console.error('Truck stats error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============ COMPREHENSIVE TRUCK CRUD ============

// GET - List all trucks with full details
app.get('/api/trucks', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const trucks = await Truck.findAll({
      order: [['plate_no', 'ASC']],
      include: ['documents']
    });

    const result = [];
    for (const truck of trucks) {
      const docs = await TruckDocument.findAll({ where: { truck_id: truck.id } });
      result.push({
        ...truck.toJSON(),
        documents: docs,
        document_status: {
          lto: docs.find(d => d.document_type === 'lto_registration')?.status || 'missing',
          fire: docs.find(d => d.document_type === 'fire_permit')?.status || 'missing',
          dost: docs.find(d => d.document_type === 'dost_calibration')?.status || 'missing'
        }
      });
    }

    res.json({ status: 'success', data: result, total: result.length });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET - Single truck by ID
app.get('/api/trucks/:id', authenticate, async (req, res) => {
  try {
    const truck = await Truck.findByPk(req.params.id, { include: ['documents'] });
    if (!truck) return res.status(404).json({ error: 'Truck not found' });
    res.json({ status: 'success', data: truck });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST - Create new truck
app.post('/api/trucks', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { plate_no, make, driver_name, hauler_name, total_capacity, num_tps, calibration_date, next_calibration_date, discharge_line, remarks, documents } = req.body;

    const existing = await Truck.findOne({ where: { plate_no: plate_no.toUpperCase() } });
    if (existing) return res.status(400).json({ error: 'Truck already exists' });

    const truck = await Truck.create({
      plate_no: plate_no.toUpperCase(), make,
      driver_name: driver_name || null, hauler_name: hauler_name || null,
      total_capacity: total_capacity || 0, num_tps: num_tps || 0,
      calibration_date: calibration_date || null,
      next_calibration_date: next_calibration_date || null,
      discharge_line: discharge_line || 'including',
      remarks: remarks || null, is_active: true
    });

    if (documents && Array.isArray(documents)) {
      for (const doc of documents) {
        if (doc.expiry_date) {
          await TruckDocument.create({
            truck_id: truck.id,
            document_type: doc.type,
            document_number: doc.number || null,
            issue_date: doc.issue_date || new Date(),
            expiry_date: doc.expiry_date,
            status: 'valid'
          });
          console.log(`Created document: ${doc.type} for ${plate_no}, expiry: ${doc.expiry_date}`);
        }
      }
    }

    const created = await Truck.findByPk(truck.id, { include: ['documents'] });
    res.status(201).json({ status: 'success', message: 'Truck created', data: created });
  } catch (error) {
    console.error('Create truck error:', error);
    res.status(400).json({ error: error.message });
  }
});

// PUT - Update truck with documents
app.put('/api/trucks/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const truck = await Truck.findByPk(req.params.id);
    if (!truck) return res.status(404).json({ error: 'Truck not found' });

    const { plate_no, make, driver_name, hauler_name, total_capacity, num_tps, calibration_date, next_calibration_date, discharge_line, remarks, is_active, documents } = req.body;

    // Check plate uniqueness if changed
    if (plate_no && plate_no.toUpperCase() !== truck.plate_no) {
      const existing = await Truck.findOne({ where: { plate_no: plate_no.toUpperCase() } });
      if (existing) return res.status(400).json({ error: 'Plate number already in use' });
    }

    // Update truck fields
    await truck.update({
      plate_no: plate_no ? plate_no.toUpperCase() : truck.plate_no,
      make: make || truck.make,
      driver_name: driver_name !== undefined ? driver_name : truck.driver_name,
      hauler_name: hauler_name !== undefined ? hauler_name : truck.hauler_name,
      total_capacity: total_capacity || truck.total_capacity,
      num_tps: num_tps !== undefined ? num_tps : truck.num_tps,
      calibration_date: calibration_date !== undefined ? calibration_date : truck.calibration_date,
      next_calibration_date: next_calibration_date !== undefined ? next_calibration_date : truck.next_calibration_date,
      discharge_line: discharge_line || truck.discharge_line,
      remarks: remarks !== undefined ? remarks : truck.remarks,
      is_active: is_active !== undefined ? is_active : truck.is_active
    });

    // Update documents - only if provided
    if (documents && Array.isArray(documents)) {
      for (const doc of documents) {
        if (!doc.expiry_date) continue; // Skip if no expiry date
        
        // Find existing document of this type
        const existingDoc = await TruckDocument.findOne({
          where: { truck_id: truck.id, document_type: doc.type }
        });

        if (existingDoc) {
          // Update existing document
          await existingDoc.update({
            document_number: doc.number || existingDoc.document_number,
            issue_date: doc.issue_date || existingDoc.issue_date || new Date(),
            expiry_date: doc.expiry_date,
            status: new Date(doc.expiry_date) >= new Date() ? 'valid' : 'expired',
            reminder_sent: false
          });
          console.log(`Updated document: ${doc.type} for truck ${truck.plate_no}, expiry: ${doc.expiry_date}`);
        } else {
          // Create new document
          await TruckDocument.create({
            truck_id: truck.id,
            document_type: doc.type,
            document_number: doc.number || null,
            issue_date: doc.issue_date || new Date(),
            expiry_date: doc.expiry_date,
            status: new Date(doc.expiry_date) >= new Date() ? 'valid' : 'expired'
          });
          console.log(`Created document: ${doc.type} for truck ${truck.plate_no}, expiry: ${doc.expiry_date}`);
        }
      }
    }

    // Return updated truck with documents
    const updated = await Truck.findByPk(truck.id, { include: ['documents'] });
    
    console.log(`Truck ${updated.plate_no} updated. Documents: ${updated.documents?.length || 0}`);
    
    res.json({ 
      status: 'success', 
      message: 'Truck updated successfully',
      data: updated 
    });
  } catch (error) {
    console.error('Update truck error:', error);
    res.status(400).json({ error: error.message });
  }
});

// DELETE - Deactivate truck
app.delete('/api/trucks/:id', authenticate, authorize('management'), async (req, res) => {
  try {
    const truck = await Truck.findByPk(req.params.id);
    if (!truck) return res.status(404).json({ error: 'Truck not found' });

    const activeATLs = await AuthorityToLoad.count({
      where: { truck_id: truck.id, status: ['pending', 'approved', 'dispatched'] }
    });
    if (activeATLs > 0) return res.status(400).json({ error: `Cannot delete. ${activeATLs} active ATL(s) exist.` });

    await truck.update({ is_active: false });
    res.json({ status: 'success', message: 'Truck deactivated' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// PATCH - Restore truck
app.patch('/api/trucks/:id/restore', authenticate, authorize('management'), async (req, res) => {
  try {
    const truck = await Truck.findByPk(req.params.id);
    if (!truck) return res.status(404).json({ error: 'Truck not found' });
    await truck.update({ is_active: true });
    res.json({ status: 'success', message: 'Truck reactivated' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// GET - Trucks with expired documents
app.get('/api/trucks/expired-documents', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const trucks = await Truck.findAll({ include: ['documents'] });
    const expired = [];
    for (const truck of trucks) {
      const docs = truck.documents || [];
      const expiredDocs = docs.filter(d => new Date(d.expiry_date) < new Date());
      if (expiredDocs.length > 0) {
        expired.push({ ...truck.toJSON(), expired_documents: expiredDocs });
      }
    }
    res.json({ status: 'success', data: expired, total: expired.length });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Keep old routes for backward compatibility
app.get('/api/trucks/all', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const trucks = await Truck.findAll({ order: [['plate_no', 'ASC']] });
    const result = [];
    for (const truck of trucks) {
      const docs = await TruckDocument.findAll({ where: { truck_id: truck.id } });
      result.push({ ...truck.toJSON(), documents: docs });
    }
    res.json({ status: 'success', data: result });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/trucks/add', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { plate_no, make, driver_name, hauler_name, total_capacity, documents } = req.body;
    const existing = await Truck.findOne({ where: { plate_no: plate_no.toUpperCase() } });
    if (existing) return res.status(400).json({ error: 'Truck already exists' });

    const truck = await Truck.create({
      plate_no: plate_no.toUpperCase(), make,
      driver_name: driver_name || null, hauler_name: hauler_name || null,
      total_capacity: total_capacity || 0, is_active: true
    });

    if (documents && Array.isArray(documents)) {
      for (const doc of documents) {
        if (doc.expiry_date) {
          await TruckDocument.create({ truck_id: truck.id, document_type: doc.type, expiry_date: doc.expiry_date, status: 'valid' });
        }
      }
    }

    const docs = await TruckDocument.findAll({ where: { truck_id: truck.id } });
    res.status(201).json({ status: 'success', message: 'Truck added', data: { ...truck.toJSON(), documents: docs } });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============ CLIENT MANAGEMENT CRUD (DISPATCHER/ADMIN) ============

// GET - List all clients with details
app.get('/api/clients', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const clients = await User.findAll({
      where: { role: 'client' },
      attributes: ['id', 'email', 'mobile', 'company_name', 'is_active', 'is_verified', 'last_login', 'createdAt'],
      order: [['createdAt', 'DESC']]
    });

    const result = [];
    for (const client of clients) {
      const atls = await AuthorityToLoad.findAll({ 
        where: { client_id: client.id },
        order: [['createdAt', 'DESC']]
      });
      
      result.push({
        ...client.toJSON(),
        total_atls: atls.length,
        pending_atls: atls.filter(a => a.status === 'pending').length,
        approved_atls: atls.filter(a => a.status === 'approved').length,
        dispatched_atls: atls.filter(a => a.status === 'dispatched').length,
        completed_atls: atls.filter(a => a.status === 'completed').length,
        last_atl_date: atls[0]?.createdAt || null
      });
    }

    res.json({ status: 'success', data: result, total: result.length });
  } catch (error) {
    console.error('Clients list error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// GET - Single client details
app.get('/api/clients/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const client = await User.findOne({
      where: { id: req.params.id, role: 'client' },
      attributes: ['id', 'email', 'mobile', 'company_name', 'is_active', 'is_verified', 'last_login', 'createdAt']
    });
    
    if (!client) return res.status(404).json({ error: 'Client not found' });

    const atls = await AuthorityToLoad.findAll({
      where: { client_id: client.id },
      include: [{ model: Truck, as: 'truck', attributes: ['plate_no', 'total_capacity'] }],
      order: [['createdAt', 'DESC']],
      limit: 20
    });

    res.json({
      status: 'success',
      data: {
        ...client.toJSON(),
        atls: atls,
        atl_stats: {
          total: atls.length,
          pending: atls.filter(a => a.status === 'pending').length,
          approved: atls.filter(a => a.status === 'approved').length,
          dispatched: atls.filter(a => a.status === 'dispatched').length,
          completed: atls.filter(a => a.status === 'completed').length,
          rejected: atls.filter(a => a.status === 'rejected').length,
          cancelled: atls.filter(a => a.status === 'cancelled').length
        }
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST - Create new client (on-premise)
app.post('/api/clients', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { email, password, mobile, company_name } = req.body;

    // Validate
    if (!email || !password || !mobile) {
      return res.status(400).json({ error: 'Email, password, and mobile are required' });
    }

    const mobileRegex = /^(09\d{9}|\+639\d{9})$/;
    if (!mobileRegex.test(mobile)) {
      return res.status(400).json({ error: 'Invalid mobile format. Use 09XXXXXXXXX or +639XXXXXXXXX' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    // Check existing
    const existing = await User.findOne({ where: { email } });
    if (existing) return res.status(400).json({ error: 'Email already registered' });

    // Create client (pre-verified since added by admin)
    const client = await User.create({
      email,
      password,
      mobile,
      company_name: company_name || null,
      role: 'client',
      is_verified: true,
      is_active: true
    });

    console.log(`✅ Client created by admin: ${email}`);

    res.status(201).json({
      status: 'success',
      message: 'Client created successfully',
      data: {
        id: client.id,
        email: client.email,
        mobile: client.mobile,
        company_name: client.company_name,
        is_active: client.is_active,
        is_verified: client.is_verified
      }
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// PUT - Update client
app.put('/api/clients/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const client = await User.findOne({ where: { id: req.params.id, role: 'client' } });
    if (!client) return res.status(404).json({ error: 'Client not found' });

    const { email, mobile, company_name, password } = req.body;

    // Check email uniqueness if changed
    if (email && email !== client.email) {
      const existing = await User.findOne({ where: { email } });
      if (existing) return res.status(400).json({ error: 'Email already in use' });
    }

    const updateData = {
      email: email || client.email,
      mobile: mobile || client.mobile,
      company_name: company_name !== undefined ? company_name : client.company_name
    };

    // Only update password if provided
    if (password && password.length >= 8) {
      updateData.password = password;
    }

    await client.update(updateData);

    res.json({
      status: 'success',
      message: 'Client updated successfully',
      data: {
        id: client.id,
        email: client.email,
        mobile: client.mobile,
        company_name: client.company_name
      }
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// PATCH - Toggle client active/inactive
app.patch('/api/clients/:id/toggle-status', authenticate, authorize('management'), async (req, res) => {
  try {
    const client = await User.findOne({ where: { id: req.params.id, role: 'client' } });
    if (!client) return res.status(404).json({ error: 'Client not found' });

    await client.update({ is_active: !client.is_active });

    res.json({
      status: 'success',
      message: `Client ${client.is_active ? 'activated' : 'deactivated'}`,
      is_active: client.is_active
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// DELETE - Remove client (only if no active ATLs)
app.delete('/api/clients/:id', authenticate, authorize('management'), async (req, res) => {
  try {
    const client = await User.findOne({ where: { id: req.params.id, role: 'client' } });
    if (!client) return res.status(404).json({ error: 'Client not found' });

    // Check for active ATLs
    const activeATLs = await AuthorityToLoad.count({
      where: { client_id: client.id, status: ['pending', 'approved', 'dispatched'] }
    });

    if (activeATLs > 0) {
      return res.status(400).json({
        error: `Cannot delete client. They have ${activeATLs} active ATL(s). Complete or cancel them first.`
      });
    }

    await client.destroy();

    res.json({ status: 'success', message: 'Client deleted permanently' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// GET - Client ATL history (for admin view)
app.get('/api/clients/:id/atls', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const atls = await AuthorityToLoad.findAll({
      where: { client_id: req.params.id },
      include: [{ model: Truck, as: 'truck', attributes: ['plate_no', 'total_capacity', 'driver_name'] }],
      order: [['createdAt', 'DESC']]
    });

    res.json({ status: 'success', data: atls, total: atls.length });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/dispatcher/clients', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const clients = await User.findAll({
      where: { role: 'client' },
      attributes: ['id', 'email', 'company_name', 'mobile', 'is_active']
    });

    const result = [];
    for (const client of clients) {
      const atls = await AuthorityToLoad.findAll({ where: { client_id: client.id } });
      result.push({ ...client.toJSON(), total_atls: atls.length });
    }

    res.json({ status: 'success', data: result });
  } catch (error) {
    console.error('Clients error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============ LOADING MANAGEMENT ============

// Get approved ATLs ready for loading
app.get('/api/dispatch/approved-for-loading', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const approved = await AuthorityToLoad.findAll({
      where: { status: 'approved' },
      order: [['createdAt', 'DESC']]
    });

    const result = [];
    for (const atl of approved) {
      const truck = await Truck.findByPk(atl.truck_id);
      const client = await User.findByPk(atl.client_id, { attributes: ['id', 'email', 'company_name'] });
      result.push({
        ...atl.toJSON(),
        truck: truck ? truck.toJSON() : null,
        client: client ? client.toJSON() : null
      });
    }

    res.json({ status: 'success', data: result });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mark ATL as loading in progress
app.post('/api/dispatch/start-loading/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const atl = await AuthorityToLoad.findByPk(req.params.id);
    if (!atl) return res.status(404).json({ error: 'ATL not found' });
    if (atl.status !== 'approved') return res.status(400).json({ error: 'ATL must be approved first' });

    atl.status = 'dispatched';
    atl.dispatch_date = new Date();
    atl.remarks = 'Loading in progress...';
    await atl.save();

    res.json({ status: 'success', message: 'Loading started', data: atl });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Complete loading
app.post('/api/dispatch/complete-loading/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const atl = await AuthorityToLoad.findByPk(req.params.id);
    if (!atl) return res.status(404).json({ error: 'ATL not found' });
    if (atl.status !== 'dispatched') return res.status(400).json({ error: 'ATL must be in loading status first' });

    atl.status = 'completed';
    atl.remarks = `Loading completed. ${req.body.remarks || ''}`;
    await atl.save();

    res.json({ status: 'success', message: 'Loading completed', data: atl });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get loading history (completed ATLs)
app.get('/api/dispatch/loading-history', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const completed = await AuthorityToLoad.findAll({
      where: { status: ['dispatched', 'completed'] },
      order: [['dispatch_date', 'DESC']],
      limit: 50
    });

    const result = [];
    for (const atl of completed) {
      const truck = await Truck.findByPk(atl.truck_id);
      const client = await User.findByPk(atl.client_id, { attributes: ['id', 'email', 'company_name'] });
      result.push({
        ...atl.toJSON(),
        truck: truck ? truck.toJSON() : null,
        client: client ? client.toJSON() : null
      });
    }

    res.json({ status: 'success', data: result });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ REPORTS ROUTES ============

// Get reports summary with filters
app.get('/api/reports/summary', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { startDate, endDate, status, clientId, truckId } = req.query;
    
    // Build where clause
    const where = {};
    
    if (status) {
      where.status = status.split(','); // Support multiple statuses: completed,cancelled
    } else {
      where.status = ['completed', 'cancelled', 'dispatched'];
    }
    
    if (startDate && endDate) {
      where.createdAt = {
        [require('sequelize').Op.between]: [new Date(startDate), new Date(endDate + ' 23:59:59')]
      };
    } else if (startDate) {
      where.createdAt = { [require('sequelize').Op.gte]: new Date(startDate) };
    } else if (endDate) {
      where.createdAt = { [require('sequelize').Op.lte]: new Date(endDate + ' 23:59:59') };
    }
    
    if (clientId) where.client_id = clientId;
    if (truckId) where.truck_id = truckId;

    const atls = await AuthorityToLoad.findAll({
      where,
      order: [['createdAt', 'DESC']]
    });

    const result = [];
    let totalVolume = 0;
    let totalActualVolume = 0;
    let completedCount = 0;
    let cancelledCount = 0;
    let dispatchedCount = 0;

    for (const atl of atls) {
      const truck = await Truck.findByPk(atl.truck_id);
      const client = await User.findByPk(atl.client_id, { attributes: ['id', 'email', 'company_name'] });
      const approver = atl.approved_by ? await User.findByPk(atl.approved_by, { attributes: ['email'] }) : null;
      
      const volume = parseFloat(atl.volume) || 0;
      const actualVolume = parseFloat(atl.actual_volume) || 0;
      
      totalVolume += volume;
      if (atl.status === 'completed') {
        totalActualVolume += actualVolume || volume;
        completedCount++;
      } else if (atl.status === 'cancelled') {
        cancelledCount++;
      } else if (atl.status === 'dispatched') {
        dispatchedCount++;
      }

      result.push({
        id: atl.id,
        atl_code: atl.atl_code,
        so_number: atl.so_number,
        company: atl.company,
        plate_no: atl.plate_no || truck?.plate_no,
        driver_name: atl.driver_name || truck?.driver_name,
        hauler: atl.hauler || truck?.hauler_name,
        volume: volume,
        actual_volume: atl.status === 'completed' ? (actualVolume || volume) : null,
        status: atl.status,
        scheduled_date: atl.scheduled_date,
        dispatch_date: atl.dispatch_date,
        completed_date: atl.completed_date,
        remarks: atl.remarks,
        revision_history: atl.revision_history ? JSON.parse(atl.revision_history) : [],
        revision_count: atl.revision_history ? JSON.parse(atl.revision_history).length : 0,
        client: client ? { email: client.email, company_name: client.company_name } : null,
        truck: truck ? { plate_no: truck.plate_no, make: truck.make, total_capacity: truck.total_capacity } : null,
        approved_by: approver?.email || null
      });
    }

    res.json({
      status: 'success',
      data: {
        records: result,
        summary: {
          total_records: atls.length,
          completed: completedCount,
          cancelled: cancelledCount,
          dispatched: dispatchedCount,
          total_volume: totalVolume,
          total_actual_volume: totalActualVolume,
          average_volume: atls.length > 0 ? Math.round(totalVolume / atls.length) : 0
        }
      }
    });
  } catch (error) {
    console.error('Reports error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Get report filters data (clients, trucks for dropdowns)
app.get('/api/reports/filters', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const [clients, trucks] = await Promise.all([
      User.findAll({ where: { role: 'client' }, attributes: ['id', 'email', 'company_name'] }),
      Truck.findAll({ attributes: ['id', 'plate_no', 'make'] })
    ]);

    res.json({
      status: 'success',
      data: {
        clients: clients.map(c => ({ id: c.id, label: `${c.company_name || c.email} (${c.email})` })),
        trucks: trucks.map(t => ({ id: t.id, label: `${t.plate_no} - ${t.make}` }))
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Export report as CSV
app.get('/api/reports/export', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const { startDate, endDate, status } = req.query;
    
    const where = { status: status ? status.split(',') : ['completed', 'cancelled', 'dispatched'] };
    if (startDate && endDate) {
      where.createdAt = { [require('sequelize').Op.between]: [new Date(startDate), new Date(endDate + ' 23:59:59')] };
    }

    const atls = await AuthorityToLoad.findAll({ where, order: [['createdAt', 'DESC']] });
    
    let csv = 'ATL Code,SO Number,Company,Plate No,Driver,Hauler,Volume (L),Actual Volume (L),Status,Scheduled Date,Dispatch Date,Completed Date,Remarks,Revisions\n';
    
    for (const atl of atls) {
      const revisions = atl.revision_history ? JSON.parse(atl.revision_history).length : 0;
      csv += `"${atl.atl_code||''}","${atl.so_number||''}","${atl.company||''}","${atl.plate_no||''}","${atl.driver_name||''}","${atl.hauler||''}",${atl.volume||0},${atl.actual_volume||0},"${atl.status}","${atl.scheduled_date}","${atl.dispatch_date||''}","${atl.completed_date||''}","${(atl.remarks||'').replace(/"/g,'""')}",${revisions}\n`;
    }
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=fueltrak-report-${new Date().toISOString().split('T')[0]}.csv`);
    res.send(csv);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ ONGOING LOADING MANAGEMENT ============

// Get ongoing loading ATLs
app.get('/api/dispatch/ongoing-loading', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const ongoing = await AuthorityToLoad.findAll({
      where: { status: 'dispatched' },
      order: [['dispatch_date', 'DESC']]
    });

    const result = [];
    for (const atl of ongoing) {
      const truck = await Truck.findByPk(atl.truck_id);
      const client = await User.findByPk(atl.client_id, { attributes: ['id', 'email', 'company_name'] });
      result.push({
        ...atl.toJSON(),
        truck: truck ? truck.toJSON() : null,
        client: client ? client.toJSON() : null,
        revision_history: atl.revision_history ? JSON.parse(atl.revision_history) : []
      });
    }

    res.json({ status: 'success', data: result });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Edit ongoing loading (update volume, driver, etc.)
app.put('/api/dispatch/update-loading/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const atl = await AuthorityToLoad.findByPk(req.params.id);
    if (!atl) return res.status(404).json({ error: 'ATL not found' });
    if (atl.status !== 'dispatched') return res.status(400).json({ error: 'Only ongoing loading ATLs can be edited' });

    const { volume, actual_volume, driver_name, hauler, remarks } = req.body;
    
    // Track revision
    const revisions = atl.revision_history ? JSON.parse(atl.revision_history) : [];
    const changes = {};
    
    if (volume && volume !== atl.volume) { changes.volume = { from: atl.volume, to: volume }; atl.volume = volume; }
    if (actual_volume) { changes.actual_volume = { from: atl.actual_volume, to: actual_volume }; atl.actual_volume = actual_volume; }
    if (driver_name && driver_name !== atl.driver_name) { changes.driver_name = { from: atl.driver_name, to: driver_name }; atl.driver_name = driver_name; }
    if (hauler && hauler !== atl.hauler) { changes.hauler = { from: atl.hauler, to: hauler }; atl.hauler = hauler; }
    
    revisions.push({
      timestamp: new Date().toISOString(),
      revised_by: req.user.email,
      changes: changes,
      remarks: remarks || 'Updated during loading'
    });
    
    atl.revision_history = JSON.stringify(revisions);
    if (remarks) atl.remarks = remarks;
    await atl.save();

    res.json({ 
      status: 'success', 
      message: 'Loading updated successfully',
      data: atl,
      revisions: revisions
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Cancel ongoing loading (revert to approved)
app.post('/api/dispatch/cancel-loading/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const atl = await AuthorityToLoad.findByPk(req.params.id);
    if (!atl) return res.status(404).json({ error: 'ATL not found' });
    if (atl.status !== 'dispatched') return res.status(400).json({ error: 'Only ongoing loading ATLs can be cancelled' });

    // Track revision
    const revisions = atl.revision_history ? JSON.parse(atl.revision_history) : [];
    revisions.push({
      timestamp: new Date().toISOString(),
      revised_by: req.user.email,
      changes: { status: { from: 'dispatched', to: 'approved' } },
      remarks: req.body.reason || 'Loading cancelled, reverted to approved'
    });

    atl.status = 'approved';
    atl.dispatch_date = null;
    atl.revision_history = JSON.stringify(revisions);
    atl.remarks = `Loading cancelled: ${req.body.reason || 'No reason provided'}`;
    await atl.save();

    res.json({ 
      status: 'success', 
      message: 'Loading cancelled, ATL reverted to approved',
      data: atl
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Complete loading with actual volume
app.post('/api/dispatch/complete-loading/:id', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const atl = await AuthorityToLoad.findByPk(req.params.id);
    if (!atl) return res.status(404).json({ error: 'ATL not found' });
    if (atl.status !== 'dispatched') return res.status(400).json({ error: 'ATL must be in loading status first' });

    const { actual_volume } = req.body;

    // Track revision
    const revisions = atl.revision_history ? JSON.parse(atl.revision_history) : [];
    const changes = { status: { from: 'dispatched', to: 'completed' } };
    if (actual_volume) {
      changes.actual_volume = { from: atl.actual_volume, to: actual_volume };
      atl.actual_volume = actual_volume;
    }
    
    revisions.push({
      timestamp: new Date().toISOString(),
      revised_by: req.user.email,
      changes: changes,
      remarks: req.body.remarks || 'Loading completed'
    });

    atl.status = 'completed';
    atl.completed_date = new Date();
    atl.completed_by = req.user.id;
    atl.revision_history = JSON.stringify(revisions);
    atl.remarks = `Loading completed. ${req.body.remarks || ''}`;
    await atl.save();

    res.json({ 
      status: 'success', 
      message: 'Loading completed successfully',
      data: atl
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get enhanced dashboard statistics
app.get('/api/dispatch/enhanced-stats', authenticate, authorize('dispatcher', 'management'), async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const [totalPending, totalApproved, totalLoading, totalCompleted, loadedToday] = await Promise.all([
      AuthorityToLoad.count({ where: { status: 'pending' } }),
      AuthorityToLoad.count({ where: { status: 'approved' } }),
      AuthorityToLoad.count({ where: { status: 'dispatched' } }),
      AuthorityToLoad.count({ where: { status: 'completed' } }),
      AuthorityToLoad.count({ where: { status: ['dispatched', 'completed'], dispatch_date: { [require('sequelize').Op.gte]: today } } })
    ]);

    // Calculate ACTUAL volume from ATL records (not truck capacity)
    const allLoaded = await AuthorityToLoad.findAll({ 
      where: { status: ['dispatched', 'completed'] }
    });
    
    let totalVolume = 0;
    let todayVolume = 0;
    
    for (const atl of allLoaded) {
      const vol = parseFloat(atl.volume) || 0;
      totalVolume += vol;
      
      // Today's volume
      if (atl.dispatch_date && new Date(atl.dispatch_date) >= today) {
        todayVolume += vol;
      }
    }

    res.json({
      status: 'success',
      data: {
        pending: totalPending,
        approved: totalApproved,
        loading: totalLoading,
        completed: totalCompleted,
        loadedToday,
        totalVolume,      // Actual ATL volume
        todayVolume        // Today's actual volume
      }
    });
  } catch (error) {
    console.error('Stats error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============ PAGES ============
app.get('/api/health', (req, res) => res.json({ status: 'OK' }));
app.get('/atl/:code', (req, res) => res.sendFile(path.join(__dirname, 'public', 'atl.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/client', (req, res) => res.sendFile(path.join(__dirname, 'public', 'client.html')));
app.get('/dispatcher', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/reports', (req, res) => res.sendFile(path.join(__dirname, 'public', 'reports.html')));

// ============ START SERVER ============
const PORT = process.env.PORT || 3000;

async function start() {
  try {
    await testConnection();
    
    // Only sync in development (not on Vercel/Aiven production)
    if (process.env.NODE_ENV !== 'production') {
      await sequelize.sync({ alter: true });
      console.log('✅ Database synced');
    } else {
      console.log('✅ Database connected (skipping sync for production)');
    }
    
    // Only listen locally, Vercel handles this in production
    if (process.env.NODE_ENV !== 'production') {
      app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));
    }
  } catch (error) {
    console.error('❌ Startup error:', error);
  }
}

start();

module.exports = app;