require('dotenv').config({ path: require('path').join(__dirname, '../../.env') });
const { sequelize } = require('../config/database');
const { User, Truck, TruckDocument } = require('../models');

async function seed() {
  try {
    await sequelize.sync({ force: true });
    console.log('✅ Database synced');

    const users = await User.bulkCreate([
      { 
        email: 'admin@fueltrak.com', 
        password: 'password123', 
        mobile: '+639171234567', 
        role: 'management', 
        company_name: 'FuelTrak Inc' 
      },
      { 
        email: 'dispatcher@fueltrak.com', 
        password: 'password123', 
        mobile: '+639172345678', 
        role: 'dispatcher' 
      },
      { 
        email: 'client1@hauler.com', 
        password: 'password123', 
        mobile: '+639173456789', 
        role: 'client', 
        company_name: 'Fast Haulers Inc' 
      }
    ]);
    console.log('✅ Users created');

    const truck = await Truck.create({
      plate_no: 'ABC1234',
      make: 'ISUZU',
      driver_name: 'Juan Dela Cruz',
      hauler_name: 'Fast Haulers Inc',
      total_capacity: 40000,
      num_tps: 4,
      calibration_date: '2024-01-15',
      next_calibration_date: '2025-01-15',
      discharge_line: 'including'
    });
    console.log('✅ Truck created');

    await TruckDocument.bulkCreate([
      {
        truck_id: truck.id,
        document_type: 'lto_registration',
        document_number: 'LTO-2024-001',
        issue_date: '2024-01-01',
        expiry_date: '2025-06-30',
        status: 'valid'
      },
      {
        truck_id: truck.id,
        document_type: 'fire_permit',
        document_number: 'FP-2024-001',
        issue_date: '2024-01-01',
        expiry_date: '2024-12-31',
        status: 'valid'
      },
      {
        truck_id: truck.id,
        document_type: 'dost_calibration',
        document_number: 'DOST-2024-001',
        issue_date: '2024-01-15',
        expiry_date: '2025-01-15',
        status: 'valid'
      }
    ]);
    console.log('✅ Documents created');

    console.log('\n🎉 Database seeded successfully!');
    console.log('\n📋 Test Accounts:');
    console.log('  Management: admin@fueltrak.com / password123');
    console.log('  Dispatcher: dispatcher@fueltrak.com / password123');
    console.log('  Client:     client1@hauler.com / password123');
    
    process.exit(0);
  } catch (error) {
    console.error('❌ Seeding failed:', error.message);
    process.exit(1);
  }
}

seed();