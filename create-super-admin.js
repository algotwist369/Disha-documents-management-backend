/**
 * Script to create the first Super Admin user
 * Run this once to create your super admin account
 * 
 * Usage: node create-super-admin.js
 */

const mongoose = require('mongoose');
const User = require('./models/userModel');
const dotenv = require('dotenv');
const readline = require('readline');

dotenv.config();

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const question = (query) => new Promise((resolve) => rl.question(query, resolve));

const createSuperAdmin = async () => {
  try {
    console.log('\n=== Create Super Admin User ===\n');

    // Connect to database
    const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/dos';
    await mongoose.connect(MONGO_URI);
    console.log('✅ Connected to database\n');

    // Check if super admin already exists
    const existingSuperAdmin = await User.findOne({ role: 'super_admin' });
    if (existingSuperAdmin) {
      console.log('⚠️  A super admin already exists:');
      console.log(`   Name: ${existingSuperAdmin.name}`);
      console.log(`   Phone: ${existingSuperAdmin.phone}`);
      console.log(`   ID: ${existingSuperAdmin._id}\n`);
      
      const confirm = await question('Do you want to create another super admin? (yes/no): ');
      if (confirm.toLowerCase() !== 'yes') {
        console.log('\n❌ Cancelled');
        rl.close();
        process.exit(0);
      }
      console.log('');
    }

    // Get user input
    const name = await question('Enter name: ');
    if (!name || name.trim().length === 0) {
      console.log('\n❌ Name is required');
      rl.close();
      process.exit(1);
    }

    const phone = await question('Enter phone number: ');
    if (!phone || phone.trim().length === 0) {
      console.log('\n❌ Phone is required');
      rl.close();
      process.exit(1);
    }

    // Check if phone already exists
    const existingUser = await User.findOne({ phone: phone.trim() });
    if (existingUser) {
      console.log('\n❌ A user with this phone number already exists');
      console.log(`   Name: ${existingUser.name}`);
      console.log(`   Role: ${existingUser.role}`);
      console.log(`   ID: ${existingUser._id}\n`);
      
      const upgrade = await question('Do you want to upgrade this user to super admin? (yes/no): ');
      if (upgrade.toLowerCase() === 'yes') {
        existingUser.role = 'super_admin';
        existingUser.updatedAt = Date.now();
        await existingUser.save();
        
        console.log('\n✅ User upgraded to super admin successfully!');
        console.log(`   Name: ${existingUser.name}`);
        console.log(`   Phone: ${existingUser.phone}`);
        console.log(`   Role: ${existingUser.role}`);
        console.log(`   ID: ${existingUser._id}\n`);
      } else {
        console.log('\n❌ Cancelled');
      }
      rl.close();
      await mongoose.connection.close();
      process.exit(0);
    }

    const password = await question('Enter password (min 8 characters): ');
    if (!password || password.length < 8) {
      console.log('\n❌ Password must be at least 8 characters long');
      rl.close();
      process.exit(1);
    }

    // Create super admin
    const superAdmin = new User({
      name: name.trim(),
      phone: phone.trim(),
      password: password,
      role: 'super_admin'
    });

    await superAdmin.save();

    console.log('\n✅ Super Admin created successfully!');
    console.log(`   Name: ${superAdmin.name}`);
    console.log(`   Phone: ${superAdmin.phone}`);
    console.log(`   Role: ${superAdmin.role}`);
    console.log(`   ID: ${superAdmin._id}`);
    console.log('\n🔐 You can now login with these credentials\n');

    rl.close();
    await mongoose.connection.close();
    process.exit(0);

  } catch (error) {
    console.error('\n❌ Error:', error.message);
    rl.close();
    await mongoose.connection.close();
    process.exit(1);
  }
};

createSuperAdmin();

