#!/usr/bin/env node

/**
 * Generate a secure encryption key for AES-256-GCM
 * Run: node generate-encryption-key.js
 */

const crypto = require('crypto');

// Generate a random 32-byte (256-bit) key
const key = crypto.randomBytes(32);

// Convert to base64 for easy storage in .env
const keyBase64 = key.toString('base64');

console.log('\n=================================================');
console.log('  FILE ENCRYPTION KEY GENERATOR');
console.log('=================================================\n');
console.log('Your secure encryption key (base64 encoded):');
console.log('\n' + keyBase64 + '\n');
console.log('Add this to your .env file:');
console.log('\nFILE_ENCRYPTION_KEY=' + keyBase64);
console.log('\n=================================================');
console.log('⚠️  IMPORTANT: Keep this key secure!');
console.log('   - Never commit it to git');
console.log('   - Store it securely');
console.log('   - If you lose it, encrypted files cannot be decrypted');
console.log('=================================================\n');

