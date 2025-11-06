/**
 * Simple in-memory cache for frequently accessed data
 * Production-ready with TTL and size limits
 */

class SimpleCache {
  constructor(maxSize = 100, defaultTTL = 300000) { // 5 minutes default TTL
    this.cache = new Map();
    this.maxSize = maxSize;
    this.defaultTTL = defaultTTL;
  }

  get(key) {
    const item = this.cache.get(key);
    if (!item) return null;
    
    // Check if expired
    if (Date.now() > item.expiresAt) {
      this.cache.delete(key);
      return null;
    }
    
    return item.value;
  }

  set(key, value, ttl = this.defaultTTL) {
    // If cache is full, remove oldest entry
    if (this.cache.size >= this.maxSize && !this.cache.has(key)) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    
    this.cache.set(key, {
      value,
      expiresAt: Date.now() + ttl
    });
  }

  delete(key) {
    return this.cache.delete(key);
  }

  clear() {
    this.cache.clear();
  }

  size() {
    return this.cache.size;
  }
}

// Create cache instances for different data types
const categoryCache = new SimpleCache(50, 600000); // 10 minutes for categories
const statsCache = new SimpleCache(10, 60000); // 1 minute for stats
const userCache = new SimpleCache(100, 300000); // 5 minutes for users

module.exports = {
  categoryCache,
  statsCache,
  userCache,
  SimpleCache
};

