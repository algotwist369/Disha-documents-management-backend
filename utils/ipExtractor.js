const os = require('os');
const https = require('https');
const http = require('http');

/**
 * Get the actual network IP address of the server
 * This helps when client is connecting from localhost but we want to show network IP
 */
const getNetworkIP = () => {
    const interfaces = os.networkInterfaces();
    
    // Priority order: eth0, wlan0, en0, en1, or first non-localhost IPv4
    const priorityOrder = ['eth0', 'wlan0', 'en0', 'en1', 'Wi-Fi', 'Ethernet'];
    
    // First try priority interfaces
    for (const ifaceName of priorityOrder) {
        const iface = interfaces[ifaceName];
        if (iface) {
            for (const addr of iface) {
                if (addr.family === 'IPv4' && !addr.internal) {
                    return addr.address;
                }
            }
        }
    }
    
    // Fallback: find first non-localhost IPv4 address
    for (const ifaceName of Object.keys(interfaces)) {
        const iface = interfaces[ifaceName];
        for (const addr of iface) {
            if (addr.family === 'IPv4' && !addr.internal) {
                return addr.address;
            }
        }
    }
    
    return null;
};

/**
 * Check if an IP is a private/local network IP
 */
const isPrivateIP = (ip) => {
    if (!ip) return false;
    
    // Check for localhost
    if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') {
        return true;
    }
    
    // Check for private IP ranges
    const privateRanges = [
        /^10\./,           // 10.0.0.0/8
        /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12
        /^192\.168\./,      // 192.168.0.0/16
        /^169\.254\./,      // Link-local
        /^::1$/,            // IPv6 localhost
        /^fe80:/,           // IPv6 link-local
        /^fc00:/,           // IPv6 private
        /^fd00:/            // IPv6 private
    ];
    
    return privateRanges.some(range => range.test(ip));
};

/**
 * Get public IP from external service (fallback only)
 * This is async and should only be used as last resort
 */
const getPublicIPFromService = () => {
    return new Promise((resolve) => {
        // Try multiple services for reliability
        const services = [
            'https://api.ipify.org',
            'https://api64.ipify.org',
            'https://icanhazip.com',
            'https://ifconfig.me/ip'
        ];
        
        let attempts = 0;
        const tryService = (index) => {
            if (index >= services.length) {
                resolve(null);
                return;
            }
            
            const url = new URL(services[index]);
            const client = url.protocol === 'https:' ? https : http;
            
            const req = client.get(url.href, (res) => {
                let data = '';
                res.on('data', (chunk) => { data += chunk; });
                res.on('end', () => {
                    const ip = data.trim();
                    if (ip && /^[\d\.]+$/.test(ip)) {
                        resolve(ip);
                    } else {
                        tryService(index + 1);
                    }
                });
            });
            
            req.on('error', () => {
                tryService(index + 1);
            });
            
            req.setTimeout(2000, () => {
                req.destroy();
                tryService(index + 1);
            });
        };
        
        tryService(0);
    });
};

/**
 * Process and clean an IP address string
 */
const processIP = (ip) => {
    if (!ip) return null;
    
    let processed = ip.trim();
    
    // Remove IPv6 brackets
    if (processed.startsWith('[') && processed.endsWith(']')) {
        processed = processed.slice(1, -1);
    }
    
    // Handle IPv6-mapped IPv4 addresses (::ffff:192.168.1.1 -> 192.168.1.1)
    if (processed.startsWith('::ffff:')) {
        processed = processed.replace('::ffff:', '');
    }
    
    // Validate IP format (basic check)
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipv4Regex.test(processed) && processed !== '::1' && !processed.includes(':')) {
        return null; // Invalid IP format
    }
    
    return processed;
};

/**
 * Extract real client IP address from request
 * Handles proxies, IPv6, and various headers
 * Prioritizes PUBLIC IP addresses over private network IPs
 */
const getClientIP = (req) => {
    let publicIP = null;
    let privateIP = null;
    let extractedIP = null;
    
    // Debug: Log all relevant headers
    const debugHeaders = {
        'x-forwarded-for': req.headers['x-forwarded-for'],
        'x-real-ip': req.headers['x-real-ip'],
        'cf-connecting-ip': req.headers['cf-connecting-ip'],
        'x-forwarded': req.headers['x-forwarded'],
        'forwarded': req.headers['forwarded'],
        'req.ip': req.ip,
        'remoteAddress': req.connection?.remoteAddress || req.socket?.remoteAddress
    };
    
    // Priority 1: X-Forwarded-For header (most common with reverse proxies)
    // Format: "client-ip, proxy1-ip, proxy2-ip" or just "client-ip"
    // IMPORTANT: When behind a reverse proxy, X-Forwarded-For contains the CLIENT's public IP
    // The FIRST IP is typically the original client's public IP
    const xForwardedFor = req.headers['x-forwarded-for'];
    if (xForwardedFor) {
        const ips = xForwardedFor.split(',').map(ip => processIP(ip.trim())).filter(Boolean);
        
        // CRITICAL: Check ALL IPs in the chain, but prioritize PUBLIC IPs
        // Reverse proxies often add: "client-public-ip, proxy-private-ip, proxy2-ip"
        // We want the PUBLIC IP (which is usually the first one if client is external)
        for (const ip of ips) {
            if (!isPrivateIP(ip)) {
                // Found a public IP - this is what we want!
                publicIP = ip;
                break; // Use first public IP found (this is the client's public IP)
            }
        }
        
        // If no public IP in X-Forwarded-For, use first IP anyway
        // (might be private if client is on same network, but it's what proxy sent)
        if (!publicIP && ips.length > 0) {
            privateIP = ips[0];
        }
    }
    
    // Priority 2: X-Real-IP header (nginx, other proxies)
    if (!publicIP) {
        const xRealIP = req.headers['x-real-ip'];
        if (xRealIP) {
            const ip = processIP(xRealIP);
            if (ip) {
                if (!isPrivateIP(ip)) {
                    publicIP = ip;
                } else if (!privateIP) {
                    privateIP = ip;
                }
            }
        }
    }
    
    // Priority 3: CF-Connecting-IP (Cloudflare) - always public
    const cfConnectingIP = req.headers['cf-connecting-ip'];
    if (cfConnectingIP && !publicIP) {
        const ip = processIP(cfConnectingIP);
        if (ip && !isPrivateIP(ip)) {
            publicIP = ip;
        }
    }
    
    // Priority 4: Forwarded header (RFC 7239 standard)
    const forwarded = req.headers['forwarded'];
    if (forwarded && !publicIP) {
        // Parse Forwarded header: Forwarded: for=192.0.2.60;proto=http;by=203.0.113.43
        const forMatch = forwarded.match(/for=([^;,\s]+)/i);
        if (forMatch) {
            let ip = forMatch[1];
            // Remove quotes if present
            if (ip.startsWith('"') && ip.endsWith('"')) {
                ip = ip.slice(1, -1);
            }
            // Remove IPv6 brackets
            if (ip.startsWith('[') && ip.endsWith(']')) {
                ip = ip.slice(1, -1);
            }
            const processedIP = processIP(ip);
            if (processedIP && !isPrivateIP(processedIP)) {
                publicIP = processedIP;
            }
        }
    }
    
    // Priority 5: req.ip (works with trust proxy setting)
    if (!publicIP && req.ip) {
        const ip = processIP(req.ip);
        if (ip) {
            if (!isPrivateIP(ip)) {
                publicIP = ip;
            } else if (!privateIP) {
                privateIP = ip;
            }
        }
    }
    
    // Priority 6: Connection remote address (last resort)
    if (!publicIP && !privateIP) {
        const remoteAddr = req.connection?.remoteAddress || req.socket?.remoteAddress;
        if (remoteAddr) {
            const ip = processIP(remoteAddr);
            if (ip) {
                if (!isPrivateIP(ip)) {
                    publicIP = ip;
                } else {
                    privateIP = ip;
                }
            }
        }
    }
    
    // Return public IP if found, otherwise return private IP
    extractedIP = publicIP || privateIP;
    
    // IMPORTANT: If we have a private IP but the client is accessing from outside,
    // the public IP should be in X-Forwarded-For if there's a reverse proxy
    // If we're still getting private IP, it means:
    // 1. Client is on same network (direct connection)
    // 2. OR reverse proxy is not configured to forward public IP
    
    // If we only have a private IP and it's localhost, try to get network IP
    if (extractedIP && isPrivateIP(extractedIP) && 
        (extractedIP === '127.0.0.1' || extractedIP === '::1')) {
        const networkIP = getNetworkIP();
        if (networkIP) {
            extractedIP = networkIP;
        }
    }
    
    // Log for debugging (always log in dev, optionally in production)
    if (extractedIP) {
        const logLevel = process.env.NODE_ENV === 'production' ? 'warn' : 'log';
        console[logLevel]('🔍 IP Extraction:', {
            extractedIP,
            isPublic: !isPrivateIP(extractedIP),
            foundPublicIP: !!publicIP,
            foundPrivateIP: !!privateIP,
            'x-forwarded-for': req.headers['x-forwarded-for'] || 'not present',
            'x-real-ip': req.headers['x-real-ip'] || 'not present',
            'req.ip': req.ip || 'not present'
        });
    }
    
    return extractedIP || 'Unknown';
};

module.exports = { getClientIP, getNetworkIP };

