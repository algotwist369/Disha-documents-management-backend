/**
 * Parse user agent string to extract device information
 */
const parseDeviceInfo = (userAgent, ip) => {
    if (!userAgent) {
        return {
            userAgent: 'Unknown',
            browser: 'Unknown',
            os: 'Unknown',
            device: 'Unknown',
            ip: ip || 'Unknown'
        };
    }

    // Detect Browser
    let browser = 'Unknown';
    if (userAgent.includes('Chrome') && !userAgent.includes('Edg')) {
        browser = 'Chrome';
    } else if (userAgent.includes('Firefox')) {
        browser = 'Firefox';
    } else if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) {
        browser = 'Safari';
    } else if (userAgent.includes('Edg')) {
        browser = 'Edge';
    } else if (userAgent.includes('Opera') || userAgent.includes('OPR')) {
        browser = 'Opera';
    }

    // Detect OS
    let os = 'Unknown';
    if (userAgent.includes('Windows')) {
        os = 'Windows';
    } else if (userAgent.includes('Mac')) {
        os = 'MacOS';
    } else if (userAgent.includes('Linux')) {
        os = 'Linux';
    } else if (userAgent.includes('Android')) {
        os = 'Android';
    } else if (userAgent.includes('iOS') || userAgent.includes('iPhone') || userAgent.includes('iPad')) {
        os = 'iOS';
    }

    // Detect Device Type
    let device = 'Desktop';
    if (userAgent.includes('Mobile')) {
        device = 'Mobile';
    } else if (userAgent.includes('Tablet') || userAgent.includes('iPad')) {
        device = 'Tablet';
    }

    return {
        userAgent,
        browser,
        os,
        device,
        ip: ip || 'Unknown'
    };
};

module.exports = { parseDeviceInfo };

