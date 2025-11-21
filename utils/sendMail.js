const nodemailer = require('nodemailer');
require('dotenv').config();

const parseBoolean = (value, fallback = undefined) => {
    if (value === undefined || value === null || value === '') return fallback;
    return value === true || value === 'true' || value === '1';
};

const createTransport = (secureOverride) => {
    const {
        SMTP_HOST,
        SMTP_PORT,
        SMTP_USER,
        SMTP_PASS,
        SMTP_SECURE,
        SMTP_TLS_REJECT_UNAUTHORIZED,
    } = process.env;

    if (!SMTP_HOST || !SMTP_PORT) {
        throw new Error('SMTP configuration missing: please set SMTP_HOST and SMTP_PORT in environment');
    }

    const numericPort = Number(SMTP_PORT);
    const secureFlag = parseBoolean(SMTP_SECURE);
    const secure =
        secureOverride !== undefined
            ? secureOverride
            : secureFlag !== undefined
                ? secureFlag
                : numericPort === 465 // implicit TLS
                    ? true
                    : false; // default STARTTLS/PLAIN

    const transportConfig = {
        host: SMTP_HOST.replace(/^https?:\/\//i, ''), // guard against accidental scheme prefixes
        port: numericPort,
        secure,
        auth: SMTP_USER && SMTP_PASS ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
        tls: {
            rejectUnauthorized: parseBoolean(SMTP_TLS_REJECT_UNAUTHORIZED, true),
        },
    };

    return {
        transporter: nodemailer.createTransport(transportConfig),
        config: transportConfig,
    };
};

// Send an email using configured SMTP.

const shouldRetryWithOppositeSecure = (error) => {
    if (!error || typeof error !== 'object') return false;
    if (error.code !== 'ESOCKET') return false;
    if (!error.reason && !error.message) return false;
    const message = `${error.reason || ''} ${error.message || ''}`.toLowerCase();
    return message.includes('wrong version number');
};

const logPreviewIfAvailable = (info) => {
    if (info && info.messageId && nodemailer.getTestMessageUrl) {
        const preview = nodemailer.getTestMessageUrl(info);
        if (preview) console.info('Preview URL:', preview);
    }
};

const sendMail = async ({ to, subject, text, html, attachments } = {}) => {
    if (!to) throw new Error('`to` is required');
    if (!subject) throw new Error('`subject` is required');
    if (!text && !html) throw new Error('Either `text` or `html` is required');

    const { transporter, config } = createTransport();

    const from = process.env.SMTP_FROM || process.env.SMTP_USER || `no-reply@${process.env.SMTP_HOST || 'localhost'}`;

    const mailOptions = {
        from,
        to,
        subject,
        text,
        html,
        attachments,
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        logPreviewIfAvailable(info);
        return info;
    } catch (error) {
        if (shouldRetryWithOppositeSecure(error)) {
            try {
                const fallbackSecure = !config.secure;
                console.warn(
                    `sendMail: TLS handshake failed with secure=${config.secure}. Retrying with secure=${fallbackSecure}...`
                );
                const { transporter: fallbackTransporter } = createTransport(fallbackSecure);
                const info = await fallbackTransporter.sendMail(mailOptions);
                logPreviewIfAvailable(info);
                return info;
            } catch (fallbackError) {
                console.error('sendMail fallback attempt failed:', fallbackError);
                throw fallbackError;
            }
        }
        throw error;
    }
}

module.exports = sendMail;
