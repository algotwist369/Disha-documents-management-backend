const nodemailer = require('nodemailer');
require('dotenv').config();

const parseBoolean = (value, fallback = undefined) => {
    if (value === undefined || value === null || value === '') return fallback;
    return value === true || value === 'true' || value === '1';
};

const createTransport = () => {
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
        secureFlag !== undefined
            ? secureFlag
            : numericPort === 465 // implicit TLS
                ? true
                : false; // default STARTTLS/PLAIN

    return nodemailer.createTransport({
        host: SMTP_HOST.replace(/^https?:\/\//i, ''), // guard against accidental scheme prefixes
        port: numericPort,
        secure,
        auth: SMTP_USER && SMTP_PASS ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
        tls: {
            rejectUnauthorized: parseBoolean(SMTP_TLS_REJECT_UNAUTHORIZED, true),
        },
    });
};

// Send an email using configured SMTP.

const sendMail = async ({ to, subject, text, html, attachments } = {}) => {
    if (!to) throw new Error('`to` is required');
    if (!subject) throw new Error('`subject` is required');
    if (!text && !html) throw new Error('Either `text` or `html` is required');

    const transporter = createTransport();

    const from = process.env.SMTP_FROM || process.env.SMTP_USER || `no-reply@${process.env.SMTP_HOST || 'localhost'}`;

    const mailOptions = {
        from,
        to,
        subject,
        text,
        html,
        attachments,
    };

    const info = await transporter.sendMail(mailOptions);
    // If using services like Ethereal, log preview url when available
    if (info && info.messageId && nodemailer.getTestMessageUrl) {
        const preview = nodemailer.getTestMessageUrl(info);
        if (preview) console.info('Preview URL:', preview);
    }

    return info;
}

module.exports = sendMail;
