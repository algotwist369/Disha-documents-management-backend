const nodemailer = require('nodemailer');
const dotenv = require('dotenv');

dotenv.config();

// Contract:
// - inputs: { to, subject, text, html, attachments }
// - outputs: result info from nodemailer or thrown error
// - errors: throws when transport config missing or send fails

const createTransport = () => {
    const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_SECURE } = process.env;

    if (!SMTP_HOST || !SMTP_PORT) {
        throw new Error('SMTP configuration missing: please set SMTP_HOST and SMTP_PORT in environment');
    }

    return nodemailer.createTransport({
        host: SMTP_HOST,
        port: Number(SMTP_PORT),
        secure: SMTP_SECURE === 'true' || SMTP_SECURE === '1',
        auth: SMTP_USER && SMTP_PASS ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
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
