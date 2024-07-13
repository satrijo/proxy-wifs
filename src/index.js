import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import env from 'dotenv';
env.config();

const app = express();

// Ganti dengan URL asli yang ingin Anda proxy, termasuk kredensial asli
const targetUrl = 'https://aviationweather.gov/wifs/data/';
const auth = {
    username: process.env.USERNAME || 'admin',
    password: process.env.PASSWORD || 'password'
};

// Middleware untuk autentikasi basic pada endpoint utama
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        res.set('WWW-Authenticate', 'Basic realm="example"');
        res.status(401).send('Unauthorized');
    } else {
        // Decode kredensial dari header Authorization
        const encodedCreds = authHeader.split(' ')[1];
        const decodedCreds = Buffer.from(encodedCreds, 'base64').toString();
        const [username, password] = decodedCreds.split(':');
        console.log(username, password);

        // Memeriksa kredensial yang diberikan
        if (username === 'admin' && password === 'password') {
            req.headers.authorization = `Basic ${Buffer.from(`${auth.username}:${auth.password}`).toString('base64')}`;
            next();
        } else {
            res.set('WWW-Authenticate', 'Basic realm="example"');
            res.status(401).send('Unauthorized');
        }
    }
};

app.use(authMiddleware);

// Menyediakan endpoint proxy dengan autentikasi basic untuk kredensial asli
app.use('/', createProxyMiddleware({
    target: targetUrl,
    changeOrigin: true,
    onError: (err, req, res) => {
        console.error('Proxy Error:', err);
        res.status(500).send('Proxy Error');
    }
}));

// Port yang digunakan oleh server proxy
const port = 3000;
app.listen(port, () => {
    console.log(`Proxy server listening on port ${port}`);
});
