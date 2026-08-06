const helmet = require('helmet');
const compression = require('compression');
const cors = require('cors');
const path = require('path');
const express = require('express');
const crypto = require('crypto');

function setupSecurity(app) {
    app.set('trust proxy', 1);
    app.use(express.json({ limit: '10kb' }));
    app.use(express.urlencoded({ extended: false, limit: '10kb' }));
    
    app.use((req, res, next) => {
        if (req.path === '/' || req.path === '/index.html' || req.path === '/client') {
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
            res.setHeader('Pragma', 'no-cache'); res.setHeader('Expires', '0');
        }
        next();
    });
    
    // 1. Create a dynamic nonce for every single HTTP request
    app.use((req, res, next) => {
        res.locals.nonce = crypto.randomBytes(16).toString('base64');
        next();
    });
    
    // 2. Configure Helmet to dynamically read and pass this nonce to the browser
    app.use(helmet({
        // 📍 Temp Test: Turn off CSP to see if your layout immediately comes back
        contentSecurityPolicy: false, 
        hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
        frameguard: { action: 'deny' },
        hidePoweredBy: true,
        noSniff: true,
        xssFilter: true,
        referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
        permittedCrossDomainPolicies: { permittedPolicies: 'none' },
        dnsPrefetchControl: { allow: false },
        // 📍 Critical: Disable strict resource isolation which breaks Tailwind CDN
        crossOriginEmbedderPolicy: false, 
        crossOriginOpenerPolicy: false,
        crossOriginResourcePolicy: false,
    }));

    
    app.use((req, res, next) => {
        res.removeHeader('X-Powered-By');
        res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=(), payment=(), usb=(), accelerometer=(), autoplay=(), clipboard-read=(), clipboard-write=(self), display-capture=(), fullscreen=(self), gyroscope=(), magnetometer=(), midi=(), picture-in-picture=(), sync-xhr=()');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-DNS-Prefetch-Control', 'off');
        res.setHeader('X-Download-Options', 'noopen');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
        res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
        res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
        if (req.path.startsWith('/api/')) {
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        }
        next();
    });
    
    app.use(compression());
    
    app.use(cors({
        origin: (origin, callback) => {
            const allowedOrigins = ['https://vercel.app', 'https://vercel.app', 'http://localhost:3000', 'http://localhost:8080'];
            if (!origin) return callback(null, true);
            if (allowedOrigins.includes(origin)) { callback(null, true); }
            else { console.warn('CORS blocked origin: ' + origin); callback(new Error('Not allowed by CORS')); }
        },
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
        exposedHeaders: ['Content-Length', 'X-RateLimit-Limit', 'X-RateLimit-Remaining'],
        maxAge: 86400
    }));
    
    app.use('/css', express.static(path.join(__dirname, '..', '..', 'public', 'css'), { maxAge: '1h', setHeaders: (res) => res.setHeader('Cache-Control', 'public, max-age=3600') }));
    app.use('/js', express.static(path.join(__dirname, '..', '..', 'public', 'js'), { maxAge: '1h', setHeaders: (res) => res.setHeader('Cache-Control', 'public, max-age=3600') }));
    app.use('/images', express.static(path.join(__dirname, '..', '..', 'public', 'images'), { maxAge: '24h', setHeaders: (res) => res.setHeader('Cache-Control', 'public, max-age=86400') }));
    app.use('/public', express.static(path.join(__dirname, '..', '..', 'public'), { maxAge: '1h', setHeaders: (res, fp) => res.setHeader('Cache-Control', fp.endsWith('.html') ? 'public, max-age=0, must-revalidate' : 'public, max-age=3600') }));
}

module.exports = { setupSecurity };
