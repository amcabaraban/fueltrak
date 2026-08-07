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
            res.setHeader('Pragma', 'no-cache'); 
            res.setHeader('Expires', '0');
        }
        next();
    });
    
    app.use(helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://cdnjs.cloudflare.com"],
                scriptSrcAttr: ["'self'", "'unsafe-inline'", "'unsafe-hashes'"],
                styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
                styleSrcAttr: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", "data:", "https:"],
                connectSrc: ["'self'", "https://fueltraksystem.vercel.app", "https://fueltrak-seven.vercel.app"],
                fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
                objectSrc: ["'none'"],
                frameAncestors: ["'none'"],
                formAction: ["'self'"],
                baseUri: ["'self'"],
            }
        },
        hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
        frameguard: { action: 'deny' },
        hidePoweredBy: true,
        noSniff: true,
        xssFilter: true,
        referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
        permittedCrossDomainPolicies: { permittedPolicies: 'none' },
        dnsPrefetchControl: { allow: false },
        crossOriginEmbedderPolicy: { policy: 'credentialless' },
        crossOriginOpenerPolicy: { policy: 'same-origin' },
        crossOriginResourcePolicy: { policy: 'same-origin' },
    }));
    
    app.use((req, res, next) => {
        res.removeHeader('X-Powered-By');
        res.setHeader('X-XSS-Protection', '1; mode=block');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Download-Options', 'noopen');
        res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=(), payment=(), usb=(), accelerometer=(), autoplay=(), clipboard-read=(), clipboard-write=(self), display-capture=(), fullscreen=(self), gyroscope=(), magnetometer=(), midi=(), picture-in-picture=(), sync-xhr=()');
        if (req.path.startsWith('/api/')) {
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        }
        next();
    });
    
    app.use(compression());
    
    app.use(cors({
        origin: (origin, callback) => {
            if (!origin) return callback(null, true);
            const allowedOrigins = [
                'https://fueltraksystem.vercel.app',
                'https://fueltrak-seven.vercel.app',
                'http://localhost:3000',
                'http://localhost:8080'
            ];
            if (allowedOrigins.includes(origin.replace(/\/$/, ''))) {
                callback(null, true);
            } else {
                console.warn('CORS blocked: ' + origin);
                callback(new Error('Not allowed by CORS'));
            }
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