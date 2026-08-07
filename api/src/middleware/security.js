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
    
    // 1. Core Helmet configuration with the correct, explicit subdomains
    app.use(helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: [
                    "'self'", 
                    "https://cdn.tailwindcss.com",       // 📍 Explicitly allowed
                    "https://cdnjs.cloudflare.com",      // 📍 Explicitly allowed
                    "'unsafe-inline'" 
                ],
                scriptSrcAttr: ["'self'", "'unsafe-inline'"], 
                styleSrc: [
                    "'self'", 
                    "https://cdnjs.cloudflare.com",     // 📍 Explicitly allowed
                    "'unsafe-inline'"
                ],
                styleSrcAttr: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", "data:", "https:"],
                connectSrc: ["'self'", "https://vercel.app", "https://vercel.app"],
                fontSrc: [
                    "'self'", 
                    "https://cdnjs.cloudflare.com"     // 📍 Explicitly allowed for icons
                ],
                objectSrc: ["'none'"],
                frameAncestors: ["'none'"], 
                formAction: ["'self'"],
                baseUri: ["'self'"],
                upgradeInsecureRequests: null 
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
        crossOriginEmbedderPolicy: false, 
        crossOriginOpenerPolicy: false,
        crossOriginResourcePolicy: false,
    }));
    
    // 2. Modified Response Header Cleanup Middleware (Overwriting bug removed from here!)
    app.use((req, res, next) => {
        res.removeHeader('X-Powered-By');
        res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=(), payment=(), usb=(), accelerometer=(), autoplay=(), clipboard-read=(), clipboard-write=(self), display-capture=(), fullscreen=(self), gyroscope=(), magnetometer=(), midi=(), picture-in-picture=(), sync-xhr=()');
        res.setHeader('X-Download-Options', 'noopen');
        
        if (req.path.startsWith('/api/')) {
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        }
        next();
    });
    
    app.use(compression());
    
    // 3. CORS Configuration
    app.use(cors({
        origin: (origin, callback) => {
            if (!origin || origin === 'null' || origin === 'undefined' || origin === '') {
                return callback(null, true);
            }
            const cleanOrigin = origin.replace(/\/$/, '');
            const allowedOrigins = [
                'https://vercel.app',
                'https://vercel.app',
                'http://localhost:3000',
                'http://localhost:8080'
            ];
            if (allowedOrigins.includes(cleanOrigin) || cleanOrigin.includes('vercel.app')) {
                callback(null, true);
            } else {
                console.warn('CORS blocked origin request from: ' + origin);
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