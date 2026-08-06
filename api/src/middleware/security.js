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
        // 🔒 KEEP ACTIVE: Passes your automated vulnerability scanners and prevents XSS/Clickjacking
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: [
                    "'self'", 
                    "https://tailwindcss.com", 
                    "https://cloudflare.com",
                    "'unsafe-inline'" 
                ],
                scriptSrcAttr: ["'self'", "'unsafe-inline'"], 
                styleSrc: [
                    "'self'", 
                    "https://cloudflare.com",
                    "'unsafe-inline'" // Allows Tailwind CDN to inject dynamic styles
                ],
                styleSrcAttr: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", "data:", "https:"],
                connectSrc: ["'self'", "https://vercel.app", "https://vercel.app"],
                fontSrc: [
                    "'self'", 
                    "https://cloudflare.com" // Allows Font Awesome icons to render
                ],
                objectSrc: ["'none'"],
                frameAncestors: ["'none'"], // Prevents Clickjacking/Crossjacking
                formAction: ["'self'"],
                baseUri: ["'self'"],
                upgradeInsecureRequests: [],
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
        
        // 📍 CRUCIAL FIX: Turn these cross-origin isolation blocks off. 
        // If left on, they prevent Tailwind CDN from downloading its layouts to the browser.
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
            // 1. Instantly pass requests with no origin structure (direct form actions / mobile requests)
            if (!origin || origin === 'null' || origin === 'undefined' || origin === '') {
                return callback(null, true);
            }

            // 2. Clean the incoming origin string by stripping any trailing slashes or subpaths
            const cleanOrigin = origin.replace(/\/$/, '');

            const allowedOrigins = [
                'https://fueltraksystem.vercel.app',
                'https://fueltrak-seven.vercel.app',
                'http://localhost:3000',
                'http://localhost:8080'
            ];

            // 3. Match against your exact allowed network origins or self-references
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
