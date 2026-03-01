const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const path = require('path');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const csrf = require('csurf');
const jwt = require('jsonwebtoken');
const winston = require('winston');
const { Connection, PublicKey, LAMPORTS_PER_SOL } = require('@solana/web3.js');
const validator = require('validator');
require('dotenv').config();

// Enhanced Logging Setup
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'solana-game' },
    transports: [
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/combined.log' }),
        new winston.transports.File({ filename: 'logs/audit.log', level: 'warn' })
    ]
});

if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.simple()
    }));
}

// Environment variables validation
const requiredEnvVars = [
    'ADMIN_KEY', 'MONGO_URI', 'SESSION_SECRET', 'JWT_SECRET',
    'ADMIN_WALLET', 'GAME_WALLET', 'ADMIN_USERNAME', 'ADMIN_PASSWORD_HASH'
];

for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
        logger.error(`Missing required environment variable: ${envVar}`);
        process.exit(1);
    }
}

const app = express();
const server = http.createServer(app);

// Enhanced CORS configuration
const corsOptions = {
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    credentials: true,
    optionsSuccessStatus: 200,
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Admin-Key']
};

const io = socketIo(server, {
    cors: corsOptions,
    // Enhanced socket.io security
    allowRequest: (req, callback) => {
        // Verify origin
        const origin = req.headers.origin;
        const allowedOrigins = [process.env.FRONTEND_URL || "http://localhost:4001"];

        if (!allowedOrigins.includes(origin)) {
            logger.warn('Unauthorized socket connection attempt', { origin, ip: req.connection.remoteAddress });
            return callback('Origin not allowed', false);
        }

        callback(null, true);
    }
});

// Enhanced Security Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.socket.io"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            connectSrc: ["'self'", "ws:", "wss:"],
            imgSrc: ["'self'", "data:", "https:"],
            fontSrc: ["'self'", "https:"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"]
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    noSniff: true,
    xssFilter: true,
    referrerPolicy: { policy: 'same-origin' }
}));

// Enhanced Rate limiting with different tiers
const strictLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 50,
    message: { error: 'Too many requests from this IP' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        // Skip rate limiting for admin from whitelisted IPs (if needed)
        const adminIPs = (process.env.ADMIN_IPS || '').split(',');
        return adminIPs.includes(req.ip);
    }
});

const joinGameLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 2, // Reduced from 3
    message: { error: 'Too many join attempts, please wait' },
    standardHeaders: true,
    legacyHeaders: false
});

const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Reduced from 10
    message: { error: 'Too many admin requests' }
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 3, // Only 3 login attempts per 15 minutes
    message: { error: 'Too many login attempts' },
    skipSuccessfulRequests: true
});

app.use(strictLimiter);
app.use(cors(corsOptions));
app.use(express.json({ limit: '500kb' })); // Further reduced limit
app.use(express.urlencoded({ extended: true, limit: '500kb' }));

// Enhanced session configuration
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGO_URI,
        touchAfter: 24 * 3600,
        crypto: {
            secret: process.env.SESSION_SECRET
        }
    }),
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 2, // Reduced to 2 hours
        sameSite: 'strict'
    },
    name: 'sessionId' // Don't use default session name
}));

// CSRF Protection
const csrfProtection = csrf({
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    }
});

app.use(express.static('public'));

// Solana connection with enhanced error handling

// Solana connection with enhanced error handling using QuickNode
let connection;
try {
    // استخدم QuickNode RPC URL
    require("dotenv").config();
    const connection = new web3.Connection(process.env.RPC_URL, "confirmed");

    connection = new Connection(
        SOLANA_RPC_URL, {
            commitment: 'confirmed',
            httpHeaders: {
                'User-Agent': 'SolanaGame/1.0.0'
            }
        }
    );

    // Test connection with better error handling
    connection.getVersion().then((version) => {
        logger.info('Solana connection established via QuickNode', {
            version: version['solana-core'],
            rpcUrl: SOLANA_RPC_URL.substring(0, 50) + '...'
        });

        // Test slot information
        return connection.getSlot();
    }).then((slot) => {
        logger.info('Current Solana slot:', { slot });
    }).catch(err => {
        logger.error('Solana connection test failed:', err);
        process.exit(1);
    });
} catch (error) {
    logger.error('Failed to connect to Solana:', error);
    process.exit(1);
}

// Validate wallet addresses
const ADMIN_WALLET = process.env.ADMIN_WALLET;
const GAME_WALLET = process.env.GAME_WALLET;

function isValidSolanaAddress(address) {
    try {
        new PublicKey(address);
        return true;
    } catch {
        return false;
    }
}

if (!isValidSolanaAddress(ADMIN_WALLET) || !isValidSolanaAddress(GAME_WALLET)) {
    logger.error('Invalid Solana wallet addresses');
    process.exit(1);
}

// MongoDB connection with better error handling
mongoose.connect(process.env.MONGO_URI, {
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
    })
    .then(() => console.log('✅ MongoDB connected successfully'))
    .catch(err => {
        console.error('❌ MongoDB connection error:', err);
        process.exit(1);
    });
// Import models
const Player = require('./models/Player');

// Enhanced Game State with additional security
let gameState = {
    isActive: false,
    timeLeft: 240,
    totalPot: 0,
    roundNumber: 1,
    timer: null,
    playersCount: 0,
    winner: null,
    maxPlayers: 50, // Reduced for better control
    entryFee: 0.1, // SOL
    lastRoundStart: null,
    minTimeBetweenRounds: 30000, // 30 seconds minimum between rounds
    suspiciousActivities: new Map() // Track suspicious activities
};

// Enhanced Input validation middleware
const validateInput = (req, res, next) => {
    const { name, walletAddress, amount } = req.body;

    // Audit log for all join attempts
    logger.info('Join game attempt', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        name: name ? name.substring(0, 10) + '...' : 'undefined',
        walletAddress: walletAddress ? walletAddress.substring(0, 10) + '...' : 'undefined'
    });

    if (name && (!validator.isLength(name.trim(), { min: 1, max: 30 }) ||
            !validator.matches(name.trim(), /^[a-zA-Z0-9\s]+$/))) {
        logger.warn('Invalid name format attempted', { ip: req.ip, name });
        return res.status(400).json({ error: 'Invalid name format' });
    }

    if (walletAddress && !isValidSolanaAddress(walletAddress)) {
        logger.warn('Invalid wallet address attempted', { ip: req.ip, walletAddress });
        return res.status(400).json({ error: 'Invalid wallet address' });
    }

    if (amount && (!validator.isFloat(amount.toString(), { min: 0.0001, max: 10 }))) {
        logger.warn('Invalid amount attempted', { ip: req.ip, amount });
        return res.status(400).json({ error: 'Invalid amount' });
    }

    next();
};

// Enhanced admin authentication middleware
const requireAdmin = (req, res, next) => {
    if (!req.session.admin || !req.session.adminId) {
        logger.warn('Unauthorized admin access attempt', {
            ip: req.ip,
            session: !!req.session.admin,
            userAgent: req.get('User-Agent')
        });
        return res.status(401).json({ error: 'Admin authentication required' });
    }

    // Additional security: check session age
    if (req.session.adminLoginTime &&
        Date.now() - req.session.adminLoginTime > 2 * 60 * 60 * 1000) { // 2 hours
        logger.warn('Admin session expired', { adminId: req.session.adminId });
        req.session.destroy();
        return res.status(401).json({ error: 'Session expired' });
    }

    next();
};

// Enhanced admin key validation
const validateAdminKey = (req, res, next) => {
    const adminKey = req.body.adminKey || req.headers['x-admin-key'];
    if (!adminKey || adminKey !== process.env.ADMIN_KEY) {
        logger.warn('Invalid admin key attempt', {
            ip: req.ip,
            adminId: req.session.adminId,
            hasKey: !!adminKey
        });
        return res.status(401).json({ error: 'Invalid admin key' });
    }
    next();
};

// Anti-bot middleware
const antibotMiddleware = (req, res, next) => {
    const userAgent = req.get('User-Agent') || '';
    const suspiciousPatterns = [
        /bot/i, /crawler/i, /spider/i, /scraper/i,
        /curl/i, /wget/i, /python/i, /node/i
    ];

    if (suspiciousPatterns.some(pattern => pattern.test(userAgent))) {
        logger.warn('Suspicious user agent detected', {
            ip: req.ip,
            userAgent: userAgent.substring(0, 100)
        });
        return res.status(403).json({ error: 'Access denied' });
    }

    next();
};

// JWT token generation for socket authentication
function generateSocketToken(sessionId) {
    return jwt.sign({ sessionId, timestamp: Date.now() },
        process.env.JWT_SECRET, { expiresIn: '1h' }
    );
}

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Enhanced admin login with CSRF protection
app.get('/login', csrfProtection, (req, res) => {
    if (req.session.admin) {
        return res.redirect('/admin');
    }
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Login</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    max-width: 400px; 
                    margin: 100px auto; 
                    padding: 20px;
                    background: #f5f5f5;
                }
                .login-form {
                    background: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                input, button { 
                    width: 100%; 
                    padding: 12px; 
                    margin: 10px 0; 
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    box-sizing: border-box;
                }
                button { 
                    background: #007bff; 
                    color: white; 
                    border: none; 
                    cursor: pointer;
                    font-weight: bold;
                }
                button:hover { background: #0056b3; }
                .security-notice {
                    font-size: 12px;
                    color: #666;
                    margin-top: 20px;
                    text-align: center;
                }
            </style>
        </head>
        <body>
            <div class="login-form">
                <form method="POST" action="/login">
                    <h2>🔒 Secure Admin Login</h2>
                    <input type="hidden" name="_csrf" value="${req.csrfToken()}" />
                    <input type="text" name="username" placeholder="Username" required maxlength="50" autocomplete="username" />
                    <input type="password" name="password" placeholder="Password" required autocomplete="current-password" />
                    <button type="submit">Login</button>
                </form>
                <div class="security-notice">
                    All login attempts are monitored and logged.
                </div>
            </div>
        </body>
        </html>
    `);
});

app.post('/login', loginLimiter, csrfProtection, async(req, res) => {
    try {
        const { username, password } = req.body;
        const clientIp = req.ip;
        const userAgent = req.get('User-Agent');

        logger.info('Login attempt', { username, ip: clientIp, userAgent });

        if (!username || !password) {
            logger.warn('Login attempt without credentials', { ip: clientIp });
            return res.status(400).send('❌ Username and password required. <a href="/login">Try again</a>');
        }

        // Enhanced security checks
        const isValidUsername = username === process.env.ADMIN_USERNAME;
        const isValidPassword = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);

        if (isValidUsername && isValidPassword) {
            req.session.admin = true;
            req.session.adminId = username;
            req.session.adminLoginTime = Date.now();
            req.session.adminIP = clientIp;

            logger.info('Successful admin login', {
                adminId: username,
                ip: clientIp,
                sessionId: req.sessionID
            });

            return res.redirect('/admin');
        }

        logger.warn('Failed login attempt', {
            username,
            ip: clientIp,
            userAgent
        });

        res.status(401).send('❌ Invalid credentials. <a href="/login">Try again</a>');
    } catch (error) {
        logger.error('Login error:', error);
        res.status(500).send('❌ Login error. <a href="/login">Try again</a>');
    }
});

app.get('/admin', requireAdmin, csrfProtection, (req, res) => {
    // Generate socket token for admin
    const socketToken = generateSocketToken(req.sessionID);
    res.cookie('socketToken', socketToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    });

    res.sendFile(path.join(__dirname, 'admin', 'admin.html'));
});

app.get('/logout', (req, res) => {
    const adminId = req.session.adminId;
    req.session.destroy((err) => {
        if (err) {
            logger.error('Logout error:', err);
        } else {
            logger.info('Admin logout', { adminId });
        }
        res.redirect('/login');
    });
});

// Enhanced API Routes with pagination
app.get('/api/game-state', antibotMiddleware, async(req, res) => {
    try {
        const players = await Player.find({
            roundNumber: gameState.roundNumber,
            paidOut: false
        }).select('amount timestamp').lean(); // Use lean() for better performance

        gameState.playersCount = players.length;
        gameState.totalPot = players.reduce((sum, player) => sum + player.amount, 0);

        const publicGameState = {
            isActive: gameState.isActive,
            timeLeft: gameState.timeLeft,
            totalPot: gameState.totalPot,
            roundNumber: gameState.roundNumber,
            playersCount: gameState.playersCount,
            winner: gameState.winner ? {
                name: gameState.winner.name,
                amount: gameState.winner.amount
            } : null,
            entryFee: gameState.entryFee,
            maxPlayers: gameState.maxPlayers
        };

        res.json(publicGameState);
    } catch (error) {
        logger.error('Game state error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/join-game', joinGameLimiter, antibotMiddleware, validateInput, async(req, res) => {
    try {
        const { name, walletAddress, amount, transactionSignature } = req.body;
        const clientIp = req.ip;

        // Enhanced validation
        if (!gameState.isActive) {
            return res.status(400).json({ error: 'Game is not active' });
        }

        if (!name || !walletAddress || !amount || !transactionSignature) {
            logger.warn('Join game with missing fields', { ip: clientIp });
            return res.status(400).json({ error: 'Missing required fields' });
        }

        if (Math.abs(amount - gameState.entryFee) > 0.001) {
            logger.warn('Invalid entry fee attempted', {
                ip: clientIp,
                attempted: amount,
                required: gameState.entryFee
            });
            return res.status(400).json({ error: `Entry fee must be exactly ${gameState.entryFee} SOL` });
        }

        if (gameState.playersCount >= gameState.maxPlayers) {
            return res.status(400).json({ error: 'Game is full' });
        }

        // Check for duplicate transaction
        const existingPlayer = await Player.findOne({ transactionSignature }).lean();
        if (existingPlayer) {
            logger.warn('Duplicate transaction attempted', {
                ip: clientIp,
                transactionSignature
            });
            return res.status(400).json({ error: 'Transaction already used' });
        }

        // Check if player already joined this round
        const existingRoundPlayer = await Player.findOne({
            walletAddress,
            roundNumber: gameState.roundNumber,
            paidOut: false
        }).lean();

        if (existingRoundPlayer) {
            return res.status(400).json({ error: 'Already joined this round' });
        }

        // Detect suspicious activity (same IP multiple wallets)
        const recentPlayersFromIP = await Player.find({
            ipAddress: clientIp,
            timestamp: { $gte: new Date(Date.now() - 60 * 60 * 1000) } // Last hour
        }).lean();

        if (recentPlayersFromIP.length >= 3) {
            logger.warn('Suspicious activity: multiple wallets from same IP', {
                ip: clientIp,
                count: recentPlayersFromIP.length
            });
            return res.status(429).json({ error: 'Too many attempts from this location' });
        }

        // Verify Solana transaction with enhanced checks
        const verified = await verifyTransaction(transactionSignature, walletAddress, amount);
        if (!verified) {
            logger.warn('Transaction verification failed', {
                ip: clientIp,
                walletAddress: walletAddress.substring(0, 10) + '...',
                transactionSignature
            });
            return res.status(400).json({ error: 'Invalid or unconfirmed transaction' });
        }

        // Create player with sanitized data
        const player = new Player({
            name: validator.escape(name.trim()),
            walletAddress: walletAddress.trim(),
            amount: parseFloat(amount),
            transactionSignature: transactionSignature.trim(),
            roundNumber: gameState.roundNumber,
            ipAddress: clientIp,
            userAgent: req.get('User-Agent') || 'Unknown'
        });

        await player.save();
        await updateGameState();

        logger.info('Player joined game', {
            playerId: player._id,
            name: player.name,
            roundNumber: gameState.roundNumber,
            totalPot: gameState.totalPot
        });

        // Broadcast update
        io.emit('gameUpdate', {
            isActive: gameState.isActive,
            timeLeft: gameState.timeLeft,
            totalPot: gameState.totalPot,
            roundNumber: gameState.roundNumber,
            playersCount: gameState.playersCount
        });

        res.json({
            success: true,
            player: {
                id: player._id,
                name: player.name,
                amount: player.amount,
                timestamp: player.timestamp
            }
        });

    } catch (error) {
        logger.error('Join game error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin routes with enhanced security
app.post('/api/start-round', requireAdmin, validateAdminKey, csrfProtection, async(req, res) => {
    try {
        // Prevent rapid round starts
        if (gameState.lastRoundStart &&
            Date.now() - gameState.lastRoundStart < gameState.minTimeBetweenRounds) {
            return res.status(429).json({ error: 'Too soon to start new round' });
        }

        await startNewRound();

        logger.info('New round started by admin', {
            adminId: req.session.adminId,
            roundNumber: gameState.roundNumber
        });

        res.json({ success: true, roundNumber: gameState.roundNumber });
    } catch (error) {
        logger.error('Start round error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/end-round', requireAdmin, validateAdminKey, csrfProtection, async(req, res) => {
    try {
        if (gameState.timer) clearInterval(gameState.timer);
        gameState.isActive = false;

        logger.info('Round ended by admin', {
            adminId: req.session.adminId,
            roundNumber: gameState.roundNumber
        });

        io.emit('gameUpdate', {
            isActive: gameState.isActive,
            timeLeft: gameState.timeLeft,
            totalPot: gameState.totalPot,
            roundNumber: gameState.roundNumber,
            playersCount: gameState.playersCount
        });

        res.json({ success: true });
    } catch (error) {
        logger.error('End round error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/select-winner', requireAdmin, validateAdminKey, csrfProtection, async(req, res) => {
    try {
        const { playerId } = req.body;

        if (!playerId || !mongoose.Types.ObjectId.isValid(playerId)) {
            return res.status(400).json({ error: 'Invalid player ID' });
        }

        const winner = await Player.findById(playerId);
        if (!winner || winner.roundNumber !== gameState.roundNumber) {
            return res.status(400).json({ error: 'Player not found in current round' });
        }

        // Mark as winner
        winner.isWinner = true;
        winner.winnerSelectedAt = new Date();
        await winner.save();

        gameState.winner = {
            id: winner._id,
            name: winner.name,
            walletAddress: winner.walletAddress,
            amount: winner.amount
        };

        gameState.isActive = false;
        if (gameState.timer) clearInterval(gameState.timer);

        logger.info('Winner selected', {
            adminId: req.session.adminId,
            winnerId: winner._id,
            winnerName: winner.name,
            roundNumber: gameState.roundNumber,
            totalPot: gameState.totalPot
        });

        io.emit('gameUpdate', {
            isActive: gameState.isActive,
            winner: {
                name: gameState.winner.name,
                amount: gameState.winner.amount
            },
            totalPot: gameState.totalPot,
            roundNumber: gameState.roundNumber
        });

        res.json({ success: true, winner: gameState.winner });

    } catch (error) {
        logger.error('Select winner error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Enhanced players endpoint with pagination
app.get('/api/players/:roundNumber', requireAdmin, async(req, res) => {
    try {
        const roundNumber = parseInt(req.params.roundNumber);
        const page = parseInt(req.query.page) || 1;
        const limit = Math.min(parseInt(req.query.limit) || 50, 100); // Max 100 per page
        const skip = (page - 1) * limit;

        if (isNaN(roundNumber) || roundNumber < 1) {
            return res.status(400).json({ error: 'Invalid round number' });
        }

        const [players, totalCount] = await Promise.all([
            Player.find({ roundNumber })
            .select('name walletAddress amount timestamp isWinner ipAddress')
            .sort({ timestamp: 1 })
            .skip(skip)
            .limit(limit)
            .lean(),
            Player.countDocuments({ roundNumber })
        ]);

        res.json({
            players,
            pagination: {
                currentPage: page,
                totalPages: Math.ceil(totalCount / limit),
                totalCount,
                hasNext: skip + limit < totalCount,
                hasPrev: page > 1
            }
        });
    } catch (error) {
        logger.error('Get players error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Enhanced transaction verification with recency check
async function verifyTransaction(signature, fromWallet, expectedAmount) {
    try {
        // Wait for transaction confirmation with timeout
        const timeoutPromise = new Promise((_, reject) => {
            setTimeout(() => reject(new Error('Transaction verification timeout')), 10000);
        });

        const transactionPromise = connection.getTransaction(signature, {
            commitment: 'confirmed',
            maxSupportedTransactionVersion: 0
        });

        const transaction = await Promise.race([transactionPromise, timeoutPromise]);

        if (!transaction || !transaction.meta) {
            logger.warn('Transaction not found or no metadata', { signature });
            return false;
        }

        if (transaction.meta.err) {
            logger.warn('Transaction failed on blockchain', { signature, error: transaction.meta.err });
            return false;
        }

        // Check transaction recency (not older than 5 minutes)
        if (transaction.blockTime &&
            Date.now() - transaction.blockTime * 1000 > 5 * 60 * 1000) {
            logger.warn('Transaction too old', {
                signature,
                age: Date.now() - transaction.blockTime * 1000
            });
            return false;
        }

        // Enhanced verification
        const accountKeys = transaction.transaction.message.accountKeys.map(key => key.toString());
        const hasFromWallet = accountKeys.includes(fromWallet);
        const hasGameWallet = accountKeys.includes(GAME_WALLET);

        if (!hasFromWallet || !hasGameWallet) {
            logger.warn('Transaction missing required wallets', {
                signature,
                hasFromWallet,
                hasGameWallet
            });
            return false;
        }

        // Verify amount transferred with more precision
        const preBalances = transaction.meta.preBalances;
        const postBalances = transaction.meta.postBalances;

        for (let i = 0; i < accountKeys.length; i++) {
            if (accountKeys[i] === GAME_WALLET) {
                const balanceChange = (postBalances[i] - preBalances[i]) / LAMPORTS_PER_SOL;
                if (Math.abs(balanceChange - expectedAmount) < 0.0001) {
                    logger.info('Transaction verified successfully', {
                        signature,
                        amount: balanceChange
                    });
                    return true;
                }
            }
        }

        logger.warn('Transaction amount mismatch', {
            signature,
            expectedAmount
        });
        return false;

    } catch (error) {
        logger.error('Transaction verification error:', { signature, error: error.message });
        return false;
    }
}

async function updateGameState() {
    try {
        const players = await Player.find({
            roundNumber: gameState.roundNumber,
            paidOut: false
        }).lean();

        gameState.playersCount = players.length;
        gameState.totalPot = players.reduce((sum, player) => sum + player.amount, 0);
    } catch (error) {
        logger.error('Update game state error:', error);
    }
}

async function startNewRound() {
    try {
        if (gameState.timer) clearInterval(gameState.timer);

        // Anti-spam: check time between rounds
        if (gameState.lastRoundStart &&
            Date.now() - gameState.lastRoundStart < gameState.minTimeBetweenRounds) {
            throw new Error('Too soon to start new round');
        }

        gameState = {
            ...gameState,
            isActive: true,
            timeLeft: 240,
            totalPot: 0,
            roundNumber: gameState.roundNumber + 1,
            timer: null,
            playersCount: 0,
            winner: null,
            lastRoundStart: Date.now()
        };

        logger.info('New round started', { roundNumber: gameState.roundNumber });

        // Start countdown timer
        gameState.timer = setInterval(async() => {
            gameState.timeLeft--;

            if (gameState.timeLeft <= 0) {
                gameState.isActive = false;
                clearInterval(gameState.timer);

                logger.info('Round ended by timer', {
                    roundNumber: gameState.roundNumber,
                    finalPot: gameState.totalPot,
                    playersCount: gameState.playersCount
                });
            }

            // Broadcast update every 10 seconds to reduce load
            if (gameState.timeLeft % 10 === 0 || gameState.timeLeft <= 10) {
                io.emit('gameUpdate', {
                    isActive: gameState.isActive,
                    timeLeft: gameState.timeLeft,
                    totalPot: gameState.totalPot,
                    roundNumber: gameState.roundNumber,
                    playersCount: gameState.playersCount
                });
            }
        }, 1000);

        // Initial broadcast
        io.emit('gameUpdate', {
            isActive: gameState.isActive,
            timeLeft: gameState.timeLeft,
            totalPot: gameState.totalPot,
            roundNumber: gameState.roundNumber,
            playersCount: gameState.playersCount,
            winner: null
        });
    } catch (error) {
        logger.error('Start new round error:', error);
        throw error;
    }
}

// Enhanced Socket.io with authentication
// Enhanced Socket.io with authentication - CORRECTED VERSION
io.use((socket, next) => {
    // Fix the problematic line - more reliable cookie parsing
    let token = socket.handshake.auth.token;

    // Alternative cookie parsing method
    if (!token && socket.handshake.headers.cookie) {
        const cookies = socket.handshake.headers.cookie.split(';');
        for (let cookie of cookies) {
            const [name, value] = cookie.trim().split('=');
            if (name === 'socketToken') {
                token = value;
                break;
            }
        }
    }

    if (token) {
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            socket.isAdmin = true;
            socket.sessionId = decoded.sessionId;
            logger.info('Admin socket authenticated', { socketId: socket.id });
        } catch (error) {
            logger.warn('Invalid socket token', { socketId: socket.id, error: error.message });
            socket.isAdmin = false;
        }
    } else {
        socket.isAdmin = false;
    }

    // Rate limit socket connections per IP
    const clientIp = socket.handshake.address;
    const connections = io.engine.clientsCount;

    if (connections > 100) { // Max 100 concurrent connections
        logger.warn('Too many socket connections', {
            count: connections,
            ip: clientIp
        });
        return next(new Error('Server busy'));
    }

    next();
});

io.on('connection', (socket) => {
    const clientIp = socket.handshake.address;
    logger.info('Socket connected', {
        socketId: socket.id,
        ip: clientIp,
        isAdmin: socket.isAdmin
    });

    // Send safe game state
    socket.emit('gameUpdate', {
        isActive: gameState.isActive,
        timeLeft: gameState.timeLeft,
        totalPot: gameState.totalPot,
        roundNumber: gameState.roundNumber,
        playersCount: gameState.playersCount,
        winner: gameState.winner ? {
            name: gameState.winner.name,
            amount: gameState.winner.amount
        } : null,
        entryFee: gameState.entryFee,
        maxPlayers: gameState.maxPlayers
    });

    // Admin-only events
    if (socket.isAdmin) {
        socket.on('requestPlayersList', async(data) => {
            try {
                const { roundNumber, page = 1 } = data;
                const limit = 20;
                const skip = (page - 1) * limit;

                const players = await Player.find({ roundNumber })
                    .select('name walletAddress amount timestamp isWinner')
                    .sort({ timestamp: 1 })
                    .skip(skip)
                    .limit(limit)
                    .lean();

                socket.emit('playersListUpdate', { players, page, roundNumber });
            } catch (error) {
                logger.error('Socket players list error:', error);
                socket.emit('error', { message: 'Failed to fetch players' });
            }
        });
    }

    // Rate limit socket events
    const eventLimiter = new Map();

    socket.use(([event, ...args], next) => {
        const now = Date.now();
        const key = `${clientIp}:${event}`;
        const lastCall = eventLimiter.get(key) || 0;

        if (now - lastCall < 1000) { // 1 second between events
            logger.warn('Socket event rate limited', {
                ip: clientIp,
                event,
                socketId: socket.id
            });
            return next(new Error('Rate limited'));
        }

        eventLimiter.set(key, now);
        next();
    });

    socket.on('disconnect', (reason) => {
        logger.info('Socket disconnected', {
            socketId: socket.id,
            reason,
            ip: clientIp
        });
    });

    socket.on('error', (error) => {
        logger.error('Socket error:', {
            socketId: socket.id,
            error: error.message,
            ip: clientIp
        });
    });
});

// Security monitoring endpoints
app.get('/api/security/status', requireAdmin, (req, res) => {
    const memUsage = process.memoryUsage();
    const uptime = process.uptime();

    res.json({
        status: 'secure',
        uptime: Math.floor(uptime),
        memory: {
            used: Math.floor(memUsage.heapUsed / 1024 / 1024) + ' MB',
            total: Math.floor(memUsage.heapTotal / 1024 / 1024) + ' MB'
        },
        connections: io.engine.clientsCount,
        gameState: {
            isActive: gameState.isActive,
            roundNumber: gameState.roundNumber,
            playersCount: gameState.playersCount
        }
    });
});

// Health check endpoint (no auth required)
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: process.env.npm_package_version || '1.0.0'
    });
});

// Enhanced error handling with detailed logging
app.use((error, req, res, next) => {
    logger.error('Express error handler:', {
        error: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent')
    });

    // Don't leak error details in production
    if (process.env.NODE_ENV === 'production') {
        res.status(500).json({ error: 'Internal server error' });
    } else {
        res.status(500).json({
            error: error.message,
            stack: error.stack
        });
    }
});

// 404 handler
app.use((req, res) => {
    logger.warn('404 Not Found', {
        url: req.url,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent')
    });

    res.status(404).json({ error: 'Not found' });
});

// Enhanced process error handling
process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Promise Rejection:', {
        reason: reason.toString(),
        stack: reason.stack,
        promise: promise.toString()
    });
});

process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', {
        error: error.message,
        stack: error.stack
    });

    // Graceful shutdown
    server.close(() => {
        process.exit(1);
    });
});

// Graceful shutdown handling
const gracefulShutdown = (signal) => {
    logger.info(`${signal} received, shutting down gracefully`);

    server.close(() => {
        logger.info('HTTP server closed');

        // Close database connection
        mongoose.connection.close(() => {
            logger.info('MongoDB connection closed');
            process.exit(0);
        });
    });

    // Force close after 30 seconds
    setTimeout(() => {
        logger.error('Forced shutdown after 30 seconds');
        process.exit(1);
    }, 30000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Security monitoring - log suspicious activities
setInterval(() => {
    const connections = io.engine.clientsCount;
    const memUsage = process.memoryUsage();

    if (connections > 80 || memUsage.heapUsed > 500 * 1024 * 1024) { // 500MB
        logger.warn('High resource usage detected', {
            connections,
            memoryMB: Math.floor(memUsage.heapUsed / 1024 / 1024)
        });
    }
}, 60000); // Check every minute

const PORT = process.env.PORT || 4001;
server.listen(PORT, () => {
    logger.info(`Server started on port ${PORT}`, {
        nodeEnv: process.env.NODE_ENV,
        mongoConnected: mongoose.connection.readyState === 1,
        solanaConnected: !!connection
    });

    console.log(`🚀 Secure Server running on port ${PORT}`);
    console.log(`🎮 Player Interface: http://localhost:${PORT}`);
    console.log(`👑 Admin Dashboard: http://localhost:${PORT}/admin`);
    console.log(`📊 Health Check: http://localhost:${PORT}/health`);
});