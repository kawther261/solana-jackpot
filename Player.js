const mongoose = require('mongoose');

const playerSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true,
        minlength: 1,
        maxlength: 30
    },
    walletAddress: {
        type: String,
        required: true,
        trim: true,
        validate: {
            validator: function(v) {
                // Basic Solana address validation (44 characters base58)
                return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(v);
            },
            message: 'Invalid Solana wallet address'
        }
    },
    amount: {
        type: Number,
        required: true,
        min: 0.0001,
        max: 10
    },
    transactionSignature: {
        type: String,
        required: true,
        unique: true, // This creates the index - remove any duplicate schema.index() calls
        trim: true,
        validate: {
            validator: function(v) {
                // Solana transaction signature validation (base58, typically 87-88 chars)
                return /^[1-9A-HJ-NP-Za-km-z]{87,88}$/.test(v);
            },
            message: 'Invalid transaction signature'
        }
    },
    roundNumber: {
        type: Number,
        required: true,
        min: 1,
        index: true // This is fine - creates compound indexes
    },
    timestamp: {
        type: Date,
        default: Date.now,
        index: true
    },
    isWinner: {
        type: Boolean,
        default: false,
        index: true
    },
    winnerSelectedAt: {
        type: Date,
        default: null
    },
    paidOut: {
        type: Boolean,
        default: false,
        index: true
    },
    paidOutAt: {
        type: Date,
        default: null
    },
    ipAddress: {
        type: String,
        required: true,
        index: true
    },
    userAgent: {
        type: String,
        maxlength: 500
    }
}, {
    timestamps: true, // Adds createdAt and updatedAt automatically
    versionKey: false // Removes __v field
});

// Compound indexes for better query performance
playerSchema.index({ roundNumber: 1, paidOut: 1 }); // For active round queries
playerSchema.index({ walletAddress: 1, roundNumber: 1 }); // For duplicate checking
playerSchema.index({ ipAddress: 1, timestamp: -1 }); // For suspicious activity detection
playerSchema.index({ timestamp: -1 }); // For recent players queries

// Remove any duplicate index definitions - DON'T add these:
// playerSchema.index({ transactionSignature: 1 }); // Already created by unique: true

// Virtual for player display name (truncated wallet if no name)
playerSchema.virtual('displayName').get(function() {
    return this.name || `${this.walletAddress.substring(0, 6)}...${this.walletAddress.substring(-4)}`;
});

// Instance method to check if player is recent
playerSchema.methods.isRecent = function(minutes = 5) {
    return Date.now() - this.timestamp.getTime() < minutes * 60 * 1000;
};

// Static method to get active players for a round
playerSchema.statics.getActivePlayersForRound = function(roundNumber, options = {}) {
    const { limit = 50, skip = 0 } = options;

    return this.find({
            roundNumber,
            paidOut: false
        })
        .select('name walletAddress amount timestamp isWinner')
        .sort({ timestamp: 1 })
        .skip(skip)
        .limit(limit)
        .lean();
};

// Static method to get round statistics
playerSchema.statics.getRoundStats = function(roundNumber) {
    return this.aggregate([
        { $match: { roundNumber, paidOut: false } },
        {
            $group: {
                _id: null,
                totalPlayers: { $sum: 1 },
                totalPot: { $sum: '$amount' },
                avgAmount: { $avg: '$amount' },
                minAmount: { $min: '$amount' },
                maxAmount: { $max: '$amount' },
                firstJoin: { $min: '$timestamp' },
                lastJoin: { $max: '$timestamp' }
            }
        }
    ]);
};

// Pre-save middleware for additional validation
playerSchema.pre('save', function(next) {
    // Ensure amount has reasonable precision
    this.amount = Math.round(this.amount * 10000) / 10000; // 4 decimal places

    // Sanitize name
    if (this.name) {
        this.name = this.name.trim().replace(/[<>\"'&]/g, ''); // Basic XSS prevention
    }

    next();
});

// Post-save middleware for logging
playerSchema.post('save', function(doc) {
    console.log(`Player saved: ${doc.name} (${doc.walletAddress.substring(0, 8)}...) - Round ${doc.roundNumber}`);
});

module.exports = mongoose.model('Player', playerSchema);