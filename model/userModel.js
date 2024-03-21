const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    firstName: {
        type: String,
    }, 
    lastName: {
        type: String,
    },
    email: {
        type: String,
    },
    password: {
        type: String,
    },
    isVerified: {
        type: Boolean,
        default: false,
    },
    token: {
        type: String,
    }, 
    data: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Data', 
    }]
}, {timestamps: true});

const userModel = mongoose.model('User', userSchema);

module.exports = userModel;