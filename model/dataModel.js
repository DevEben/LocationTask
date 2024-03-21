const mongoose = require('mongoose');

const dataSchema = new mongoose.Schema({
date: {
    type: String,
},
time: {
    type: String,
},
location: {
    type: String,
},
image: {
    url: {
        type: String,
    },
    public_id: {
        type: String,
    },
},
userId: {
    type: String, 
}, 
}, {timestamps: true});

const dataModel = mongoose.model('Data', dataSchema);

module.exports = dataModel;