const express = require('express');

const router = express.Router();

const { signUp, verify, logIn, forgotPassword, resetPasswordPage, resetPassword, signOut, LocationData,  } = require('../controllers/userController');
const { authenticate, } = require("../middleware/authentation");

//endpoint to register a new user
router.post('/signup', signUp);

//endpoint to verify a registered user
router.get('/verify/:id/:token', verify);

//endpoint to login a verified user
router.post('/login', logIn);

//endpoint for forget Password
router.post('/forgot', forgotPassword);

//endpoint for reset Password Page
router.get('/reset/:userId', resetPasswordPage);

//endpoint to reset user Password
router.post('/reset-user/:userId', resetPassword);

//endpoint to sign out a user
router.post("/signout", authenticate, signOut);

//endpoint to add user location and image
router.post("/location", authenticate, LocationData);




module.exports = router;