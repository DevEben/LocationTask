const joi = require('@hapi/joi');

const validateUser = (data) => {
    try {
        const validateSchema = joi.object({
            firstName: joi.string().min(3).max(30).regex(/^[a-zA-Z]+$/).trim().required().messages({
                'string.empty': "First name field can't be left empty",
                'string.min': "Minimum of 3 characters for the first name field",
                'any.required': "Please first name is required"
            }),
            lastName: joi.string().min(3).max(30).regex(/^[a-zA-Z]+$/).trim().required().messages({
                'string.empty': "Last name field can't be left empty",
                'string.min': "Minimum of 3 characters for the last name field",
                'any.required': "Please last name is required"
            }),
            email: joi.string().max(40).trim().email( {tlds: {allow: false} } ).required().messages({
                'string.empty': "Email field can't be left empty",
                'any.required': "Please Email is required"
            }),
            password: joi.string().min(8).max(20).regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/).trim().required().messages({
                'string.empty': "Password field can't be left empty",
                'string.pattern.base': 'Password must contain Lowercase, Uppercase, Numbers, and special characters',
                'string.min': "Password must be at least 8 characters long",
                'any.required': "Please password field is required"
            }),
        })
        return validateSchema.validate(data);
    } catch (error) {
            throw new Error("Error while validating user: " + error.message)
    }
}


const validateUserLogin = (data) => {
    try {
        const validateSchema = joi.object({
            email: joi.string().max(40).trim().email( {tlds: {allow: false} } ).messages({
                'string.empty': "Email field can't be left empty",
                'any.required': "Please Email is required"
            }),
            userName: joi.string().min(3).max(30).alphanum().trim().messages({
                'string.empty': "Username field can't be left empty",
                'string.min': "Minimum of 3 characters for the username field",
                'any.required': "Please username is required"
            }),
            password: joi.string().min(8).max(20).regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/).trim().required().messages({
                'string.empty': "Password field can't be left empty",
                'string.pattern.base': 'Password must contain Lowercase, Uppercase, Numbers, and special characters',
                'string.min': "Password must be at least 8 characters long",
                'any.required': "Please password field is required"
            }),
        })
        return validateSchema.validate(data);
    } catch (error) {
            throw new Error("Error while validating user: " + error.message)
    }
}


const validateUserLocation = (data) => {
    try {
        const validateSchema = joi.object({
            location: joi.string().min(3).max(30).regex(/^[A-Za-z]+(?: [A-Za-z]+)*$/).trim().required().messages({
                'string.empty': "location field can't be left empty",
                'string.min': "Minimum of 3 characters for the location field",
                'any.required': "Please location is required"
            })
        })
        return validateSchema.validate(data);
    } catch (error) {
            throw new Error("Error while validating user: " + error.message)
    }
}


module.exports = {
    validateUser,
    validateUserLogin,
    validateUserLocation,
}