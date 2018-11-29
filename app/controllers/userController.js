const mongoose = require('mongoose');
const response = require('./../libs/responseLib');
const shortId = require('short-id')
const logger = require('./../libs/loggerLib');
const validationLib = require('./../libs/validationLib')
const passwordLib = require('./../libs/passwordLib')
const tokenLib = require('./../libs/tokenLib')
const config = require('./../../config/appConfig')
const fs = require('fs')

const User = mongoose.model('User')
const Auth = mongoose.model('Auth')


let signup = function (req, res) {

    let verifyUserInput = function () {

        return new Promise((resolve, reject) => {
            if (!validationLib.isValidEmail(req.body.email)) {
                let apiResponse = response.generate(true, "Invalid email id.", 400, null)
                reject(apiResponse)
            }

            if (req.body.password == undefined || !validationLib.isValidPassword(req.body.password)) {
                let apiResponse = response.generate(true, "Invalid password pattern. Password should be minimum 8 characters and start with an alphabet or a number", 400, null)
                reject(apiResponse)
            }

            if (req.body.firstName == undefined) {
                let apiResponse = response.generate(true, "First name missing.", 400, null)
                reject(apiResponse)
            }

            resolve()
        })
    }

    let checkExistingUser = function () {
        return new Promise((resolve, reject) => {
            User.findOne({ email: req.body.email })
                .lean()
                .exec((err, result) => {
                    if (err) {
                        logger.error(err.message, "User SignUp: checkExistingUser", 5)
                        let apiResponse = response.generate(true, "Some error occured.", 500, null)
                        reject(apiResponse)
                    } else if (result) {
                        let apiResponse = response.generate(true, "Email already registered.", 400, null)
                        reject(apiResponse)
                    } else {
                        resolve()
                    }
                })
        })
    }

    let createUser = function () {

        return new Promise((resolve, reject) => {

            let user = new User({
                email: req.body.email,
                firstName: req.body.firstName,
                lastName: req.body.lastName,
                userId: shortId.generate(),
                password: passwordLib.encryptPassword(req.body.password)
            })

            user.save((err, result) => {
                if (err) {
                    let apiResponse
                    if (err.name = "ValidationError") {
                        apiResponse = response.generate(true, "Input validation error", 400, null)
                    } else {
                        apiResponse = response.generate(true, "Internal server error.", 500, null)
                    }
                    reject(apiResponse)
                } else {
                    resolve()
                }
            })
        })

    }


    verifyUserInput()
        .then(checkExistingUser)
        .then(createUser)
        .then(() => {

            let apiResponse = response.generate(false, "User registered successfully.", 200, null)
            res.send(apiResponse)
        })
        .catch((err) => {
            res.send(err)
        })
}

let login = function (req, res) {


    let validateAndFind = function () {
        return new Promise((resolve, reject) => {
            if (req.body.email && req.body.password) {
                User.findOne({ email: req.body.email })
                    .select("firstName lastName email userId password")
                    .lean()
                    .exec((err, result) => {
                        if (err) {
                            let apiResponse = response.generate(true, "Internal server error", 500, null)
                            reject(apiResponse)
                        } else if (result) {
                            passwordLib.comparePassword(req.body.password, result.password, (err, match) => {
                                if (err) {
                                    let apiResponse = response.generate(true, "Internal server error", 500, null)
                                    reject(apiResponse)
                                } else if (!match) {
                                    let apiResponse = response.generate(true, "Invalid credentials", 403, null)
                                    reject(apiResponse)
                                } else {
                                    delete result.password
                                    resolve(result)
                                }
                            })

                        } else {
                            let apiResponse = response.generate(true, "Email not registered", 404, null)
                            reject(apiResponse)
                        }
                    })
            } else {
                let apiResponse = response.generate(true, "Email and password must be provided", 403, null)
                reject(apiResponse)
            }
        })
    }

    let getToken = function (userData) {

        return new Promise((resolve, reject) => {
            tokenLib.generateToken(userData, (err, token) => {
                if (err) {
                    let apiResponse = response.generate(true, "Internal server error.", 500, null)
                    reject(apiResponse)
                } else {
                    resolve(token)
                }
            })
        })
    }

    let saveToken = function (token) {
        return new Promise((resolve, reject) => {

            let auth = new Auth({
                authToken: token
            })

            auth.save((err, result) => {
                if (err) {
                    let apiResponse = response.generate(true, "Internal server error", 500, null)
                    reject(apiResponse)
                } else {
                    resolve(token)
                }
            })
        })

    }

    validateAndFind()
        .then(getToken)
        .then(saveToken)
        .then((token) => {
            let apiResponse = response.generate(false, "User logged in", 200, { authToken: token })
            res.send(apiResponse)
        })
        .catch((err) => {
            res.send(err)
        })
}

let updatePassword = function (req, res) {

    // verify if new password is valid one or not.
    if (req.body.password && validationLib.isValidPassword(req.body.password)) {

        // update the password and clear the password reset token to prevent further use.
        User.updateOne({ userId: req.user.userId }, { password: passwordLib.encryptPassword(req.body.password) })
            .exec((err, result) => {
                if (err) {
                    let apiResponse = response.generate(true, "Internal server error", 500, null)
                    res.send(apiResponse)
                } else {
                    let apiResponse = response.generate(false, "Password updated", 200, null)
                    res.send(apiResponse)
                }
            })
    } else {
        let apiResponse = response.generate(true, "New password should be at least 8 characters and start with a number or alphabet", 500, null)
        res.send(apiResponse)
    }
}

let listUserInfo = function (req, res) {

    User.findOne({ userId: req.user.userId })
        .select('firstName lastName email -_id')
        .lean()
        .exec((err, result) => {
            if (err) {
                logger.error(err.message, 'User Controller: listUsers', 5)
                let apiResponse = response.generate(true, 'Internarl server error', 500, null)
                res.send(apiResponse)
            } else if (result) {
                let apiResponse = response.generate(false, 'User Detail', 200, result)
                res.send(apiResponse)
            } else {
                let apiResponse = response.generate(true, 'Invalid user', 404, null)
                res.send(apiResponse)
            }
        })

}


let updateUserInfo = function (req, res) {

    if (!req.body.firstName && !req.body.lastName) {
        let apiResponse = response.generate(true, 'Nothing to update', 400, null)
        res.send(apiResponse)
    } else {

        User.findOne({ userId: req.user.userId })
            .select('firstName lastName email')
            .lean()
            .exec((err, result) => {
                if (err) {
                    logger.error(err.message, 'User Controller: listUsers', 5)
                    let apiResponse = response.generate(true, 'Internarl server error', 500, null)
                    res.send(apiResponse)
                } else if (result) {
                    //If the user is found update its fields and return udpated data.
                    delete result._id
                    if (req.body.firstName) result.firstName = req.body.firstName
                    if (req.body.lastName) result.lastName = req.body.lastName

                    User.updateOne({ userId: req.user.userId }, result).exec((err, updateResult) => {
                        if (err) {
                            logger.error(err.message, 'User Controller: UpdateUserInfo', 5)
                            let apiResponse = response.generate(true, 'Internarl server error', 500, null)
                            res.send(apiResponse)
                        } else if (updateResult.nModified === 1) {
                            let apiResponse = response.generate(false, "User info updated", 200, result)
                            res.send(apiResponse)
                        } else {
                            let apiResponse = response.generate(true, 'Nothing to update', 400, null)
                            res.send(apiResponse)
                        }
                    })

                } else {
                    let apiResponse = response.generate(true, 'Invalid user', 404, null)
                    res.send(apiResponse)
                }
            })
    }

}



let logout = function (req, res) {
    // delete the authtoken from the db
    Auth.deleteOne({ authToken: req.body.authToken }).exec((err, result) => {

        if (err) {
            let apiResponse = response.generate(true, 'Internal server err', 500, false)
            res.send(apiResponse)
        } else {
            let apiResponse = response.generate(false, 'User successfully logged out', 200, null)
            res.send(apiResponse)
        }

    })
}


let fileUpload = function (req, res) {

    if (req.busboy) {
        req.busboy.on("file", function (fieldName, fileStream, fileName, encoding, mimeType) {
            var fstream = fs.createWriteStream(config.imgFolder + fileName);
            fileStream.pipe(fstream);
            fstream.on('close', function () {
                let apiResponse = response.generate(false, 'File uploaded successfully', 200, null)
                res.send(apiResponse);
            });
            fstream.on('error', function (err) {
                let apiResponse = response.generate(true, 'File uploaded failed', 500, null)
                res.send(apiResponse);
            });


        });
        return req.pipe(req.busboy);
    } else {
        let apiResponse = response.generate(true, 'Internal server error', 500, null)
        res.send(apiResponse);
    }

}






module.exports = {
    signup: signup,
    login: login,
    updatePassword: updatePassword,
    listUsersInfo: listUserInfo,
    updateUserInfo: updateUserInfo,
    logout: logout,
    fileUpload: fileUpload
}
