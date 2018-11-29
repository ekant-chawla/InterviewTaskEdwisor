const express = require('express')
const userController = require('./../controllers/userController');
const config = require('./../../config/appConfig')
const routeMiddleware = require('./../middlewares/routeMiddleware');


let setRoutes = function (app) {
    let baseUrl = config.version + "/user"

    app.post(baseUrl + '/signup', userController.signup);

    app.post(baseUrl + '/login', userController.login);

    app.post(baseUrl + '/updatePass', routeMiddleware.verifyAuthToken, userController.updatePassword);

    app.post(baseUrl + '/listUserInfo', routeMiddleware.verifyAuthToken, userController.listUsersInfo)

    app.post(baseUrl + '/updateUserInfo', routeMiddleware.verifyAuthToken, userController.updateUserInfo)

    app.post(baseUrl + '/logout', routeMiddleware.verifyAuthToken, userController.logout)

    app.post(baseUrl + '/upload', userController.fileUpload)

}


module.exports = {
    setRoutes: setRoutes
}
