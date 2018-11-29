/*Wrapper functions around the pino logger to log error*/

const logger = require('pino')()

let captureError = (errorMessage, errorOrigin, errorLevel) => {

  let error = {
    dateTime: Date.now(),
    errorMessage: errorMessage,
    errorOrigin: errorOrigin,
    errorLevel: errorLevel
  }

  logger.error(error)
} 

let captureInfo = (message, origin, importance) => {

  let info = {
    dateTime: Date.now(),
    message: message,
    origin: origin,
    level: importance
  }

  logger.info(info)
}

module.exports = {
  error: captureError,
  info: captureInfo
}
