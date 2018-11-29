const config = {};

config.port = 3000;
config.database = {
    url: "mongodb://127.0.0.1:27017/InterviewTestdb"
}
config.allowedOrigins = "*"
config.version = "/api/v1"
config.env = "dev"
config.tokenExpiry = 24 //token expires after this many hours
config.imgFolder = './ProfilePhotoDir/'

module.exports = config;