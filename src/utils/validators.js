const mongoose = require('mongoose');
const ObjectId = mongoose.Types.ObjectId;

const emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
const passwordRegex =
/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])(?=.{8,19})/;

const isValidObjectId = function (data) {
    return ObjectId.isValid(data);
};

const isValidRequestBody = function (data) {
    return Object.keys(data).length != 0
}

const isValidString = function (data) {
    if (Object.prototype.toString.call(data) != "[object String]" || data.trim().length == 0) {
        return false
    }
    return true
}

const isValidEmail = function (data) {
    if (Object.prototype.toString.call(data) != "[object String]" || !emailRegex.test(data)) {
        return false
    }
    return true
}

const isValid = function (value) {
    if (typeof value === "undefined" || value === null) return false;
    return true;
};

const isValidPassword = function (data) {
    return passwordRegex.test(data);
};

const isValidDate = function(date) {
    return (new Date(date) !== "Invalid Date") && !isNaN(new Date(date));
}


module.exports = {
    isValidEmail,
    isValidRequestBody,
    isValidString,
    isValid,
    isValidObjectId,
    isValidPassword,
    isValidDate
}