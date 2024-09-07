const mongoose = require('mongoose')

const UserSchema = new mongoose.Schema({
    first_name: { type: String, trim: true, required: true },
    last_name: { type: String, trim: true },
    email: { type: String, trim: true, required: true, lowercase:true },
    password: { type: String, trim: true }
    // profileUrl: {type:String, required:true}

}, { timestamps: true })

const UserModel = mongoose.models.Users || mongoose.model("Users", UserSchema)

module.exports = UserModel