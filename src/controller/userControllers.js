const UserModel = require("../models/usersModel");
const validator = require("../utils/validators");
const bcrypt = require('bcrypt');
const jwt = require("jsonwebtoken")


const createUser = async function (req, res) {
    try {

        if (!validator.isValidRequestBody(req.body)) {
            return res.status(400).send({ status: false, message: "Provide user's data" })
        }
        let { first_name, last_name, email, password } = req.body

        //   Validation for null and undefined values
        if (!validator.isValid(first_name)) {
            return res.status(400).send({ status: false, message: "first_name field is required" })
        }
        if (!validator.isValid(last_name)) {
            return res.status(400).send({ status: false, message: "last_name field is required" })
        }
        if (!validator.isValid(email)) {
            return res.status(400).send({ status: false, message: "email field is required" })
        }
        if (!validator.isValid(password)) {
            return res.status(400).send({ status: false, message: "password field is required" })
        }

        //   Validation for type string, email and password
        if (!validator.isValidString(first_name)) {
            return res.status(400).send({ status: false, message: "first_name field must contain a valid string" })
        }
        if (!validator.isValidString(last_name)) {
            return res.status(400).send({ status: false, message: "last_name field must contain a valid string" })
        }
        if (!validator.isValidEmail(email)) {
            return res.status(400).send({ status: false, message: "Invalid email" })
        }
        if (!validator.isValidPassword(password)) {
            return res.status(400).send({
                status: false, message: "Password must contain uppercases,lowercase,special characters and numerics, length 8-19.",
            });
        }

        const existedUser = await UserModel.findOne({ email }).lean()
        if (existedUser) {
            return res.status(400).send({ status: false, message: "Email already existed" })
        }

        bcrypt.hash(password, 10, async function (err, hash) {
            if (err) {
                return res.status(400).send({ status: false, message: err.message })
            }

            const data = await UserModel.create({ first_name, last_name, email, password: hash })

            return res.status(201).send({ status: true, message: "User created successfuly" })
        });

    } catch (err) {
        console.error("Error saving data:", err.message);
        return res.status(500).send({ status: false, message: "Failed to save data", error: err.message });
    }
}

const userLogin = async function (req, res) {
    try {
        if (!validator.isValidRequestBody(req.body)) {
            return res.status(400).send({ status: false, message: "Provide user's data." })
        }

        let { email, password } = req.body

        //   Validation for null and undefined values
        if (!validator.isValid(email)) {
            return res.status(400).send({ status: false, message: "email field is required." })
        }
        if (!validator.isValid(password)) {
            return res.status(400).send({ status: false, message: "password field is required." })
        }

        const existedUser = await UserModel.findOne({ email })
        if (!existedUser) {
            return res.status(404).send({ status: false, message: 'Email is not registered.' })
        }

        const passwordMatched = await bcrypt.compare(password, existedUser.password);

        if (passwordMatched) {
            let token = jwt.sign({
                id: existedUser._id,
                email: email
            }, process.env.JWT_SECRET_KEY, { expiresIn: '1day' });


            res.cookie('token', token, {
                httpOnly: true, // Prevent JavaScript from accessing the cookie
                sameSite: 'None', // Necessary for cross-origin cookies
                secure: true, // Set to true if using HTTPS
                maxAge: 24 * 60 * 60 * 1000 // 1 day in milliseconds
            });
            // .sed({stats: true, message: "Loged in successfuly"});

            return res.status(200).send({ status: true, message: "Logged in successfuly" })
        }
        else {
            return res.status(400).send({ status: false, message: "Invalid credentials" })
        }
    }
    catch (err) {
        return res.status(500).send({ status: false, message: err.message })

    }
}

const userDetails =async function (req,res){
    try{
        const userId = req.decodedToken.id

        if(!validator.isValidObjectId(userId)){
            return res.status(400).send({status:false,message:"User id is not valid"}) 
        }

        const existedUser = await UserModel.findById(userId)
        if(!existedUser){
            return res.status(404).send({status:false, message:'No user found'}) 
        }

        return res.status(200).send({status:true, data:existedUser._id})
    }
    catch(err){
        return res.status(500).send({ status: false, message: err.message })
    }
}

const tokenValidation = async function (req, res) {
    try {
        
        return res.status(200).send({ status: true, message: "Token is valid" })
    }
    catch (err) {
        return res.status(500).send({ status: false, message: err.message })
    }
}

module.exports = { createUser, userLogin, tokenValidation,userDetails }