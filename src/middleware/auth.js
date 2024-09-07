const jwt = require("jsonwebtoken");

async function auth(req, res, next) {
    try {
        let  token = req.cookies.token;
        //  token = req.headers["Authorization"];
        
        if (!token) {
            return res
                .status(401)
                .send({ status: false, message: "Token is missing" });
        }
        
        jwt.verify(token, process.env.JWT_SECRET_KEY, (err, result) => {
            if (err) return res.status(401).send(err.message);
            req["decodedToken"] = result;
            next();
        });
    } catch (error) {
        res.status(500).send({ status: false, message: error.message });
    }
}

module.exports={
    auth
}