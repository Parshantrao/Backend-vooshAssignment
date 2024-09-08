const express = require('express')

const router = express.Router()
const taskController = require("../controller/taskControllers")
const userController = require("../controller/userControllers")
const middleware = require("../middleware/auth");
const passport = require('passport');
const jwt = require('jsonwebtoken')



router.get("/get", (req, res) => {
  res.status(200).send({ message: "Working" })
})

// ==== Task APIs ====

// Create a task
router.post('/tasks', middleware.auth, taskController.createTask);

// Get all tasks
router.get('/tasks', middleware.auth, taskController.getTasks);

// Update a specific task by ID
router.put('/tasks/:taskId', middleware.auth, taskController.updateTask);

// Update status of a specific task by ID
router.put("/tasks/status/:taskId", middleware.auth, taskController.updateTaskStatus)

// Delete a specific task by ID
router.delete('/tasks/:taskId', middleware.auth, taskController.deleteTask);



// ==== User APIs ====

// Create a new user
router.post('/users', userController.createUser);

// Get user's Info
router.get("/user", middleware.auth, userController.userDetails)

// User login
router.post('/login', userController.userLogin);

// Token validation
router.get('/token-validation', middleware.auth, userController.tokenValidation);


// Goole Login Routes
router.get('/google-login', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login-failure' }),
  (req, res) => {
    const user = req.user;
    let token = jwt.sign({
      id: user._id,
      email: user.email
    }, process.env.JWT_SECRET_KEY, { expiresIn: '1day' });

    res.cookie('token', token, {
      httpOnly: true, 
      sameSite: 'None', 
      secure: true, 
      maxAge: 24 * 60 * 60 * 1000 
    })

    res.redirect(process.env.REDIRECT_URL_AFTER_GOOGLE_LOGIN_DPRODUCTION);
  }
);


router.get('/login-failure', (req, res) => {
  res.send('Login unsuccessful. Try again later.');
});

router.get('/logout', (req, res) => {
  req.logout(function (err) {
    if (err) { return next(err); }
  });

  // Clear cookies and session storage
  res.clearCookie('token', {
    httpOnly: true,
    secure: true, // Ensure secure cookies in production
    sameSite: 'None', // Adjust based on your requirements
  
  });
  res.clearCookie('connect.sid', {
    httpOnly: true,
    secure: true, // Ensure secure cookies in production
    sameSite: 'None', // Adjust based on your requirements
   
  });

  res.send({ message: "Logged out" });
});


module.exports = router