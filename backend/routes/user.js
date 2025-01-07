const {userAuthSchema} = require('../validators/user_auth.js');
const { Router } = require("express");
const router = Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const auth_middleware = require("../middleware/user_auth.js");
const loginThresholdMiddleware = require("../middleware/loginThresholdMiddleware.js");
const { User , User_details} = require("../db/index.js");

// const jwt_pass = process.env.JWT_PASS;
const jwt_pass = "B374A26A71490437AA024E4FADD5B497FDFF1A8EA6FF12F6FB65AF2720B59CCF";
const encryption_rounds = process.env.encryption_rounds;


//SIGNUP ROUTE

router.post("/signup", async (req, res) => {
    console.log('hi form signup route');
    
    const { 
        firstName, 
        middleName, 
        lastName, 
        mobile_no, 
        email, 
        password, 
        DOB
    } = req.body;

    try {
        userAuthSchema.safeparse({email: Email, password});
    } catch (error) {
        return res.status(400).json({ message: error.errors[0].message });
    }


    if (!firstName || !lastName || !mobile_no || !email || !password || !DOB) {
        return res.status(400).json({ message: "All fields are required" });
    }

    try {
        // Hash password
        userAuthSchema.safeparse({email, password});

        if(await User.exists({ email })){
            return res.status(400).json({ message: "Email already exists" });
        }

        const hashed_pass = await bcrypt.hash(password, encryption_rounds);

        const user_details = new User_details({
            user_id: user._id,
            amount: 0
        });

        const user = new User({
            firstName,
            middleName,
            lastName,
            mobile_no,
            email,
            password: hashed_pass,
            DOB,
            user_details: user_details._id
        });

        //creates a user details object for the user with balance 0
        

        await user.save();
        await user_details.save();

        // Generate token expires in 1hr needs to be saved locally
        const token = jwt.sign({ email: user.email, id: user._id }, jwt_pass, {
            expiresIn: "1h"
        });

        res.status(201).json({ message: "Signup successful", token: `Bearer ${token}` });
    } catch (err) {
        console.error("Signup Error:", err.message);
        res.status(500).json({ message: "Internal server error" });
    }
});


// SIGNIN ROUTE

router.post('/signin', loginThresholdMiddleware, async (req, res) => {
    const { Email, password } = req.body;


    if (!Email || !password) {
        return res.status(400).json({ message: "Email and password are required" });
    }

    // try {
    //     userAuthSchema.safeparse({email: Email, password});
    // } catch (error) {
    //     return res.status(400).json({ message: error.errors[0].message });
    // }

    try {
        const user = req.user; // From loginThresholdMiddleware

        // Verify password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            await user.incrementLoginAttempts();
            return res.status(401).json({ message: "Invalid credentials" });
        }
        else{
            await user.resetLoginAttempts();
        }
        
        //unlocks the accout if the lock time is over
        if(user.lockUntil && user.lockUntil < Date.now(new Date().toLocaleString('en-US', { timeZone: 'Asia/Kolkata' }))){
            await user.resetLoginAttempts();
        }


        // Successful login - reset attempts
        await user.resetLoginAttempts();

        // Generate token
        let token;
        try{
            token = jwt.sign({ email: user.email, id: user._id }, jwt_pass, {
                expiresIn: "1h"
            });
        }
        catch(error){
            console.log("error in token generation");
            return res.status(500).json({ message: "Internal server error" });
        }

        res.status(202).json({ message: "Login successful", token: `Bearer ${token}` });
    } catch (error) {
        console.error("Signin Error:", error.message);
        res.status(500).json({ message: "Internal server error" });
    }
});


module.exports = router;

