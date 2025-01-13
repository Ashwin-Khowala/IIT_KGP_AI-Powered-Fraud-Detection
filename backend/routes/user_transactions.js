const { User, User_details } = require('../db/index.js');
const jwt = require('jsonwebtoken');
const express = require('express');
const router = express.Router();
const JWT_PASS = "B374A26A71490437AA024E4FADD5B497FDFF1A8EA6FF12F6FB65AF2720B59CCF";

// Route to handle sending money
router.post('/transaction', async (req, res) => {
    try {
        const { token, receiverId, amount } = req.body;
        if (token == null) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        try {
            const decoded = jwt.verify(token, JWT_PASS);
            const user = await User.findOne({ _id: decoded.id });
            if (user == null) {
                return res.status(401).json({ message: "Unauthorized" });
            }
            const senderId = decoded.id;
            const numericAmount = Number(amount);
            if (isNaN(numericAmount) || numericAmount <= 0) {
                throw new Error("Invalid amount. Please provide a valid number greater than zero.");
            }
            const result = await User_details.sendMoney(senderId, receiverId, numericAmount);

            res.status(200).json(result);
        } catch (error) {
            res.status(400).json({ success: false, message: error.message });
        }

    } catch (error) {
        return res.status(401).json({ message: "Unauthorized" });
    }


});


//sends the user data and sends to the frontend side by verifying the token
router.get('/user', async (req, res) => {
    try {
        const token = req.headers.token?.split(' ')[1];

        const decoded = jwt.verify(token, JWT_PASS);
        const user = await User.findOne({ _id: decoded.id });
        const user_details = await User_details.getUserDetails(user._id);

        res.status(200).json({ user, user_details });
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

//sends the user data and sends to the frontend side by verifying the token
router.get('/transaction-history', async (req, res) => {
    try {
        const token = req.headers.token?.split(' ')[1]; 
        
        const decoded = jwt.verify(token, JWT_PASS);
        const user = await User.findOne({ _id: decoded.id });
        const transactions = await User_details.getTransactions(user._id);
        console.log(transactions);
        
        res.status(200).json(transactions);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

module.exports = router;


