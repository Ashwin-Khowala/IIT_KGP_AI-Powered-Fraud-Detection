const mongoose = require("mongoose");

const { Schema } = mongoose;

mongoose.connect(`mongodb+srv://ashwinkhowala1:${process.env.DB_PASSWORD}/iit-kgp-db`);

// User schema  
const userSchema = new Schema({
    firstName:{
        type: String,
        required: true
    },
    middleName:{
        type:String,
    },
    lastName:{
        type:String,
        required:true
    },
    email:{ 
        type:String,
        unique:true,
        required:true
    },
    password:{
        type:String,
        required:true
    },
    mobile_no:{
        type:String,
        required:true
    },
    DOB:{
        type:Date,
        required:true
    },
    loginAttempts: {
        type: Number,
        default: 0
    },
    lockUntil: {
        type: Date,
        default: null
    },
    user_details: {
        // required:true,
        type: Schema.Types.ObjectId,
        ref: 'User_details'
    }
});


// userSchema.statics.getUser = async function (id) {
//     return await this.findById(id);
// };

// Increment login attempts
userSchema.methods.incrementLoginAttempts = async function () {
    if (this.lockUntil && this.lockUntil > Date.now(new Date().toLocaleString('en-US', { timeZone: 'Asia/Kolkata' }))) {
        return;
    }

    this.loginAttempts += 1;

    if (this.loginAttempts >= 5) {
        this.lockUntil = new Date(Date.now(new Date().toLocaleString('en-US', { timeZone: 'Asia/Kolkata' })) + 15 * 60 * 1000); // Lock for 15 minutes
    }

    await this.save();
};

// Reset login attempts
userSchema.methods.resetLoginAttempts = async function () {
    this.loginAttempts = 0;
    this.lockUntil = null;
    await this.save();
};


const user_details=new Schema({
    amount: {
        type: Number,
        required: true
    },
    transactions: [{
        type: Schema.Types.ObjectId,
        ref: 'Transaction'
    }],
    transaction_limit: {
        type: Number,
        default: 100000
    },
    user_id: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true
    }
});

user_details.statics.sendMoney = async function (senderId, receiverId, amount) {
    try {

        if (amount <= 0) {
            throw new Error("Amount must be greater than zero.");
        }

           
        const sender = await this.findOne({ user_id: senderId });
        const receiver = await this.findOne({ user_id: receiverId });

        if (!sender) {
            throw new Error("Sender not found.");
        }

        if (!receiver) {
            throw new Error("Receiver not found.");
        }

        
        sender.amount = Number(sender.amount);
        receiver.amount = Number(receiver.amount);

        
        if (sender.amount < amount) {
            throw new Error("Insufficient balance.");
        }

        // Start a transaction session
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            sender.amount -= amount;
            receiver.amount += amount;

            await sender.save({ session });
            await receiver.save({ session });

            // Create transaction records for both sender and receiver
            const debitTransaction = await Transaction.create([{
                user_id: senderId,
                amount: amount,
                type: "Debit",
                date: new Date()
            }], { session });

            const creditTransaction = await Transaction.create([{
                user_id: receiverId,
                amount: amount,
                type: "Credit",
                date: new Date()
            }], { session });

            // Update transactions array in sender and receiver details
            sender.transactions.push(debitTransaction[0]._id);
            receiver.transactions.push(creditTransaction[0]._id);

            await sender.save({ session });
            await receiver.save({ session });

            // Commit the transaction
            await session.commitTransaction();
            session.endSession();

            return { success: true, message: "Transaction successful!" };
        } catch (error) {
            // Abort the transaction on error
            await session.abortTransaction();
            session.endSession();
            throw error;
        }
    } catch (error) {
        console.error("Error in sendMoney:", error.message);
        throw error;
    }
};


user_details.statics.getTransactions = async function (userId) {
    try {
        return await this.findOne({ user_id: userId }).populate('transactions').exec();
    } catch (error) {
        console.error('Error in getTransactions:', error.message);
        throw error;
    }
};




const transactionSchema = new Schema({
    user_id: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    amount: {
        type: Number,
        required: true
    },
    type: {
        type: String,
        required: true
    },
    description: {
        type: String,
        default: "",
        required: false
    },
    date: {
        type: Date,
        required: true
    }
});

// Get user details
user_details.statics.getUserDetails = async function (userId) {
    return await this.find({ user_id: userId });
}






// Create models
const User = mongoose.model("User", userSchema);
const User_details = mongoose.model("User_details", user_details);
const Transaction = mongoose.model("Transaction", transactionSchema);

// Export models
module.exports = {
    User,
    User_details,
    Transaction
};
