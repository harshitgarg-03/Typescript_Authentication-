import mongoose from "mongoose";

let iscoonected : boolean = false
export const connectDB = async () => {
    
    
    if(iscoonected){
        return
    }
    
    try {
        const db = await mongoose.connect(process.env.MONGO_URI as string)
        iscoonected = db.connection.readyState === 1
        console.log("Database connected successfully !☑️ ");
    } catch (error) {
        if(error instanceof Error){
            console.log("Database Not connected ❌", error.message);
        } else {
            console.log("Database Not connected ❌", error);
        }
        process.exit(1)
    }
}