import { UserM } from "../Models/user.model.js";
import { AsyncHandler } from "../Utils/Asynchandler.js";
import { ApiError } from "../Utils/Apierror.js";
import { ApiResponse } from "../Utils/Apiresponse.js";
import type { Request, Response } from "express";
import {
    SendMail,
    EmailverificationMailgen,
    ForgotPasswordMailgen,
} from "../Utils/Mail.js";
import crypto from "crypto";
import type { Types } from "mongoose";
import { log } from "console";
import { userInfo } from "os";



const Generate_Access_Refresh_Token = async (
    userId: string | Types.ObjectId
) => {
    const user = await UserM.findById(userId);

    try {
        const RefreshToken = await user?.generateRefreshtoken();
        const AccessToken = await user?.generateAccestoken();
        if (user) {
            user.refreshtoken = RefreshToken!;
        }
        await user?.save({ validateBeforeSave: false });
        return { AccessToken, RefreshToken };
    } catch (error) {
        console.log("error is generating in tokens ", error);
        return { AccessToken: undefined, RefreshToken: undefined };
    }
};

export const RegisterUser = AsyncHandler(
    async (req: Request, res: Response) => {
        const { name, email, password } = req.validation;

        if (!name || !email || !password) {
            throw new ApiError(422, "All Fields required!", []);
        }

        const existuser = await UserM.findOne({ email });

        if (existuser) {
            throw new ApiError(409, "User's occurence already!", []);
        }

        // const otp: number = GenerateOtp()

        // await SendMail ({
        //     email: email,
        //     name: name,
        //     mailgenContent: EmailverificationMailgen(name, otp),
        //     subject: "",
        //     outro: ""
        // })
        // console.log(otp);

        // const {reqotp} = req.body
        // if(otp != reqotp){
        //     throw new ApiError(400, "invalid otp enterd !")
        // }

        const user = await UserM.create({ name, email, password });

        const createdUser = await UserM.findById(user?._id).select(
            "-password -refreshtoken"
        );

        const { unhashedTempToken, Hashedtemptoken, TemptokenExpiry } =
            await user.generateTemporarytoken();

        // console.log(unhashedTempToken);
        // console.log(Hashedtemptoken);
        // console.log(TemptokenExpiry);

        await SendMail({
            email: email,
            name: user?.name,
            mailgenContent: EmailverificationMailgen(
                user?.name,
                `${req.protocol}://${req.get(
                    "host"
                )}/api/v1/user/verify-email/${unhashedTempToken}`
            ),
            subject: "Verifu your email ",
            outro: "click on given button ",
        });

        // const tokenexpirydate = new Date(TemptokenExpiry ?? "");
        user.emailverificationToken = Hashedtemptoken as string;
        user.emailverificationexpiry = TemptokenExpiry;

        await user.save({ validateBeforeSave: false });
        return res
            .status(200)
            .json(
                new ApiResponse(
                    200,
                    "User Registerd Success! and verification email send",
                    { data: createdUser }
                )
            );
    }
);

export const VerifyEmail = AsyncHandler(async (req: Request, res: Response) => {

    const { verificationtoken } = req.params;
    console.log(verificationtoken);

    const verificationhasedtoken = crypto
        .createHash("sha256")
        .update(verificationtoken!)
        .digest("hex");

    const verifysucces = await UserM.findOne({
        emailverificationToken: verificationhasedtoken,
        emailverificationexpiry: { $gt: Date.now() },
    }).select("-password, -refreshtoken");

    if (!verifysucces) {
        throw new ApiError(400, "user not  found ! ");
    }

    if (verifysucces.isEmailverified) {
        return res.json(new ApiResponse(200, "email verified alreday "));
    }
    verifysucces.isEmailverified = true;
    verifysucces.emailverificationToken = undefined
    verifysucces.emailverificationexpiry = undefined

    await verifysucces.save({ validateBeforeSave: false });
    
    res.status(200).json(
        new ApiResponse(200, "email verifed successfully!", {
            data: verifysucces,
        })
    );
});

export const LoginUser =  AsyncHandler(async (req: Request, res: Response) => {
    const { email, password } = req.body;

    if (!email || !password) {
        throw new ApiError(400, "incoming credentials required!");
    }

    const existuser = await UserM.findOne({ email }).exec();

    if (!existuser) {
        throw new ApiError(400, "first signup then login ");
    }

    const { AccessToken, RefreshToken } = await Generate_Access_Refresh_Token(
        existuser._id
    );

    const isPassword = await existuser.ispasswordCorrect(password);

    if (!isPassword) {
        throw new ApiError(400, "password incorrect!");
    }
    const options = {
        httpOnly: true,
        secure: true,
    };

    res.status(200)
        .cookie("AccessToken", AccessToken, options)
        .cookie("RefreshToken", RefreshToken, options)
        .json(new ApiResponse(200, "Login successfull"));
});

export const LogoutUser = AsyncHandler(async (req : Request, res : Response) => {
    const { _id } = await req.user

    const user = await UserM.findByIdAndUpdate(
        _id,
        {
            $set: {
                refreshtoken: "",
            },
        },

        {
            new: true,
        }
    );

    if (!user) {
        throw new ApiError(400, "first signup & login ");
    }

    const options = {
        httpOnly: true,
        secure: true,
    };
    res.status(200)
        .clearCookie("AccessToken", options)
        .clearCookie("RefreshToken", options)
        .json(new ApiResponse(200, "logout success "));
});

export const GetcurrentUser = AsyncHandler(async(req : Request, res : Response) => {
    const {name , email} = await req.user

    
    // if(!user){
    //     throw new ApiError(401, "authentication unvalid ")
    // }
    
    const cuurentUser =  {
            name : name,
            email : email
        }
    res.status(200).json(
        new ApiResponse(200, "Current user got success", {data : cuurentUser})
    )
})

export const CurrentPasswordChange = AsyncHandler(async(req : Request, res : Response) => {
    // const {user} = req.user
    const {oldpassword, newpassword} = req.body
    const {id} = await req.user;
    
    const user = await UserM.findById(id)
    if(!user){
        throw new ApiError(400, "user not found !")
    }

    const oldpasswordcorrect = await user.ispasswordCorrect(oldpassword)

    if(!oldpasswordcorrect){
        throw new ApiError(401, "oldpassword not matched")
    }

    user.password = newpassword

    await user.save({ validateBeforeSave: false })

    res
    .status(200)
    .json(
        new ApiResponse(200, "passsword change successfull")
    )
})

export const ForgotPassword = AsyncHandler(async(req : Request, res : Response) => {
    const {email} = req.body

    const user = await UserM.findOne({email})

    const {unhashedTempToken, Hashedtemptoken, TemptokenExpiry} = (await user?.generateTemporarytoken())!

    const resetlink = `${req.protocol}://${req.get("host")}/api/v1/user/forgotPassword/${unhashedTempToken}`

        if(!user){
            throw new ApiError(400, "user not found !")
        }
        user.forgotPasswordToken = Hashedtemptoken
        user.forgotPasswordexpiry = TemptokenExpiry


    await user.save({validateBeforeSave : false})
    await SendMail({
            email: email,
            name: user?.name,
            mailgenContent: ForgotPasswordMailgen(
                (user?.name)!,
                resetlink
            ),
            subject: "Reset your password ",
            outro: "click on given button ",
    })

    
    res.status(200).json(new ApiResponse(200, "forgot password mail has send"))

})

export const ResetPassword = AsyncHandler(async(req : Request, res : Response) => {
  const { resetlinktoken } = req.params 
  const {newpassword} = req.body  

  console.log(resetlinktoken, newpassword);
  
  const resetlinkhashtoken = await crypto
                                        .createHash("sha256")
                                        .update(resetlinktoken!)
                                        .digest("hex")
    console.log(resetlinkhashtoken);
    
   const user = await UserM.findOneAndUpdate(
    {
        forgotPasswordToken : resetlinkhashtoken,
        forgotPasswordexpiry : {$gt : Date.now()}
   }, 
   {
        password: newpassword,
        forgotPasswordToken: undefined,
        forgotPasswordexpiry: undefined
   })    
   console.log(user);
   
   if(!user){
    throw new ApiError(400, "user not found !")
   }

  res.status(200)
     .json( new ApiResponse (200, "Reset password successfull"))
})

export const EmailUpdate = AsyncHandler(async(req : Request, res : Response) => {
    const { oldEmail, password } = req.body
    const emailchangeotp = GenerateOtp()
    const user = await UserM.findOneAndUpdate(
        {
            email: oldEmail
        },
        {
            emailotp: emailchangeotp
        }
    )
    if(!user) throw new ApiError(400, "user not found ")
    
    const ispassword = user.ispasswordCorrect(password)
    if(!ispassword) throw new ApiError(400, "password not matched!")

    await SendMail(
        {
            email: oldEmail,
            name: req.user?.name,
            mailgenContent: EmailverificationMailgen(
                req.user?.name,
                `Otp for change email ${emailchangeotp}`
            ),
            subject: "Verify your email ",
            outro: "click on given button ",
        }
    )
    res.status(200).json(new ApiResponse(200, "check otp on old email "))
})

export const FinallychangeEmail = AsyncHandler(async(req : Request, res : Response) => {
    const {enteredotp} = req.body
    const {email, _id} = await req.user
    const user = await UserM.findById(_id)
    if(!user){
        throw new ApiError(400, "user not found ")

    }
    if(enteredotp != user.emailotp){
        throw new ApiError(400, "given otp not matched!")
    }

    const { newemail } = req.body
    user.emailotp = ""
    user.email = newemail
    await user.save({validateBeforeSave : false})
    res.status(200).json(
        new ApiResponse(200, "email changed successfully!", {data: req.user})
    )

})

const GenerateOtp = function() {
    const otpnum = Math.floor(Math.random()*10)+100000
    return otpnum
}