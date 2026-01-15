import type { NextFunction, Request, Response } from "express"
import { ApiError } from "../Utils/Apierror.js"
import jwt from "jsonwebtoken"
import { UserM } from "../Models/user.model.js"
import cookieParser from "cookie-parser"
import type { JwtPayload } from "../Types/jwtpayload.js"
export const Authvalidation = (req : Request, res : Response, next : NextFunction) => {
    const  refreshtoken  = req.cookies?.RefreshToken


    
    if(!refreshtoken) {
        throw new ApiError(401, "Unauthoruzed user acces to token !")
    }

    try {
        const decodeRefreshtoken = jwt.verify(refreshtoken, process.env.REFRESHTOKEN_SECRET!) as JwtPayload

        if(!decodeRefreshtoken){
            throw new ApiError(401, "not authorized!")
        }

        const user = UserM.findById(decodeRefreshtoken._id).select(
            "-password -refreshtoken"
        ).exec()

        req.user = user
        next() 
    } catch (error) {
        console.log("something went wrong in verify email validation", error);
        
    }
}