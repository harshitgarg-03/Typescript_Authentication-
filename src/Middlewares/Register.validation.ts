import type { NextFunction, Request, Response } from "express";
import * as z from "zod";
import { ApiError } from "../Utils/Apierror.js";


const Usre_ValidationSchema = z.object({
    name: z
        .preprocess(
            (val) => (typeof val == "string" ? val.trim().toLowerCase() : val),
            z
                .string({ message: "please enter a name in string formatt" })
                .min(3, { message: "at least three character required !" })
                .max(20, { message: "at most 20 character required !" })
        )
        .optional(),

    email: z
        .preprocess(
            (val) => (typeof val == "string" ? val.trim().toLowerCase() : val),
            z
                .string({ message: "please enter an email in string formatt" })
                .email({ message: "please enter valid email!" })
        )
        .optional(),

    password: z
        .preprocess(
            (val) => (typeof val == "string" ? val.trim() : val),
            z
                .string({ message: "password must be an string formatt !" })
                .min(8, "Password must be at least 8 characters long")
                .max(32, "Password must be a maximum of 32 characters long")
                .regex(/[A-Z]/, {
                    message:
                        "Password must contain at least one uppercase letter",
                })
                .regex(/[a-z]/, {
                    message:
                        "Password must contain at least one lowercase letter",
                })
                .regex(/[0-9]/, {
                    message: "Password must contain at least one number",
                })
                .regex(/[@$!%*?&#]/, {
                    message:
                        "Password must contain at least one special character (@, $, !, %, *, ?, &, #)",
                })
        )
        .optional(),

    RefreshToken: z
        .preprocess(
            (val) => (typeof val == "string" ? val.trim().toLowerCase() : val),
            z.string()
        )
        .optional(),
});

export const RegisterValidation = async (
    req: Request<
        {},
        {},
        {
            name: string;
            email: string;
            password: string;
        }
    >,
    res: Response,
    next: NextFunction
) => {
    // console.log("Helli I am in Validation");

    const { name, email, password } = req.body;

    const result = Usre_ValidationSchema.safeParse({ name, email, password });

    if (!result.success) {
        res.json({
            error: result.error.format(),
        });
        throw new ApiError(400, "Fill the field attentively");
    }

    console.log(`result is ${result}`);

    req.validation = result.data;
    next();
};
