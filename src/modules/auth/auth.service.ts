import jwt, { JwtPayload } from "jsonwebtoken";
import { User } from "../user/user.model";
import { TLoginUser } from "./auth.interface";
import config from "../../config";
import { createToken } from "./auth.utils";
import nodemailer from "nodemailer";
import AppError from "../../errors/appError";
import httpStatus from "http-status";
import crypto from 'crypto';
import bcrypt from "bcrypt";

// Service to handle user sign-in.
const signInIntoDB = async (payload: TLoginUser) => {
    const { email, password } = payload;

    if (!email || !password) {
        throw new AppError(httpStatus.NOT_FOUND, "Name and password are required");
    }

    const passwordMatch = await User.isPasswordMatch(email, password);
    if (!passwordMatch) {
        throw new AppError(httpStatus.NOT_FOUND, "Password did not match");
    }

    // Generate access and refresh tokens
    const accessToken = createToken({ email: payload.email || '' }, config.jwt_access_key as string, config.jwt_access_expire_in as string);
    const refreshToken = createToken({ email: payload.email || '' }, config.jwt_refresh_key as string, config.jwt_refresh_expire_in as string);

    return { accessToken, refreshToken };
}

// Service to handle forget password with OTP.
const forgetPasswordWithOtp = async (email: string) => {
    const user = await User.findOne({ email });
    if (!user) {
        throw new AppError(httpStatus.NOT_FOUND, "Account not found");
    }

    const otp = crypto.randomInt(100000, 999999); // Generates a 6-digit OTP

    // Send email with OTP code.
    const transporter = nodemailer.createTransport({
        service: config.email_service,
        host: config.email_host,
        auth: {
            user: config.email_user,
            pass: config.email_password,
        },
    });

    const mailOptions = {
        from: config.email,
        to: [email],
        subject: 'Forget Your Password',
        text: `Your OTP code ${otp}`,
    };

    try {
        // Verify connection configuration.
        await new Promise((resolve, reject) => {
            transporter.verify((error, success) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(success);
                }
            });
        });

        //  Send mail.
        await new Promise((resolve, reject) => {
            transporter.sendMail(mailOptions, function (error) {
                if (error) reject(new AppError(httpStatus.INTERNAL_SERVER_ERROR, error.message));
                resolve(undefined);
            });
        })
    } catch (error) {
        throw new AppError(httpStatus.INTERNAL_SERVER_ERROR, "Failed to send email");
    }

    // Save OTP in DB.
    const res = await User.findOneAndUpdate({ email }, { otp }, { new: true }).select("email -_id");
    return res;
}


// Service to verify the OTP.
const verifyOtp = async (email: string, otp: string) => {
    // Check if the user exists.
    const user = await User.findOne({ email });
    if (!user) {
        throw new AppError(httpStatus.NOT_FOUND, "User not found");
    }

    // Check if the provided OTP matches the stored OTP
    if (user.otp !== otp) {
        throw new AppError(httpStatus.NOT_FOUND, "OTP is not matching");
    }

    // Delete OTP from DB.
    await User.findOneAndUpdate({ email }, { otp: null });
}

// Service to reset the password
const resetPassword = async (email: string, newPassword: string) => {
    // Check if the user exists
    const user = await User.findOne({ email });
    if (!user) {
        throw new AppError(httpStatus.NOT_FOUND, "User not found");
    }

    // Hash the new password
    const hashedNewPasswword = await bcrypt.hash(newPassword, Number(config.salt_rounds));

    // Update password in DB
    await User.findOneAndUpdate({ email }, { password: hashedNewPasswword });
}

// // Service to handle token refresh
const refreshToken = async (token: string) => {
    if (!token) {
        throw new AppError(httpStatus.NOT_FOUND, "Token not provided");
    }

    // Verify and decode the refresh token
    const decoded = jwt.verify(token, config.jwt_refresh_key as string) as JwtPayload;
    const { email } = decoded;

    // Generate a new access token
    const accessToken = createToken({ email: email || '' }, config.jwt_access_key as string, config.jwt_access_expire_in as string);
    return { accessToken };
}

export const authService = {
    signInIntoDB,
    forgetPasswordWithOtp,
    verifyOtp,
    resetPassword,
    refreshToken,
}
