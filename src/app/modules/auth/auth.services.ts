/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable no-unused-vars */

import httpStatus from 'http-status-codes';

import { IUser, IUserAuth } from '../user/user.interface';
import { User } from '../user/user.model';

import AppError from '../../errors/AppError';
import config from '../../config';
import { createToken, verifyToken } from './auth.utils';

import bcrypt from 'bcrypt';

import { JwtPayload } from 'jsonwebtoken';
import jwt from 'jsonwebtoken';

import { EmailHelper } from '../../utils/sendEmail';
import { generateOTPEmail } from '../../utils/emailTemplate';
import { generateOtp } from '../../utils/generateOtp';

// eslint-disable-next-line no-undef
const registerUserIntoDB = async (payload: IUser) => {
  const isUserExits = await User.findOne({ email: payload.email });
  if (isUserExits)
    throw new AppError(
      httpStatus.NOT_FOUND,
      'User with this email id already exists',
    );

  try {
    const userData: Partial<IUser> = payload;

    userData.password = payload.password || (config.default_password as string);

    const newUser = await User.create(userData);
    if (!newUser)
      throw new AppError(httpStatus.BAD_REQUEST, 'Failed to create a new user');

    const jwtPayload = {
      email: userData.email!,
      username: userData.username,
      role: userData.role!,
    };

    const accessToken = createToken(
      jwtPayload,
      config.jwt_access_secret as string,
      config.jwt_access_expires_in as string,
    );
    const refreshToken = createToken(
      jwtPayload,
      config.jwt_refresh_secret as string,
      config.jwt_refresh_expires_in as string,
    );

    // SENT USER DATA WITHOUT PASSWORD
    const { password, ...userWithoutPassword } = newUser;
    return {
      accessToken,
      refreshToken,
      user: userWithoutPassword,
    };
    // return newUser;
  } catch (err) {
    throw new AppError(httpStatus.BAD_REQUEST, 'Failed to create a user');
  }
};

// USER LOGIN
const userSignIntoDB = async (payload: IUserAuth) => {
  const user = await User.isUserExistByEmail(payload.email);

  if (!user) throw new AppError(httpStatus.NOT_FOUND, 'User not found');

  if (typeof payload.password !== 'string')
    throw new AppError(httpStatus.BAD_REQUEST, 'Please provide a password');

  if (
    !(await User.isPasswordMatched(payload.password, user?.password as string))
  )
    throw new AppError(httpStatus.UNAUTHORIZED, 'Incorrect credentials');

  if (user.isDeleted)
    throw new AppError(
      httpStatus.FORBIDDEN,
      'Your account is deleted, you are not allowed to login',
    );

  if (user.status === 'Blocked')
    throw new AppError(httpStatus.FORBIDDEN, 'Your account is blocked');

  const jwtPayload = {
    email: user.email,
    username: user.username,
    role: user.role,
  };

  const accessToken = createToken(
    jwtPayload,
    config.jwt_access_secret as string,
    config.jwt_access_expires_in as string,
  );
  const refreshToken = createToken(
    jwtPayload,
    config.jwt_refresh_secret as string,
    config.jwt_refresh_expires_in as string,
  );

  // SENT USER DATA WITHOUT PASSWORD
  const { password, ...userWithoutPassword } = user;

  return {
    accessToken,
    refreshToken,
    user: userWithoutPassword,
  };
};

const getCurrentUser = async (payload: { email: string }) => {
  const user = await User.findOne({ email: payload.email });
  if (!user) throw new AppError(httpStatus.NOT_FOUND, 'User not found');

  return user;
};

const refreshToken = async (token: string) => {
  const decoded = verifyToken(token, config.jwt_refresh_secret as string);

  const { email, iat } = decoded;

  const user = await User.isUserExistByEmail(email);
  if (!user) throw new AppError(httpStatus.NOT_FOUND, 'user is not register');

  if (
    user.passwordChangeAt &&
    User.isJWTIssuedBeforePasswordChanged(user.passwordChangeAt, iat as number)
  ) {
    throw new AppError(httpStatus.UNAUTHORIZED, 'You are not authorized !');
  }

  const jwtPayload = {
    email: user.email,
    role: user.role,
  };

  const accessToken = createToken(
    jwtPayload,
    config.jwt_access_secret as string,
    config.jwt_access_expires_in as string,
  );

  return {
    accessToken,
  };
};

// ADMIN PARTS
const blockUserFromDB = async (id: string) => {
  const deletedStudent = await User.findByIdAndUpdate(
    id,
    { isBlocked: true },
    { new: true },
  );

  if (!deletedStudent)
    throw new AppError(httpStatus.BAD_REQUEST, 'Failed to block the user');

  return deletedStudent;
};

const changePassword = async (
  userData: JwtPayload,
  payload: { oldPassword: string; newPassword: string },
) => {
  // CHECKING IF THE USER EXISTS
  const user = await User.isUserExistByEmail(userData.email);

  if (!user)
    throw new AppError(httpStatus.NOT_FOUND, 'This user is not found!');

  // CHECKING IF THE USER IS BLOCKED
  const userStatus = user?.isDeleted;

  if (userStatus)
    throw new AppError(httpStatus.FORBIDDEN, 'This user was deleted!');

  // CHECKING IF PASSWORD IS CORRECT
  if (
    !(await User.isPasswordMatched(
      payload.oldPassword,
      user?.password as string,
    ))
  )
    throw new AppError(httpStatus.FORBIDDEN, 'Password do not match');

  // HASH NEW PASSWORD
  const newHashedPassword = await bcrypt.hash(
    payload.newPassword,
    Number(config.bcrypt_salt_round),
  );

  // console.log('change pass service', newHashedPassword);
  // console.log(userData);

  await User.findOneAndUpdate(
    {
      email: userData.email,
      role: userData.role,
    },
    {
      password: newHashedPassword,
      passwordChangedAt: new Date(),
    },
  );

  return null;
};

// FORGOTTEN PASSWORD ORIGINALLY - IMPLEMMENTED OTP
const forgottenPassword = async (email: string) => {
  // CHECK IF USER EXISTS
  const user = await User.findOne({ email });
  if (!user) throw new AppError(httpStatus.NOT_FOUND, 'User not found');

  // CHECK IF USER IS ALREADY DELETED
  if (user.isDeleted)
    throw new AppError(httpStatus.FORBIDDEN, 'User is already deleted');

  // CHECK USER STATUS
  if (user.status === 'Blocked')
    throw new AppError(httpStatus.FORBIDDEN, 'User is blocked');

  const otp = generateOtp();

  const otpToken = jwt.sign({ otp, email }, config.jwt_otp_secret as string, {
    expiresIn: '5m',
  });

  await User.updateOne({ email }, { otpToken });

  await EmailHelper.sendEmail({
    to: {
      name: user.name,
      address: user.email,
    },
    subject: 'Your Password Reset OTP',
    text: `Your OTP is ${otp}. It is valid for 5 minutes.`,
    html: generateOTPEmail({ otp, name: user.name }),
  });
};

const verifyOTP = async ({ email, otp }: { email: string; otp: string }) => {
  const user = await User.findOne({ email: email });

  if (!user) throw new AppError(httpStatus.NOT_FOUND, 'User not found');

  if (!user.otpToken || user.otpToken === '')
    throw new AppError(
      httpStatus.BAD_REQUEST,
      'No OTP token found. Please request a new password reset OTP.',
    );

  const decodedOtpData = verifyToken(
    user.otpToken as string,
    config.jwt_otp_secret as string,
  );

  if (!decodedOtpData) {
    user.otpToken = null; // CLEAR EXPIRED OTP
    await user.save();
    throw new AppError(httpStatus.FORBIDDEN, 'OTP has expired or is invalid');
  }

  if (decodedOtpData.otp !== otp)
    throw new AppError(httpStatus.FORBIDDEN, 'Invalid OTP');

  user.otpToken = null;
  await user.save();

  const resetToken = jwt.sign(
    { email },
    config.jwt_pass_reset_secret as string,
    {
      expiresIn: config.jwt_pass_reset_expires_in,
    },
  );

  user.resetToken = resetToken; // Store reset token in DB
  await user.save();

  // Return the reset token
  return {
    resetToken,
  };
};

// RESET PASSWORD
const resetPassword = async (
  payload: { newPassword: string },
  token: string,
) => {
  const decodedData = verifyToken(
    token as string,
    config.jwt_pass_reset_secret as string,
  );
  // console.log('Decoded data initial', decodedData);

  const user = await User.findOne({ email: decodedData.email });

  if (!user) throw new AppError(httpStatus.NOT_FOUND, 'User not found'); // CHECK IF USER EXISTS OR NOT

  // CHECK IF USER IS ALREADY DELETED
  if (user.isDeleted)
    throw new AppError(httpStatus.FORBIDDEN, 'User is already deleted');

  // CHECK USER STATUS
  if (user.status === 'Blocked')
    throw new AppError(httpStatus.FORBIDDEN, 'User is blocked');

  if (!decodedData || !decodedData.email)
    throw new AppError(httpStatus.FORBIDDEN, 'Invalid or expired reset token');

  // HASH NEW PASSWORD
  const newHashedPassword = await bcrypt.hash(
    payload.newPassword,
    Number(config.bcrypt_salt_round),
  );

  return await User.findOneAndUpdate(
    {
      email: decodedData.email,
    },
    {
      password: newHashedPassword,
      passwordChangeAt: new Date(),
      resetToken: null, // CLEAR THE RESET TOKEN
    },
    {
      new: true,
      runValidators: true,
    },
  );
};

export const AuthService = {
  registerUserIntoDB,
  userSignIntoDB,

  changePassword,
  forgottenPassword,
  verifyOTP,

  resetPassword,

  getCurrentUser,

  refreshToken,

  blockUserFromDB,
};
