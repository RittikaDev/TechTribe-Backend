import httpStatus from 'http-status-codes';
import catchAsync from '../../utils/catchAsync';
import sendResponse from '../../utils/sendResponse';
import { AuthService } from './auth.services';
import config from '../../config';
import AppError from '../../errors/AppError';

// REGISTER
const registerUser = catchAsync(async (req, res) => {
  const userData = req.body;

  const user = await AuthService.registerUserIntoDB(userData);
  const { refreshToken, accessToken } = user;

  sendResponse(res, {
    success: true,
    message: 'User registered successfully',
    statusCode: httpStatus.CREATED,
    data: {
      accessToken,
      refreshToken,
    },
  });
});

// LOGIN
const login = catchAsync(async (req, res) => {
  const result = await AuthService.userSignIntoDB(req.body);
  const { refreshToken, accessToken } = result;

  res.cookie('refreshToken', refreshToken, {
    secure: config.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'none',
    maxAge: 1000 * 60 * 60 * 24 * 365,
  });

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Login successful',
    data: {
      token: `${accessToken}`,
    },
  });
});

const getCurrentUser = catchAsync(async (req, res) => {
  console.log(req.body);
  const user = await AuthService.getCurrentUser(req.body);
  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: 'User fetched successfully',
    data: user,
  });
});

// refresh Token
const refreshToken = catchAsync(async (req, res) => {
  const { refreshToken } = req.cookies;
  const result = await AuthService.refreshToken(refreshToken);
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Access token retrived successfully',
    data: result,
  });
});

const changePassword = catchAsync(async (req, res) => {
  const { ...passwordData } = req.body;

  const result = await AuthService.changePassword(req.user!, passwordData);
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Password is updated succesfully!',
    data: result,
  });
});

// forget password
const forgottenPassword = catchAsync(async (req, res) => {
  const { email } = req.body;
  const result = await AuthService.forgottenPassword(email);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Password reset link sent successfully',
    data: result,
  });
});

const verifyOTP = catchAsync(async (req, res) => {
  const result = await AuthService.verifyOTP(req.body);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'OTP verified successfully.',
    data: result,
  });
});

// reset password
const resetPassword = catchAsync(async (req, res) => {
  const token = req.headers?.authorization?.split(' ')[1];

  if (!token) throw new AppError(httpStatus.FORBIDDEN, 'Access Forbidden');

  const result = await AuthService.resetPassword(req.body, token);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Password reset successfully',
    data: result,
  });
});

// ADMIN PARTS
const blockAUser = catchAsync(async (req, res) => {
  // console.log(req);
  const { id } = req.params;
  await AuthService.blockUserFromDB(id);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'User blocked successfully',
  });
});

export const AuthControllers = {
  registerUser,
  login,

  changePassword,
  forgottenPassword,
  verifyOTP,
  resetPassword,

  getCurrentUser,

  refreshToken,

  blockAUser,
};
