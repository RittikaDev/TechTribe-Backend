import catchAsync from '../../utils/catchAsync';
import sendResponse from '../../utils/sendResponse';
import { UserService } from './user.services';
import httpStatus from 'http-status-codes';

// USER: UPDATE PROFILE
const updateProfile = catchAsync(async (req, res) => {
  const updatedUser = await UserService.updateProfile(req.user!, req.body);
  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: 'User profile has been updated successfully',
    data: updatedUser,
  });
});

const updateSocialLinks = catchAsync(async (req, res) => {
  const result = await UserService.updateSocialLinks(req.user!, req.body);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: 'User social links has been updated successfully',
    data: result,
  });
});

const getAllUsers = catchAsync(async (req, res) => {
  const { paginationMetaData, result } = await UserService.getAllUsers(
    req.query,
  );

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: 'Cars retrieved successfully',
    paginationMetaData,
    data: result,
  });
});

const getSingleUser = catchAsync(async (req, res) => {
  const { username } = req.params;
  const result = await UserService.getSingleUser(username);

  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: 'User retrieved successfully',
    data: result,
  });
});

// MANAGING USERS
const manageUserStatus = catchAsync(async (req, res) => {
  const { id } = req.params;
  const updatedUser = await UserService.manageUserStatus(id, req.body);
  sendResponse(res, {
    success: true,
    statusCode: httpStatus.OK,
    message: 'User status updated successfully',
    data: updatedUser,
  });
});

export const UserController = {
  updateProfile,
  updateSocialLinks,

  getAllUsers,
  getSingleUser,

  manageUserStatus,
};
