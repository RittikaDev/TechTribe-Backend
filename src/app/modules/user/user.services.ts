import { JwtPayload } from 'jsonwebtoken';
import { User } from './user.model';

import AppError from '../../errors/AppError';
import httpStatus from 'http-status-codes';
import { IUser, TSocialLinks } from './user.interface';
import QueryBuilder from '../../builder/QueryBuilder';
import { searchableUsers } from '../car/car.constants';

// UPDATE USER PROFILE
const updateProfile = async (userData: JwtPayload, payload: IUser) => {
  const user = await User.isUserExistByEmail(userData.email);
  if (!user) throw new AppError(httpStatus.NOT_FOUND, 'User not found');

  const updatedUser = await User.findByIdAndUpdate(user._id, payload, {
    new: true,
    runValidators: true,
  });

  return updatedUser;
};

// UPDATE USER SOCIAL LINKS
const updateSocialLinks = async (
  userData: JwtPayload,
  payload: TSocialLinks[],
) => {
  const updatedUser = await User.findOneAndUpdate(
    { email: userData.email },
    payload,
    {
      new: true,
      runValidators: true,
    },
  );

  if (!updatedUser) throw new AppError(httpStatus.NOT_FOUND, 'User not found');

  return updatedUser;
};

const getAllUsers = async (query: Record<string, unknown>) => {
  const carQuery = new QueryBuilder(User.find({}), query)
    .filter()
    .sort()
    .paginate()
    .fields()
    .search(searchableUsers);

  const result = await carQuery.modelQuery;
  const paginationMetaData = await carQuery.countTotal();

  return { result, paginationMetaData };
};

// get single user by username
const getSingleUser = async (username: string) => {
  const user = await User.findOne({ username });
  if (!user) throw new AppError(httpStatus.NOT_FOUND, 'User not found');

  return user;
};

// MANAGING USERS
const manageUserStatus = async (
  id: string,
  payload: Pick<IUser, 'isDeleted'>,
) => {
  const user = await User.findByIdAndUpdate(id, payload, {
    new: true,
    runValidators: true,
  });

  if (!user) throw new AppError(httpStatus.NOT_FOUND, 'User not found');

  return user;
};

export const UserService = {
  updateProfile,
  updateSocialLinks,

  getAllUsers,
  getSingleUser,

  manageUserStatus,
};
