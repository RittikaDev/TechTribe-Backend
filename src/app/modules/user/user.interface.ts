import { Model, Document } from 'mongoose';

export type TRole = 'admin' | 'user';

export type TUserStatus = 'Active' | 'Blocked';
export type TUserGender = 'Male' | 'Female' | 'Other';
export type TSocials =
  | 'Facebook'
  | 'Instagram'
  | 'Linkedin'
  | 'Twitter'
  | 'Github'
  | 'Youtube';

export type TSocialLinks = {
  platform: TSocials;
  url: string;
};

export interface IUser extends Document {
  name: string;
  username: string;
  bio: string;
  email: string;
  phone: string;
  gender: TUserGender;
  password: string;
  passwordChangeAt?: Date;
  profilePicture: string;
  role: TRole;
  status: TUserStatus;
  totalFollowers: number;
  totalFollowing: number;
  totalPosts: number;
  socialLinks: TSocialLinks[];
  location: string;
  dateOfBirth: Date;
  isVerified: boolean;
  isPremiumUser: boolean;
  isDeleted: boolean;
  otpToken: string | null;
  resetToken: string | null;
}

export type IUserAuth = {
  email: string;
  password: string;
};

export interface UserModel extends Model<IUser> {
  // eslint-disable-next-line no-unused-vars
  isUserExistByEmail(email: string): Promise<IUser>;

  isPasswordMatched(
    // eslint-disable-next-line no-unused-vars
    plainTextPassword: string,
    // eslint-disable-next-line no-unused-vars
    hashedPassword: string,
  ): Promise<boolean>;
  isJWTIssuedBeforePasswordChanged(
    passwordChangedTimestamp: Date,
    jwtIssuedTimestamp: number,
  ): boolean;
}
