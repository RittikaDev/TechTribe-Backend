import { Schema, model } from 'mongoose';
import bcrypt from 'bcrypt';
import config from '../../config';

import { IUser, TSocials, UserModel } from './user.interface';
import { SocialPlatform, UserGender, UserStatus } from './user.constant';

const socialLinksSchema = new Schema<TSocials>(
  {
    platform: {
      type: String,
      enum: {
        values: SocialPlatform,
        message: '{VALUE} is not a valid social platform',
      },
    },
    url: {
      type: String,
      required: [true, 'Url is required'],
    },
  },
  { _id: false },
);

const userSchema = new Schema<IUser, UserModel>(
  {
    name: {
      type: String,
      trim: true,
      required: [true, 'Full Name is required'],
    },
    username: {
      type: String,
      trim: true,
      required: [true, 'Username is required'],
      unique: true,
    },
    bio: {
      type: String,
      default: '',
    },
    email: {
      type: String,
      trim: true,
      required: [true, 'Email is required'],
      unique: true,
    },
    phone: {
      type: String,
      trim: true,
      default: '',
    },
    location: {
      type: String,
      default: '',
    },
    password: {
      type: String,
      minlength: [6, 'Password must be at least 6 characters'],
      select: 0,
    },
    passwordChangeAt: {
      type: Date,
    },
    profilePicture: {
      type: String,
      default: '',
    },
    gender: {
      type: String,
      enum: {
        values: UserGender,
        message: '{VALUE} is not a valid gender',
      },
    },
    role: {
      type: String,
      enum: ['admin', 'user'],
      default: 'user',
    },
    status: {
      type: String,
      enum: {
        values: UserStatus,
        message: '{VALUE} is not a valid status',
      },
      default: 'Active',
    },
    totalFollowers: {
      type: Number,
      default: 0,
    },
    totalFollowing: {
      type: Number,
      default: 0,
    },
    totalPosts: {
      type: Number,
      default: 0,
    },
    dateOfBirth: {
      type: Date,
      default: null,
    },
    socialLinks: {
      type: [socialLinksSchema],
      default: [],
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    isPremiumUser: {
      type: Boolean,
      default: false,
    },
    isDeleted: {
      type: Boolean,
      default: false,
    },
    otpToken: {
      type: String,
      default: null,
    },
    resetToken: {
      type: String,
      default: null,
    },
  },
  { timestamps: true },
);

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  // eslint-disable-next-line @typescript-eslint/no-this-alias
  const user = this; // doc
  // hashing password and save into DB
  user.password = await bcrypt.hash(
    user?.password as string,
    Number(config.bcrypt_salt_round),
  );
  next();
});

userSchema.post('save', function (doc, next) {
  doc.password = '';
  next();
});

userSchema.statics.isUserExistByEmail = async function (email: string) {
  return await User.findOne({ email }).select('+password');
};

userSchema.statics.isPasswordMatched = async function (
  plainTextPassword,
  hashedPassword,
) {
  // console.log('Inside password match', hashedPassword);
  return await bcrypt.compare(plainTextPassword, hashedPassword);
};

userSchema.statics.isJWTIssuedBeforePasswordChanged = function (
  passwordChangedTimestamp: Date,
  jwtIssuedTimestamp: number,
) {
  const passwordChangedTime =
    new Date(passwordChangedTimestamp).getTime() / 1000;
  return passwordChangedTime > jwtIssuedTimestamp;
};

export const User = model<IUser, UserModel>('User', userSchema);
