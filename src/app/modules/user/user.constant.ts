import { TSocials, TUserGender, TUserStatus } from './user.interface';

export const USER_ROLE = {
  admin: 'admin',
  user: 'user',
} as const;

export const UserStatus: TUserStatus[] = ['Active', 'Blocked'];
export const UserGender: TUserGender[] = ['Male', 'Female', 'Other'];
export const SocialPlatform: TSocials[] = [
  'Facebook',
  'Instagram',
  'Github',
  'Twitter',
  'Youtube',
  'Linkedin',
];
