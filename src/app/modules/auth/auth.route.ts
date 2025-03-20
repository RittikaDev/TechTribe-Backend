import express from 'express';

import validateRequest from '../../middlewares/validateRequest';
import auth from '../../middlewares/auth';

import { USER_ROLE } from './auth.constant';
import { AuthControllers } from './auth.controllers';
import { AuthValidation } from './auth.validation';

const router = express.Router();

router.post(
  '/register',
  validateRequest(AuthValidation.CreateUserValidationSchema),
  AuthControllers.registerUser,
);

router.post(
  '/login',
  validateRequest(AuthValidation.LoginValidationSchema),
  AuthControllers.login,
);

router.post('/current-user', AuthControllers.getCurrentUser);

router.post(
  '/refresh-token',
  validateRequest(AuthValidation.RefreshTokenValidationSchema),
  AuthControllers.refreshToken,
);

router.post(
  '/update-password',
  auth(USER_ROLE.user),
  validateRequest(AuthValidation.ChangePasswordValidationSchema),
  AuthControllers.changePassword,
);

router.post(
  '/forgot-password',
  validateRequest(AuthValidation.ForgottenPasswordValidation),
  AuthControllers.forgottenPassword,
);

router.post('/verify-otp', AuthControllers.verifyOTP);

router.post(
  '/reset-password',
  validateRequest(AuthValidation.ResetPasswordValidation),
  AuthControllers.resetPassword,
);

// ADMIN
router.patch('/:id/block', auth(USER_ROLE.admin), AuthControllers.blockAUser);

export const AuthRoutes = router;
