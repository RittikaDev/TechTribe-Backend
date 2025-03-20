import { z } from 'zod';
import { UserGender } from '../user/user.constant';

// DEFINING THE IUser SCHEMA WITH CUSTOM ERROR MESSAGE
const CreateUserValidationSchema = z.object({
  body: z.object({
    name: z.string({
      required_error: 'Full Name is required',
      invalid_type_error: 'Full Name must be string',
    }),
    username: z
      .string({
        required_error: 'Username is required',
        invalid_type_error: 'Username must be string',
      })
      .min(3, 'Username must be at least 3 characters long')
      .max(10, 'Username must not exceed 10 characters')
      .regex(
        /^[a-zA-Z0-9._]+$/,
        'Username can only contain letters, numbers, ".", and "_"',
      ),
    email: z.string({
      required_error: 'Email is required',
      invalid_type_error: 'Email must be string',
    }),
    password: z.string({
      required_error: 'Password is required',
      invalid_type_error: 'Password must be string',
    }),
    gender: z.enum([...UserGender] as [string, ...string[]], {
      required_error: 'Gender is required',
      invalid_type_error: 'Gender must be string',
    }),
    dateOfBirth: z
      .string({
        required_error: 'Date of Birth is required',
        invalid_type_error: 'Date of Birth must be string',
      })
      .date('Invalid Date, Expected format: YYYY-MM-DD'),
    profilePicture: z
      .string({
        required_error: 'Profile picture is required',
        invalid_type_error: 'Profile Picture must be string',
      })
      .optional(),
  }),
});

const LoginValidationSchema = z.object({
  body: z.object({
    email: z.string({ required_error: 'Email is required' }),
    password: z.string({ required_error: ' Password is required' }),
  }),
});

const UpdateUserValidationSchema = z.object({
  body: z.object({
    name: z.string().min(1, { message: 'Name is required' }).optional(),
    email: z
      .string()
      .email({ message: 'Invalid email address' })
      .nonempty({ message: 'Email is required' })
      .optional(),
    password: z
      .string()
      .min(6, { message: 'Password must be at least 6 characters long' })
      .nonempty({ message: 'Password is required' })
      .optional(),
    phone: z.string().optional().optional(),
    address: z.string().optional().optional(),
    city: z.string().optional().optional(),
    role: z.enum(['admin', 'user']).optional().default('user'),
    isBlocked: z.boolean().optional().default(false).optional(),
  }),
});

const ChangePasswordValidationSchema = z.object({
  body: z.object({
    oldPassword: z.string({
      required_error: 'Old password is required',
    }),
    newPassword: z.string({ required_error: 'Password is required' }),
  }),
});

const ForgottenPasswordValidation = z.object({
  body: z
    .object({
      email: z.string({
        required_error: 'Email is required',
        invalid_type_error: 'Email must be a string',
      }),
    })
    .strict(),
});

const ResetPasswordValidation = z.object({
  body: z
    .object({
      // email: z.string({
      //   required_error: 'Email is required',
      //   invalid_type_error: 'Email must be a string',
      // }),
      newPassword: z
        .string({
          required_error: 'New password is required',
          invalid_type_error: 'New password must be a string',
        })
        .min(6, 'New password must be at least 8 characters'),
    })
    .strict(),
});

const RefreshTokenValidationSchema = z.object({
  cookies: z.object({
    refreshToken: z.string({
      required_error: 'refresh token is required',
    }),
  }),
});

export const AuthValidation = {
  CreateUserValidationSchema,
  LoginValidationSchema,

  UpdateUserValidationSchema,

  ChangePasswordValidationSchema,
  ForgottenPasswordValidation,
  ResetPasswordValidation,

  RefreshTokenValidationSchema,
};
