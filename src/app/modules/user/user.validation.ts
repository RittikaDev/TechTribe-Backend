import { z } from 'zod';
import { SocialPlatform } from './user.constant';

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

const ManageStatusValidationSchema = z.object({
  body: z
    .object({
      isBlocked: z.boolean(),
    })
    .strict(),
});

const updatePassValidationSchema = z.object({
  body: z.object({
    password: z.string({ required_error: ' Password is required' }),
  }),
});

const socialLinkSchema = z
  .object({
    platform: z.enum([...SocialPlatform] as [string, ...string[]], {
      required_error: 'Social Platform is required',
      invalid_type_error: 'Social Platform must be string',
    }),
    url: z.string().url('Invalid URL'),
  })
  .optional();

const UpdateSocialLinksValidationSchema = z.object({
  body: z
    .object({
      socialLinks: z
        .array(socialLinkSchema)
        .min(1, 'At least one social link is required')
        .max(6, 'No more than 6 social links are allowed')
        .refine(
          (socialLinks) => {
            const platforms = socialLinks.map((link) => link?.platform);
            return new Set(platforms).size === platforms.length;
          },
          {
            message: 'Social platforms must be unique',
          },
        )
        .optional(),
    })
    .strict(),
});

export const UserValidations = {
  ManageStatusValidationSchema,
  updatePassValidationSchema,

  UpdateUserValidationSchema,
  UpdateSocialLinksValidationSchema,
};
