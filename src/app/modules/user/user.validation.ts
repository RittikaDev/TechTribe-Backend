import { z } from 'zod';

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

export const UserValidations = {
  ManageStatusValidationSchema,
  updatePassValidationSchema,
};
