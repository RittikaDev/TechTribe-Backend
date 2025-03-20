import dotenv from 'dotenv';
import path from 'path';

dotenv.config({ path: path.join(process.cwd(), '.env') }); // ACCESSING ENV FILE

export default {
  NODE_ENV: process.env.NODE_ENV,
  port: process.env.PORT || 5000,
  database_url: process.env.DATABASE_URL,

  client_base_url: process.env.CLIENT_BASE_URL,

  bcrypt_salt_round: process.env.BCRYPT_SALT_ROUNDS,
  default_password: process.env.DEFAULT_PASS,

  jwt_access_secret: process.env.JWT_ACCESS_SECRET,
  jwt_refresh_secret: process.env.JWT_REFRESH_SECRET,
  jwt_access_expires_in: process.env.JWT_ACCESS_EXPIRES_IN,
  jwt_refresh_expires_in: process.env.JWT_REFRESH_EXPIRES_IN,

  jwt_otp_secret: process.env.JWT_OTP_SECRET,
  jwt_pass_reset_secret: process.env.JWT_PASS_RESET_SECRET,
  jwt_pass_reset_expires_in: process.env.JWT_PASS_RESET_EXPIRES_IN,

  reset_password_ui_url: process.env.RESET_PASSWORD_UI_URL,

  // SMTP EMAIL SEND
  smtp_auth_user: process.env.SMTP_AUTH_USER,
  smtp_auth_password: process.env.SMTP_AUTH_PASSWORD,
  nodemailer_email_from: process.env.NODEMAILER_EMAIL_FROM,

  // SHURJOPAY
  sp: {
    sp_endpoint: process.env.SP_ENDPOINT,
    sp_username: process.env.SP_USERNAME,
    sp_password: process.env.SP_PASSWORD,
    sp_prefix: process.env.SP_PREFIX,
    sp_return_url: process.env.SP_RETURN_URL,
    // db_file: process.env.DB_FILE,
  },
};
