import { format } from 'date-fns';
import config from '../config';
import { toZonedTime } from 'date-fns-tz';

// payment success
export const generatePaymentSuccessEmail = ({
  fullName,
  status,
  amount,
  currency,
  paymentMethod,
  subscriptionType,
  startDate,
  endDate,
  paidAt,
  transactionId,
  username,
}: {
  fullName: string;
  status: string;
  amount: number;
  currency: string;
  paymentMethod: string;
  subscriptionType: string;
  startDate: string;
  endDate: string;
  paidAt: string;
  transactionId: string;
  username: string;
}) => {
  return `
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>

<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <title>Payment Confirmation</title>
</head>

<body
  style="margin: 0; padding: 0; font-family: Arial, sans-serif; font-size: 16px; line-height: 1.5; color: #333333; background-color: #f7f7f7;">
  <table border="0" cellpadding="0" cellspacing="0" width="100%"
    style="max-width: 600px; margin: 0 auto; background-color: #ffffff;">
    <tr>
      <td style="padding: 40px 30px; text-align: center; background-color: #00d351;">
        <h2 style="color: #ffffff; margin: 0;">
          <img src="https://cdn-icons-png.flaticon.com/128/190/190411.png" alt="Check"
            style="vertical-align: middle; margin-right: 10px; width: 38px; height: 38px;">
          Payment Successful
        </h2>
      </td>
    </tr>
    <tr>
      <td style="padding: 40px 10px;">
        <h2 style="margin: 0 0 20px; font-size: 24px; color: #333333;">Payment Confirmation</h2>
        <p style="margin: 0 0 20px;">Dear ${fullName},</p>
        <p style="margin: 0 0 20px;">Thank you for your payment. Your transaction was successful.</p>
        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom: 20px;">
          <tr>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee;">
              <strong>
                <img src="https://cdn-icons-png.flaticon.com/128/471/471662.png" alt="Info"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                Status:
              </strong>
            </td>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; text-align: right;">${status}</td>
          </tr>
          <tr>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee;">
              <strong>
                <img src="https://cdn-icons-png.flaticon.com/128/2454/2454282.png" alt="Money"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                Amount:
              </strong>
            </td>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; text-align: right;">${amount} ${currency}</td>
          </tr>
          <tr>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee;">
              <strong>
                <img src="https://cdn-icons-png.flaticon.com/128/9368/9368835.png" alt="Fingerprint"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                Transaction Id:
              </strong>
            </td>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; text-align: right;">${transactionId}</td>
          </tr>
          <tr>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee;">
              <strong>
                <img src="https://cdn-icons-png.flaticon.com/128/633/633611.png" alt="Credit Card"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                Payment Method:
              </strong>
            </td>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; text-align: right;">${paymentMethod}</td>
          </tr>
          <tr>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee;">
              <strong>
                <img src="https://cdn-icons-png.flaticon.com/128/11282/11282361.png" alt="Sync"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                Subscription:
              </strong>
            </td>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; text-align: right;">${subscriptionType}</td>
          </tr>
          <tr>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee;">
              <strong>
                <img src="https://cdn-icons-png.flaticon.com/128/2693/2693507.png" alt="Calendar Plus"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                Subscription Start:
              </strong>
            </td>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; text-align: right;">${startDate}
            </td>
          </tr>
          <tr>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee;">
              <strong>
                <img src="https://cdn-icons-png.flaticon.com/128/2693/2693507.png" alt="Calendar Minus"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                Subscription End:
              </strong>
            </td>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; text-align: right;">${endDate}</td>
          </tr>
          <tr>
            <td style="padding: 10px 0;">
              <strong>
                <img src="https://cdn-icons-png.flaticon.com/128/2693/2693507.png" alt="Calendar"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                Paid At:
              </strong>
            </td>
            <td style="padding: 10px 0; text-align: right;">${paidAt}</td>
          </tr>
        </table>
        <p style="margin: 0 0 20px;">If you have any questions, please contact our support team.</p>
        <table border="0" cellpadding="0" cellspacing="0" width="100%">
          <tr>
            <td>
              <a href="${config.client_base_url}/profile/@${username}"
                style="display: inline-block; padding: 12px 20px; background-color: #00d351; color: #ffffff; text-decoration: none; border-radius: 4px;">
                <img src="https://cdn-icons-png.flaticon.com/128/17707/17707812.png" alt="User"
                  style="vertical-align: middle; margin-right: 10px; width: 18px; height: 18px;">
                View Account
              </a>
            </td>
          </tr>
        </table>
      </td>
    </tr>
    <tr>
      <td style="padding: 20px 30px; text-align: center; font-size: 14px; color: #666666; background-color: #f0f0f0;">
        <p>&copy; 2024 Tech Tips Hub. All rights reserved.</p>
        <p>
          <a target="_blank" href="https://facebook.com/noyonalways"
            style="color: #00d351; text-decoration: none; margin: 0 10px;">
            <img src="https://cdn-icons-png.flaticon.com/128/733/733547.png" alt="Facebook"
              style="width: 24px; height: 24px;">
          </a>
          <a target="_blank" href="https://twitter.com/noyonalways"
            style="color: #00d351; text-decoration: none; margin: 0 10px;">
            <img src="https://cdn-icons-png.flaticon.com/128/733/733579.png" alt="Twitter"
              style="width: 24px; height: 24px;">
          </a>
          <a target="_blank" href="https://instagram.com/noyonalways"
            style="color: #00d351; text-decoration: none; margin: 0 10px;">
            <img src="https://cdn-icons-png.flaticon.com/128/2111/2111463.png" alt="Instagram"
              style="width: 24px; height: 24px;">
          </a>
        </p>
      </td>
    </tr>
  </table>
</body>

</html>
  `;
};

// payment failed
export const generatePaymentFailedEmail = ({
  fullName,
  status,
  amount,
  currency,
  paymentMethod,
  transactionId,
  username,
  subscriptionType,
}: {
  fullName: string;
  status: string;
  amount: number;
  currency: string;
  paymentMethod: string;
  transactionId: string;
  username: string;
  subscriptionType: string;
}) => {
  return `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>

<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <title>Payment Failed</title>
</head>

<body
  style="margin: 0; padding: 0; font-family: Arial, sans-serif; font-size: 16px; line-height: 1.5; color: #333333; background-color: #f7f7f7;">
  <table border="0" cellpadding="0" cellspacing="0" width="100%"
    style="max-width: 600px; margin: 0 auto; background-color: #ffffff;">
    <tr>
      <td style="padding: 40px 30px; text-align: center; background-color: #f44336;">
        <h2 style="color: #ffffff; margin: 0;">
          <img src="https://cdn-icons-png.flaticon.com/128/1828/1828843.png" alt="Error"
            style="vertical-align: middle; margin-right: 10px; width: 38px; height: 38px;">
          Payment Failed
        </h2>
      </td>
    </tr>
    <tr>
      <td style="padding: 40px 10px;">
        <h2 style="margin: 0 0 20px; font-size: 24px; color: #333333;">Payment Failure Notice</h2>
        <p style="margin: 0 0 20px;">Dear ${fullName},</p>
        <p style="margin: 0 0 20px;">We regret to inform you that your recent payment attempt was unsuccessful. Here are
          the details of the failed transaction:</p>
        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom: 20px;">
          <tr>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee;">
              <strong>
                <img src="https://cdn-icons-png.flaticon.com/128/471/471662.png" alt="Info"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                Status:
              </strong>
            </td>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; text-align: right; color: #f44336;">
            ${status}
            </td>
          </tr>
          <tr>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee;">
              <strong>
                <img src="https://cdn-icons-png.flaticon.com/128/2454/2454282.png" alt="Money"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                Amount:
              </strong>
            </td>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; text-align: right;">${amount} ${currency}</td>
          </tr>
          <tr>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee;">
              <strong>
                <img src="https://cdn-icons-png.flaticon.com/128/9368/9368835.png" alt="Fingerprint"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                Transaction Id:
              </strong>
            </td>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; text-align: right;">${transactionId}</td>
          </tr>
          <tr>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee;">
              <strong>
                <img src="https://cdn-icons-png.flaticon.com/128/633/633611.png" alt="Credit Card"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                Payment Method:
              </strong>
            </td>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; text-align: right;">${paymentMethod}</td>
          </tr>
          <tr>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee;">
              <strong>
                <img src="https://cdn-icons-png.flaticon.com/128/11282/11282361.png" alt="Sync"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                Subscription:
              </strong>
            </td>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; text-align: right;">${subscriptionType}</td>
          </tr>
          <tr>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee;">
              <strong>
                <img src="https://cdn-icons-png.flaticon.com/128/2693/2693507.png" alt="Calendar"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                Attempt At:
              </strong>
            </td>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; text-align: right;">${format(toZonedTime(new Date(), 'Asia/Dhaka'), 'M/d/yyyy, h:mm:ss a')}</td>
          </tr>
        </table>
        <p style="margin: 0 0 20px;">Please take a moment to review your payment information and try again. Common
          reasons for payment failure include:</p>
        <ul style="margin: 0 0 20px; padding-left: 20px;">
          <li>Insufficient funds</li>
          <li>Incorrect card details</li>
          <li>Expired card</li>
          <li>Transaction limit exceeded</li>
        </ul>
        <p style="margin: 0 0 20px;">If you continue to experience issues or need assistance, please don't hesitate to
          contact our support team.</p>
        <table border="0" cellpadding="0" cellspacing="0" width="100%">
          <tr>
            <td>
              <a href="${config.client_base_url}/profile/@${username}"
                style="display: inline-block; padding: 12px 20px; background-color: #f44336; color: #ffffff; text-decoration: none; border-radius: 4px;">
                <img src="https://cdn-icons-png.flaticon.com/128/1077/1077114.png" alt="User"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                Retry Payment
              </a>
            </td>
          </tr>
        </table>
      </td>
    </tr>
    <tr>
      <td style="padding: 20px 30px; text-align: center; font-size: 14px; color: #666666; background-color: #f0f0f0;">
        <p>&copy; 2024 Tech Tips Hub. All rights reserved.</p>
        <p>
          <a target="_blank" href="https://facebook.com/noyonalways"
            style="color: #ff4136; text-decoration: none; margin: 0 10px;">
            <img src="https://cdn-icons-png.flaticon.com/128/733/733547.png" alt="Facebook"
              style="width: 24px; height: 24px;">
          </a>
          <a target="_blank" href="https://twitter.com/noyonalways"
            style="color: #ff4136; text-decoration: none; margin: 0 10px;">
            <img src="https://cdn-icons-png.flaticon.com/128/733/733579.png" alt="Twitter"
              style="width: 24px; height: 24px;">
          </a>
          <a target="_blank" href="https://instagram.com/noyonalways"
            style="color: #ff4136; text-decoration: none; margin: 0 10px;">
            <img src="https://cdn-icons-png.flaticon.com/128/2111/2111463.png" alt="Instagram"
              style="width: 24px; height: 24px;">
          </a>
        </p>
      </td>
    </tr>
  </table>
</body>

</html>`;
};

// payment canceled
export const generatePaymentCanceledEmail = ({
  fullName,
  status,
  amount,
  currency,
  paymentMethod,
  transactionId,
  username,
  subscriptionType,
}: {
  fullName: string;
  status: string;
  amount: number;
  currency: string;
  paymentMethod: string;
  transactionId: string;
  username: string;
  subscriptionType: string;
}) => {
  return `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>

<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <title>Payment Cancelled</title>
</head>

<body
  style="margin: 0; padding: 0; font-family: Arial, sans-serif; font-size: 16px; line-height: 1.5; color: #333333; background-color: #f7f7f7;">
  <table border="0" cellpadding="0" cellspacing="0" width="100%"
    style="max-width: 600px; margin: 0 auto; background-color: #ffffff;">
    <tr>
      <td style="padding: 40px 30px; text-align: center; background-color: #ffa500;">
        <h2 style="color: #ffffff; margin: 0;">
          <img src="https://cdn-icons-png.flaticon.com/128/16231/16231728.png" alt="Warning"
            style="vertical-align: middle; margin-right: 10px; width: 38px; height: 38px;">
          Payment Cancelled
        </h2>
      </td>
    </tr>
    <tr>
      <td style="padding: 40px 10px;">
        <h2 style="margin: 0 0 20px; font-size: 24px; color: #333333;">Payment Cancellation Notice</h2>
        <p style="margin: 0 0 20px;">Dear ${fullName},</p>
        <p style="margin: 0 0 20px;">This email is to confirm that your recent payment has been cancelled. Here are the
          details of the cancelled transaction:</p>
        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom: 20px;">
          <tr>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee;">
              <strong>
                <img src="https://cdn-icons-png.flaticon.com/128/471/471662.png" alt="Info"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                Status:
              </strong>
            </td>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; text-align: right; color: #ffa500;">${status}
            </td>
          </tr>
          <tr>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee;">
              <strong>
                <img src="https://cdn-icons-png.flaticon.com/128/2454/2454282.png" alt="Money"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                Amount:
              </strong>
            </td>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; text-align: right;">${amount} ${currency}</td>
          </tr>
          <tr>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee;">
              <strong>
                <img src="https://cdn-icons-png.flaticon.com/128/9368/9368835.png" alt="Fingerprint"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                Transaction Id:
              </strong>
            </td>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; text-align: right;">${transactionId}</td>
          </tr>
          <tr>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee;">
              <strong>
                <img src="https://cdn-icons-png.flaticon.com/128/633/633611.png" alt="Credit Card"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                Payment Method:
              </strong>
            </td>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; text-align: right;">${paymentMethod}</td>
          </tr>
          <tr>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee;">
              <strong>
                <img src="https://cdn-icons-png.flaticon.com/128/11282/11282361.png" alt="Sync"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                Subscription:
              </strong>
            </td>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; text-align: right;">${subscriptionType}</td>
          </tr>
          <tr>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee;">
              <strong>
                <img src="https://cdn-icons-png.flaticon.com/128/2693/2693507.png" alt="Calendar"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                Cancellation At:
              </strong>
            </td>
            <td style="padding: 10px 0; border-bottom: 1px solid #eeeeee; text-align: right;">${format(toZonedTime(new Date(), 'Asia/Dhaka'), 'M/d/yyyy, h:mm:ss a')}</td>
          </tr>
        </table>
        <p style="margin: 0 0 20px;">If you did not initiate this cancellation or if you have any questions about this
          transaction, please contact our support team immediately.</p>
        <p style="margin: 0 0 20px;">If you wish to make a new payment or reinstate your subscription, you can do so
          through your account dashboard.</p>
        <table border="0" cellpadding="0" cellspacing="0" width="100%">
          <tr>
            <td>
              <a href="${config.client_base_url}/profile/@${username}"
                style="display: inline-block; padding: 12px 20px; background-color: #ffa500; color: #ffffff; text-decoration: none; border-radius: 4px;">
                <img src="https://cdn-icons-png.flaticon.com/128/1077/1077114.png" alt="User"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                View Account
              </a>
            </td>
          </tr>
        </table>
      </td>
    </tr>
    <tr>
      <td style="padding: 20px 30px; text-align: center; font-size: 14px; color: #666666; background-color: #f0f0f0;">
        <p>&copy; 2024 Tech Tips Hub. All rights reserved.</p>
        <p>
          <a target="_blank" href="https://facebook.com/noyonalways"
            style="color: #ffa500; text-decoration: none; margin: 0 10px;">
            <img src="https://cdn-icons-png.flaticon.com/128/733/733547.png" alt="Facebook"
              style="width: 24px; height: 24px;">
          </a>
          <a target="_blank" href="https://twitter.com/noyonalways"
            style="color: #ffa500; text-decoration: none; margin: 0 10px;">
            <img src="https://cdn-icons-png.flaticon.com/128/733/733579.png" alt="Twitter"
              style="width: 24px; height: 24px;">
          </a>
          <a target="_blank" href="https://instagram.com/noyonalways"
            style="color: #ffa500; text-decoration: none; margin: 0 10px;">
            <img src="https://cdn-icons-png.flaticon.com/128/2111/2111463.png" alt="Instagram"
              style="width: 24px; height: 24px;">
          </a>
        </p>
      </td>
    </tr>
  </table>
</body>

</html>`;
};

// reset password
export const generateResetPasswordEmail = ({
  resetPasswordLink,
  fullName,
}: {
  resetPasswordLink: string;
  fullName: string;
}) => {
  return `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>

<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <title>Reset Your Password</title>
</head>

<body
  style="margin: 0; padding: 0; font-family: Arial, sans-serif; font-size: 16px; line-height: 1.5; color: #333333; background-color: #f7f7f7;">
  <table border="0" cellpadding="0" cellspacing="0" width="100%"
    style="max-width: 600px; margin: 0 auto; background-color: #ffffff;">
    <tr>
      <td style="padding: 40px 10px; text-align: center; background-color: #3498db;">
        <h2 style="color: #ffffff; margin: 0;">
          <img src="https://cdn-icons-png.flaticon.com/128/14669/14669107.png" alt="Lock"
            style="vertical-align: middle; margin-right: 10px; width: 40px; height: 40px;">
          Reset Your Password
        </h2>
      </td>
    </tr>
    <tr>
      <td style="padding: 40px 10px;">
        <p style="margin: 0 0 20px;">Dear ${fullName},</p>
        <p style="margin: 0 0 20px;">We received a request to reset your password. If you didn't make this request,
          please ignore this email.</p>
        <p style="margin: 0 0 20px;">To reset your password, click the button below. This link will expire in 30 minutes
          for security reasons.</p>
        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom: 20px;">
          <tr>
            <td align="center">
              <a target="_blank" href="${resetPasswordLink}"
                style="display: inline-block; padding: 14px 30px; background-color: #3498db; color: #ffffff; text-decoration: none; border-radius: 4px; font-weight: bold;">
                Reset Password
              </a>
            </td>
          </tr>
        </table>
        <p style="margin: 0 0 20px;">If the button above doesn't work, you can also copy and paste the following link
          into your browser:</p>
        <p style="margin: 0 0 20px; word-break: break-all; color: #3498db;">${resetPasswordLink}</p>
        <table border="0" cellpadding="0" cellspacing="0" width="100%"
          style="margin-bottom: 20px; background-color: #f8f8f8; border-radius: 4px;">
          <tr>
            <td style="padding: 15px;">
              <p style="margin: 0; font-size: 14px; color: #666666;">
                <img src="https://cdn-icons-png.flaticon.com/128/1827/1827370.png" alt="Clock"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                This password reset link will expire in 30 minutes.
              </p>
            </td>
          </tr>
        </table>
        <p style="margin: 0 0 20px;">For security reasons, please do not share this email or the reset link with anyone.
          Our support team will never ask for your password.</p>
        <p style="margin: 0 0 20px;">If you didn't request a password reset or need assistance, please contact our
          support team immediately.</p>
        <table border="0" cellpadding="0" cellspacing="0" width="100%">
          <tr>
            <td style="text-align: center;">
              <a href="mailto:noyonrahman2003@gmail.com" style="color: #3498db; text-decoration: none;">
                <img src="https://cdn-icons-png.flaticon.com/128/561/561127.png" alt="Email"
                  style="vertical-align: middle; margin-right: 10px; width: 16px; height: 16px;">
                support@tech-tribe.com
              </a>
            </td>
          </tr>
        </table>
      </td>
    </tr>
    <tr>
      <td style="padding: 20px 30px; text-align: center; font-size: 14px; color: #666666; background-color: #f0f0f0;">
        <p>&copy; 2024 Tech Tips Hub. All rights reserved.</p>
        <p>
          <a target="_blank" href="https://facebook.com/noyonalways"
            style="color: #3498db; text-decoration: none; margin: 0 10px;">
            <img src="https://cdn-icons-png.flaticon.com/128/733/733547.png" alt="Facebook"
              style="width: 24px; height: 24px;">
          </a>
          <a target="_blank" href="https://twitter.com/noyonalways"
            style="color: #3498db; text-decoration: none; margin: 0 10px;">
            <img src="https://cdn-icons-png.flaticon.com/128/733/733579.png" alt="Twitter"
              style="width: 24px; height: 24px;">
          </a>
          <a target="_blank" href="https://instagram.com/noyonalways"
            style="color: #3498db; text-decoration: none; margin: 0 10px;">
            <img src="https://cdn-icons-png.flaticon.com/128/2111/2111463.png" alt="Instagram"
              style="width: 24px; height: 24px;">
          </a>
        </p>
      </td>
    </tr>
  </table>
</body>

</html>`;
};

// verify email
export const generateVerifyEmail = ({
  fullName,
  verifyEmailLink,
}: {
  fullName: string;
  verifyEmailLink: string;
}) => {
  return `
  <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>

<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <title>Verify Your Email Address</title>
</head>

<body bgcolor="#f0f0f0" style="margin: 0; padding: 0; font-family: Arial, sans-serif;">
  <table width="100%" border="0" cellspacing="0" cellpadding="0" bgcolor="#f0f0f0">
    <tr>
      <td align="center" valign="top">
        <table width="600" border="0" cellspacing="0" cellpadding="0">
          <tr>
            <td align="center" valign="top" bgcolor="#44d3d1" style="padding: 40px 0 30px 0;">
              <h2 style="color: #fff;">
                <img src="https://cdn-icons-png.flaticon.com/128/2530/2530973.png" alt="Check"
                  style="vertical-align: middle; margin-right: 10px; width: 40px; height: 40px;">
                Verify Email
              </h2>
            </td>
          </tr>
          <tr>
            <td bgcolor="#ffffff" style="padding: 40px 10px;">
              <table border="0" cellpadding="0" cellspacing="0" width="100%">
                <tr>
                  <td style="color: #153643; font-family: Arial, sans-serif; font-size: 24px;">
                    <b>Verify Your Email Address</b>
                  </td>
                </tr>
                <tr>
                  <td
                    style="padding: 20px 0 30px 0; color: #153643; font-family: Arial, sans-serif; font-size: 16px; line-height: 20px;">
                    Dear ${fullName},<br><br>
                    Thank you for creating an account with Tech Tips Hub. To ensure the security of your
                    account and activate all features, please verify your email address by clicking the button below:
                  </td>
                </tr>
                <tr>
                  <td align="center">
                    <table border="0" cellspacing="0" cellpadding="0">
                      <tr>
                        <td align="center">
                          <a href="${verifyEmailLink}" target="_blank"
                            style="font-size: 16px; font-family: Arial, sans-serif; color: #ffffff; text-decoration: none; padding: 12px 30px; border: 1px solid #44d3d1; display: inline-block; background-color: #44d3d1; border-radius: 3px;">Verify
                            Email Address</a>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                <tr>
                  <td
                    style="padding: 30px 0 0 0; color: #153643; font-family: Arial, sans-serif; font-size: 16px; line-height: 20px;">
                    If the button above doesn't work, please copy and paste the following link into your web browser:
                  </td>
                </tr>
                <tr>
                  <td
                    style="padding: 10px 0 0 0; font-family: Arial, sans-serif; font-size: 16px; line-height: 20px;">
                    <span style="color: #44d3d1; text-decoration: underline;">${verifyEmailLink}</span>
                  </td>
                </tr>
                <tr>
                  <td
                    style="padding: 30px 0 0 0; color: #153643; font-family: Arial, sans-serif; font-size: 16px; line-height: 20px;">
                    This link will expire in 24 hours for security reasons. If you did not create an account with us,
                    please disregard this email.<br><br>
                    If you have any questions or need assistance, please don't hesitate to contact our support team at
                    support@tech-tips-hub.com.<br><br>
                    Best regards,<br>
                    Tech Tips Hub Team
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td bgcolor="#44d3d1" style="padding: 30px 30px 30px 30px;">
              <table border="0" cellpadding="0" cellspacing="0" width="100%">
                <tr>
                  <td style="color: #ffffff; font-family: Arial, sans-serif; font-size: 14px;" width="75%">
                    &copy; Tech Tips Hub 2023<br />

                  </td>
                  <td align="right" width="25%">
                    <table border="0" cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="font-family: Arial, sans-serif; font-size: 12px; font-weight: bold;">
                          <a href="http://www.twitter.com/" style="color: #ffffff;">
                            <img src="https://cdn-icons-png.flaticon.com/128/733/733579.png" alt="Twitter" width="24"
                              height="24" style="display: block;" border="0" />
                          </a>
                        </td>
                        <td style="font-size: 0; line-height: 0;" width="20">&nbsp;</td>
                        <td style="font-family: Arial, sans-serif; font-size: 12px; font-weight: bold;">
                          <a href="http://www.facebook.com/" style="color: #ffffff;">
                            <img src="https://cdn-icons-png.flaticon.com/128/5968/5968764.png" alt="Facebook" width="24"
                              height="24" style="display: block;" border="0" />
                          </a>
                        </td>
                        <td style="font-size: 0; line-height: 0;" width="20">&nbsp;</td>
                        <td style="font-family: Arial, sans-serif; font-size: 12px; font-weight: bold;">
                          <a href="http://www.facebook.com/" style="color: #ffffff;">
                            <img src="https://cdn-icons-png.flaticon.com/128/2111/2111463.png" alt="Facebook" width="24"
                              height="24" style="display: block;" border="0" />
                          </a>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>

</html>`;
};

// delete blog email confirmation

export const deleteBlogEmailConfirmation = (
  blogTitle: string,
  reason: string,
) => {
  return `
  <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>

<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <title>Blog Post Deletion Confirmation</title>
</head>

<body style="margin: 0; padding: 0; background-color: #f6f9fc; font-family: Arial, sans-serif;">
  <table border="0" cellpadding="0" cellspacing="0" width="100%">
    <tr>
      <td style="padding: 20px 0;">
        <table align="center" border="0" cellpadding="0" cellspacing="0" width="600"
          style="border-collapse: collapse; background-color: #ffffff; border: 1px solid #dedede;">
          <tr>
            <td align="center" style="padding: 40px 0 30px 0;">
              <img src="https://i.ibb.co.com/8dwgWQk/tech-tips-hub-logo.png" alt="Tech-Tips-Hub-Logo" width="60"
                style="display: block;" />
            </td>
          </tr>
          <tr>
            <td align="center" style="padding: 20px 0 30px 0;">
              <h1 style="color: #333333; font-size: 24px; margin: 0;">Blog Post Deletion Confirmation</h1>
            </td>
          </tr>
          <tr>
            <td style="padding: 20px 30px 40px 30px;">
              <table border="0" cellpadding="0" cellspacing="0" width="100%">
                <tr>
                  <td
                    style="color: #333333; font-family: Arial, sans-serif; font-size: 16px; line-height: 24px; padding: 20px 0 30px 0;">
                    We regret to inform you that your blog post titled "<span
                      style="font-weight: bold;">${blogTitle}</span>" has been deleted from our platform.
                  </td>
                </tr>
                <tr>
                  <td style="padding: 20px 0; border: 1px solid #dedede; background-color: #f8f8f8;">
                    <table border="0" cellpadding="0" cellspacing="0" width="100%">
                      <tr>
                        <td style="padding: 0 20px;">
                          <h2 style="color: #333333; font-size: 18px; margin: 0 0 10px 0;">Reason for Deletion:</h2>
                          <p style="color: #e53e3e; font-size: 16px; font-weight: bold; margin: 0;">${reason}
                          </p>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                <tr>
                  <td
                    style="color: #333333; font-family: Arial, sans-serif; font-size: 16px; line-height: 24px; padding: 30px 0;">
                    If you believe this action was taken in error or if you have any questions, please don't hesitate to
                    contact our support team.
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding: 30px; border-top: 1px solid #dedede;">
              <table border="0" cellpadding="0" cellspacing="0" width="100%">
                <tr>
                  <td style="color: #8898aa; font-family: Arial, sans-serif; font-size: 14px;">
                    This is an automated message. Please do not reply directly to this email.
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>

</html>
  `;
};

// FORGOT PASSWORD EMAIL

export const generateOTPEmail = ({
  otp,
  name,
}: {
  otp: string;
  name: string;
}) => {
  return `
  <!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta http-equiv="X-UA-Compatible" content="IE=edge" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>One-Time Password (OTP) Verification</title>
      <style>
        body {
          font-family: "Arial", sans-serif;
          margin: 0;
          padding: 0;
          background-color: #f4f4f4;
          color: #333;
        }

        .container {
          max-width: 600px;
          margin: 40px auto;
          padding: 20px;
          background: #ffffff;
          border-radius: 8px;
          box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
          text-align: center;
        }

        .header {
          background: #007bff;
          color: #fff;
          padding: 15px;
          border-radius: 8px 8px 0 0;
          font-size: 20px;
        }

        .content {
          padding: 20px;
          line-height: 1.6;
        }

        .otp-box {
          display: inline-block;
          background-color: #007bff;
          padding: 12px 24px;
          color: #fff;
          font-size: 24px;
          font-weight: bold;
          border-radius: 6px;
          letter-spacing: 2px;
          margin-top: 10px;
        }

        .footer {
          margin-top: 20px;
          font-size: 14px;
          color: #666;
        }

        .logo {
          max-width: 120px;
          margin: 20px auto;
          display: block;
        }

        .note {
          font-size: 14px;
          color: #777;
          margin-top: 15px;
        }
      </style>
    </head>

    <body>
      <div class="container">
        <img src="https://via.placeholder.com/120" alt="Company Logo" class="logo" />
        <div class="header">
          <h2>One-Time Password (OTP)</h2>
        </div>
        <div class="content">
          <p>Hello <strong>${name}</strong>,</p>
          <p>
            Use the OTP code below to complete your request. 
            This code is valid for the next <strong>5 minutes</strong>:
          </p>
          <div class="otp-box">${otp}</div>
          <p>If you didn’t request this, you can safely ignore this email.</p>
        </div>
        <div class="footer">
          <p>Thank you for using our service!</p>
          <p class="note">Need help? Contact our support team.</p>
        </div>
      </div>
    </body>
  </html>
`;
};
