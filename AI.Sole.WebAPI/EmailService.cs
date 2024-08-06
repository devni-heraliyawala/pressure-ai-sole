
using Microsoft.AspNetCore.Identity;
using SendGrid;
using SendGrid.Helpers.Mail;
using System.Net.Mail;

namespace AI.Sole.WebAPI
{
    public class EmailService : IEmailService
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public EmailService(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }
        public async Task SendPasswordResetEmailAsync(string email, string resetLink)
        {
            string subject = "Reset Password";
            string body = $"<p>Please reset your password by clicking <a href=\"{resetLink}\">here</a>.</p>";

            var apiKey = Globals.SMTP_API_KEY;
            var client = new SendGridClient(apiKey);
            var from = new EmailAddress(Globals.SMTP_SENDER_EMAIL, Globals.SMTP_SENDER_DISPLAY_NAME);
            var to = new EmailAddress(email);
            var msg = MailHelper.CreateSingleEmail(from, to, subject, "", body);

            var response = await client.SendEmailAsync(msg);
            if (response.StatusCode != System.Net.HttpStatusCode.Accepted)
            {
                var responseBody = await response.Body.ReadAsStringAsync();
                throw new Exception($"Failed to send email. Status code: {response.StatusCode}, Response: {responseBody}");
            }
        }

        //public async Task Send2FACodeAsync(IdentityUser user)
        //{
        //    var token = await _userManager.GenerateTwoFactorTokenAsync((ApplicationUser)user, "Email");
        //    var email = await _userManager.GetEmailAsync((ApplicationUser)user);

        //    var subject = "Your 2FA Code";
        //    var htmlContent = $"<p>Your 2FA code is: <strong>{token}</strong></p>";

        //    var apiKey = Globals.SMTP_API_KEY;
        //    var client = new SendGridClient(apiKey);
        //    var from = new EmailAddress(Globals.SMTP_SENDER_EMAIL, Globals.SMTP_SENDER_DISPLAY_NAME);
        //    var to = new EmailAddress(email);
        //    var msg = MailHelper.CreateSingleEmail(from, to, subject, "", htmlContent);

        //    var response = await client.SendEmailAsync(msg);
        //    if (response.StatusCode != System.Net.HttpStatusCode.Accepted)
        //    {
        //        var responseBody = await response.Body.ReadAsStringAsync();
        //        throw new Exception($"Failed to send email. Status code: {response.StatusCode}, Response: {responseBody}");
        //    }
        //}

        public async Task SendAccountUnlockEmailAsync(string? email, string callbackUrl)
        {
            var subject = "Unlock your account";
            var htmlContent = $"<p>Please unlock your account by clicking <a href=\"{callbackUrl}\">here</a>.</p>";

            var apiKey = Globals.SMTP_API_KEY;
            var client = new SendGridClient(apiKey);
            var from = new EmailAddress(Globals.SMTP_SENDER_EMAIL, Globals.SMTP_SENDER_DISPLAY_NAME);
            var to = new EmailAddress(email);
            var msg = MailHelper.CreateSingleEmail(from, to, subject, "", htmlContent);

            var response = await client.SendEmailAsync(msg);
            if (response.StatusCode != System.Net.HttpStatusCode.Accepted)
            {
                var responseBody = await response.Body.ReadAsStringAsync();
                throw new Exception($"Failed to send email. Status code: {response.StatusCode}, Response: {responseBody}");
            }
        }

        public async Task SendAppointmentCancellationEmailAsync(string email, DateTime appointmentDate, string reason)
        {
            var message = $"The appointment scheduled on {appointmentDate} has been canceled.\n\nReason: {reason ?? "Not provided"}";
            var subject = "Appointment Cancelled";

            var apiKey = Globals.SMTP_API_KEY;
            var client = new SendGridClient(apiKey);
            var from = new EmailAddress(Globals.SMTP_SENDER_EMAIL, Globals.SMTP_SENDER_DISPLAY_NAME);
            var to = new EmailAddress(email);
            var msg = MailHelper.CreateSingleEmail(from, to, subject, message, string.Empty);

            var response = await client.SendEmailAsync(msg);
            if (response.StatusCode != System.Net.HttpStatusCode.Accepted)
            {
                var responseBody = await response.Body.ReadAsStringAsync();
                throw new Exception($"Failed to send email. Status code: {response.StatusCode}, Response: {responseBody}");
            }
        }
    }
}
