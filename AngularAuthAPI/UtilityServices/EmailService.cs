using AngularAuthAPI.Models;
using MailKit.Net.Smtp;
using MimeKit;

namespace AngularAuthAPI.UtilityServices
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        public EmailService(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        public void SendEmail(EmailModel emailModel)
        {
            var mailMessage=new MimeMessage();
            var from = _configuration["EmailSettings:From"];
            mailMessage.From.Add(new MailboxAddress("Sreeni", from));
            mailMessage.To.Add(new MailboxAddress(emailModel.To, emailModel.To));
            mailMessage.Subject=emailModel.Subject;
            mailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Html)
            {
                Text = string.Format(emailModel.Content)
            };

            using (var smtp = new SmtpClient())
            {
                try
                {
                    int port = Convert.ToInt32(_configuration["EmailSettings:Port"]);
                    smtp.Connect(_configuration["EmailSettings:SmtpServer"], port, true);
                    smtp.Authenticate(from, _configuration["EmailSettings:Password"]);
                    smtp.Send(mailMessage);
                }
                catch (Exception ex)
                {
                    throw;
                }
                finally
                {
                    smtp.Disconnect(true);
                    smtp.Dispose();
                }
            }
        }
    }
}
