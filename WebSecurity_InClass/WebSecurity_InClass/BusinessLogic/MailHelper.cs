using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Web;
using WebSecurity_InClass.Models.ViewModels;

namespace WebSecurity_InClass.BusinessLogic
{
    public class MailHelper
    {
        public const string SUCCESS
= "Instructions have been sent to your email, please check your junk mail.";
        public string EmailFromArvixe(RegisteredUser message, string confirmEmail)
        {
            // Use credentials of the Mail account that you created with the steps above.
            const string FROM = "MarioSSD@develo-bomb.com";
            const string FROM_PWD = "Websitesdragons93";
            const bool USE_HTML = true;

            // Get the mail server obtained in the steps described above.
            const string SMTP_SERVER = "143.95.249.35";
            try
            {
                MailMessage mailMsg = new MailMessage(FROM, message.Email);
                mailMsg.Subject = "Confirmation Email!";
                mailMsg.Body =  confirmEmail+"<br/>sent by:" + message.UserName;
                mailMsg.IsBodyHtml = USE_HTML;

                SmtpClient smtp = new SmtpClient();
                smtp.Port = 587;
                smtp.Host = SMTP_SERVER;
                smtp.Credentials = new System.Net.NetworkCredential(FROM, FROM_PWD);
                smtp.Send(mailMsg);
            }
            catch (System.Exception ex)
            {
                return ex.Message;
            }
            return SUCCESS;
        }

    }
}