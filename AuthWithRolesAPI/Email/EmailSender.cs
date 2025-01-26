using Microsoft.AspNetCore.Authorization;
using System.Net;
using System.Net.Mail;
namespace Email
{
   
    public class EmailSender 
    {
        
        public Task SendEmailAsync(string email, string subject, string message)
        {
            var mail = "leenomar420@gmail.com";
            var pw = "slsz yrno mznv kifu";
            var client = new SmtpClient("smtp.gmail.com", 587) {
                EnableSsl = true,
                Credentials=new NetworkCredential(mail,pw)
            
            
            };
            return client.SendMailAsync(new MailMessage(from:mail,to:email,subject,message));
        }
    }
}
