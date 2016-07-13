using System;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Net.Mail;
using System.Net.Mime;
using System.Xml.Serialization;

namespace ThreatCrawler
{
    internal class MailOps
    {
        public static void SendEmailWithAttachment(string vulnReport, string exploitReport)
        {
            var senderEmail = ConfigurationManager.AppSettings["Sender Address"];
            var recipients = ConfigurationManager.AppSettings["Mail Recipients"].Split(',');
            var smtpServer = ConfigurationManager.AppSettings["SMTP Server"];
            var smtpPort = ConfigurationManager.AppSettings["SMTP Port"];

            using (var ms = new MemoryStream())
            {
                using (var writer = new StreamWriter(ms))
                {
                    writer.Write(exploitReport);

                    var contentType = new ContentType(MediaTypeNames.Application.Octet);
                    var attachment = new Attachment(ms, contentType);
                    attachment.ContentDisposition.FileName = string.Format("exploit_report_{0}.html", StringOps.FriendlyTimestamp());

                    writer.Flush();
                    ms.Position = 0;

                    using (var mail = new MailMessage())
                    {
                        mail.From = new MailAddress(senderEmail);

                        foreach (var recipient in recipients)
                        {
                            mail.To.Add(recipient);
                        }

                        using (var client = new SmtpClient
                        {
                            Port = Convert.ToInt32(smtpPort),
                            DeliveryMethod = SmtpDeliveryMethod.Network,
                            UseDefaultCredentials = false,
                            Host = smtpServer
                        })
                        {
                            mail.Subject = "ThreatCrawler Report";
                            mail.Body = vulnReport;
                            mail.IsBodyHtml = true;
                            mail.Attachments.Add(attachment);

                            try
                            {
                                client.Send(mail);
                            }
                            catch (Exception ex)
                            {
                                Debug.WriteLine(ex.ToString());
                            }
                        }
                    }

                    attachment.Dispose();
                }
            }
        }

        public static void SendEmail(string vulnReport)
        {
            var senderEmail = ConfigurationManager.AppSettings["Sender Address"];
            var recipients = ConfigurationManager.AppSettings["Mail Recipients"].Split(',');
            var smtpServer = ConfigurationManager.AppSettings["SMTP Server"];
            var smtpPort = ConfigurationManager.AppSettings["SMTP Port"];

            using (var mail = new MailMessage())
            {
                mail.From = new MailAddress(senderEmail);

                foreach (var recipient in recipients)
                {
                    mail.To.Add(recipient);
                }

                using (var client = new SmtpClient
                {
                    Port = Convert.ToInt32(smtpPort),
                    DeliveryMethod = SmtpDeliveryMethod.Network,
                    UseDefaultCredentials = false,
                    Host = smtpServer
                })
                {
                    mail.Subject = "ThreatCrawler Report";
                    mail.Body = vulnReport;
                    mail.IsBodyHtml = true;

                    try
                    {
                        client.Send(mail);
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine(ex.ToString());
                    }
                }
            }
        }
    }
}