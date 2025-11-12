using System.Net;
using System.Net.Mail;

namespace ApiLogin.DataAccess.Utilities
{
    public class EmailBuilder
    {
        private readonly IConfiguration _configuration;

        public EmailBuilder(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task EnviaCorreoRecuperacion(string correoDestino, string enlace)
        {
            try
            {
                string asunto = "Recuperación de contraseña";
                string cuerpo = $@"
                    <div style='font-family: Arial, sans-serif; color: #333;'>
                        <h2 style='color: #0056b3;'>Recuperación de contraseña</h2>
                        <p>Recibimos una solicitud para restablecer la contraseña de tu cuenta.</p>
                        <p>Si fuiste tú quien realizó esta solicitud, haz clic en el siguiente botón para crear una nueva contraseña:</p>
                        <p style='text-align: center;'>
                        <a href='{enlace}' target='_blank' 
                            style='display: inline-block; background-color: #0056b3; color: #fff; 
                            padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;'>
                            Restablecer contraseña
                        </a>
                        </p>
                        <p>Este enlace estará disponible por <strong>30 minutos</strong>. 
                        Si no solicitaste el cambio, puedes ignorar este correo; tu contraseña actual seguirá siendo la misma.</p>
                        <p style='margin-top: 20px; font-size: 13px; color: #777;'>Por seguridad, no compartas este enlace con nadie.</p>
                        <hr />
                        <p style='font-size: 12px; color: #aaa;'>Nombre de la empresa o enlace del sitio web.</p>
                    </div>";

                var smtpHost = _configuration.GetValue<string>("EmailSettings:SmtpHost") ?? string.Empty;
                var smtpPort = _configuration.GetValue<int>("EmailSettings:SmtpPort");
                var smtpUser = _configuration.GetValue<string>("EmailSettings:SmtpUser") ?? string.Empty;
                var smtpPass = _configuration.GetValue<string>("EmailSettings:SmtpPass") ?? string.Empty;

                using (MailMessage mail = new MailMessage())
                {
                    mail.From = new MailAddress(smtpUser);
                    mail.To.Add(correoDestino);
                    mail.Subject = asunto;
                    mail.Body = cuerpo;
                    mail.IsBodyHtml = true;

                    using (SmtpClient smtp = new SmtpClient(smtpHost, smtpPort))
                    {
                        smtp.Credentials = new NetworkCredential(smtpUser, smtpPass);
                        smtp.EnableSsl = true;
                        await smtp.SendMailAsync(mail);
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Error al enviar el correo de recuperació de contraseña: {ex.Message}");
            }
        }
    }
}