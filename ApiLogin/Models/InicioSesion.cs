namespace ApiLogin.Models
{
    public class InicioSesion
    {
        public string usernameCorreo { get; set; }
        public string contrasena { get; set; }
        public string ipAddress { get; set; }

        public InicioSesion()
        {
            this.usernameCorreo = "";
            this.contrasena = "";
            this.ipAddress = "";
        }
    }
}