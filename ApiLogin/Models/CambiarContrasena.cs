namespace ApiLogin.Models
{
    public class CambiarContrasena
    {
        public string contrasenaActual { get; set; }
        public string contrasenaNueva { get; set; }
        public string confirmarContrasena { get; set; }

        public CambiarContrasena()
        {
            this.contrasenaActual = "";
            this.contrasenaNueva = "";
            this.confirmarContrasena = "";
        }
    }
}