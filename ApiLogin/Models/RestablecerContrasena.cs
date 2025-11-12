namespace ApiLogin.Models {
    public class RestablecerContrasena
    {
        public string token { get; set; }
        public string contrasenaNueva { get; set; }
        public string confirmarContrasena { get; set; }

        public RestablecerContrasena()
        {
            this.token = "";
            this.contrasenaNueva = "";
            this.confirmarContrasena = "";
        }
    }
}