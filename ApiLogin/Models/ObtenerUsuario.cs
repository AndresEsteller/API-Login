namespace ApiLogin.Models
{
    public class ObtenerUsuario
    {
        public int usuarioId { get; set; }
        public string username { get; set; }
        public string correo { get; set; }
        public string rol { get; set; }
        public string estado { get; set; }
        public DateTime fechaRegistro { get; set; }

        public ObtenerUsuario()
        {
            this.usuarioId = 0;
            this.username = "";
            this.correo = "";
            this.rol = "";
            this.estado = "";
            this.fechaRegistro = DateTime.Now;
        }
    }
}