namespace ApiLogin.Models
{
    public class AuditoriaLogin
    {
        public int auditoriaId { get; set; }
        public int usuarioId { get; set; }
        public string username { get; set; }
        public string correo { get; set; }
        public string correoIntento { get; set; }
        public bool estado { get; set; }
        public string estadoDescripcion { get; set; }
        public DateTime fechaIntento { get; set; }
        public string ipAddress { get; set; }

        public AuditoriaLogin()
        {
            this.auditoriaId = 0;
            this.usuarioId = 0;
            this.username = "";
            this.correo = "";
            this.correoIntento = "";
            this.estado = false;
            this.estadoDescripcion = "";
            this.fechaIntento = DateTime.Now;
            this.ipAddress = "";
        }
    }
}