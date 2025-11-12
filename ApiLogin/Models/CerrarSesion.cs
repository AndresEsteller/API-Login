using System.Collections.Generic;

namespace ApiLogin.Models
{
    public class CerrarSesion
    {
        public string token { get; set; }

        public CerrarSesion()
        {
            this.token = "";
        }
    }
}