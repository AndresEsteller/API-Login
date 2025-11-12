using System;
using System.Collections.Generic;

namespace ApiLogin.Models
{
    public class Usuario
    {
        public required string username { get; set; }
        public required string correo { get; set; }
        public required string contrasena { get; set; }
        public string rol { get; set; }

        public Usuario()
        {
            this.username = "";
            this.correo = "";
            this.contrasena = "";
            this.rol = "";
        }
    }
}