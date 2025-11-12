using System;
using System.Collections.Generic;

namespace ApiLogin.Models
{
    public class UsuarioDTO
    {
        public required string username { get; set; }
        public required string correo { get; set; }
        public required string contrasena { get; set; }

        public UsuarioDTO()
        {
            this.username = "";
            this.correo = "";
            this.contrasena = "";
        }
    }
}