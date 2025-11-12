using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using ApiLogin.Models;
using ApiLogin.DataAccess.Services;

namespace ApiLogin.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly LoginService _loginService;

        public LoginController(LoginService loginService)
        {
            _loginService = loginService;
        }

        [HttpPost("registro-usuario")]
        public async Task<IActionResult> RegistroUsuario([FromBody] UsuarioDTO usuarioDTO)
        {
            if (!ModelState.IsValid)
                return BadRequest(new { mensaje = "Datos del usuario inválidos." });

            try
            {
                var (Resultado, Mensaje) = await _loginService.RegistroUsuario(usuarioDTO);

                if (Resultado)
                    return Ok(new { mensaje = Mensaje });
                else
                    return BadRequest(new { mensaje = Mensaje });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { mensaje = "Ocurrió un error inesperado: " + ex.Message });
            }
        }

        [HttpPost("registro-usuario-rol")]
        public async Task<IActionResult> RegistroUsuarioConRol([FromBody] Usuario usuario)
        {
            if (!ModelState.IsValid)
                return BadRequest(new { mensaje = "Datos del usuario inválidos." });

            try
            {
                var (Resultado, Mensaje) = await _loginService.RegistroUsuarioConRol(usuario);

                if (Resultado)
                    return Ok(new { mensaje = Mensaje });
                else
                    return BadRequest(new { mensaje = Mensaje });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { mensaje = "Ocurrió un error inesperado: " + ex.Message });
            }
        }

        [HttpPost("inicio-sesion")]
        public async Task<IActionResult> InicioSesion([FromBody] InicioSesion inicioSesion)
        {
            if (!ModelState.IsValid)
                return BadRequest(new { mensaje = "Credenciales inválidas para iniciar sesión." });

            try
            {
                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
                var (Resultado, Mensaje) = await _loginService.InicioSesion(inicioSesion, ipAddress);

                if (Resultado)
                    return Ok(new { mensaje = Mensaje});
                else
                    return BadRequest(new { mensaje = Mensaje });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { mensaje = "Ocurrió un error inesperado: " + ex.Message });
            }
        }

        [HttpPost("cerrar-sesion")]
        public async Task<IActionResult> CerrarSesion([FromBody] CerrarSesion cerrarSesion)
        {
            if (string.IsNullOrWhiteSpace(cerrarSesion.token))
                return BadRequest(new { mensaje = "El token es requerido." });
                
            try
            {
                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
                var (Resultado, Mensaje) = await _loginService.CerrarSesion(cerrarSesion, ipAddress);

                if (Resultado)
                    return Ok(new { mensaje = Mensaje });
                else
                    return BadRequest(new { mensaje = Mensaje });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { mensaje = "Ocurrió un error inesperado: " + ex.Message });
            }
        }

        [HttpGet("intentos-login")]
        public async Task<IActionResult> ObtenerIntentosLogin()
        {
            try
            {
                var resultado = await _loginService.ObtenerIntentosLogin();

                return Ok(resultado);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { mensaje = "Ocurrió un error inesperado: " + ex.Message });
            }
        }

        [HttpGet("obtener-usuarios")]
        public async Task<IActionResult> ObtenerUsuarios([FromQuery] bool? estado = null)
        {
            try
            {
                var resultado = await _loginService.ObtenerUsuarios(estado);

                return Ok(resultado);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { mensaje = "Ocurrió un error inesperado: " + ex.Message });
            }
        }

        [HttpPut("actualiza-usuario/{usuarioId}")]
        public async Task<IActionResult> ActualizarUsuarioConRol(int usuarioId, [FromBody] ActualizarUsuario actualizarUsuario)
        {
            try
            {
                var (Resultado, Mensaje) = await _loginService.ActualizarUsuarioConRol(usuarioId, actualizarUsuario);

                if (Resultado)
                    return Ok(new { mensaje = Mensaje });
                else
                    return BadRequest(new { mensaje = Mensaje });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { mensaje = "Ocurrió un error inesperado: " + ex.Message });
            }
        }

        [HttpPut("cambiar-contrasena/{usuarioId}")]
        public async Task<IActionResult> CambiarContrasena(int usuarioId, [FromBody] CambiarContrasena cambiarContrasena)
        {
            try
            {
                var (Resultado, Mensaje) = await _loginService.CambiarContrasena(usuarioId, cambiarContrasena);

                if (Resultado)
                    return Ok(new { mensaje = Mensaje });
                else
                    return BadRequest(new { mensaje = Mensaje });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { mensaje = "Ocurrió un error inesperado: " + ex.Message });
            }
        }

        [HttpPost("olvide-contrasena")]
        public async Task<IActionResult> OlvideContrasena([FromBody] OlvideContrasena olvideContrasena)
        {
            try
            {
                string ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
                var (Resultado, Mensaje) = await _loginService.OlvideContrasena(olvideContrasena, ipAddress);

                if (Resultado)
                    return Ok(new { mensaje = Mensaje });
                else
                    return BadRequest(new { mensaje = Mensaje });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { mensaje = "Ocurrió un error inesperado: " + ex.Message });
            }
        }

        [HttpPut("restablecer-contrasena")]
        public async Task<IActionResult> RestablecerContrasena([FromBody] RestablecerContrasena restablecerContrasena)
        {
            try
            {
                var (Resultado, Mensaje) = await _loginService.RestablecerContrasena(restablecerContrasena);

                if (Resultado)
                    return Ok(new { mensaje = Mensaje });
                else
                    return BadRequest(new { mensaje = Mensaje });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { mensaje = "Ocurrió un error inesperado: " + ex.Message });
            }
        }
    }
}
