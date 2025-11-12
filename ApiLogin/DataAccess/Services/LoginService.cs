using System.Data;
using Microsoft.Data.SqlClient;
using ApiLogin.Models;
using System.Security.Cryptography;
using System.Text;
using System.Net.Mail;
using System.Net;
using ApiLogin.DataAccess.Utilities;

namespace ApiLogin.DataAccess.Services
{
    public class LoginService
    {
        private readonly ConnectionDB _db;
        private readonly EmailBuilder _emailBuilder;

        public LoginService(ConnectionDB db, EmailBuilder emailBuilder)
        {
            _db = db;
            _emailBuilder = emailBuilder;
        }

        public async Task<(bool Resultado, string Mensaje)> RegistroUsuario(UsuarioDTO usuarioDTO)
        {
            try
            {
                using SqlConnection connection = _db.GetConnection();
                using SqlCommand cmd = new SqlCommand("SP_RegistroUsuario", connection)
                {
                    CommandType = CommandType.StoredProcedure
                };

                cmd.Parameters.AddWithValue("@pUsername", usuarioDTO.username);
                cmd.Parameters.AddWithValue("@pCorreo", usuarioDTO.correo);
                cmd.Parameters.AddWithValue("@pContrasena", usuarioDTO.contrasena);

                await cmd.ExecuteNonQueryAsync();
                return (true, "Usuario registrado correctamente.");
            }
            catch (SqlException ex)
            {
                return (false, $"Error en la base de datos: {ex.Message}");
            }
            catch (Exception ex)
            {
                return (false, $"Error no se pudo registrar al usuario: {ex.Message}");
            }
        }

        public async Task<(bool Resultado, string Mensaje)> RegistroUsuarioConRol(Usuario usuario)
        {
            try
            {
                using SqlConnection connection = _db.GetConnection();
                using SqlCommand cmd = new SqlCommand("SP_RegistroUsuarioConRol", connection)
                {
                    CommandType = CommandType.StoredProcedure
                };

                cmd.Parameters.AddWithValue("@pUsername", usuario.username);
                cmd.Parameters.AddWithValue("@pCorreo", usuario.correo);
                cmd.Parameters.AddWithValue("@pContrasena", usuario.contrasena);
                cmd.Parameters.AddWithValue("@pRol", usuario.rol);

                await cmd.ExecuteNonQueryAsync();
                return (true, "Usuario con rol registrado correctamente.");
            }
            catch (SqlException ex)
            {
                return (false, $"Error en la base de datos: {ex.Message}");
            }
            catch (Exception ex)
            {
                return (false, $"Error no se pudo registrar al usuario con rol: {ex.Message}");
            }
        }

        public async Task<(bool Resultado, string Mensaje)> InicioSesion(InicioSesion inicioSesion, string ipAddress)
        {
            try
            {
                using SqlConnection connection = _db.GetConnection();
                using SqlCommand cmd = new SqlCommand("SP_InicioSesion", connection)
                {
                    CommandType = CommandType.StoredProcedure
                };

                cmd.Parameters.AddWithValue("@pUsernameCorreo", inicioSesion.usernameCorreo);
                cmd.Parameters.AddWithValue("@pContrasena", inicioSesion.contrasena);
                cmd.Parameters.AddWithValue("@pIpAddress", (object?)ipAddress ?? DBNull.Value);

                await cmd.ExecuteNonQueryAsync();
                return (true, "Inicio de sesión exitoso.");
            }
            catch (SqlException ex)
            {
                return (false, $"Error en la base de datos: {ex.Message}");
            }
            catch (Exception ex)
            {
                return (false, $"Error al iniciar sesión: {ex.Message}");
            }
        }

        public async Task<(bool Resultado, string Mensaje)> CerrarSesion(CerrarSesion cerrarSesion, string ipAddress)
        {
            try
            {
                using SqlConnection connection = _db.GetConnection();
                using SqlCommand cmd = new SqlCommand("SP_CerrarSesion", connection)
                {
                    CommandType = CommandType.StoredProcedure
                };

                cmd.Parameters.AddWithValue("@pToken", cerrarSesion.token);
                cmd.Parameters.AddWithValue("@pIpAddress", (object)ipAddress ?? DBNull.Value);

                await cmd.ExecuteNonQueryAsync();
                return (true, "Sesión cerrada correctamente.");
            }
            catch (SqlException ex)
            {
                return (false, $"Error en la base de datos: {ex.Message}");
            }
            catch (Exception ex)
            {
                return (false, $"Error al cerrar sesión: {ex.Message}");
            }
        }

        public async Task<List<AuditoriaLogin>> ObtenerIntentosLogin()
        {
            try
            {
                var listIntentos = new List<AuditoriaLogin>();

                using (SqlConnection connection = _db.GetConnection())
                {
                    using (SqlCommand cmd = new SqlCommand("SP_ObtenerIntentosLogin", connection))
                    {
                        cmd.CommandType = CommandType.StoredProcedure;

                        using (var reader = await cmd.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                listIntentos.Add(new AuditoriaLogin
                                {
                                    auditoriaId = Convert.ToInt32(reader["AuditoriaId"]),
                                    username = reader["UsuarioId"].ToString() ?? string.Empty,
                                    correo = reader["Correo"].ToString() ?? string.Empty,
                                    correoIntento = reader["CorreoIntento"].ToString() ?? string.Empty,
                                    estado = Convert.ToBoolean(reader["Estado"]),
                                    estadoDescripcion = reader["EstadoDescripcion"].ToString() ?? string.Empty,
                                    fechaIntento = Convert.ToDateTime(reader["FechaIntento"]),
                                    ipAddress = reader["IpAddress"].ToString() ?? string.Empty
                                });
                            }
                        }
                    }
                    return listIntentos;
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Error al obtener los datos: {ex.Message}");
            }
        }

        public async Task<List<ObtenerUsuario>> ObtenerUsuarios(bool? estado = null)
        {
            try
            {
                var usuarios = new List<ObtenerUsuario>();

                using (SqlConnection connection = _db.GetConnection())
                {
                    using (SqlCommand cmd = new SqlCommand("SP_ObtenerUsuarios", connection))
                    {
                        cmd.CommandType = CommandType.StoredProcedure;
                        cmd.Parameters.AddWithValue("@pEstado", (object?)estado ?? DBNull.Value);

                        using (var reader = await cmd.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                usuarios.Add(new ObtenerUsuario
                                {
                                    usuarioId = Convert.ToInt32(reader["UsuarioId"]),
                                    username = reader["Username"].ToString() ?? string.Empty,
                                    correo = reader["Correo"].ToString() ?? string.Empty,
                                    rol = reader["Rol"].ToString() ?? string.Empty,
                                    estado = reader["Estado"].ToString() ?? string.Empty,
                                    fechaRegistro = Convert.ToDateTime(reader["FechaRegistro"])
                                });
                            }
                        }
                    }
                    return usuarios;
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Error al obtener los datos: {ex.Message}");
            }
        }

        public async Task<(bool Resultado, string Mensaje)> ActualizarUsuarioConRol(int usuarioId, ActualizarUsuario actualizarUsuario)
        {
            try
            {
                using SqlConnection connection = _db.GetConnection();
                using SqlCommand cmd = new SqlCommand("SP_ActualizarUsuarioConRol", connection)
                {
                    CommandType = CommandType.StoredProcedure
                };

                cmd.Parameters.AddWithValue("@pUsuarioId", usuarioId);
                cmd.Parameters.AddWithValue("@pEstado", (object?)actualizarUsuario.estado ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@pRol", string.IsNullOrEmpty(actualizarUsuario.rol) ? DBNull.Value : actualizarUsuario.rol);

                await cmd.ExecuteNonQueryAsync();
                return (true, "Usuario actualizado correctamente.");
            }
            catch (SqlException ex)
            {
                return (false, $"Error en la base de datos: {ex.Message}");
            }
            catch (Exception ex)
            {
                return (false, $"Error al actualizar el usuario con rol: {ex.Message}");
            }
        }

        public async Task<(bool Resultado, string Mensaje)> CambiarContrasena(int usuarioId, CambiarContrasena cambiarContrasena)
        {
            try
            {
                using SqlConnection connection = _db.GetConnection();
                using SqlCommand cmd = new SqlCommand("SP_CambiarContrasena", connection)
                {
                    CommandType = CommandType.StoredProcedure
                };

                cmd.Parameters.AddWithValue("@pUsuarioId", usuarioId);
                cmd.Parameters.AddWithValue("@pContrasenaActual", cambiarContrasena.contrasenaActual);
                cmd.Parameters.AddWithValue("@pContrasenaNueva", cambiarContrasena.contrasenaNueva);
                cmd.Parameters.AddWithValue("@pConfirmarContrasena", cambiarContrasena.confirmarContrasena);

                await cmd.ExecuteNonQueryAsync();
                return (true, "La contraseña se actualizó correctamente.");
            }
            catch (SqlException ex)
            {
                return (false, $"Error en la base de datos: {ex.Message}");
            }
            catch (Exception ex)
            {
                return (false, $"Error al cambiar la contraseña: {ex.Message}");
            }
        }

        public async Task<(bool Resultado, string Mensaje)> OlvideContrasena(OlvideContrasena olvideContrasena, string ipAddress)
        {
            try
            {
                using SqlConnection connection = _db.GetConnection();
                using SqlCommand cmd = new SqlCommand("SP_OlvideContrasena", connection)
                {
                    CommandType = CommandType.StoredProcedure
                };

                cmd.Parameters.AddWithValue("@pCorreo", olvideContrasena.correo);
                cmd.Parameters.AddWithValue("@pIpAddress", ipAddress);

                using SqlDataReader reader = await cmd.ExecuteReaderAsync();
                if (await reader.ReadAsync())
                {
                    string token = reader["Token"].ToString() ?? string.Empty;
                    string mensaje = reader["Mensaje"].ToString() ?? string.Empty;
                    string enlace = $"https://sitio.com/restablecer-contrasena?token={token}";

                    await _emailBuilder.EnviaCorreoRecuperacion(olvideContrasena.correo, enlace);

                    return (true, mensaje);
                }

                return (false, "No se encontró el correo o el usuario está inactivo.");
            }
            catch (SqlException ex)
            {
                return (false, $"Error en la base de datos: {ex.Message}");
            }
            catch (Exception ex)
            {
                return (false, $"Error al enviar el correo de recuperación: {ex.Message}");
            }
        }

        public async Task<(bool Resultado, string Mensaje)> RestablecerContrasena(RestablecerContrasena restablecerContrasena)
        {
            try
            {
                using SqlConnection connection = _db.GetConnection();
                using SqlCommand cmd = new SqlCommand("SP_RestablecerContrasena", connection)
                {
                    CommandType = CommandType.StoredProcedure
                };

                cmd.Parameters.AddWithValue("@pToken", restablecerContrasena.token);
                cmd.Parameters.AddWithValue("@pContrasenaNueva", restablecerContrasena.contrasenaNueva);
                cmd.Parameters.AddWithValue("@pConfirmarContrasena", restablecerContrasena.confirmarContrasena);

                await cmd.ExecuteNonQueryAsync();
                return (true, "La contraseña ha sido restablecida correctamente.");
            }
            catch (SqlException ex)
            {
                return (false, $"Error en la base de datos: {ex.Message}");
            }
            catch (Exception ex)
            {
                return (false, $"Error al restablecer la contraseña: {ex.Message}");
            }
        }
    }
}
