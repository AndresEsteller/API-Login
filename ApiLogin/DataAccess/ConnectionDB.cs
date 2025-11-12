using System;
using Microsoft.Data.SqlClient;


namespace ApiLogin.DataAccess
{
    public class ConnectionDB
    {
        private readonly string _connectionString;

        public ConnectionDB(string connectionString)
        {
            _connectionString = connectionString;
        }

        public SqlConnection GetConnection()
        {
            try
            {
                var connection = new SqlConnection(_connectionString);
                connection.Open();
                return connection;
            }
            catch (Exception ex)
            {
                throw new Exception("Error al conectar la base de datos: " + ex.Message);
            }
        }
    }
}
