CREATE DATABASE DBLogin;

GO

USE DBLogin;

GO

CREATE TABLE Rol (
    RolId INT IDENTITY(1,1) PRIMARY KEY,
    NombreRol NVARCHAR(50) NOT NULL UNIQUE,
    Descripcion NVARCHAR(200) NULL
)

GO

CREATE TABLE Usuario (
    UsuarioId INT IDENTITY(1,1) PRIMARY KEY,
    Username NVARCHAR(50) NOT NULL UNIQUE,
    Correo NVARCHAR(100) NOT NULL UNIQUE,
    Contrasena NVARCHAR(200) NOT NULL,
    Salt NVARCHAR(200) NOT NULL,
    FechaRegistro DATETIME DEFAULT GETDATE(),
    Estado BIT DEFAULT 1
)

GO

CREATE TABLE UsuarioRol(
    UsuarioRolId INT IDENTITY(1,1) PRIMARY KEY,
    UsuarioId INT NOT NULL,
    RolId INT NOT NULL,
    FechaAsignacion DATETIME DEFAULT GETDATE(),
    
    CONSTRAINT FK_UsuarioRol_Usuario FOREIGN KEY(UsuarioId) REFERENCES Usuario(UsuarioId),
    CONSTRAINT FK_UsuarioRol_Rol FOREIGN KEY(RolId) REFERENCES Rol(RolId),
    CONSTRAINT UQ_UsuarioRol UNIQUE (UsuarioId, RolId)
)

GO

CREATE TABLE Sesion ( 
    SesionId UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    UsuarioId INT NOT NULL,
    Token NVARCHAR(500) NOT NULL,
    FechaInicio DATETIME DEFAULT GETDATE(),
    FechaExpiracion DATETIME NOT NULL, 
    Estado BIT DEFAULT 1, 
    
    CONSTRAINT FK_Sesion_Usuario FOREIGN KEY(UsuarioId) REFERENCES Usuario(UsuarioId)
)

GO

CREATE TABLE AuditoriaLogin (
    AuditoriaId INT IDENTITY(1,1) PRIMARY KEY,
    UsuarioId INT NULL, -- Puede ser null si el usuario no existe
    CorreoIntento NVARCHAR(100) NULL,
    Estado BIT NOT NULL,
    FechaIntento DATETIME DEFAULT GETDATE(),
    IpAddress NVARCHAR(45) NULL, -- Soporta IPv4 / IPv6
    
    CONSTRAINT FK_AuditoriaLogin_Usuario FOREIGN KEY(UsuarioId) REFERENCES Usuario(UsuarioId)
)

GO

CREATE TABLE RecuperacionContrasena (
	RecuperacionId UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
	UsuarioId INT NOT NULL,
	Token NVARCHAR(500) NOT NULL,
	FechaSolicitud DATETIME DEFAULT GETDATE(),
	FechaExpiracion DATETIME NOT NULL,
	Estado BIT DEFAULT 0,
	IpAddress NVARCHAR(45) NULL,
	
	CONSTRAINT FK_RecuperacionContrasena_Usuario FOREIGN KEY(UsuarioId) REFERENCES Usuario(UsuarioId)
)

GO

-- Insertar roles por defecto
INSERT INTO Rol (NombreRol, Descripcion)
VALUES 
('Admin', 'Acceso completo al sistema'),
('Usuario', 'Acceso básico para uso normal del sistema');

GO


-- Procedimientos almacenados


-- Procedimiento almacenado - Registro de usuarios normales

CREATE PROCEDURE SP_RegistroUsuario
    @pUsername NVARCHAR(50),
    @pCorreo NVARCHAR(100),
    @pContrasena NVARCHAR(200)
AS
BEGIN
	 
    SET NOCOUNT ON;

    BEGIN TRY
        BEGIN TRANSACTION;

        -- Validación de username
        IF (@pUsername IS NULL OR LTRIM(RTRIM(@pUsername)) = '')
        BEGIN
            RAISERROR('El username es obligatorio.', 16, 1);
            ROLLBACK TRANSACTION;
            RETURN;
        END

        -- Validación de correo electrónico
        IF (@pCorreo IS NULL OR LTRIM(RTRIM(@pCorreo)) = '')
        BEGIN
            RAISERROR('El correo electrónico es obligatorio.', 16, 1);
            ROLLBACK TRANSACTION;
            RETURN;
        END
        
        -- Valida si el correo tiene el formato correcto
        IF @pCorreo NOT LIKE '%_@_%._%'
        BEGIN
        	RAISERROR('El correo electrónico tiene un formato inválido.', 16, 1);
        	ROLLBACK TRANSACTION;
        	RETURN;
        END

        -- Validación de contraseña
        IF (@pContrasena IS NULL OR LTRIM(RTRIM(@pContrasena)) = '')
        BEGIN
            RAISERROR('Debe ingresar una contraseña.', 16, 1);
            ROLLBACK TRANSACTION;
            RETURN;
        END
        
        -- Valida si cumple los requisitos de seguridad
        IF LEN(@pContrasena) < 8 OR
           @pContrasena NOT LIKE '%[A-Z]%' OR
           @pContrasena NOT LIKE '%[a-z]%' OR
           @pContrasena NOT LIKE '%[0-9]%' OR
           @pContrasena NOT LIKE '%[^A-Za-z0-9]%'
        BEGIN
        	RAISERROR('La contraseña no cumple los requisitos de seguridad. Debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un símbolo.', 16, 1);
        	ROLLBACK TRANSACTION;
        	RETURN;
        END
        

        -- Valida si el username o correo ya existen en el sistema
        IF EXISTS (SELECT 1 FROM Usuario WHERE Username = @pUsername OR Correo = @pCorreo)
        BEGIN
            RAISERROR('Las credenciales ya existen en el sistema. Intente de nuevo.', 16, 1);
            ROLLBACK TRANSACTION;
            RETURN;
        END

        -- Genera el salt
        DECLARE @Salt NVARCHAR(200) = CONVERT(NVARCHAR(200), NEWID());
        
        -- Genera el hash de la contraseña
        DECLARE @ContrasenaHash NVARCHAR(200);
        SET @ContrasenaHash = CONVERT(NVARCHAR(200), HASHBYTES('SHA2_256', @pContrasena + @Salt), 2);

        INSERT INTO Usuario (Username, Correo, Contrasena, Salt, Estado)
        VALUES (
            @pUsername,
            @pCorreo,
            @ContrasenaHash,
            @Salt,
            1 -- Estado - activo
        );
        
        -- Asigna el rol al usuario por defecto
        DECLARE @UsuarioId INT = SCOPE_IDENTITY();
        DECLARE @RolUsuarioId INT = (SELECT RolId FROM Rol WHERE NombreRol = 'Usuario');
        
        INSERT INTO UsuarioRol (UsuarioId, RolId)
        VALUES (@UsuarioId, @RolUsuarioId)

        COMMIT TRANSACTION;
        
    END TRY
    BEGIN CATCH
        ROLLBACK TRANSACTION;

        DECLARE @ErrorMessage NVARCHAR(4000) = ERROR_MESSAGE();
        DECLARE @ErrorSeverity INT = ERROR_SEVERITY();
        DECLARE @ErrorState INT = ERROR_STATE();

        RAISERROR(@ErrorMessage, @ErrorSeverity, @ErrorState);
    END CATCH
END

GO

-- Procedimiento almacenado - Registro de usuarios con roles

CREATE PROCEDURE SP_RegistroUsuarioConRol
    @pUsername NVARCHAR(50),
    @pCorreo NVARCHAR(100),
    @pContrasena NVARCHAR(200),
    @pRol NVARCHAR(50)
AS
BEGIN
	 
    SET NOCOUNT ON; 

    BEGIN TRY
        BEGIN TRANSACTION;

        -- Validación de username
        IF (@pUsername IS NULL OR LTRIM(RTRIM(@pUsername)) = '')
        BEGIN
            RAISERROR('El username es obligatorio.', 16, 1);
            ROLLBACK TRANSACTION;
            RETURN;
        END

        -- Validación de correo electrónico
        IF (@pCorreo IS NULL OR LTRIM(RTRIM(@pCorreo)) = '')
        BEGIN
            RAISERROR('El correo electrónico es obligatorio.', 16, 1);
            ROLLBACK TRANSACTION;
            RETURN;
        END
        
        -- Valida si el correo tiene el formato correcto 
        IF @pCorreo NOT LIKE '%_@_%._%'
        BEGIN
        	RAISERROR('El correo electrónico tiene un formato inválido.', 16, 1);
        	ROLLBACK TRANSACTION;
        	RETURN;
        END

        -- Validación de contraseña
        IF (@pContrasena IS NULL OR LTRIM(RTRIM(@pContrasena)) = '')
        BEGIN
            RAISERROR('Debe ingresar una contraseña.', 16, 1);
            ROLLBACK TRANSACTION;
            RETURN;
        END
        
        -- Valida si cumple los requisitos de seguridad
        IF LEN(@pContrasena) < 8 OR
           @pContrasena NOT LIKE '%[A-Z]%' OR
           @pContrasena NOT LIKE '%[a-z]%' OR
           @pContrasena NOT LIKE '%[0-9]%' OR
           @pContrasena NOT LIKE '%[^A-Za-z0-9]%'
        BEGIN
        	RAISERROR('La contraseña no cumple los requisitos de seguridad. Debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un símbolo.', 16, 1);
        	ROLLBACK TRANSACTION;
        	RETURN;
        END
        

        -- Valida si el username o correo ya existen
        IF EXISTS (SELECT 1 FROM Usuario WHERE Username = @pUsername OR Correo = @pCorreo)
        BEGIN
            RAISERROR('Las credenciales ya existen en el sistema. Intente de nuevo.', 16, 1);
            ROLLBACK TRANSACTION;
            RETURN;
        END
        
        -- Valida que el rol exista
        DECLARE @RolId INT;
        SELECT @RolId = RolId FROM Rol WHERE NombreRol = @pRol;
        
        IF @RolId IS NULL
        BEGIN
        	RAISERROR('El rol ingresado no existe.', 16, 1);
        	ROLLBACK TRANSACTION;
        	RETURN;
        END

        -- Genera el salt
        DECLARE @Salt NVARCHAR(200) = CONVERT(NVARCHAR(200), NEWID());
        
        -- Genera el hash de la contraseña
        DECLARE @ContrasenaHash NVARCHAR(200);
        SET @ContrasenaHash = CONVERT(NVARCHAR(200), HASHBYTES('SHA2_256', @pContrasena + @Salt), 2);

        INSERT INTO Usuario (Username, Correo, Contrasena, Salt, Estado)
        VALUES (
            @pUsername,
            @pCorreo,
            @ContrasenaHash,
            @Salt,
            1 -- Estado - activo
        );
        
        -- Asigna el rol al usuario de forma manual
        DECLARE @UsuarioId INT = SCOPE_IDENTITY();
        INSERT INTO UsuarioRol (UsuarioId, RolId)
        VALUES (@UsuarioId, @RolId)

        COMMIT TRANSACTION;
        
    END TRY
    BEGIN CATCH
        ROLLBACK TRANSACTION;

        DECLARE @ErrorMessage NVARCHAR(4000) = ERROR_MESSAGE();
        DECLARE @ErrorSeverity INT = ERROR_SEVERITY();
        DECLARE @ErrorState INT = ERROR_STATE();

        RAISERROR(@ErrorMessage, @ErrorSeverity, @ErrorState);
    END CATCH
END

GO

-- Procedimiento almacenado - Inicio de sesión

CREATE PROCEDURE SP_InicioSesion
    @pUsernameCorreo NVARCHAR(100),
    @pContrasena NVARCHAR(200), 
    @pIpAddress NVARCHAR(45) -- Registra la ipAddress del usuario
AS
BEGIN
    SET NOCOUNT ON;

    BEGIN TRY
        BEGIN TRANSACTION;

        -- Variables para almacenar la información del usuario y hash
        DECLARE @UsuarioId INT;
        DECLARE @Salt NVARCHAR(200);
        DECLARE @HashContrasena NVARCHAR(200);
        DECLARE @ContrasenaAlmacenada NVARCHAR(200);
        DECLARE @Estado BIT;

        -- Busca si el usuario esta activo por username o correo
        SELECT TOP 1 
            @UsuarioId = UsuarioId, 
            @Salt = Salt,
            @ContrasenaAlmacenada = Contrasena,
            @Estado = Estado
        FROM Usuario
        WHERE (Username = @pUsernameCorreo OR Correo = @pUsernameCorreo);

        -- Validación de usuario no encontrado
        IF @UsuarioId IS NULL
        BEGIN
            INSERT INTO AuditoriaLogin (UsuarioId, CorreoIntento, Estado, IpAddress)
            VALUES (NULL, @pUsernameCorreo, 0, @pIpAddress);

            RAISERROR('Usuario no encontrado.', 16, 1);
            ROLLBACK TRANSACTION;
            RETURN;
        END

        -- Validación de cuenta deshabilitada
        IF @Estado = 0
        BEGIN
            INSERT INTO AuditoriaLogin (UsuarioId, CorreoIntento, Estado, IpAddress)
            VALUES (@UsuarioId, @pUsernameCorreo, 0, @pIpAddress);

            RAISERROR('La cuenta está deshabilitada.', 16, 1);
            ROLLBACK TRANSACTION;
            RETURN;
        END

        -- Validación de campos vacios
        IF (@pUsernameCorreo IS NULL OR LTRIM(RTRIM(@pUsernameCorreo)) = '')
        BEGIN
            RAISERROR('Debe ingresar un correo electrónico o username.', 16, 1);
            ROLLBACK TRANSACTION;
            RETURN;
        END
        
        IF (@pContrasena IS NULL OR LTRIM(RTRIM(@pContrasena)) = '')
        BEGIN
            RAISERROR('Debe ingresar una contraseña.', 16, 1);
            ROLLBACK TRANSACTION;
            RETURN;
        END   

        -- Genera el hash de la contraseña ingresada
        SET @HashContrasena = CONVERT(NVARCHAR(200), HASHBYTES('SHA2_256', @pContrasena + @Salt), 2);

        -- Compara si la contraseña ingresada coincide con la contraseña almacenada
        IF (@HashContrasena <> @ContrasenaAlmacenada)
        BEGIN
            INSERT INTO AuditoriaLogin (UsuarioId, CorreoIntento, Estado, IpAddress)
            VALUES (@UsuarioId, @pUsernameCorreo, 0, @pIpAddress);

            RAISERROR('Credenciales incorrectas.', 16, 1);
            ROLLBACK TRANSACTION;
            RETURN;
        END
        
        -- Genera el token
        DECLARE @Token NVARCHAR(500) = CONVERT(NVARCHAR(200), NEWID());
        DECLARE @FechaExpiracion DATETIME = DATEADD(HOUR, 1, GETDATE());
        
        -- Registra la sesión
        INSERT INTO Sesion (UsuarioId, Token, FechaInicio, FechaExpiracion, Estado)
        VALUES (@UsuarioId, @Token, GETDATE(), @FechaExpiracion, 1);
        
        -- Registra la auditoría de login
        INSERT INTO AuditoriaLogin (UsuarioId, CorreoIntento, Estado, FechaIntento, IpAddress)
        VALUES (@UsuarioId, @pUsernameCorreo, 1, GETDATE(), @pIpAddress);

        COMMIT TRANSACTION;
        
    END TRY
    BEGIN CATCH
        ROLLBACK TRANSACTION;
        
        DECLARE @ErrorMessage NVARCHAR(4000) = ERROR_MESSAGE();
        DECLARE @ErrorSeverity INT = ERROR_SEVERITY();
        DECLARE @ErrorState INT = ERROR_STATE();
        
        RAISERROR(@ErrorMessage, @ErrorSeverity, @ErrorState);
    END CATCH
END

GO

-- Procedimiento almacenado - Cerrar sesión

CREATE PROCEDURE SP_CerrarSesion
    @pToken NVARCHAR(500),
    @pIpAddress NVARCHAR(45) -- Registra la ipAddress del usuario
AS
BEGIN
    SET NOCOUNT ON;

    BEGIN TRY
        BEGIN TRANSACTION;
    	
    	DECLARE @UsuarioId INT;
    	
    	-- Busca la sesión activa
    	SELECT @UsuarioId = UsuarioId FROM Sesion WHERE Token = @pToken AND Estado = 1;
    	
    	IF @UsuarioId IS NULL 
    	BEGIN
    		RAISERROR('Sesión inválida o ya esta cerrada.', 16, 1);
    		ROLLBACK TRANSACTION;
    		RETURN;
    	END
    	
    	-- Invalida la sesión
    	UPDATE Sesion SET Estado = 0, FechaExpiracion = GETDATE() WHERE Token = @pToken;
    	
    	-- Registra la auditoría de login
   		INSERT INTO AuditoriaLogin (UsuarioId, CorreoIntento, Estado, FechaIntento, IpAddress)
        VALUES (@UsuarioId, NULL, 0, GETDATE(), @pIpAddress);
    	
    	COMMIT TRANSACTION;
    	
    	END TRY
    	BEGIN CATCH 
    		ROLLBACK TRANSACTION;
    	
        	DECLARE @ErrorMessage NVARCHAR(4000) = ERROR_MESSAGE();
        	DECLARE @ErrorSeverity INT = ERROR_SEVERITY();
        	DECLARE @ErrorState INT = ERROR_STATE();
        	
        	RAISERROR(@ErrorMessage, @ErrorSeverity, @ErrorState);
        END CATCH
END

GO

-- Procedimiento almacenado - Obtener los intentos de Login

CREATE PROCEDURE SP_ObtenerIntentosLogin
AS
BEGIN
		SET NOCOUNT ON;
	
		SELECT 
			a.AuditoriaId,
			a.UsuarioId,
			u.Username,
			u.Correo,
			a.CorreoIntento,
			a.Estado,
			CASE a.Estado
				WHEN 1 THEN 'Activa'
				ELSE 'Inactivo'
			END AS EstadoDescripcion,
			a.FechaIntento,
			a.IpAddress
		FROM AuditoriaLogin a
		LEFT JOIN Usuario u ON a.UsuarioId = u.UsuarioId
		ORDER BY a.FechaIntento DESC;
END

GO

-- Procedimiento almacenado - Obtener los usuarios

CREATE PROCEDURE SP_ObtenerUsuarios
    @pEstado BIT = NULL  -- NULL = todos, 1 = activos, 0 = inactivos
AS
BEGIN
    SET NOCOUNT ON;

    SELECT 
    	u.UsuarioId,
        u.Username,
        u.Correo,
        r.NombreRol AS Rol,
        CASE 
            WHEN u.Estado = 1 THEN 'Activo'
            ELSE 'Inactivo'
        END AS Estado,
        CAST(u.FechaRegistro AS DATE) AS FechaRegistro
    FROM Usuario u
    INNER JOIN UsuarioRol ur ON u.UsuarioId = ur.UsuarioId
    INNER JOIN Rol r ON ur.RolId = r.RolId
    WHERE (@pEstado IS NULL OR u.Estado = @pEstado)
    ORDER BY u.FechaRegistro DESC;
END

GO

-- Procedimiento almacenado - Actualizar usuario con rol

CREATE PROCEDURE SP_ActualizarUsuarioConRol
	@pUsuarioId INT,
	@pEstado BIT = NULL,
	@pRol NVARCHAR(50) = NULL
AS
BEGIN
	SET NOCOUNT ON;

	BEGIN TRY
		BEGIN TRANSACTION;
	
		-- Valida si el usuario existe
		IF NOT EXISTS (SELECT 1 FROM Usuario WHERE UsuarioId = @pUsuarioId)
		BEGIN
			RAISERROR('El usuario no existe.', 16, 1);
			ROLLBACK TRANSACTION;
			RETURN;
		END
		
		-- Valida que si el estado no esta vacío, se actualiza
		IF @pEstado IS NOT NULL
		BEGIN
			UPDATE Usuario
			SET Estado = @pEstado
			WHERE UsuarioId = @pUsuarioId
		END
		
		-- Valida si el rol existe
		IF @pRol IS NOT NULL
		BEGIN
			DECLARE @pRolId INT;
			SELECT @pRolId = RolId FROM Rol WHERE NombreRol = @pRol;
		
			IF @pRolId IS NULL
			BEGIN
				RAISERROR('El rol especificado no existe.', 16, 1);
				ROLLBACK TRANSACTION;
				RETURN;
			END
			
			-- Si existe se actualiza
			IF EXISTS (SELECT 1 FROM UsuarioRol WHERE UsuarioId = @pUsuarioId)
			BEGIN
				UPDATE UsuarioRol
				SET RolId = @pRolId,
				FechaAsignacion = GETDATE()
				WHERE UsuarioId = @pUsuarioId;
			END		
		END
		
		COMMIT TRANSACTION;
		
	END TRY
	BEGIN CATCH
		ROLLBACK TRANSACTION;
    	
        DECLARE @ErrorMessage NVARCHAR(4000) = ERROR_MESSAGE();
        DECLARE @ErrorSeverity INT = ERROR_SEVERITY();
        DECLARE @ErrorState INT = ERROR_STATE();
        	
        RAISERROR(@ErrorMessage, @ErrorSeverity, @ErrorState);
	END CATCH
END

GO

-- Procedimiento almacenado - Cambiar contraseña

CREATE PROCEDURE SP_CambiarContrasena
	@pUsuarioId INT,
	@pContrasenaActual NVARCHAR(200),
	@pContrasenaNueva NVARCHAR(200),
	@pConfirmarContrasena NVARCHAR(200)
AS
BEGIN
	SET NOCOUNT ON;
	
	BEGIN TRY
		BEGIN TRANSACTION;
	
		-- Variables para almacenar la contraseña
		DECLARE @ContrasenaHash NVARCHAR(200);
		DECLARE @Salt NVARCHAR(200);
		DECLARE @HashIngresado NVARCHAR(200);
		DECLARE @SaltNuevo NVARCHAR(200);
		DECLARE @ContrasenaNuevaHash NVARCHAR(200);
		
		-- Valida si el usuario existe
		IF NOT EXISTS (SELECT 1 FROM Usuario WHERE UsuarioId = @pUsuarioId)
		BEGIN
			RAISERROR('El usuario no existe.', 16, 1);
			ROLLBACK TRANSACTION;
			RETURN;
		END
		
		-- Valida si la contraseña nueva coincide con confirmar contraseña
		IF @pContrasenaNueva <> @pConfirmarContrasena
		BEGIN
			RAISERROR('La contraseña nueva no coincide con confirmar contraseña.', 16, 1);
			ROLLBACK TRANSACTION;
			RETURN;
		END
		
		-- Obtiene la contraseña y el salt actual
		SELECT @ContrasenaHash = Contrasena, @Salt = Salt
		FROM Usuario 
		WHERE UsuarioId = @pUsuarioId;
		
		-- Genera el hash de la contraseña actual ingresada
		DECLARE @Combined NVARCHAR(400) = @pContrasenaActual + @Salt;
		SET @HashIngresado = CONVERT(NVARCHAR(200), HASHBYTES('SHA2_256', @Combined), 2);
		
		-- Valida que la contraseña actual sea correcta
		IF @HashIngresado <> @ContrasenaHash
		BEGIN
			RAISERROR('La contraseña actual es incorrecta.', 16, 1);
			ROLLBACK TRANSACTION;
			RETURN;
		END
		
		-- Valida que la nueva contraseña cumpla todos los requisitos de seguridad
        IF LEN(@pContrasenaNueva) < 8
            RAISERROR('La contraseña debe tener al menos 8 caracteres.', 16, 1);

        IF @pContrasenaNueva NOT LIKE '%[A-Z]%'
            RAISERROR('Debe contener al menos una letra mayúscula.', 16, 1);

        IF @pContrasenaNueva NOT LIKE '%[a-z]%'
            RAISERROR('Debe contener al menos una letra minúscula.', 16, 1);

        IF @pContrasenaNueva NOT LIKE '%[0-9]%'
            RAISERROR('Debe contener al menos un número.', 16, 1);

        IF @pContrasenaNueva NOT LIKE '%[^a-zA-Z0-9]%'
            RAISERROR('Debe contener al menos un carácter especial.', 16, 1);
        
        -- Si sucede un error, se detiene antes de continuar
        IF @@ERROR <> 0 
        BEGIN
        	ROLLBACK TRANSACTION;
        	RETURN;
        END
        
        -- Genera el nuevo salt
        SET @SaltNuevo = CONVERT(NVARCHAR(200), NEWID());
        
        -- Genera el nuevo hash con SHA2_256
        DECLARE @CombinedNew NVARCHAR(400) = @pContrasenaNueva + @SaltNuevo;
        SET @ContrasenaNuevaHash = CONVERT(NVARCHAR(200), HASHBYTES('SHA2_256', @CombinedNew), 2);
		
        -- Actualiza la contraseña
        UPDATE Usuario
        SET Contrasena = @ContrasenaNuevaHash,
        	Salt = @SaltNuevo
        WHERE UsuarioId = @pUsuarioId;
        
        COMMIT TRANSACTION;
        
	END TRY
	BEGIN CATCH
		ROLLBACK TRANSACTION;
    	
        DECLARE @ErrorMessage NVARCHAR(4000) = ERROR_MESSAGE();
        DECLARE @ErrorSeverity INT = ERROR_SEVERITY();
        DECLARE @ErrorState INT = ERROR_STATE();
        	
        RAISERROR(@ErrorMessage, @ErrorSeverity, @ErrorState);
	END CATCH
END

GO

-- Procedimiento almacenado - Olvide mi contraseña

CREATE PROCEDURE SP_OlvideContrasena
	@pCorreo NVARCHAR(100),
	@pIpAddress NVARCHAR(45) = NULL -- Registra la ipAddress del usuario
AS
BEGIN
	SET NOCOUNT ON;
	BEGIN TRY
		BEGIN TRANSACTION;

		-- Variables para almacenar datos de la recuperación de contraseña
		DECLARE @UsuarioId INT;
		DECLARE @Token NVARCHAR(500);
		DECLARE @FechaExpiracion DATETIME = DATEADD(MINUTE, 30, GETDATE()); -- Token valido por 30 minutos
		
		-- Valida que el usuario exista
		SELECT @UsuarioId = UsuarioId FROM Usuario WHERE Correo = @pCorreo AND Estado = 1;
		
		IF @UsuarioId IS NULL
		BEGIN
			RAISERROR('El correo electrónico ingresado no está registrado o el usuario está inactivo.', 16, 1);
			ROLLBACK TRANSACTION;
			RETURN;
		END
		
		-- Deshabilita tokens anteriores no utilizados
		UPDATE RecuperacionContrasena
		SET Estado = 1
		WHERE UsuarioId = @UsuarioId AND Estado = 0;
		
		-- Genera el token
		SET @Token = LOWER(CONVERT(NVARCHAR(500), NEWID()));
		
		INSERT INTO RecuperacionContrasena (UsuarioId, Token, FechaExpiracion, IpAddress)
		VALUES (@UsuarioId, @Token, @FechaExpiracion, @pIpAddress);
		
		COMMIT TRANSACTION;
		
		-- Retorna el token al sistema para que se envíe por correo electrónico (No se muestra directamente al usuario)
		SELECT 
			@UsuarioId AS UsuarioId,
			@Token AS Token,
			FORMAT(@FechaExpiracion, 'yyyy-MM-dd HH:mm:ss') AS FechaExpiracion,
			'Se ha enviado un enlace temporal para restablecer la contraseña. Revise su correo electrónico. Si el correo no le llego, es porque el correo electrónico ingresado no existe en el sistema.' AS Mensaje;
	END TRY
	BEGIN CATCH
		ROLLBACK TRANSACTION;
    	
        DECLARE @ErrorMessage NVARCHAR(4000) = ERROR_MESSAGE();
        DECLARE @ErrorSeverity INT = ERROR_SEVERITY();
        DECLARE @ErrorState INT = ERROR_STATE();
        	
        RAISERROR(@ErrorMessage, @ErrorSeverity, @ErrorState);
	END CATCH
END

GO

-- Procedimiento almacenado - Restablecer la contraseña

CREATE PROCEDURE SP_RestablecerContrasena
	@pToken NVARCHAR(500),
	@pContrasenaNueva NVARCHAR(200),
	@pConfirmarContrasena NVARCHAR(200)
AS
BEGIN
	SET NOCOUNT ON;
	
	BEGIN TRY
		BEGIN TRANSACTION;
		
		-- Variables para almacenar la contraseña y datos del restablecimiento
		DECLARE @UsuarioId INT;
		DECLARE @Salt NVARCHAR(200);
		DECLARE @ContrasenaHash NVARCHAR(200);
		DECLARE @FechaExpiracion DATETIME;
		DECLARE @Estado BIT;
		
		-- Valida que el token exista y no haya sido utilizado o expirado
		SELECT 
			@UsuarioId = UsuarioId,
			@FechaExpiracion = FechaExpiracion,
			@Estado = Estado
		FROM RecuperacionContrasena
		WHERE Token = @pToken;
		
		IF @UsuarioId IS NULL
		BEGIN
			RAISERROR('El token de recuperación no es válido.', 16, 1);
            ROLLBACK TRANSACTION;
            RETURN;
		END
		
		-- Valida si el token fue utilizado 
		IF @Estado = 1
		BEGIN
			RAISERROR('El token ya fue utilizado.', 16, 1);
            ROLLBACK TRANSACTION;
            RETURN;
		END
		
		-- Valida si el token ya expiró
		IF GETDATE() > @FechaExpiracion
		BEGIN
			RAISERROR('El tiempo de recuperación ha expirado. Solicite una nueva recuperación de contraseña.', 16, 1);
			UPDATE RecuperacionContrasena 
			SET Estado = 1
			WHERE Token = @pToken;
            ROLLBACK TRANSACTION;
            RETURN;
		END
		
		-- Valida si la contraseña nueva coincide con confirmar contraseña
		IF @pContrasenaNueva <> @pConfirmarContrasena
		BEGIN
			RAISERROR('La contraseña nueva no coincide con confirmar contraseña. Por favor, verifique e intente nuevamente.', 16, 1);
            ROLLBACK TRANSACTION;
            RETURN;
		END
		
		
		-- Validación de requisitos de seguridad de la contraseña nueva
		IF LEN(@pContrasenaNueva) < 8
           OR @pContrasenaNueva NOT LIKE '%[A-Z]%'
           OR @pContrasenaNueva NOT LIKE '%[a-z]%'
           OR @pContrasenaNueva NOT LIKE '%[0-9]%'
           OR @pContrasenaNueva NOT LIKE '%[^A-Za-z0-9]%'
        BEGIN
            RAISERROR('La contraseña no cumple los requisitos de seguridad. Debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un símbolo.', 16, 1);
            ROLLBACK TRANSACTION;
            RETURN;
        END	
        
        -- Genera el salt nuevo
        SET @Salt = CONVERT(NVARCHAR(200), NEWID());
        
        -- Genera el hash de la contraseña nueva
        SET @ContrasenaHash = CONVERT(NVARCHAR(200), HASHBYTES('SHA2_256', @pContrasenaNueva + @Salt), 2);
        
        -- Actualiza la contraseña y salt
        UPDATE Usuario 
        SET Contrasena = @ContrasenaHash,
        	Salt = @Salt
        WHERE UsuarioId = @UsuarioId;
        
        -- Marca el token como utilizado
        UPDATE RecuperacionContrasena
        SET Estado = 1
        WHERE Token = @pToken;
        
        COMMIT TRANSACTION;
        
	END TRY
	BEGIN CATCH
		ROLLBACK TRANSACTION;
    	
        DECLARE @ErrorMessage NVARCHAR(4000) = ERROR_MESSAGE();
        DECLARE @ErrorSeverity INT = ERROR_SEVERITY();
        DECLARE @ErrorState INT = ERROR_STATE();
        	
        RAISERROR(@ErrorMessage, @ErrorSeverity, @ErrorState);	
	END CATCH
END




    	






