-- AlterTable: Agregar columna gamertag opcional a la tabla usuarios
ALTER TABLE `usuarios` ADD COLUMN `gamertag` VARCHAR(50) NULL;

-- AlterEnum: Agregar estado 'baneado' al enum EstadoCuenta en la tabla usuarios
ALTER TABLE `usuarios` MODIFY `estado_cuenta` ENUM('activo', 'suspendido', 'baneado') NOT NULL DEFAULT 'activo';
