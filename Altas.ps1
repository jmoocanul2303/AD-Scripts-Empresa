# habilitar_usuario.ps1
# Script para habilitar una cuenta de usuario en Active Directory y moverla a la OU de destino activa.

param(
    [Parameter(Mandatory=$true)]
    [string]$usuarioSam,

    [Parameter(Mandatory=$true)]
    [string]$targetOUName # El nombre de la OU de destino activa (ej: 'GrupoMarketing', 'GrupoTI')
)

try {
    # Importar el módulo ActiveDirectory si no está ya cargado
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "El módulo ActiveDirectory no está disponible. Asegúrese de que las RSAT (Herramientas de Administración de Servidor Remoto) estén instaladas."
        exit 1
    }
    Import-Module ActiveDirectory

    # Obtener el DistinguishedName del dominio
    $dominioDN = (Get-ADDomain).DistinguishedName

    # 1. Construir el Distinguished Name (DN) completo de la OU de destino activa
    # Asumimos que todas las OUs activas de departamentos están bajo 'OU=UsuariosActivos'
    # EJEMPLO: OU=GrupoMarketing,OU=UsuariosActivos,DC=redforce,DC=local
    $ouActivosBase = "OU=UsuariosActivos,$dominioDN"
    $targetOUDn = "OU=$targetOUName," + $ouActivosBase

    # Validar que la OU de destino activa realmente existe en AD
    $targetOUObject = Get-ADOrganizationalUnit -Identity $targetOUDn -ErrorAction SilentlyContinue
    if (-not $targetOUObject) {
        Write-Error "La OU de destino activa '$targetOUName' (DN esperado: '$targetOUDn') no fue encontrada en Active Directory. No se pudo mover el usuario."
        exit 1
    }
    
    # Obtener el objeto de usuario en AD
    $user = Get-ADUser -Identity $usuarioSam -Properties DistinguishedName, Enabled -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Error "Usuario '$usuarioSam' no encontrado en Active Directory."
        exit 1
    }

    # 2. Habilitar el usuario si está deshabilitado
    if ($user.Enabled -eq $false) {
        Enable-ADAccount -Identity $usuarioSam -ErrorAction Stop
        Write-Host "Usuario '$usuarioSam' habilitado correctamente en Active Directory."
    } else {
        Write-Warning "El usuario '$usuarioSam' ya está habilitado en Active Directory. No se requirió habilitación."
    }

    # 3. Mover el usuario a la OU de destino activa
    # Obtener el DN de la OU actual del usuario para comparar
    # El DN de un usuario es "CN=Nombre,OU=OUActual,DC=Dominio,DC=com"
    # Necesitamos extraer "OU=OUActual,DC=Dominio,DC=com"
    $userCurrentOUDn = ($user.DistinguishedName -split ',', 2)[1]

    if ($userCurrentOUDn -ne $targetOUDn) {
        Move-ADObject -Identity $user.DistinguishedName -TargetPath $targetOUDn -ErrorAction Stop
        Write-Host "Usuario '$usuarioSam' movido correctamente a la OU activa '$targetOUName'."
    } else {
        Write-Warning "El usuario '$usuarioSam' ya se encuentra en la OU activa '$targetOUName'. No se requirió movimiento."
    }

    exit 0 # Éxito general
}
catch {
    Write-Error "Error en la operación del usuario '$usuarioSam': $($_.Exception.Message)"
    exit 1 # Error
}