[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $role = "min"
)
filter timestamp { "$(Get-Date -Format o): $_" }
$logFilePath = "$PSScriptRoot\logs\workstation-config.log"
if (-not (Test-Path $logFilePath)) {
    Write-Output "Create log file $logFilePath..." | timestamp
    New-Item -Path $logFilePath -ItemType File -Force | Out-Null
}

Write-Output "Loading helper script..." | timestamp
. $PSScriptRoot\helper.ps1
Write-Output "Register NuGet source ..." | timestamp
Register-PackageSource -provider NuGet -name nugetRepository -location https://www.nuget.org/api/v2 -ForceBootstrap -Force -ErrorAction SilentlyContinue | Out-Null

Write-Output "Getting package config ..." | timestamp
$packageConfigBase = Get-Content $PSScriptRoot\packages-min.json | ConvertFrom-Json
if($role -ne 'min'){
    $packageConfig = Get-Content $PSScriptRoot\packages-$role.json | ConvertFrom-Json
}

$wingetPackages = ($packageConfigBase.winget + $packageConfig.winget) | Select-Object -Unique -Property id,source,override
if ($wingetPackages -and $wingetPackages.Count -gt 0) {
    Install-WinGet
    #call winget list as the first time it takes some time to load
    Write-Output "Run winget list ..." | timestamp
    winget list --accept-source-agreements | Out-Null
    Start-Sleep -Milliseconds 2000
    foreach ($pack in $wingetPackages) {
        if ($pack.override) {
            Install-WinGetPackage -packageId $pack.id -overrideParameters $pack.override -source $pack.source
        }
        else {
            Install-WinGetPackage -packageId $pack.id -source $pack.source
        }
    }
}
    
$chocoPackages = ($packageConfigBase.chocolatey + $packageConfig.chocolatey) | Select-Object -Unique -Property name,additionalParameters
if ($chocoPackages -and $chocoPackages.Count -gt 0) {
    Install-Choco
    foreach ($pack in $chocoPackages) {
        Install-ChocoPackage -packageName $pack.name -additionalParameters $pack.additionalParameters
    }
}

$psModules = ($packageConfigBase.powershellModule + $packageConfig.powershellModule) | Select-Object -Unique -Property name

foreach ($module in $psModules) {
    Install-PSModule -PsModuleName $module.name
}
