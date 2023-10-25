$ver = "v0.9"
$updated = "25/10/2023"
$sys = "#### ~~~~ Server Config Grabber (SCG) Script - Version " + $ver + " - Last updated " + $updated + " - Created by Elyn Leon ~~~~ ####"
$computer = $env:computername
$dateValue = Get-Date -format "MM-dd-yy-HH-mm"
$logName = "C:\SCG\" + $computer + "\SCG-Log-" + $dateValue + ".log"
$workDir = "C:\SCG\" + $computer + "\"
$module

function HyperVConfigExport
{  
    param(
        [string]$HVExportPath
    )
    "########################## HYPER V IS INSTALLED - RUNNING CONFIG EXPORT ##########################"
    Write-Host "Hyper-V Configs are being prepared and exported - Please do not disturb this operation" -ForegroundColor Red
    Import-Module Hyper-V
    Get-VM >$HVExportPath\VirtualMachines.txt
    Write-Host "Generating Detailed Virtual Machine Config - Please wait (This could take a while)"
    Get-VM | Select-Object * >$HVExportPath\VirtualMachines-Detailed.txt
    Write-Host "VM Details Exported" -ForegroundColor Green
    Write-Host "Generating Cluster Config Export - Please wait (This could take a while)" -ForegroundColor Cyan
    Get-Cluster | Format-List -Property * >$HVExportPath\Cluster-Detailed.txt
    Get-ClusterGroup | Format-List -Property * >$HVExportPath\ClusterGroup-Detailed.txt
    Get-ClusterNode >$HVExportPath\ClusterNodes.txt
    Write-Host "Cluster Details Exported" -ForegroundColor Green
}

<# CHECK IF ADMIN #
$isAdmin = [System.Security.Principal.WindowsPrincipal]::new(
    [System.Security.Principal.WindowsIdentity]::GetCurrent()).
        IsInRole('Administrators')

if(-not $isAdmin) {
    $params = @{
        FilePath     = 'powershell'
        Verb         = 'RunAs'
        ArgumentList = @(
            '-NoExit'
            '-ExecutionPolicy ByPass'
            '-File "{0}"' -f $PSCommandPath
        )
    }

    Start-Process @params
    return
}
"Now running in Elevated Powershell"
#>

#START#
Write-Host $sys -ForegroundColor Red
Write-Host "The script is running - Log available at "$logName -ForegroundColor Cyan
"#### ~~~~ #### ~~~~ ####"

# Create script folder #
Write-Host "Starting Folder Creation for exporting files - Please Wait"  -ForegroundColor Cyan
if (-not (test-path "C:\SCG")) {
    Write-Host "SCG folder doesnt exist - Creating Folder..." -ForegroundColor DarkBlue
    New-Item -ItemType Directory -Path "C:\" -name "SCG" | Out-Null
    Write-Host "Folder Created!" -ForegroundColor Cyan
} else {
    Write-Host "SCG folder already exists - Moving on" -ForegroundColor Cyan
}

if (-not (test-path "C:\SCG\$computer" )) {
    Write-Host "Device folder doesn't exist - Creating Folder..." -ForegroundColor DarkBlue
    New-Item -ItemType Directory -Path "C:\SCG" -name $computer | Out-Null
    Write-Host "Folder Created!" -ForegroundColor Cyan
} else {
    Write-Host "Device folder already exists - Files within will be overwritten'" -ForegroundColor Cyan
    Write-Host "Files within C:\SCG\ on this computer will be permanently lost. Would you like to proceed?"
    $folderProceed = Read-Host -Prompt "Continue? Y/N"
    if ( $folderProceed -eq 'y' ){
        Remove-Item C:\SCG\$computer\* -Recurse
    }

}
Write-Host "Folders Present - Starting Information Export" -ForegroundColor Green

"#######################################################################################################################"

###################################################### RUN SCRIPT ######################################################

## Network Configuration ##
Write-Host "Running Network Configuration Export - Please Wait" -ForegroundColor Cyan
ipconfig /all >$workDir\ipconfig.txt
Write-Host "IP CONFIG EXPORTED" -ForegroundColor Green

## System Configuration ##
Write-Host "Running System Information & Configuration Export - Please Wait" -ForegroundColor Cyan
systeminfo >$workDir\SysInfo.txt
Write-Host "SYSTEM INFORMATION EXPORTED" -ForegroundColor Green

## Prog Files - Structure ###
Write-Host "Running Program File Directory Export - Please Wait" -ForegroundColor Cyan
Set-Location "C:\Program Files\"
Get-ChildItem >$workDir\ProgFiles-Export.txt

Set-Location "C:\Program Files (x86)\"
Get-ChildItem >$workDir\ProgFilesx86-Export.txt

Set-Location "C:\ProgramData\"
Get-ChildItem >$workDir\ProgData-Export.txt

Write-Host "PROGRAM FILE DIRECTORIES EXPORTED" -ForegroundColor Green

## Software, Services & Roles ##
Write-Host "Running Software List Export - Please Wait, this step can take a while" -ForegroundColor Cyan
Get-WMIObject -Class Win32_Product >$workDir\InstalledSoftware.txt
Write-Host "SOFTWARE LIST EXPORTED" -ForegroundColor Green

Write-Host "Running Roles & Features Export - Please Wait" -ForegroundColor Cyan
Get-WindowsFeature >$workdir\Roles.txt | Out-Null
Get-WindowsOptionalFeature -Online >$workDir\Features.txt
Write-Host "ROLES & FEATURES LIST EXPORTED" -ForegroundColor Green

## Hyper V ##
Write-Host "Checking Hyper-V Configuration - Please Wait" -ForegroundColor Cyan
    $hypervstatus = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online
    # Check if Hyper-V is enabled
    if($hypervstatus.State -eq "Enabled") {
        Write-Host "Hyper-V is enabled." -ForegroundColor Green
        New-Item -ItemType File -Path $workDir -Name "#HyperV-ENABLED" | Out-Null
        New-Item -ItemType Directory -Path $workDir -Name "HyperVConfig" | Out-Null
        HyperVConfigExport -HVExportPath C:\SCG\$computer\HyperVConfig
    }
    else {
        Write-Host "Hyper-V is disabled" -ForegroundColor Red
        New-Item -ItemType File -Path $workDir -Name "#HyperV-DISABLED" | Out-Null
    }

    Write-Host "Server Configuration Grabber (SCG) is now completed - You may close this window" -ForegroundColor Magenta
    Write-Host "Your exported files are located here: " $workDir -ForegroundColor Magenta