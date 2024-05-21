$ver = "v1.6.7"
$updated = "14/05/2024"
$sys = "#### ~~~~ Server Config Grabber (SCG) Script - Version " + $ver + " - Last updated " + $updated + " - Created by Elyn Leon ~~~~ ####"
$computer = $env:computername
$dateValue = Get-Date -format "MM-dd-yy-HH-mm"
$logName = "C:\SCG\" + $computer + "\SCG-Log-" + $dateValue + ".log"
$workDir = "C:\SCG\" + $computer + "\"
$module
$NetworkStore = $null
$locations = "\\10.201.7.31\d$\Scripts\SCG\Storage",
             "\\10.201.7.32\d$\Scripts\SCG\Storage",
             "\\10.201.7.33\d$\Scripts\SCG\Storage"

function HyperVConfigExport
{  
    param(
        [string]$HVExportPath
    )
    "########################## HYPER V IS INSTALLED - RUNNING CONFIG EXPORT ##########################"
    Write-Host "Hyper-V Configs are being prepared and exported - Please do not disturb this operation" -ForegroundColor Red
    Import-Module Hyper-V
    Get-VM >$HVExportPath\$computer-VirtualMachines.txt
    Write-Host "Generating Detailed Virtual Machine Config - Please wait (This could take a while)" -ForegroundColor Cyan
    Get-VM | Select-Object * >$HVExportPath\$computer-VirtualMachines-Detailed.txt
    Write-Host "VM Details Exported" -ForegroundColor Green
    Write-Host "Generating Cluster Config Export - Please wait (This could take a while)" -ForegroundColor Cyan
    Get-Cluster | Format-List -Property * >$HVExportPath\$computer-Cluster-Detailed.txt
    Get-ClusterGroup | Format-Table -AutoSize -Property Cluster,GroupType,OwnerNode,Name,State,Id >$HVExportPath\$computer-ClusterGroup-Detailed.txt
    Get-ClusterNode >$HVExportPath\$computer-ClusterNodes.txt
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

# Identifying Network Store Location#
Write-Host "Locating suitable network store for results - Please Wait" -ForegroundColor Cyan
foreach ($location in $locations) {
    try {
        if (Test-Path -Path $location -ErrorAction Stop) {
            $NetworkStore = $location+"\"+$computer+"\"
            break
        }
    } catch {
        Write-Host "Error accessing the network store locations, please manually check access to the management cluster" -ForegroundColor Red
    }
}

if ($null -ne $NetworkStore) {
    Write-Host "Accessible network location found: $NetworkStore" -ForegroundColor Green
} else {
    Write-Host "No accessible network location found. The script will be unable to export results beyond this device" -ForegroundColor Red
}

# Create script folders #
Write-Host "Starting Folder Creation for exporting files - Please Wait"  -ForegroundColor Cyan
if (-not (test-path "C:\SCG")) {
    Write-Host "SCG folder doesnt exist - Creating Folder..." -ForegroundColor Blue
    New-Item -ItemType Directory -Path "C:\" -name "SCG" | Out-Null
    Write-Host "Folder Created!" -ForegroundColor Cyan
} else {
    Write-Host "SCG folder already exists - Moving on" -ForegroundColor Cyan
}

if (-not (test-path "C:\SCG\$computer" )) {
    Write-Host "Device folder doesn't exist - Creating Folder..." -ForegroundColor Blue
    New-Item -ItemType Directory -Path "C:\SCG" -name $computer | Out-Null
    New-Item -ItemType Directory -Path "C:\SCG\$computer" -name $computer-HyperVConfig | Out-Null
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

"##################################################################################################"
###################################################### RUN SCRIPT ######################################################

## Network Configuration ##
Write-Host "Running Network Configuration Export - Please Wait" -ForegroundColor Cyan
ipconfig /all >$workDir\$computer-ipconfig.txt
getmac /v >$workDir\$computer-GetMac.txt
Write-Host "IP CONFIG EXPORTED" -ForegroundColor Green

## System Configuration ##
Write-Host "Running System Information & Configuration Export - Please Wait" -ForegroundColor Cyan
systeminfo >$workDir\$computer-SysInfo.txt
Write-Host "SYSTEM INFORMATION EXPORTED" -ForegroundColor Green

## Prog Files - Structure ###
Write-Host "Running Program File Directory Export - Please Wait" -ForegroundColor Cyan
Set-Location "C:\Program Files\"
Get-ChildItem >$workDir\$computer-ProgFiles-Export.txt

Set-Location "C:\Program Files (x86)\"
Get-ChildItem >$workDir\$computer-ProgFilesx86-Export.txt

Set-Location "C:\ProgramData\"
Get-ChildItem >$workDir\$computer-ProgData-Export.txt

Write-Host "PROGRAM FILE DIRECTORIES EXPORTED" -ForegroundColor Green

## Software, Services & Roles ##
Write-Host "Running Software List Export - Please wait (This could take a while)" -ForegroundColor Cyan
Get-WMIObject -Class Win32_Product >$workDir\$computer-InstalledSoftware.txt
Write-Host "SOFTWARE LIST EXPORTED" -ForegroundColor Green

Write-Host "Running Roles & Features Export - Please Wait" -ForegroundColor Cyan
Get-WindowsFeature >$workDir\$computer-Roles.txt | Out-Null
Get-WindowsOptionalFeature -Online >$workDir\$computer-Features.txt
Write-Host "ROLES & FEATURES LIST EXPORTED" -ForegroundColor Green

## Hyper V ##
Write-Host "Checking Hyper-V Configuration - Please Wait" -ForegroundColor Cyan
    $hypervstatus = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online
    # Check if Hyper-V is enabled
    if($hypervstatus.State -eq "Enabled") {
        Write-Host "Hyper-V is enabled." -ForegroundColor Green
        New-Item -ItemType File -Path $workDir -Name "#HyperV-ENABLED" | Out-Null
        HyperVConfigExport -HVExportPath C:\SCG\$computer\$computer-HyperVConfig
    }
    else {
        Write-Host "Hyper-V is disabled" -ForegroundColor Red
        New-Item -ItemType File -Path $workDir -Name "#HyperV-DISABLED" | Out-Null
    }

Write-Host "Copying results directory to network store - Please Wait" -ForegroundColor Cyan
Robocopy $workDir $NetworkStore /E | Out-Null
Write-Host "SCG RESULTS DIRECTORY EXPORTED" -ForegroundColor Green 
    
Write-Host " "
Write-Host "--- **** --- **** --- **** --- **** --- **** --- **** --- **** --- **** --- **** --- **** " -ForegroundColor Red 
Write-Host " "

Write-Host "Server Configuration Grabber (SCG) is now completed - You may close this window" -ForegroundColor Magenta
Write-Host "Your results files are located here: " $workDir -ForegroundColor Magenta
Write-Host "Your results have also been exported to " $NetworkStore -ForegroundColor Magenta