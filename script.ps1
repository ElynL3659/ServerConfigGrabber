$ver = "v0.9"
$updated = "25/10/2023"
$sys = "#### ~~~~ Server Config Grabber (SCG) Script - Version " + $ver + " - Last updated " + $updated + " - Created by Elyn Leon ~~~~ ####"
$computer = $env:computername
$dateValue = Get-Date -format "MM-dd-yy-HH-mm"
$timeValue = Get-Date -format "HH-mm"
$logName = "C:\SCG\" + $computer + "\SCG-Log-" + $dateValue + ".log"
$workDir = "C:\SCG\" + $computer + "\"

# CHECK IF ADMIN #
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


#START#
Write-Host $sys -ForegroundColor Red
Write-Host "The script is running - Log available at " + $logName -ForegroundColor Cyan
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
    Write-Host "Device folder already exists - Creating Folder Appended by 'Time'" -ForegroundColor Cyan
    New-Item -ItemType Directory -Path "C:\SCG" -name $computer-$timeValue -ErrorAction Inquire | Out-Null
    Write-Host "Folder Created - C:\SCG\"$computer-$timeValue -ForegroundColor Cyan
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
Write-Host "Running Software List Export - Please Wait" -ForegroundColor Cyan
Get-WMIObject -Class Win32_Product >$workDir\InstalledSoftware.txt
Write-Host "SOFTWARE LIST EXPORTED" -ForegroundColor Green


## Hyper V ##
Write-Host "Checking Hyper-V Configuration - Please Wait" -ForegroundColor Cyan
    $hyperv = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online
    # Check if Hyper-V is enabled
    if($hyperv.State -eq "Enabled") {
        Write-Host "Hyper-V is enabled." -ForegroundColor Green
        New-Item -ItemType File -Path $workDir -Name "#HyperV-ENABLED" | Out-Null
        New-Item -ItemType Diretory -Path $workDir -Name "Hyper-V Config" | Out-Null
    }
    else {
        Write-Host "Hyper-V is disabled" -ForegroundColor Red
        New-Item -ItemType File -Path $workDir -Name "#HyperV-DISABLED" | Out-Null
    }