<#
.SYNOPSIS
    Builds a complete AD DS lab for contoso.com with OUs, users, groups (AGDLP),
    file shares, NTFS/share ACLs, printers per office, and a GPO that runs a
    user logon script to map drives & printers based on group membership.

.NOTES
    Run as Administrator on a clean Windows Server.
    The script is two-phase:
      1) If no AD forest -> installs AD DS/DNS, schedules itself to resume, reboots.
      2) Post-reboot -> creates OUs, users, groups, shares, printers, GPO, etc.
#>

[CmdletBinding()]
param(
    [switch]$PostAD
)

#----------------------------- helpers -----------------------------------------
function Write-Info { param([string]$m); Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Ok   { param([string]$m); Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn { param([string]$m); Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Err  { param([string]$m); Write-Host "[-] $m" -ForegroundColor Red }

# Safer retry wrapper
function Invoke-Retry {
    param([scriptblock]$Script,[int]$Retries=5,[int]$DelaySec=2)
    for($i=1;$i -le $Retries;$i++){
        try { return & $Script } catch { if($i -eq $Retries){ throw } else { Start-Sleep -Seconds $DelaySec } }
    }
}

# Create OU if missing
function Ensure-OU {
    param([string]$DistinguishedName)
    if(-not (Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$DistinguishedName)" -ErrorAction SilentlyContinue)){
        New-ADOrganizationalUnit -Name (($DistinguishedName -split ",")[0] -replace "^OU=") -Path ($DistinguishedName -replace "^[^,]+,") -ProtectedFromAccidentalDeletion:$true | Out-Null
        Write-Ok "OU created: $DistinguishedName"
    }
}

# Create Group if missing
function Ensure-Group {
    param(
        [string]$Name,
        [string]$Path,
        [string]$Scope="Global",
        [string]$Category="Security"
    )
    if(-not (Get-ADGroup -LDAPFilter "(cn=$Name)" -SearchBase $Path -ErrorAction SilentlyContinue)){
        New-ADGroup -Name $Name -GroupScope $Scope -GroupCategory $Category -Path $Path | Out-Null
        Write-Ok "Group created: $Name"
    }
}

# Create User if missing
function Ensure-User {
    param(
        [string]$GivenName,[string]$Surname,[string]$Sam,[string]$UPN,
        [string]$OU,[securestring]$Password,[string[]]$MemberOf=@()
    )
    $existing = Get-ADUser -LDAPFilter "(sAMAccountName=$Sam)" -ErrorAction SilentlyContinue
    if(-not $existing){
        New-ADUser -Name "$GivenName $Surname" -GivenName $GivenName -Surname $Surname `
            -SamAccountName $Sam -UserPrincipalName $UPN -DisplayName "$GivenName $Surname" `
            -Enabled $true -Path $OU -ChangePasswordAtLogon $true -AccountPassword $Password |
            Out-Null
        Write-Ok "User created: $Sam"
    }
    foreach($g in $MemberOf){
        try { Add-ADGroupMember -Identity $g -Members $Sam -ErrorAction Stop } catch {}
    }
}

# Create directory if missing
function Ensure-Dir { param([string]$Path); if(-not (Test-Path $Path)){ New-Item -ItemType Directory -Path $Path | Out-Null } }

# Decide best share root (prefer D:)
$ShareRoot = (Test-Path "D:\") ? "D:\LabShares" : "C:\LabShares"
$HomeRoot  = (Test-Path "D:\") ? "D:\Home"      : "C:\Home"

#------------------ Phase 1: Create forest if not present ----------------------
if(-not $PostAD){
    $domain = "contoso.com"
    $netbios = "CONTOSO"

    # If AD already exists, skip to phase 2
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $d = Get-ADDomain -ErrorAction Stop
        Write-Warn "Domain already present ($($d.DNSRoot)). Continuing with phase 2 tasks..."
        $PostAD = $true
    } catch {
        Write-Info "Installing AD DS/DNS/GPMC/RSAT + Print-Server role..."
        Install-WindowsFeature AD-Domain-Services, DNS, GPMC, RSAT-AD-Tools, Print-Server -IncludeManagementTools | Out-Null

        # Schedule self to resume after reboot
        Write-Info "Registering one-shot scheduled task to resume post-reboot..."
        $act = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -PostAD"
        $trg = New-ScheduledTaskTrigger -AtStartup
        $prn = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
        Register-ScheduledTask -TaskName "ContosoLab-Phase2" -Action $act -Trigger $trg -Principal $prn -Force | Out-Null

        # Ask for DSRM password (use a lab-safe value if unattended)
        if(-not $env:DSRM_PWD){
            Write-Info "You will be prompted for the DSRM (Directory Services Restore Mode) password."
        }
        $dsrm = $env:DSRM_PWD ? (ConvertTo-SecureString $env:DSRM_PWD -AsPlainText -Force) : (Read-Host -AsSecureString "Enter DSRM password")

        Write-Info "Creating new forest $domain (this will reboot automatically)..."
        Install-ADDSForest `
            -DomainName $domain `
            -DomainNetbiosName $netbios `
            -SafeModeAdministratorPassword $dsrm `
            -InstallDNS `
            -Force

        # The server will reboot here.
        return
    }
}

#------------------ Phase 2: Post-forest configuration ------------------------
# Remove one-shot task if present
try { Unregister-ScheduledTask -TaskName "ContosoLab-Phase2" -Confirm:$false -ErrorAction SilentlyContinue } catch {}

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

$domain     = (Get-ADDomain).DNSRoot
$netbios    = (Get-ADDomain).NetBIOSName
$domainDN   = (Get-ADDomain).DistinguishedName
$serverName = $env:COMPUTERNAME

# Paths & roots
$OU_Corp        = "OU=Corp,$domainDN"
$OU_Users       = "OU=Users,$OU_Corp"
$OU_Depts       = "OU=Departments,$OU_Users"
$OU_Service     = "OU=ServiceAccounts,$OU_Corp"
$OU_Groups      = "OU=Groups,$OU_Corp"
$OU_G_Global    = "OU=Global,$OU_Groups"
$OU_G_DLocal    = "OU=DomainLocal,$OU_Groups"
$OU_Computers   = "OU=Computers,$OU_Corp"
$OU_Servers     = "OU=Servers,$OU_Corp"
$OU_Offices     = "OU=Offices,$OU_Corp"

# OU structure
Write-Info "Creating OU structure..."
Ensure-OU $OU_Corp
Ensure-OU $OU_Users
Ensure-OU $OU_Depts
Ensure-OU $OU_Service
Ensure-OU $OU_Groups
Ensure-OU $OU_G_Global
Ensure-OU $OU_G_DLocal
Ensure-OU $OU_Computers
Ensure-OU $OU_Servers
Ensure-OU $OU_Offices

# Offices (sample global)
$Offices = @(
  "Brisbane","Sydney","Melbourne",
  "London","NewYork","Singapore"
)
foreach($o in $Offices){
    Ensure-OU "OU=$o,$OU_Offices"
}

# Departments
$Departments = @(
  "Executive","IT","Helpdesk","HR","Finance",
  "Accounting","Sales","Marketing","Engineering","Operations","Legal"
)
foreach($d in $Departments){
    Ensure-OU "OU=$d,$OU_Depts"
}

# Sites & Subnets (optional, illustrative)
Write-Info "Creating sample AD Sites & Subnets..."
$siteBase = 20
$i = 0
foreach($o in $Offices){
    $siteName = "SITE-$o"
    if(-not (Get-ADReplicationSite -Filter "Name -eq '$siteName'" -ErrorAction SilentlyContinue)){
        New-ADReplicationSite -Name $siteName | Out-Null
        Write-Ok "Site created: $siteName"
    }
    $octet = $siteBase + ($i*10)
    $subnet = "10.$octet.0.0/16"
    if(-not (Get-ADReplicationSubnet -Filter "Name -eq '$subnet'" -ErrorAction SilentlyContinue)){
        New-ADReplicationSubnet -Name $subnet -Site $siteName | Out-Null
        Write-Ok "Subnet created: $subnet -> $siteName"
    }
    $i++
}

# SECURITY GROUPS (AGDLP)
Write-Info "Creating security groups (Global for roles, Domain Local for resources)..."
# Department Global groups
foreach($d in $Departments){
    Ensure-Group -Name "GG_$d" -Path $OU_G_Global -Scope "Global"
}
# Office Global groups
foreach($o in $Offices){
    Ensure-Group -Name "GG_Office_$o" -Path $OU_G_Global -Scope "Global"
}

# Domain Local resource groups (per department share RW)
foreach($d in $Departments){
    Ensure-Group -Name "DL_Sh_${d}_RW" -Path $OU_G_DLocal -Scope "DomainLocal"
}

# Add role->resource (AGDLP): GG_Department -> DL_Sh_Department_RW
foreach($d in $Departments){
    try { Add-ADGroupMember -Identity "DL_Sh_${d}_RW" -Members "GG_$d" -ErrorAction Stop } catch {}
}

# ADMIN users: few named admins -> Domain Admins (lab)
Write-Info "Creating a few delegated admin accounts (lab)..."
$AdminOU = "OU=IT,$OU_Depts"
$LabAdminPwd = ConvertTo-SecureString "P@ssw0rd!23" -AsPlainText -Force
$Admins = @(
  @{Given="Alex";   Surname="King";   Sam="adm-aking"},
  @{Given="Jordan"; Surname="Lee";    Sam="adm-jlee"},
  @{Given="Morgan"; Surname="Taylor"; Sam="adm-mtaylor"}
)
foreach($a in $Admins){
    Ensure-User -GivenName $a.Given -Surname $a.Surname -Sam $a.Sam `
        -UPN "$($a.Sam)@$domain" -OU $AdminOU -Password $LabAdminPwd `
        -MemberOf @("GG_IT")
    try { Add-ADGroupMember "Domain Admins" $a.Sam -ErrorAction SilentlyContinue } catch {}
}

# Service accounts (not domain admins)
Write-Info "Creating a couple of service accounts..."
$Svc = @(
  @{Sam="svc-sql";    Given="SQL";    Surname="Service"},
  @{Sam="svc-backup"; Given="Backup"; Surname="Service"}
)
foreach($s in $Svc){
    Ensure-User -GivenName $s.Given -Surname $s.Surname -Sam $s.Sam `
        -UPN "$($s.Sam)@$domain" -OU $OU_Service -Password $LabAdminPwd `
        -MemberOf @()
}

# LARGE USER SET
Write-Info "Creating sample users across departments & offices (big-company feel)..."
$First = @("Olivia","Emma","Ava","Sophia","Isabella","Mia","Charlotte","Amelia","Harper","Evelyn",
           "Liam","Noah","Oliver","Elijah","James","William","Benjamin","Lucas","Henry","Alexander")
$Last  = @("Smith","Johnson","Williams","Brown","Jones","Garcia","Miller","Davis","Rodriguez","Martinez",
           "Hernandez","Lopez","Gonzalez","Wilson","Anderson","Thomas","Taylor","Moore","Jackson","Martin")

$UsersPerDept = 12  # tweak for more/less
$allUsers = @()
$rand = New-Object System.Random
foreach($dept in $Departments){
    1..$UsersPerDept | ForEach-Object {
        $fn = $First[$rand.Next(0,$First.Count)]
        $ln = $Last[$rand.Next(0,$Last.Count)]
        $base = "$fn.$ln".ToLower().Replace(" ","")
        # Ensure uniqueness
        $suffix= ""
        $n=1
        while(Get-ADUser -Filter "sAMAccountName -eq '$($base)$suffix'" -ErrorAction SilentlyContinue){ $suffix = $n; $n++ }
        $sam = "$base$suffix"
        $ou  = "OU=$dept,$OU_Depts"
        $ofc = $Offices[$rand.Next(0,$Offices.Count)]
        Ensure-User -GivenName $fn -Surname $ln -Sam $sam -UPN "$sam@$domain" -OU $ou -Password $LabAdminPwd `
            -MemberOf @("GG_$dept","GG_Office_$ofc")
        $allUsers += [pscustomobject]@{ Sam=$sam; Dept=$dept; Office=$ofc }
    }
}
Write-Ok "Created ~$($Departments.Count*$UsersPerDept) users."

# HOME FOLDERS
Write-Info "Creating home folders with NTFS perms (Modify to user)..."
Ensure-Dir $HomeRoot
foreach($u in $allUsers){
    $path = Join-Path $HomeRoot $u.Sam
    if(-not (Test-Path $path)){ New-Item -ItemType Directory -Path $path | Out-Null }
    # NTFS: remove inherited, grant user Modify, admins Full
    cmd /c "icacls `"$path`" /inheritance:r" | Out-Null
    cmd /c "icacls `"$path`" /grant `"$netbios\$($u.Sam)`":(OI)(CI)M /grant `"$netbios\Domain Admins`":(OI)(CI)F /T" | Out-Null
}

# SHARES + NTFS (lab on DC)
Write-Info "Creating lab shares + permissions (DC-hosted for lab only)..."
Ensure-Dir $ShareRoot
$DeptShares = $Departments | Where-Object { $_ -notin @("Executive") }  # leave Executive private (optional)
foreach($d in $DeptShares){
    $path = Join-Path $ShareRoot $d
    Ensure-Dir $path
    $shareName = "SH-$d"
    if(-not (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue)){
        New-SmbShare -Name $shareName -Path $path -FullAccess "$netbios\Domain Admins" | Out-Null
        # Share perms: Add DL group Change
        Grant-SmbShareAccess -Name $shareName -AccountName "$netbios\DL_Sh_${d}_RW" -AccessRight Change -Force | Out-Null
        # NTFS perms: DL RW, Admins Full
        cmd /c "icacls `"$path`" /inheritance:r" | Out-Null
        cmd /c "icacls `"$path`" /grant `"$netbios\DL_Sh_${d}_RW`":(OI)(CI)M /grant `"$netbios\Domain Admins`":(OI)(CI)F /T" | Out-Null
        Write-Ok "Share ready: \\$serverName\$shareName"
    }
}
# Public share
$PublicPath = Join-Path $ShareRoot "Public"
Ensure-Dir $PublicPath
if(-not (Get-SmbShare -Name "SH-Public" -ErrorAction SilentlyContinue)){
    New-SmbShare -Name "SH-Public" -Path $PublicPath -FullAccess "$netbios\Domain Admins" | Out-Null
    Grant-SmbShareAccess -Name "SH-Public" -AccountName "Authenticated Users" -AccessRight Read -Force | Out-Null
    cmd /c "icacls `"$PublicPath`" /inheritance:r" | Out-Null
    cmd /c "icacls `"$PublicPath`" /grant `"$netbios\Domain Users`":(OI)(CI)RX /grant `"$netbios\Domain Admins`":(OI)(CI)F /T" | Out-Null
    Write-Ok "Share ready: \\$serverName\SH-Public"
}

# USERS share (for Home drive parent)
if(-not (Get-SmbShare -Name "Users" -ErrorAction SilentlyContinue)){
    New-SmbShare -Name "Users" -Path $HomeRoot -FullAccess "$netbios\Domain Admins" | Out-Null
    Grant-SmbShareAccess -Name "Users" -AccountName "$netbios\Domain Users" -AccessRight Change -Force | Out-Null
    Write-Ok "Share ready: \\$serverName\Users"
}

# PRINTERS (per office) - dummy ports + shared printers
Write-Info "Installing generic printer driver & creating office printers..."
try { Add-PrinterDriver -Name "Generic / Text Only" -ErrorAction SilentlyContinue } catch {}
$ipBase = 50
$Printers = @()
foreach($o in $Offices){
    $ip = "192.0.2.$ipBase" # TEST-NET-1 space
    $port = "IP_$ip"
    if(-not (Get-PrinterPort -Name $port -ErrorAction SilentlyContinue)){
        Add-PrinterPort -Name $port -PrinterHostAddress $ip | Out-Null
    }
    $pName = "PRN-$o-01"
    if(-not (Get-Printer -Name $pName -ErrorAction SilentlyContinue)){
        Add-Printer -Name $pName -DriverName "Generic / Text Only" -PortName $port -Shared -ShareName $pName | Out-Null
        Write-Ok "Printer created/shared: \\$serverName\$pName"
    }
    $Printers += @{ Office=$o; Share=$pName }
    $ipBase += 1
}

# LOGON MAP SCRIPT in SYSVOL
Write-Info "Publishing mapping script in SYSVOL..."
$sysvol = "\\$domain\SYSVOL\$domain\scripts"
Ensure-Dir $sysvol
$scriptPath = Join-Path $sysvol "Map.ps1"

$mapScript = @"
# Maps department drives and connects office printers based on AD group membership.
# Safe to run repeatedly at each logon.

function In-Group([string]\$Group){
    try{
        \$wi  = [Security.Principal.WindowsIdentity]::GetCurrent()
        \$wp  = New-Object Security.Principal.WindowsPrincipal(\$wi)
        return \$wp.IsInRole("\$Group")
    }catch{ return \$false }
}

function Map-Drive([string]\$Letter,[string]\$Path){
    try{
        if((Get-PSDrive -Name \$Letter -ErrorAction SilentlyContinue)){ Remove-PSDrive -Name \$Letter -Force -ErrorAction SilentlyContinue }
        New-PSDrive -Name \$Letter -PSProvider FileSystem -Root \$Path -Persist -ErrorAction SilentlyContinue | Out-Null
    }catch{}
}

function Ensure-Printer([string]\$Name,[string]\$Server){
    try{
        \$conn = "\\\\\$Server\\\$Name"
        if(-not (Get-Printer -Name \$Name -ErrorAction SilentlyContinue)){
            Add-Printer -ConnectionName \$conn | Out-Null
        }
    }catch{}
}

\$server = \$env:LOGONSERVER.TrimStart("\")
\$domainNetBIOS = (whoami).Split("\")[0]

# Everyone: Public (S:)
Map-Drive -Letter "S" -Path "\\\\\$server\\SH-Public"

# Home drive (H:)
\$home = "\\\\\$server\\Users\\$env:USERNAME"
try{ if(-not (Test-Path \$home)){ New-Item -ItemType Directory -Path \$home -ErrorAction SilentlyContinue | Out-Null } }catch{}
Map-Drive -Letter "H" -Path \$home

# Department drives
if(In-Group "\$domainNetBIOS\\GG_IT"){          Map-Drive -Letter "T" -Path "\\\\\$server\\SH-IT" }
if(In-Group "\$domainNetBIOS\\GG_Helpdesk"){     Map-Drive -Letter "K" -Path "\\\\\$server\\SH-Helpdesk" }
if(In-Group "\$domainNetBIOS\\GG_HR"){           Map-Drive -Letter "R" -Path "\\\\\$server\\SH-HR" }
if(In-Group "\$domainNetBIOS\\GG_Finance"){      Map-Drive -Letter "F" -Path "\\\\\$server\\SH-Finance" }
if(In-Group "\$domainNetBIOS\\GG_Accounting"){   Map-Drive -Letter "A" -Path "\\\\\$server\\SH-Accounting" }
if(In-Group "\$domainNetBIOS\\GG_Sales"){        Map-Drive -Letter "Z" -Path "\\\\\$server\\SH-Sales" }
if(In-Group "\$domainNetBIOS\\GG_Marketing"){    Map-Drive -Letter "M" -Path "\\\\\$server\\SH-Marketing" }
if(In-Group "\$domainNetBIOS\\GG_Engineering"){  Map-Drive -Letter "E" -Path "\\\\\$server\\SH-Engineering" }
if(In-Group "\$domainNetBIOS\\GG_Operations"){   Map-Drive -Letter "O" -Path "\\\\\$server\\SH-Operations" }
if(In-Group "\$domainNetBIOS\\GG_Legal"){        Map-Drive -Letter "L" -Path "\\\\\$server\\SH-Legal" }

# Office printers
if(In-Group "\$domainNetBIOS\\GG_Office_Brisbane"){   Ensure-Printer -Name "PRN-Brisbane-01" -Server \$server }
if(In-Group "\$domainNetBIOS\\GG_Office_Sydney"){     Ensure-Printer -Name "PRN-Sydney-01" -Server \$server }
if(In-Group "\$domainNetBIOS\\GG_Office_Melbourne"){  Ensure-Printer -Name "PRN-Melbourne-01" -Server \$server }
if(In-Group "\$domainNetBIOS\\GG_Office_London"){     Ensure-Printer -Name "PRN-London-01" -Server \$server }
if(In-Group "\$domainNetBIOS\\GG_Office_NewYork"){    Ensure-Printer -Name "PRN-NewYork-01" -Server \$server }
if(In-Group "\$domainNetBIOS\\GG_Office_Singapore"){  Ensure-Printer -Name "PRN-Singapore-01" -Server \$server }
"@

Set-Content -Path $scriptPath -Value $mapScript -Encoding UTF8
Write-Ok "Logon mapping script: $scriptPath"

# GPO to run the mapping script at user logon via HKCU\...\Run
Write-Info "Creating & linking GPO to run mapping script at user logon..."
$gpoName = "GPO-User-Run-MapScript"
$gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
if(-not $gpo){ $gpo = New-GPO -Name $gpoName }
# HKCU Run value
Set-GPRegistryValue -Name $gpoName `
  -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" `
  -ValueName "ContosoMap" -Type String `
  -Value "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\$domain\SYSVOL\$domain\scripts\Map.ps1"
# Link at Corp\Users (affects all lab users)
$usersOU_DN = $OU_Users
if(-not (Get-GPInheritance -Target $usersOU_DN | Select-Object -ExpandProperty GpoLinks | Where-Object {$_.DisplayName -eq $gpoName})){
    New-GPLink -Name $gpoName -Target $usersOU_DN | Out-Null
}
Write-Ok "GPO linked: $gpoName -> $usersOU_DN"

# Optional: A tiny workstation baseline (screen lock after 15 min)
Write-Info "Adding a small workstation-baseline GPO (screen lock)..."
$baseGpo = "GPO-Workstation-Baseline"
$g2 = Get-GPO -Name $baseGpo -ErrorAction SilentlyContinue
if(-not $g2){ $g2 = New-GPO -Name $baseGpo }
# HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop
Set-GPRegistryValue -Name $baseGpo -Key "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ValueName "ScreenSaveActive" -Type String -Value "1"
Set-GPRegistryValue -Name $baseGpo -Key "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ValueName "ScreenSaverIsSecure" -Type String -Value "1"
Set-GPRegistryValue -Name $baseGpo -Key "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ValueName "ScreenSaveTimeOut" -Type String -Value "900"
# Link at Users
if(-not (Get-GPInheritance -Target $usersOU_DN | Select-Object -ExpandProperty GpoLinks | Where-Object {$_.DisplayName -eq $baseGpo})){
    New-GPLink -Name $baseGpo -Target $usersOU_DN | Out-Null
}
Write-Ok "Baseline GPO linked."

Write-Ok "Contoso lab build complete. Log off/on as a test user to see drives/printers map via groups."
Write-Info "Notes:
- AGDLP used: GG_Department -> DL_Sh_Department_RW -> resource ACLs.
- File shares & printers are on the DC for LAB ONLY (not best practice for production).
- We did not modify Default Domain Policy/Domain Controllers Policy.
- Extend easily: add departments/offices; adjust drive letters; increase UsersPerDept."
