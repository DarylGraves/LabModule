<#
.SYNOPSIS
Generates a random password

.DESCRIPTION
Generates a random password - Used in New-LabUser()

.PARAMETER Length
Length of the password, by default this is 24.

.EXAMPLE
New-Password -Length 30
#>
function New-LabPassword {
    param (
        [Int]$Length = 24
    )
    
    $AvailableChars = ([char] 33 .. [char] 57) + ([char] 65 .. [char] 90) + ([char] 97 .. [char] 122)
    
    $Password = ""

    for ($i = 0; $i -lt $Length; $i++) {
        $Password += [char] $AvailableChars[(Get-Random -Minimum 0 -Maximum $AvailableChars.Count)]
    }

    return $Password
}

<#
.SYNOPSIS
Creates an office organizational unit and the users, computers, clients and servers organizational units inside.

.DESCRIPTION
Creates an office organizational unit and the users, computers, clients and servers organizational units inside

.PARAMETER Office
Office. E.g "GB-London"

.EXAMPLE
New-LabOffice -Office "GB-London"
#>
function New-LabOffice {
    param (
        [String]$Office,
        [String]$Server,
        [PSCredential]$Credential = [PSCredential]::Empty
    )
    
    $Params = @{}

    if ($Server) {
        $Params.Server = $Server
    }

    if ($Credential -ne [PSCredential]::Empty) {
        $Params.Credential = $Credential
    }

    # Check "Offices" OU Exists:
    $Ou = Get-ADOrganizationalUnit @Params -Filter "Name -like 'Offices'"
    if ($null -eq $Ou) {
        Write-Host "Creating 'Offices' OU" -ForegroundColor Yellow
        $Ou = New-ADOrganizationalUnit @Params -Name "Offices" -Description "Offices OU" -PassThru
    }

    Write-Host "Creating Office OU: $Office" -ForegroundColor Yellow
    $OfficeOu = New-ADOrganizationalUnit @Params -Name $Office -Description $Office -Path $Ou.DistinguishedName -PassThru
    New-ADOrganizationalUnit @Params -Name "Users" -Description "$Office Staff" -Path $OfficeOu.DistinguishedName

    $ComputersOu = New-ADOrganizationalUnit @Params -Name "Computers" -Description "$Office Computers" -Path $OfficeOu.DistinguishedName -PassThru
    New-ADOrganizationalUnit @Params -Name "Clients" -Description "$Office Client Computers" -Path $ComputersOu.DistinguishedName
    New-ADOrganizationalUnit @Params -Name "Servers" -Description "$Office Servers" -Path $ComputersOu.DistinguishedName
}

<#
.SYNOPSIS
Removes an office organizational unit and all nested organizational units inside.

.DESCRIPTION
Removes an office organizational unit and all nested organizational units inside.

.PARAMETER Office
Office. E.g "GB-London"

.EXAMPLE
Remove-LabOffice -Office "GB-London"
#>
function Remove-LabOffice {
    param (
        [String]$Office,
        [String]$Server,
        [pscredential]$Credential = [pscredential]::Empty
    )   

    $Params = @{}

    if ($Server) {
        $Params.Server = $Server
    }

    if ($Credential -ne [PsCredential]::Empty) {
        $Params.Credential = $Credential
    }

    $TargetOu = Get-ADOrganizationalUnit -Filter "Name -like '$Office'" @Params
    $ObjectsToMove = Get-ADObject -SearchBase $TargetOu.DistinguishedName -Filter "ObjectClass -ne 'OrganizationalUnit'" @Params 
    $UnsortedOu = Get-ADObject -Filter "Name -like 'Unsorted'" @Params | Where-Object ObjectClass -like "OrganizationalUnit"

    foreach ($object in $ObjectsToMove) {
        Write-Host "Moving $($Object.DistinguishedName)"
        Move-ADObject -Identity $Object.DistinguishedName -TargetPath $UnsortedOu.DistinguishedName @Params
    }

    Set-ADObject $TargetOu -ProtectedFromAccidentalDeletion $False -PassThru | Remove-ADOrganizationalUnit -Recursive -Confirm:$False
}

<#
.SYNOPSIS
Creates a Home Lab in seconds
.DESCRIPTION
Creates a Home Lab in seconds - Redirects new Users and Computers into an Unsorted OU, creates Office OUs and Users

.PARAMETER Server
An Active Directory Domain Controller. If left blank, attempts to action requests on localhost.

.PARAMETER Credential
Domain Admin Credentials

.PARAMETER NumberOfOffices
How many Office OUs should be created.

.PARAMETER NumberOfStaff
How many members of staff should be created.

.EXAMPLE
Initialize-Lab -Server "MyDc01" -Credential (Get-Credential) -NumberofStaff 100 -NumberOfOffices 3

.NOTES
Please note this is not designed for a produciton. User's passwords are saved to Active Directory themselves so you can use these which is a big no-no in IT Security.

Passowrds are stored in the "Comment" section of Active Directory. This can be retrieved via Active Directory Users and Computers by enabling Advanced Features or by using the following Powershell cmdlet: "Get-AdUser <Name> -Properties Commemnt"
#>
function Initialize-Lab {
    param (
        [string]$Server,
        [pscredential]$Credential = [pscredential]::Empty,
        [int]$NumberOfOffices = 10,
        [int]$NumberOfStaff = 250
    )
    
    if ($NumberOfStaff -gt 10000) {
        Write-Error "Max staff is 10,000. Don't be silly." 
        exit
    }

    $AdParams = @{}
    $ExeParams = @{}
    $ModulePath = $MyInvocation.MyCommand.Module.ModuleBase

    if ($Server) {
        $AdParams.Server = $Server
        $ExeParams.ComputerName = $Server
    }
    if ($Credential) {
        $AdParams.Credential = $Credential
        $ExeParams.Credential = $Credential
    }
    
    # Prompt user to accept risks
    Clear-Host 
    if ([System.Console]::WindowWidth -gt 80 ) {
        Write-Host "
      _   _                      _          _        ___   ___   ___   ___  
     | | | | ___  _ __ ___   ___| |    __ _| |__    / _ \ / _ \ / _ \ / _ \ 
     | |_| |/ _ \| '_   _ \ / _ \ |   / _  |  _ \  | (_) | | | | | | | | | |
     |  _  | (_) | | | | | |  __/ |__| (_| | |_) |  \__, | |_| | |_| | |_| |
     |_| |_|\___/|_| |_| |_|\___|_____\__,_|_.__/     /_/ \___/ \___/ \___/ 
                                                                            
                    For all your HomeLabbing needs!" -ForegroundColor Green
    }
    else {
        Write-Host "HomeLab 9000: For all your HomeLabbing needs!" -ForegroundColor Green
    }
    
    Start-Sleep -Seconds 2

    # Test Invoke-Command because this all breaks without it.
    Write-Host "`nTesting Invoke-Command... " -ForegroundColor Yellow -NoNewline
    try {
        Invoke-Command @ExeParams -ScriptBlock { Write-Host "Success!" -ForegroundColor Green} -ErrorAction Stop
    }
    catch {
        Write-Host "Fail." -ForegroundColor Red
        Write-Host "`nBefore you can use this script remotely you will need to add your local machine to the remote Domain Controller's Trust Hosts.`nConnect directly to the Domain Controller and then run the below:`n" -ForegroundColor Yellow
        Write-Host "`twinrm set winrm/config/client '@{TrustedHosts = " -ForegroundColor Green -NoNewline
        Write-Host "<Your Machine's Computer Name>" -ForegroundColor Blue -NoNewline
        Write-Host "}'`n" -ForegroundColor Green
        Write-Host "You can verify the output with:`n" -ForegroundColor Yellow
        Write-Host "`twinrm get winrm/config/client`n" -ForegroundColor Green
        Write-Host "Make sure you also use the FQDN for the Domain Controller - This includes the Domain Suffix at the end!" -ForegroundColor Yellow
        Write-Host "Exiting...`n" -ForegroundColor Yellow
        return
    }

    # Retrieve the Domain Details:
    try {
        $AdEnv = Get-ADRootDSE @AdParams
        Write-Host "Domain found on target: " -ForegroundColor Yellow -NoNewLine
        Write-Host "$($AdEnv.defaultNamingContext)" -ForegroundColor Green
    }
    catch {
        if ($Server -eq "") {
            Write-Host "Error: Could not find Domain on Local Machine. Aborting..." -ForegroundColor Yellow
        }
        else{
            Write-Host "Error: Could not find Domain on $Server. Potentially wrong credentials or maybe you're not targeting a Domain Controller? Either way, aborting..." -ForegroundColor Yellow
        }
        return
    }

    # Passed the test, so starting the script:
    Write-Host "`n***WARNING*** This Cmdlet creates uses and stores the passwords in Active Directory!`n" -ForegroundColor Yellow
    Write-Host "Everyone can see the passwords so under no circumstances should this be used in Production!`n" -ForegroundColor Yellow

    $IsValid = $False
    do {
        $UserInput = Read-Host -Prompt "Please enter 'Y' to confirm you understand this. Ctrl+C to cancel"
        if ($UserInput -eq "Y") {
            $IsValid = $True
        }
    } while (
        $IsValid -eq $False
    )

    # Creating the "Unsorted" OU
    try {
        Write-Host "`nCreating Unsorted OU..." -ForegroundColor Yellow
        $UnsortedOu = New-ADOrganizationalUnit @AdParams -Name "Unsorted" -Description "Unsorted Objects" -PassThru
    }
    catch {
        Write-Host "Already exists!" -ForegroundColor Yellow
        $UnsortedOu = Get-ADOrganizationalUnit @AdParams -Filter "Name -like 'Unsorted'"
    }
    
    #Redirect Computers and Users, Hide Default Containers
    Invoke-Command @ExeParams -ArgumentList $UnsortedOu.DistinguishedName, $AdEnv -ScriptBlock {
        param($Ou, $AdEnv)
        Write-Host "Redirecting new Computers to $Ou" -ForegroundColor Yellow
        redircmp.exe $Ou | Out-Null
        Write-Host "Redirecting new Users to $Ou" -ForegroundColor Yellow
        redirusr.exe $Ou | Out-Null

        Import-Module ActiveDirectory
        Set-Location Ad:\$($AdEnv.DefaultNamingContext)
        Write-Host "Setting containers on the root to only appear in Advanced View" -ForegroundColor Yellow
        try {
            $Containers = Get-ChildItem | Where-Object { ( $_.ObjectClass -like "Container" ) -or ( $_.ObjectClass -like "builtInDomain" ) }
            $Containers.DistinguishedName | ForEach-Object { Set-ADObject -Identity $_ -Replace @{ "showInAdvancedViewOnly" = $True }  }
        }
        catch {
            Write-Host "Error occured..." -ForegroundColor Red
        }
    }

    # Create Groups 
    try {
        Write-Host "Creating Group OUs" -ForegroundColor Yellow
        $GroupOu = New-ADOrganizationalUnit @AdParams -Name "Groups" -Description "Groups" -PassThru
        New-ADOrganizationalUnit @AdParams -Name "Global" -Description "Add Users to these Groups" -Path $GroupOu.DistinguishedName
        New-ADOrganizationalUnit @AdParams -Name "Domain Local" -Description "Add Global Groups to these. Do not add individual users!" -Path $GroupOu.DistinguishedName
    }
    catch {
        Write-Host "Error occured..." -ForegroundColor Red
    }

    # Create Admin Account Location
    try {
        Write-Host "Creating Elevated Accounts OU" -ForegroundColor Yellow
        New-ADOrganizationalUnit @AdParams -Name "Elevated Accounts" -Description "IT Admin Accounts Only"
    }
    catch {
        Write-Host "Error occcured, may already exist" -ForegroundColor Red
    }

    # Create the offices
    $Offices = Get-Content -Path "$ModulePath\Data\Countries.txt"

    $OfficesDone = @()
    $OfficesToCreate = $Offices | Sort-Object { Get-Random } | Select-Object -first $NumberOfOffices
    foreach ($Office in $OfficesToCreate) {
        try {
            New-LabOffice @AdParams -Office $Office
            $OfficesDone += $Office
        }
        catch {
            Write-Host "Attempted to create $Office OU but it failed (Either cred issue or OU already exists)" -ForegroundColor Yellow
        }
    }

    # Create the Users
    $UsersNameFile = Import-Csv -Path "$ModulePath\Data\Names.csv"
    $FirstNames = $UsersNameFile.FirstName | Sort-Object { Get-Random }
    $Sirnames = $UsersNameFile.Sirname | Sort-Object { Get-Random }
    $Roles = Import-Csv -Path "$ModulePath\Data\Roles.csv"

    for ($i = 0; $i -lt $NumberOfStaff; $i++) {
        # Picking a random Office and Role for the user
        $TargetOffice = $OfficesDone | Sort-Object { Get-Random } | Select-Object -First 1
        $OfficeOu = (( Get-ADOrganizationalUnit @AdParams -Filter "name -like '$TargetOffice'").DistinguishedName)
        $TargetOu = "OU=Users," + $OfficeOu
        $Role = $Roles | Sort-Object{ Get-Random } | Select-Object -First 1
        
        # Find unique SamAccountName
        $Numbering = 0
        do {
            $User = $Null
            try {
                if ($Numbering -eq 0) {
                    $User = Get-ADUser @AdParams -Identity ($Firstnames[$i][0] + $Sirnames[$i])
                    $Numbering++
                }
                else {
                    $User = Get-ADUser @AdParams -Identity ($Firstnames[$i][0] + $Sirnames[$i] + $Numbering)
                    $Numbering++
                }
            }
            catch {
                $Numbering++
            }
        } until ( $Null -eq $User )

        if ($Numbering -eq 1) {
            $SamAccountName = ($Firstnames[$i][0] + $Sirnames[$i])
        } else {
            $SamAccountName = ($Firstnames[$i][0] + $Sirnames[$i] + $Numbering)
        }

        # Create the splat
        $Password = New-LabPassword -Length 24 
        $UserParams = @{
            GivenName = $Firstnames[$i]
            Surname = $Sirnames[$i]
            Name = $Firstnames[$i] + " " + $Sirnames[$i]
            Displayname = $Firstnames[$i] + " " + $Sirnames[$i]
            SamAccountName = $SamAccountName
            UserPrincipalName = $SamAccountName
            Country = ($TargetOffice -split "-")[0]
            City = ($TargetOffice -split "-")[1]
            Title = ($Role.Role)
            Department = ($Role.Department)
            Office = ($TargetOffice -split "-")[1]
            Description = "$($Role.Role), $($Role.Department)"
            EmployeeID = $i
            EmployeeNumber = $i
            AccountPassword = ($Password | ConvertTo-SecureString -AsPlainText -Force)
            ChangePasswordAtLogon = $True
            Enabled = $True
            Path = $TargetOu
            Server = ($AdParams.Server)
            Credential = ($AdParams.Credential)
            OtherAttributes = @{
                "Comment" = $Password
            }
            
        }

        Write-Host "Creating User $($i+1) of $NumberOfStaff - $($UserParams.GivenName) $($UserParams.Surname) ($TargetOffice)" -ForegroundColor Yellow 
        
        New-AdUSer @UserParams

    }
}

#TODO: Need to make Initialize Module move things out of Containers and hide them
#TODO: Need to create Groups OU with different options (Groups -> Domain Local and Groups -> Global). Domain Local drive ACL but only Global Groups have users. They go into Domain Locals.