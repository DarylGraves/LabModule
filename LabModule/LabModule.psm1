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
function New-Password {
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

function Initialize-Lab {
    param (
        [string]$Server,
        [pscredential]$Credential = [pscredential]::Empty,
        [int]$NumberOfOffices = 5
    )

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
    
    # Created the "Unsorted" OU
    $UnsortedOu = New-ADOrganizationalUnit @AdParams -Name "Unsorted" -Description "Unsorted Objects" -PassThru
    
    #Redirect Computers and Users
    Invoke-Command @ExeParams -ArgumentList $UnsortedOu.DistinguishedName -ScriptBlock {
        param($Ou)
        Write-Host "Redirecting new Computers to $Ou - " -NoNewline -ForegroundColor Yellow
      #  redircmp.exe $Ou
        Write-Host "Redirecting new Users to $Ou - " -NoNewline -ForegroundColor Yellow
      #  redirusr.exe $Ou
    }

    $Offices = Get-Content "$ModulePath\Data\Countries.txt"

    $OfficesDone = @()
    $OfficesToCreate = $Offices | Sort-Object { Get-Random } | Select-Object -first $NumberOfOffices
    foreach ($Office in $OfficesToCreate) {
        New-LabOffice @AdParams -Office $Office
        $OfficesDone += $Office
    }


    #TODO: Create 300 Staff
    
}

