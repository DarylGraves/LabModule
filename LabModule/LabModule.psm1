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

    $OfficeOu = New-ADOrganizationalUnit @Params -Name $Office -Description $Office -PassThru
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
    Set-ADObject $TargetOu -ProtectedFromAccidentalDeletion $False -PassThru | Remove-ADOrganizationalUnit -Recursive -Confirm:$False

    #TODO: Remove-LabOffice: Better validation - What happens if computers/users are in there? Move to Unsorted OU? What if Unsorted OU isn't there?
}