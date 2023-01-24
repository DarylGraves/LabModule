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
        [System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty
    )
    
    $ScriptBlock = {
        param($Office)
        $Domain = $ENV:USERDNSDOMAIN.Split(".")
        $Domain = "DC=$($Domain[0]),DC=$($Domain[1])"

        New-ADOrganizationalUnit -Name $Office -Description $Office

        New-ADOrganizationalUnit -Name "Computers" -Description "$Office Computers" -Path "OU=$Office,$Domain"
        New-ADOrganizationalUnit -Name "Clients" -Description "$Office Client Computers" -Path "OU=Computers,OU=$Office,$Domain"
        New-ADOrganizationalUnit -Name "Servers" -Description "$Office Servers" -Path "OU=Computers,OU=$Office,$Domain"
        New-ADOrganizationalUnit -Name "Users" -Description "$Office Users" -Path "OU=$Office,$Domain"
    }

    if ($Null -ne $Server) {
        Invoke-Command -ComputerName $Server -Credential $Credential -ArgumentList $Office -ScriptBlock $ScriptBlock
    }
    else {
        . $ScriptBlock $Office
    }
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
        [System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty
    )   

    $ScriptBlock = {
        param($Office)
        $Domain = $ENV:USERDNSDOMAIN.Split(".")
        $Domain = "DC=$($Domain[0]),DC=$($Domain[1])"

        Get-ADOrganizationalUnit -Identity "OU=$Office,$Domain" | 
            Set-ADObject -ProtectedFromAccidentalDeletion $false -PassThru |
            Remove-ADOrganizationalUnit -Recursive
    }

    #TODO: Remove-LabOffice: Better validation - What happens if computers/users are in there? Move to Unsorted OU? What if Unsorted OU isn't there?
    #TODO: Remove-LabOffice: Confirm Switch so you don't have to confirm it

    if ($Null -ne $Server) {
        Invoke-Command -ComputerName $Server -Credential $Credential -ArgumentList $Office -ScriptBlock $ScriptBlock
    }
    else {
        . $ScriptBlock
    }
}