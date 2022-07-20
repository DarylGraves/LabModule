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
        [String]$Office
    )
    
    Domain = $ENV:USERDNSDOMAIN.Split(".")
    $Domain = "DC=$($Domain[0]),DC=$($Domain[1])"

    New-ADOrganizationalUnit -Name $Office -Description $Office

    New-ADOrganizationalUnit -Name "Computers" -Description "$Office Computers" -Path "OU=$Office,$Domain"
    New-ADOrganizationalUnit -Name "Clients" -Description "$Office Client Computers" -Path "OU=Computers,OU=$Office,$Domain"
    New-ADOrganizationalUnit -Name "Servers" -Description "$Office Servers" -Path "OU=Computers,OU=$Office,$Domain"
    New-ADOrganizationalUnit -Name "Users" -Description "$Office Users" -Path "OU=$Office,$Domain"

    #TODO: New-LabOffice: Credentials Parameter
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
        [String]$Office
    )   

    $Domain = $ENV:USERDNSDOMAIN.Split(".")
    $Domain = "DC=$($Domain[0]),DC=$($Domain[1])"

    Get-ADOrganizationalUnit -Identity "OU=$Office,$Domain" | 
        Set-ADObject -ProtectedFromAccidentalDeletion $false -PassThru |
        Remove-ADOrganizationalUnit -Recursive

    #TODO: Remove-LabOffice: Better validation - What happens if computers/users are in there? Move to Unsorted OU? What if Unsorted OU isn't there?
    #TODO: Remove-LabOffice: Confirm Switch so you don't have to confirm it
    #TODO: Remove-LabOffice: Credentials parameter
}