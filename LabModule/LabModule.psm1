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
Get a valid department

.DESCRIPTION
Gets a department - Used in New-LabUser()

.EXAMPLE
Get-Department
#>
function Get-Department {
    $Departments = @(
                    "Administration",
                    "Facilities",
                    "Finance",
                    "Health and Safety",
                    "Human Resources",
                    "Information Technology",
                    "Project Worker"
                )
    
    # 2/3rds of the workforce should be Project Workers
    if ((Get-Random -Minimum 0 -Maximum 3) -eq 2) {
        return $Departments[(Get-Random -Minimum 0 -Maximum $Departments.Count)]   
    } else {
        return $Departments[($Departments.Count - 1)]
    }
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

<#
.SYNOPSIS
Creates random user(s) in Active Directory.

.DESCRIPTION
Creates random user(s) in Active Directory and places them in the Office OU.

.PARAMETER Office
User's office, e.g "GB-Reading"

.PARAMETER Quantity
Number of users to create.

.EXAMPLE
New-LabUser -Office "GB-Reading" -Quantity 10
(This creates 10 users in the Reading office.)
#>
function New-LabUser {
    param (
        [Parameter(Mandatory=$True)]
        [String]$Office,
        [Int]$Quantity
    )
    

    #TODO: If moving back to the Scratchpad you need to swap this variable.
    $DataFolderPath = $MyInvocation.PSScriptRoot + "\LabModule\Data\"
    #$DataFolderPath = $MyInvocation.MyCommand.Module.ModuleBase + "\Data\"

    $FirstnamesFile = $DataFolderPath + "Firstnames.txt"
    $SurnamesFile = $DataFolderPath + "Surnames.txt"

    $Firstnames = Get-Content $FirstnamesFile
    $Surnames = Get-Content $SurnamesFile

    $OU = "OU=Users,OU=$Office,OU=Offices,Dc=lab,dc=pri"

    try {
        $EmployeeNumber = Get-AdUser -filter * -properties EmployeeNumber | Sort-Object EmployeeNumber | Select-Object -First EmployeeNumber
    }
    catch {
        # RSAT Tools aren't installed, no biggy.
    }

    if ($Quantity -eq 0) { $Quantity = 1 }
    if ($EmployeeNumber -eq 0) { $EmployeeNumber = 1 }

    $Users = for ($i = 0; $i -lt $Quantity; $i++) {
        $Firstname = $Firstnames[(Get-Random -Minimum 0 -Maximum $Firstnames.Length)]
        $Surname = $Surnames[(Get-Random -Minimum 0 -Maximum $Surnames.Length)]
        $Username = ($Firstname[0] + ($Surname -Replace " ", "")).ToLower()
        $OfficeCountry = $Office -split "-"
        $Department = Get-Department

        #TODO: If username already exists...
        
        $User = @{
            EmployeeNumber = $EmployeeNumber + $i
            GivenName = $Firstname
            Surname = $Surname
            Name = $Firstname + " " + $Surname
            DisplayName = $Firstname + " " + $Surname
            UserPrincipalName = $Username
            SamAccountName = $Username
            Office = $Office
            City = $OfficeCountry[1]
            Country = $OfficeCountry[0]
            AccountPassword = (New-Password | ConvertTo-SecureString -AsPlainText -Force)
            Department = $Department
            Description = $Department
            ChangePasswordAtLogon = $True
            Path = $OU
        }

        $User
    }

    foreach ($User in $Users) {
        New-AdUser @User
    }
}