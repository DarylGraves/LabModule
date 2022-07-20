$Domain = "DC=lab,DC=pri"

do
{
    $Valid = "N"
    $Office = Read-Host "Please enter new office OU (e.g. GB-Reading)"
    Write-Host "OU to create: " -NoNewline
    Write-Host $Office -ForegroundColor Yellow
    $Valid = Read-Host -Prompt "Type Y to proceed"

} while ($Valid -ne "Y")

Write-Host "Creating " -NoNewline
Write-Host $Office -ForegroundColor Yellow

New-ADOrganizationalUnit -Name $Office -Description $Office
New-ADOrganizationalUnit -Name "Computers" -Description "$Office Computers" -Path "OU=$Office,$Domain"
New-ADOrganizationalUnit -Name "Clients" -Description "$Office Client Computers" -Path "OU=Computers,OU=$Office,$Domain"
New-ADOrganizationalUnit -Name "Servers" -Description "$Office Servers" -Path "OU=Computers,OU=$Office,$Domain"
New-ADOrganizationalUnit -Name "Users" -Description "$Office Users" -Path "OU=$Office,$Domain"