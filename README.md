# PSWorkplaceModule

This is a PowerShell module for administration of Facebook Workplace - and is very much currently a work in progress.

# Installation

Copy the "WorkplaceModule" folder and all its contents to your local powershell modules directory (run `$env:PSModulePath` to locate.

Open Powershell and verify that the module is available

`Get-Module -ListAvailable`

WorkplaceModule should appear in the list returned. 

Next import the module to the current PowerShell session

`Import-Module WorkplaceModule`

Each time the module is imported, it will require initialisation. This is to verifiy that the Access Token for the Workplace/Facebook REST API is correct. Access tokens are encrypted using a certificate provided with the module, and stored in their encrypted form in the /Secrets/API_Key.txt file. 

`Start-WorkplaceModule -Verbose` 

*I always reccomend using the `-Verbose` parameter during the initialisation*

The module will then ask for a password. This is used to unlock the private key of the certificate provided and install into the personal certificate store. **Obviously this isn't the most secure of methods, and is on the TODO list to adapt, however it is preferable to storing the Access Token in plain text**

Enter the password 
> Password1

The module then throws an error stating that it cannot find the `API_Key.txt` file, and asks the user for the Access Token. copy and paste the token into the console window

The module will then be setup correctly with the Access Token stored.

Test the module by running the following:

`Get-WorkplaceCommunityID`

if the module is working correctly the console will display the CommunityID which generated the Access Token.

# General Usage

#### Start-WorkplaceModule
Used to initialise the module, must be run each time the module is imported

`Start-WorkplaceModule`

#### Get-WorkplaceCommunityID
Returns the community id as a string

`Get-WorkplaceCommunityID`

#### Get-WorkplaceGroup
Returns an array of all groups, or a single group based upon the parameters specified

`Get-WorkplaceGroup`

Returns all groups as an array of groups

`Get-WorkplaceGroup -GroupName "Example Group Name"`

Returns all groups with the name matching "Example Group Name"

`Get-WorkplaceGroup -GroupID "Example Group ID"`

Returns all groups with the ID matching "Example Group ID"

#### Get-WorkplaceGroupMember
Returns the Workplace user ID and group membership properties of all the members of a given Workplace group

`Get-WorkplaceGroupMember -GroupID "Example Group ID"`

#### Get-WorkplaceUser
Returns an array of users currently available within the Workplace community. By specifying parameters the result can be scoped to an individual user

`Get-WorkplaceUser`

 Returns all users within the community

`Get-WorkplaceUser -EmailAddress "Example@Email.com"`

Returns a single user with the email address "Example@Email.com"

`Get-WorkplaceUser -UserID "Example User ID"`

Returns a single user with the ID "Example User ID"

#### New-WorkplaceGroup
Creates a new group in the Workplace community and assigns an admin. This cmdlet returns the group object.

`New-WorkplaceGroup -GroupName[String] -Description[String] -Privacy["OPEN","CLOSED","SECRET"] -Admin[Workplace User ID]`

`New-WorkplaceGroup -GroupName "Example Group Name" -Description "This is a group used for the example" -Privacy "CLOSED" -Admin "1234567890"`

`New-WorkplaceGroup -GroupName "Example Group Name" -Description "This is a group used for the example" -Privacy "CLOSED" -Admin (Get-WorkplaceUser -EmailAddress "xxxxxxx@xxxxx.xxxx").id`

#### Set-WorkplaceGroup
Set properties of a group based upon supplied parameters.

`Set-WorkplaceGroup -GroupID[String](Required) -Name[String] -Description[String] -Owner[String] -Privacy[String](OPEN,CLOSED,SECRET)`

`Set-WorkplaceGroup -GroupID "Example Group ID" -Name "New Group Name" -Description "New Group Description" -Owner "Workplace User ID of Owner" -Privacy OPEN`

