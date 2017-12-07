<#  This file is part of the Workplace Powershell Module.

    Workplace Powershell Module is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Workplace Powershell Module is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.

    Copyright © 2017 Ollie Hunter (ollie@olliehunter.com)
#>

<#
.Synopsis
   INTERNAL FUNCTION - Used to encrypt the API Key using a certificate passed to the function through the $cert variable
.EXAMPLE
   Encrypt-Key -$unprotectedcontent "Example unprotected string" -cert (Get-ChildItem "Cert:\CurrentUser\My\[PATH TO CERTIFICATE - NORMALLY THE THUMBPRINT")
#>
Function Encrypt-Key ($unprotectedcontent, $cert) {

            [System.Reflection.Assembly]::LoadWithPartialName("System.Security") | Out-Null

            $utf8content = [Text.Encoding]::UTF8.GetBytes($unprotectedcontent)

            $content = New-Object Security.Cryptography.Pkcs.ContentInfo -argumentList (,$utf8content)

            $env = New-Object Security.Cryptography.Pkcs.EnvelopedCms $content

            $recpient = (New-Object System.Security.Cryptography.Pkcs.CmsRecipient($cert))

            $env.Encrypt($recpient)

            $base64string = [Convert]::ToBase64String($env.Encode())

            return $base64string

}

<#
.Synopsis
   INTERNAL FUNCTION - Used to decrypt the API Key using a certificate already stored in the certificate store
.EXAMPLE
   Decrypt-Key -$base64string "some base64 string"
#>
Function Decrypt-Key ($base64string) {

            [System.Reflection.Assembly]::LoadWithPartialName("System.Security") | Out-Null

            $content = [Convert]::FromBase64String($base64string)

 

            $env = New-Object Security.Cryptography.Pkcs.EnvelopedCms

            $env.Decode($content)

            $env.Decrypt()

 

            $utf8content = [text.encoding]::UTF8.getstring($env.ContentInfo.Content)

            return $utf8content

}

<#
.Synopsis
   Returns the ID of the Workplace Community which the API Key has been generated from. This function returns the ID as a string
.EXAMPLE
   Get-WorkplaceCommunityID
#>
Function Get-WorkplaceCommunityID {
    Begin {

    }

    Process {
        $Response = Invoke-RestMethod -Uri "https://graph.facebook.com/community" -Headers $MyInvocation.MyCommand.Module.PrivateData['workplaceHeader'] -Method get -TimeoutSec 30
        Return $Response.id
    }

    End {

    }

}

<#
.Synopsis
   INTERNAL FUNCTION - This function is used by all GRAPH API "GET" functions to return data based upon a specific URI provided in the $WorkplaceURL Parameter. This functions primary purpose is to request the data, page appropriately and return an array of objects based upon the original request.
   The Header information for the HTTP request is provided by the decrypted private data variable "workplaceHeader" which is written to memory using the Start-WorkplaceModule function.

   ENSURE THAT Start-WorkplaceModule has been run successfully before running this command (using "Start-WorkplaceModule -Verbose" will provide detailed error output)
.EXAMPLE
   Get-WorkplaceWebRequest -WorkplaceURL "https://graph.facebook.com/community"
#>
Function Get-WorkplaceWebRequest {
    PARAM(
        [Parameter(Mandatory=$true)]
        [string]$WorkplaceURL
        )

    Begin {
        $ReturnArr = @()
        Write-Verbose "Web Request Setup Complete"
    }

    Process {
        Write-Verbose "Requesting data from $WorkplaceURL"
        $RequestResult = Invoke-RestMethod -Uri $WorkplaceURL -Method Get -Headers $MyInvocation.MyCommand.Module.PrivateData['workplaceHeader'] -TimeoutSec 30

        if($RequestResult.data) {
                $ReturnArr = $RequestResult.data
                Write-Verbose "Completed 1st request: Results so far...... <<TODO>>"
                If($RequestResult.paging.next -eq "") {
                    Write-Verbose "No more data to collect..."
                    $NextUri = $False
                  } Else {
                    Write-Verbose "There is more data to collect..."
                    $NextUri = $RequestResult.paging.next
                  }

                While($NextUri) {
                    Write-Verbose "Requesting data from $NextUri"
                    $NextRequestResult = Invoke-RestMethod -Uri $NextUri -Method Get -Headers $MyInvocation.MyCommand.Module.PrivateData['workplaceHeader'] -TimeoutSec 30
                    $ReturnArr = $ReturnArr + $NextRequestResult.data
                    If($NextRequestResult.paging.next -eq "") {
                        Write-Verbose "No more data to collect..."
                        $NextUri = $false
                       } Else {
                        Write-Verbose "There is more data to collect..."
                        $NextUri = $NextRequestResult.paging.next
                       }
                    }
                Return $ReturnArr
                    
        } Else {
            Return $RequestResult
            }      
    }

    End {
        Write-Verbose "Web Request Finished"
    }

    
    
}

<#
.Synopsis
   INTERNAL FUNCTION - This function is used by all GRAPH API "PUT" functions to send data based upon a specific URI provided in the $WorkplaceURL Parameter. This functions primary purpose is to push the data to the API and return a success or error for further processing as an array.
   The Header information for the HTTP request is provided by the decrypted private data variable "workplaceHeader" which is written to memory using the Start-WorkplaceModule function.

   ENSURE THAT Start-WorkplaceModule has been run successfully before running this command (using "Start-WorkplaceModule -Verbose" will provide detailed error output)
.EXAMPLE
   Set-WorkplaceWebRequest -WorkplaceURL "https://graph.facebook.com/[CommunityID]/groups?name={...}&description={...}&privacy=OPEN"
#>
Function Set-WorkplaceWebRequest {
    PARAM(
        [Parameter(Mandatory=$false)]
        [string]$WorkplaceURL
        )

    Begin {
        $ReturnArr = @()
        Write-Verbose "Web Request Setup Complete"
    }

    Process {
        $ReturnObj = New-Object -TypeName PSObject
        $ReturnObj | Add-Member -MemberType NoteProperty -Name RequestURL -Value ""
        $ReturnObj | Add-Member -MemberType NoteProperty -Name Status -Value ""

        Write-Verbose "Posting data to $WorkplaceURL"
            try 
                {
                    $RequestResponse = Invoke-RestMethod $WorkplaceURL -Headers $MyInvocation.MyCommand.Module.PrivateData['workplaceHeader'] -Method Post -TimeoutSec 30 -ErrorVariable ErrVar -ErrorAction SilentlyContinue
                    $ReturnObj.RequestURL = $WorkplaceURL
                    $ReturnObj.Status = $RequestResponse
                    $ReturnArr = $ReturnArr + $ReturnObj
                }

            catch 
                {
                    
                    Write-host "An Error Occured for: $WorkplaceURL"
                    Write-verbose $ErrVar.message
                    Return $False
                }

                   
              
              }

    End {
        return $ReturnArr
    }

}

<#
.Synopsis
   INTERNAL FUNCTION - This function is used by all SCIM API "GET" functions to return data based upon a specific URI provided in the $WorkplaceURL Parameter. This functions primary purpose is to request the data, page appropriately and return an array of objects based upon the original request.
   The Header information for the HTTP request is provided by the decrypted private data variable "workplaceHeader" which is written to memory using the Start-WorkplaceModule function.

   ENSURE THAT Start-WorkplaceModule has been run successfully before running this command (using "Start-WorkplaceModule -Verbose" will provide detailed error output)
.EXAMPLE
   Get-WorkplaceAccountManagementWebRequest -$AccountManagementURI "https://www.facebook.com/scim/v1/Users/"
#>
Function Get-WorkplaceAccountManagementWebRequest {
    PARAM(
        [Parameter(Mandatory=$true)] 
        $AccountManagementURI
    )

    Begin
    {
        $ReturnArr = @()
        Write-Verbose "Web Request Setup Complete"
    }

    Process
    {
        Write-Verbose "Requesting data from $AccountManagementURI"
        $RequestResult = Invoke-RestMethod -Uri $AccountManagementURI -Method Get -Headers $MyInvocation.MyCommand.Module.PrivateData['workplaceHeader'] -TimeoutSec 30
        
        if($RequestResult.Resources){
                Write-Verbose "Result has resources to inspect"
                $ReturnArr = $ReturnArr + $RequestResult.Resources
        
                $totalItems = $RequestResult.totalResults
                $itemsReturned = $RequestResult.itemsPerPage
                $itemsPerPage = $RequestResult.itemsPerPage
                $startIndex = $RequestResult.startIndex

                while($totalItems -gt $itemsReturned) {
                    Write-Verbose "More than one page of results. Performing further calls ($itemsReturned/$totalItems)"
                    $Pageurl = $AccountManagementURI.Substring(0,$AccountManagementURI.LastIndexOf("?")) + "?count=$itemsPerPage&startIndex=$ItemsReturned"
                    Write-Verbose "New Page URL: $Pageurl"
                    $RequestResult = Invoke-RestMethod -Uri $Pageurl -Method Get -Headers $MyInvocation.MyCommand.Module.PrivateData['workplaceHeader'] -TimeoutSec 30
                    $ReturnArr = $ReturnArr + $RequestResult.Resources
                    $itemsReturned = $itemsReturned + $RequestResult.itemsPerPage
                    }
         } Else {
                Write-Verbose "Result is a single item with no resources"
         }

    }

    End
    {
        Return $ReturnArr
        Write-Verbose "Web Request Complete"
    }
}

<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
      
function Set-WorkplaceAccountManagementWebRequest {
    
  PARAM (
        # Param1 help description
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [ValidateCount(0,5)]
        [ValidateSet("sun", "moon", "earth")]
        [Alias("p1")] 
        $Param1,

        # Param2 help description
        [Parameter(ParameterSetName='Parameter Set 1')]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [ValidateScript({$true})]
        [ValidateRange(0,5)]
        [int]
        $Param2,

        # Param3 help description
        [Parameter(ParameterSetName='Another Parameter Set')]
        [ValidatePattern("[a-z]*")]
        [ValidateLength(0,15)]
        [String]
        $Param3
    )

    Begin {

    }

    Process {

    }

    End {
    }
}
#> <#TODO - Implement This#>

<#
.Synopsis
   INTERNAL FUNCTION - This function is used by all GRAPH API "DELETE" functions to delete data based upon a specific URI provided in the $WorkplaceURL Parameter. This functions primary purpose is to delete the data, and return success or error as an array of objects based upon the original request.
   The Header information for the HTTP request is provided by the decrypted private data variable "workplaceHeader" which is written to memory using the Start-WorkplaceModule function.

   ENSURE THAT Start-WorkplaceModule has been run successfully before running this command (using "Start-WorkplaceModule -Verbose" will provide detailed error output)
.EXAMPLE
   Remove-WorkplaceWebRequest -WorkplaceURL "https://graph.facebook.com/[groupid]/
#>  <#TODO - Add Error Capabilities #>
Function Remove-WorkplaceWebRequest {
    PARAM(
        [Parameter(Mandatory=$false)]
        [string]$RemoveWorkplaceURL
        )

    Begin {

    }

    Process {
        Write-Verbose "Posting data to $RemoveWorkplaceURL"
            try 
                {
                    Invoke-RestMethod $RemoveWorkplaceURL -Headers $MyInvocation.MyCommand.Module.PrivateData['workplaceHeader'] -Method Delete -TimeoutSec 30
                }

            catch 
                {
                    $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                    $ErrResp = $streamReader.ReadToEnd() | ConvertFrom-Json
                    $streamReader.Close()
                    Write-Verbose $ErrResp.error.error_user_title
                    Write-Verbose $ErrResp.error.error_user_msg
                }
              }

    End {

    }


}

<#
.Synopsis
   Returns an array of all groups, or a single group based upon the parameters specified
.EXAMPLE
   Get-WorkplaceGroup -GroupName "Example Group Name"

   Returns all groups with the name matching "Example Group Name"
.EXAMPLE
   Get-WorkplaceGroup -GroupID "Example Group ID"

   Returns all groups with the ID matching "Example Group ID"
.EXAMPLE
    Get-WorkplaceGroup

    Returns all groups
#>
Function Get-WorkplaceGroup {
    PARAM(
        [Parameter(Mandatory=$false)]
        [string]$GroupName,
        [Parameter(Mandatory=$false)]
        [string]$GroupID
        )

    Begin {
            Write-Verbose "Initialize stuff in Begin block"
            $RetArr = @()
            $CommunityID = Get-WorkplaceCommunityID
            $AllGroupsAPIURL = "https://graph.facebook.com/" + $CommunityID + "/groups"
        }

    Process {
            try {
                        
                if(($GroupName -eq "") -and ($GroupID -eq "")){
                        Write-Verbose "Returning all groups as no parameters were specified"
                        $AllGroups = Get-WorkplaceWebRequest -WorkplaceURL $AllGroupsAPIURL
                        foreach($Group in $AllGroups){
                            $GroupAPIURL = "https://graph.facebook.com/"+$Group.id+"?fields=name,id,owner,privacy,is_workplace_default,description,cover,icon,updated_time"
                            $GroupDataRes = Get-WorkplaceWebRequest -WorkplaceURL $GroupAPIURL
                            $RetArr = $RetArr + $GroupDataRes
                        }
                        return $RetArr
                }
                if ($GroupName -eq "" -and $GroupID -ne "") {
                        $GroupAPIURL = "https://graph.facebook.com/"+$GroupID+"?fields=name,id,owner,privacy,is_workplace_default,description,cover,icon,updated_time"
                        $RetArr = Get-WorkplaceWebRequest -WorkplaceURL $GroupAPIURL
                        return $RetArr
                }
                if ($GroupName -ne "" -and $GroupID -eq "") {
                        
                        $RetArr = Get-WorkplaceWebRequest -WorkplaceURL $AllGroupsAPIURL
                        Return $RetArr | Where-Object -FilterScript {$_.name -like "*$GroupName*"}
                }
             }  
             

            catch {
                $result = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($result)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd()
                Write-Output $responseBody
            }
        }

    End {
           Write-Verbose "Final work in End block"
        }   
    
}

<#
.Synopsis
   Creates a new group in the Workplace community and assigns an admin. This cmdlet returns the group object.
.DESCRIPTION
   New-WorkplaceGroup -GroupName[String] -Description[String] -Privacy["OPEN","CLOSED","SECRET"] -Admin[Workplace User ID]
.EXAMPLE
   New-WorkplaceGroup -GroupName "Example Group Name" -Description "This is a group used for the example" -Privacy "CLOSED" -Admin "1234567890"
.EXAMPLE
   New-WorkplaceGroup -GroupName "Example Group Name" -Description "This is a group used for the example" -Privacy "CLOSED" -Admin (Get-WorkplaceUser -EmailAddress "xxxxxxx@xxxxx.xxxx").id
#>
Function New-WorkplaceGroup {
    PARAM(
        [Parameter(Mandatory=$true)]
        [string]$GroupName,
        [Parameter(Mandatory=$true)]
        [string]$Description,
        [Parameter(Mandatory=$true)]
        [ValidateSet("OPEN","CLOSED","SECRET")]
        [string]$Privacy,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$True)]
        [Alias('id')]
        [string]$AdminUserID
        )

    Begin {
        $RetArr =@()

    }

    Process {
        Write-Verbose "Creating the URL's to create the new group and promote the admin"
        $CreateGroupURL = "https://graph.facebook.com/" + (Get-WorkplaceCommunityID) + "/groups?name=" + $GroupName + "&description=" + $Description + "&privacy=" + $Privacy
        Write-Verbose "Create Group URL: $CreateGroupURL"
        Write-Verbose "Invoking Create Group API Request"
        $CreateRequestStatus = Set-WorkplaceWebRequest -WorkplaceURL $CreateGroupURL
        if($CreateRequestStatus) {
            Write-Verbose "Invoking Promote Admin API Request"
            $AddGroupMemberURL = "https://graph.facebook.com/" + $CreateRequestStatus.Status.id + "/members/" + $AdminUserID
            $PromoteGroupAdminURL = "https://graph.facebook.com/" + $CreateRequestStatus.Status.id + "/admins/" + $AdminUserID
            Write-Verbose "Promote Admin URL: $PromoteGroupAdminURL"
            Set-WorkplaceWebRequest -WorkplaceURL $AddGroupMemberURL
            Set-WorkplaceWebRequest -WorkplaceURL $PromoteGroupAdminURL
            Write-Verbose "Adding group to the return variable"
            $RetArr = $RetArr + (Get-WorkplaceGroup -GroupID $CreateRequestStatus.Status.id)
        } Else {
            Return "There was an error creating the group. Please review the logs and try again"
        } 
    }
    
    End {
        return $RetArr
    }

}

<#
.Synopsis
   Set properties of a group based upon supplied parameters.

    Set-WorkplaceGroup -GroupID[String](Required) -Name[String] -Description[String] -Owner[String] -Privacy[String](OPEN,CLOSED,SECRET)
.EXAMPLE
   Set-WorkplaceGroup -GroupID "Example Group ID" -Name "New Group Name" -Description "New Group Description" -Owner "Workplace User ID of Owner" -Privacy OPEN

#>
Function Set-WorkplaceGroup {
    PARAM(
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("id")] 
        [String]$GroupID,
        [Parameter(Mandatory=$False, ValueFromPipelineByPropertyName=$true)]
        [String]$Name,
        [Parameter(Mandatory=$False, ValueFromPipelineByPropertyName=$true)] 
        [String]$Description,
        [Parameter(Mandatory=$False, ValueFromPipelineByPropertyName=$true)]
        [String]$Owner,
        [Parameter(Mandatory=$False, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("OPEN","CLOSED","SECRET")]
        [String]$Privacy
    )

    Begin
    { 
        $RetArr = @()
    }

    Process
    {
        Write-Verbose "Creating URL based upon parameters"
        $SetGroupAPIURL = "https://graph.facebook.com/$GroupID" + "?"
        switch ($PSBoundParameters.Keys)
            {
                'Name' { 
                            $SetGroupAPIURL = $SetGroupAPIURL + "name=" + $PSBoundParameters.Item('Name')
                            $RetArr = $RetArr + (Set-WorkplaceWebRequest -WorkplaceURL $SetGroupAPIURL)
                            $SetGroupAPIURL = "https://graph.facebook.com/$GroupID" + "?"

                       }

                'Description' { 
                            $SetGroupAPIURL = $SetGroupAPIURL + "description=" + $PSBoundParameters.Item('Description')
                            $RetArr = $RetArr + (Set-WorkplaceWebRequest -WorkplaceURL $SetGroupAPIURL) 
                            $SetGroupAPIURL = "https://graph.facebook.com/$GroupID" + "?"

                       }

                'Owner' { 
                            $SetGroupAPIURL = $SetGroupAPIURL + "owner=" + $PSBoundParameters.Item('Owner')
                            $RetArr = $RetArr + (Set-WorkplaceWebRequest -WorkplaceURL $SetGroupAPIURL)
                            $SetGroupAPIURL = "https://graph.facebook.com/$GroupID" + "?"

                        }

                'Privacy' { 
                            $SetGroupAPIURL = $SetGroupAPIURL + "privacy=" + $PSBoundParameters.Item('Privacy')
                            $RetArr = $RetArr + (Set-WorkplaceWebRequest -WorkplaceURL $SetGroupAPIURL)
                            $SetGroupAPIURL = "https://graph.facebook.com/$GroupID" + "?"

                       }
            }  
        

    }

    End
    {
        Return $RetArr
    }
}

<#
.Synopsis
   Returns the Workplace user ID and group membership properties of all the members of a given Workplace group
.EXAMPLE
   Get-WorkplaceGroupMember -GroupID "Example Group ID"
#>
Function Get-WorkplaceGroupMember {
    #Enter Parameters
    PARAM(
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$True)]
        [Alias('id')]
        [string]$GroupID
         )

    Begin {
        Write-Verbose "Initialize stuff in Begin block"
    }

    Process {
        Write-Verbose "Stuff in Process block to perform"
        $GroupMemberAPIURL = "https://graph.facebook.com/"+$GroupID+"/members?fields=name,id,joined"
        $GroupAdminAPIURL = "https://graph.facebook.com/"+$GroupID+"/admins?fields=name,id,joined"
        $GroupModAPIURL = "https://graph.facebook.com/"+$GroupID+"/moderators?fields=name,id,joined"
        $MemberDataRes = Get-WorkplaceWebRequest -WorkplaceURL $GroupMemberAPIURL
        $MemberDataRes = $MemberDataRes + (Get-WorkplaceWebRequest -WorkplaceURL $GroupAdminAPIURL)
        $MemberDataRes = $MemberDataRes + (Get-WorkplaceWebRequest -WorkplaceURL $GroupModAPIURL)
        return $MemberDataRes
    }

    End {
        Write-Verbose "Final work in End block"
    }
        
 }

<#
.Synopsis
   Adds a new group member to a Workplace group based upon Workplace group ID and Workplace User ID
.EXAMPLE
   Add-WorkplaceGroupMember -GroupID "Example Group ID" -UserID "Example User ID"
.EXAMPLE
   Add-WorkplaceGroupMember -GroupID (Get-WorkplaceGroup -Name "Example Workplace Group").id -UserID (Get-WorkplaceUser -EmailAddress "Example@Email.com").id
#>
Function Add-WorkplaceGroupMember {
    PARAM(
        [Parameter(Mandatory=$true)]
        [string]$GroupID,
        [Parameter(Mandatory=$true)]
        [string]$UserID
         )

    Begin {
        $ReturnArr = @()
    }

    Process {
        $AddMembershipURL = "https://graph.facebook.com/" + $GroupID + "/members/" + $UserID
        $ReturnArr = $ReturnArr + (Set-WorkplaceWebRequest -WorkplaceURL $AddMembershipURL)
        
  
    }

    End {
        Return $ReturnArr
    }

}

<#
.Synopsis
   Returns an array of users currently available within the Workplace community. By specifying parameters the result can be scoped to an individual user
.EXAMPLE
   Get-WorkplaceUser

   Returns all users within the community
.EXAMPLE
   Get-WorkplaceUser -EmailAddress "Example@Email.com"
.EXAMPLE
    Get-WorkplaceUser -UserID "Example User ID"
#>
Function Get-WorkplaceUser {
    #Enter Parameters 
    PARAM(
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
        [Alias('email','EmailAddress')]
        [string]$mail,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)]
        [Alias('id')]
        [string]$UserID
         )

    Begin {
            Write-Verbose "Initialize stuff in Begin block"
            $RetArr = @()
        }

    Process {
            
            write-verbose " Begining process section...."
           if (($mail -eq "") -and ($UserID -eq "")) {
                Write-Verbose "NO EMAIL ADDRESS & NO USERID SPECIFIED - RETURNING ALL USERS" 
                $RetArr = Get-WorkplaceAccountManagementWebRequest -AccountManagementURI "https://www.facebook.com/scim/v1/Users"
            } 
            
           if(($mail -eq "") -and ($UserID -ne "")) {
                Write-Verbose "USERID SPECIFIED - RETURNING SPECIFIC USER IF ONE EXISTS"
                $RetArr = $RetArr + (Get-WorkplaceAccountManagementWebRequest -AccountManagementURI "https://www.facebook.com/scim/v1/Users/$UserID")     
            }
            
            if(($mail -ne "") -and ($UserID -eq "")) {
                Write-Verbose "EMAIL ADDRESS SPECIFIED - RETURNING SPECIFIC USER IF ONE EXISTS"
                $RetArr = $RetArr + (Get-WorkplaceAccountManagementWebRequest -AccountManagementURI "https://www.facebook.com/scim/v1/Users?filter=userName%20eq%20%22$mail%22")
            }

          }

    End {
        Write-Verbose "Final work in End block"
        Return $RetArr
      }
}

<#
.Synopsis
   Use this Cmdlet to initialise the workplace module, you will need to perform this each time module is imported. During the first initialisation the user will be required to enter their API Access Token, which is subsiquently encrypted and stored with the module. This command also imports a certificate to the users personal store for encryption and decryption of the API Access Token.
.EXAMPLE
   Start-WorkplaceModule
.EXAMPLE
   Start-WorkplaceModule -Verbose
#>
Function Start-WorkplaceModule {
[CmdletBinding()]
    PARAM(    )
    <#This code runs during an import and validates the API key is correctly initialised for the session#>
    $Private:PrivateData = $MyInvocation.MyCommand.Module.PrivateData
        If(Test-Path Cert:\CurrentUser\My\F73BEBC5AA9D82855B54C8E970DED7C1DBD8A9C7)  { 
            $Cert = Get-ChildItem "Cert:\CurrentUser\My\F73BEBC5AA9D82855B54C8E970DED7C1DBD8A9C7" 
            Write-Verbose "Searching for API key from file"
                $KeyPath = ((Get-Module WorkplaceModule).path.Substring(0,(Get-Module WorkplaceModule).Path.LastIndexOf("\"))) + "\Secrets\API_Key.txt"
                        if($Key = Get-Content -Path $KeyPath) {
                            $MyInvocation.MyCommand.Module.PrivateData['workplaceAccessToken'] = Decrypt-Key -base64string (Get-Content -Path $KeyPath)
                        } Else { 
                                Write-Verbose "No API Key found in KeyFile - Requesting Key from user"
                                $ClearTextKey = Read-Host "Please enter workplace API key now:"
                                $MyInvocation.MyCommand.Module.PrivateData['workplaceAccessToken'] = $ClearTextKey
                                Write-Verbose "Saving API Key to file"
                                Encrypt-Key -unprotectedcontent $ClearTextKey -cert $Cert | Out-File -FilePath $KeyPath -NoNewline -Width 9999
                                }
        } Else { 
            Write-Warning "Workplace Module Certificate is not installed in the personal store. Attempting to install the certificate"

            try {
                $CertPath = ((Get-Module WorkplaceModule).path.Substring(0,(Get-Module WorkplaceModule).Path.LastIndexOf("\"))) + "\Secrets\Workplace_Cert.p12"
                $certRootStore = “CurrentUser”
                $certStore = “My”
                $store = new-object System.Security.Cryptography.X509Certificates.X509Store($certStore,$certRootStore)
                $certImport = Get-PfxCertificate -FilePath $CertPath
                $store.open("MaxAllowed")
                $store.add($certImport)
                $Store.Close()
            } Catch {
                Write-Warning "Certificate installation failed - Please read the documentation and try again"
                
            }
         Start-WorkplaceModule
        }

        $MyInvocation.MyCommand.Module.PrivateData['workplaceHeader'] = @{"Authorization"="Bearer "+ $MyInvocation.MyCommand.Module.PrivateData['workplaceAccessToken']}
        Write-Verbose "Module Setup Completed Successfully"
}

Write-Warning "The Workplace Powershell Module is released under the GNU GPL Licence"
Write-Warning "Remember to run Start-WorkplaceModule to enable the API connection"