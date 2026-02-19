Function Get-TcAccessKey {
  <#
    .SYNOPSIS
    List access keys.

    .DESCRIPTION
    Retrieve access keys for the current user or specified user. Access keys are used for API authentication.

    .PARAMETER targetUin
    Optional user UIN to list keys for. If not specified, lists keys for current user.

    .OUTPUTS
    Access key array with key ID and creation information.

    .EXAMPLE
    PS> Get-TcAccessKey
    Get access keys for current user.

    .EXAMPLE
    PS> Get-TcAccessKey -TargetUin '12345678'
    Get access keys for specific user.

    .LINK
    New-TcAccessKey
  #>
  param(
    [string]
      $targetUin
  )
  
  $dic = @{
    Action  = 'ListAccessKeys'
  }
  if ($targetUin) { $dic['TargetUin'] = $targetUin }
  $dic = AddApiSignature -d $dic
  $url = ConvertDic2Url $dic
  (CallApi $url).AccessKeys
}

Function New-TcAccessKey {
  <#
    .SYNOPSIS
    Create a new access key.

    .DESCRIPTION
    Generate a new access key (secret ID and secret key pair) for API authentication.

    .PARAMETER targetUin
    Optional user UIN to create key for. If not specified, creates key for current user.

    .OUTPUTS
    New access key object with secret ID and secret key.

    .EXAMPLE
    PS> New-TcAccessKey
    Create a new access key for current user.

    .EXAMPLE
    PS> New-TcAccessKey -TargetUin '12345678'
    Create a new access key for specific user.

    .WARNING
    Secret key is only displayed once. Store it securely.

    .LINK
    Get-TcAccessKey
  #>
  param(
    [string]
      $targetUin
  )
  
  $dic = @{
    Action = 'CreateAccessKey'
  }
  if ($targetUin) { $dic['TargetUin'] = $targetUin }
  $dic = AddApiSignature -d $dic
  $url = ConvertDic2Url $dic
  (CallApi $url).AccessKey
}

Function Get-TcSecurityLastUsed {
  <#
    .SYNOPSIS
    Get the last used time of a secret key.

    .DESCRIPTION
    Retrieve information about when a specific secret key was last used for authentication.

    .PARAMETER secretId
    The secret ID to check.

    .OUTPUTS
    Secret ID last used information array.

    .EXAMPLE
    PS> Get-TcSecurityLastUsed -SecretId 'AKIA2EXAMPLE123456'
    Get last used time for a secret key.
  #>
  param(
    [string]
      $secretId
  )
  
  $dic = @{
    Action = 'GetSecurityLastUsed'
    'SecretIdList.0' = $secretId
  }
  $dic = AddApiSignature -d $dic
  $url = ConvertDic2Url $dic
  (CallApi $url).SecretIdLastUsedRows
}

Function Get-TcUser {
  <#
    .SYNOPSIS
    List IAM users.

    .DESCRIPTION
    Retrieve a list of all IAM users in the account.

    .OUTPUTS
    User information array.

    .EXAMPLE
    PS> Get-TcUser
    List all IAM users in the current account.
  #>
  $dic = @{
    Action  = 'ListUsers'
  }
  $dic = AddApiSignature -d $dic
  $url = ConvertDic2Url $dic
  (CallApi $url).Data
}
