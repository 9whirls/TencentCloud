<# 
Copyright (c) 2026 Jian Liu (whirls9@hotmail.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
#>

Function GetApiHost {
  param(
    [ValidateNotNullOrEmpty()]
    [String]
      $action
  )

  $tc = Get-TencentCloud
  $apiSite = $tc.Site

  Switch ($action) {
    { $_ -in @('GetUserAppId', 'ListUsers', 'GetSecurityLastUsed') -or $_ -match 'AccessKey' } {
      @{
        url = "cam.$apiSite"
        ver = '2019-01-16'
      }
    }
    { $_ -match 'Region' -or $_ -match 'Product' } { 
      @{
        url = "region.$apiSite"
        ver = '2022-06-27'
      }
      break 
    }
    { $_ -match 'Instance' -or $_ -match 'Image' -or $_ -match 'Zone' } { 
      @{
        url = "cvm.$apiSite"
        ver = '2017-03-12'
      }
      break 
    }
    { $_ -in @('RunCommand', 'DescribeInvocations', 'DescribeInvocationTasks')} { 
      @{
        url = "tat.$apiSite"
        ver = '2020-10-28'
      }
      break 
    }
    { $_ -match 'Disk' -or $_ -match 'Snapshot' } { 
      @{
        url = "cbs.$apiSite"
        ver = '2017-03-12'
      }
      break 
    }
    { $_ -match 'Monitor' } { 
      @{
        url = "monitor.$apiSite"
        ver = '2018-07-24'
      }
      break 
    }
    { $_ -match 'vpc' -or $_ -match 'Subnet'  -or $_ -match 'SecurityGroup' } { 
      @{
        url = "vpc.$apiSite"
        ver = '2017-03-12'
      }
      break 
    }
  }
}

Function GetRegionByZone {
  param(
    [ValidateNotNullOrEmpty()]
    [String]
      $zone
  )
  $zone -replace '(\w+)(-\d+)', '$1'
}
  
Function ConvertDic2Qs {
  param(
    [ValidateNotNullOrEmpty()]
    [Hashtable]
      $dic
  )

  $query = @()
  $dic.Keys | sort | ForEach-Object {$query += $_ + '=' + $dic[$_]}
  $apihost = (GetApiHost $dic['Action']).url
  $qs = "GET$apihost/?"
  $qs += $query -join "&"
  $qs
}
  
Function ConvertDic2Url {
  param(
    [ValidateNotNullOrEmpty()]
    [Hashtable]
      $dic
  )
  
  Add-Type -AssemblyName System.Web
  $query = @()
  foreach ($k in ($dic.Keys | sort)) {
    $query += $k + '=' + [System.Web.HTTPUtility]::UrlEncode($dic[$k])
  }
  $apihost = (GetApiHost $dic['Action']).url
  $url = "https://$apihost/?"
  $url += $query -join "&"
  $url
}

Function SecureString2Text {
  param(
    [ValidateNotNullOrEmpty()]
    [SecureString]
      $secret
  )

  [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR( # https://github.com/PowerShell/PowerShell/issues/19317
    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
  )
}
  
Function AddApiSignature {
  param(
    [ValidateNotNullOrEmpty()]
    [Alias('D')]
    [Hashtable]
      $dic,

    [Alias('R')]
    [String]
      $region
  )

  $tc = Get-TencentCloud
  if (!$region) { $region = $tc.DefaultRegion }
  $secretId = SecureString2Text $tc.SecretId
  $secretKey = SecureString2Text $tc.SecretKey
  
  $dic['Language'] = 'en-US'
  $dic['Nonce'] = Get-Random -Minimum 100000 -Maximum 999999
  $dic['Version'] = (GetApiHost $dic['Action'] $tencentCloud).ver
  $dic['Region'] = $region
  $dic['SecretId'] = $secretId
  if ($PSVersionTable.PSVersion.Major -ge 7) {
    $dic['Timestamp'] = get-date -UFormat %s
  } else {
    $dic['Timestamp'] = get-date (Get-Date -format U) -uformat %s
  }
  $qs = ConvertDic2Qs $dic
  $hmacsha = New-Object System.Security.Cryptography.HMACSHA1
  $hmacsha.key = [Text.Encoding]::UTF8.GetBytes($secretKey)
  $signature = $hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($qs))
  $dic['Signature'] = [Convert]::ToBase64String($signature)
  $dic
}

Function CallApi {
  param(
    [ValidateNotNullOrEmpty()]
    [String]
      $uri
  )
  try {
    $res = Invoke-WebRequest -uri $uri -ea Stop | Select-Object -ExpandProperty content
    if ($uri -match 'Action=DescribeImages') { # fix the issue of duplicated keys
      $res = $res -ireplace "isSupportCloudinit", "IsSupportCloudinit"
    }
    $res = $res | ConvertFrom-JSON -ea stop | Select-Object -ExpandProperty response
  } catch {
    throw $_
  }
  if ($res.error) {
    throw $res.error
  } else {
    $res
  }
}

Function GetAllTcObj {
  param(
    [Parameter(Mandatory = $true)]
    [Alias('A')]
    [String]
      $action,

    [Parameter(Mandatory = $true)]
    [Alias('P')]  
    [String]
      $responseType,

    [Parameter(Mandatory = $true)]
    [Alias('R')]
    [String]
      $region
  )

  $limit = 100
  $offset = 0
  $objList = New-Object System.Collections.ArrayList
  do {
    $dic = @{
      Action = $action
      Limit = $limit
      Offset = $offset
    }
    $dic = AddApiSignature -d $dic -r $region
    $url = ConvertDic2Url $dic
    $obj = (CallApi $url).$responseType
    if ($obj) {
      $objList.AddRange(@($obj))
      $count = $obj.count
      $offset += $limit
    } else {
      $count = 0
    }
  } while ($count -eq $limit)
  $objList
}

Function Get-TencentCloud {
  <#
    .SYNOPSIS
    Get the current Tencent Cloud connection.

    .DESCRIPTION
    Retrieves the current Tencent Cloud connection object containing credentials and default settings.

    .OUTPUTS
    PSObject containing connection information including Site, DefaultRegion, OwnerUin, and AppId.

    .EXAMPLE
    PS> Get-TencentCloud
    Get the current connection object.

    .ALIAS
    Get-TC
  #>
  [Alias('Get-TC')]
  param()
  if ($defaultTc) {
    $defaultTc
  } else {
    throw "No Tencent Cloud is connected. Run Connect-TencentCloud to establish a connection first."
  }
}

Function Connect-TencentCloud {
  <#
    .SYNOPSIS
    Connect to Tencent Cloud API.

    .DESCRIPTION
    Establishes a connection to Tencent Cloud using secret ID and key credentials.

    .PARAMETER site
    The Tencent Cloud API site endpoint. Valid values are 'tencentcloudapi.com' (China) or 'intl.tencentcloudapi.com' (International).
    Default: 'tencentcloudapi.com'

    .PARAMETER region
    The default region to use for operations. Default: 'na-siliconvalley'

    .PARAMETER secretId
    Tencent Cloud secret ID for authentication.

    .PARAMETER secretKey
    Tencent Cloud secret key for authentication.

    .OUTPUTS
    PSObject containing connection information including Site, DefaultRegion, OwnerUin, and AppId.

    .EXAMPLE
    PS> Connect-TencentCloud
    Connect using prompts for credentials.

    .EXAMPLE
    PS> Connect-TencentCloud -S 'intl.tencentcloudapi.com' -R 'ap-hongkong' -I $id -K $key
    Connect to international Tencent Cloud in Hong Kong region.

    .ALIAS
    Connect-TC
  #>
  [Alias('Connect-TC')]
  param(
    [ValidateSet('tencentcloudapi.com', 'intl.tencentcloudapi.com')]
    [Alias('S')]
    [string] 
      $site = 'tencentcloudapi.com',

    [Alias('R')]
    [string]
      $region = 'na-siliconvalley',
    
    [Alias('I')]
      $secretId = $(Read-Host -AsSecureString -Prompt "Enter Tencent Cloud secret ID"),

    [Alias('K')]
      $secretKey = $(Read-Host -AsSecureString -Prompt "Enter Tencent Cloud secret key")
  )

  if ($secretId.GetType().Name -eq "String") {
    Write-Host "Plaintext secret ID provided. Converting to SecureString."
    $secretId = $secretId | ConvertTo-SecureString -AsPlainText -Force
  }

  if ($secretKey.GetType().Name -eq "String") {
    Write-Host "Plaintext secret key provided. Converting to SecureString."
    $secretKey = $secretKey | ConvertTo-SecureString -AsPlainText -Force
  }

  $props = [ordered]@{
    Site = $site
    OwnerUin = ''
    AppId = ''
    DefaultRegion = $region
    SecretId = $secretId
    SecretKey = $secretKey
  }
  
  $Global:defaultTc = New-Object PSObject -Property $props

  $dic = @{
    Action = 'GetUserAppId'
  }
  $dic = AddApiSignature $dic
  $url = ConvertDic2Url $dic
  try {
    $userApp = (CallApi $url)
    $defaultTc.OwnerUin = $userApp.OwnerUin
    $defaultTc.AppId = $userApp.AppId
    $defaultTc
  } catch {
    Remove-Variable -Name defaultTc -Scope Global
    throw $_
  }
}

Function Set-TcRegion {
  <#
    .SYNOPSIS
    Set the default region for Tencent Cloud operations.

    .DESCRIPTION
    Changes the default region used for subsequent Tencent Cloud API operations.

    .PARAMETER region
    The region to set as default. Must be a valid Tencent Cloud region.

    .EXAMPLE
    PS> Set-TcRegion -R 'ap-hongkong'
    Set the default region to Hong Kong.

    .LINK
    Get-TcRegion
  #>
  param(
    [ValidateNotNullOrEmpty()]
    [Alias('R')]
    [string]
      $region
  )
  $tc = Get-TencentCloud
  if ($region -in (Get-TcRegion).Region) {
    $tc.DefaultRegion = $region
  } else {
    throw "$region is not a valid Tencent Cloud region. Run Get-TcRegion to list all supported regions."
  }
}

Function Get-TcRegion {
  <#
    .SYNOPSIS
    Get Tencent Cloud regions.

    .DESCRIPTION
    Retrieve a list of regions of Tencent Cloud.

    .OUTPUTS
    Region information array.

    .EXAMPLE
    PS> Get-TcRegion

    .LINK
    Tencent Cloud API
    Chinese: https://cloud.tencent.com/document/product/1596/77930
  #>
  
  $dic = @{
    Action = 'DescribeRegions'
    Product = 'cvm'
  }
  $dic = AddApiSignature $dic
  $url = ConvertDic2Url $dic
  (CallApi $url).RegionSet
}

Function Get-TcProductByRegion {
  <#
    .SYNOPSIS
    Get Tencent Cloud products available by region.

    .DESCRIPTION
    Retrieve a list of products available in a specific Tencent Cloud region.

    .PARAMETER region
    Specify the region to query. Accepts pipeline input.
    Default: Current default region

    .OUTPUTS
    Product information array.

    .EXAMPLE
    PS> Get-TcProductByRegion -R 'ap-hongkong'
    Get products available in Hong Kong region.

    .EXAMPLE
    PS> Get-TcRegion | Get-TcProductByRegion
    Get products for all regions.
  #>
  param(
    [parameter(
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [Alias('R')]
    [string]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {
    $objList = New-Object System.Collections.ArrayList
  }
  process {
    $obj = GetAllTcObj -a 'DescribeProducts' -p 'Products' -r $region
    $objList.AddRange(@($obj))
  }
  end {
    $objList
  }
}

Function Get-TcZone {
  <#
    .SYNOPSIS
    Get Tencent Cloud zones.

    .DESCRIPTION
    Retrieve a list of availability zones of Tencent Cloud.

    .PARAMETER Region
    Specify the region of Tencent Cloud. 
    Default value is (Get-TencentCloud).DefaultRegion

    .INPUTS
    Region names or region objects (returned by Get-TcRegion) can pipe to this cmdlet.

    .OUTPUTS
    Availability zone information array.

    .EXAMPLE
    PS> Get-TcZone -r na-siliconvalley

    .EXAMPLE
    PS> Get-TcRegion | Get-TcZone

    .LINK
    Tencent Cloud API:
    Chinese: https://cloud.tencent.com/document/api/213/15707
    English: https://www.tencentcloud.com/document/api/213/35071
  #>
  param(
    [parameter(
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [Alias('R')]
    [String]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {}
  process {
    $dic = @{
      Action = 'DescribeZones'
    }
    $dic = AddApiSignature -d $dic -r $region
    $url = ConvertDic2Url $dic
    (CallApi $url).ZoneSet
  }
  end {}
}

Get-ChildItem -Path (Join-Path $PSScriptRoot "script") -Filter "*.ps1" | ForEach-Object {
  . $_.FullName
}
