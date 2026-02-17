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

Function EncodeCvmCommand {
  param(
    [ValidateNotNullOrEmpty()]
    [String]
      $command
  )
  $Bytes = [System.Text.Encoding]::ASCII.GetBytes($command)
  [Convert]::ToBase64String($Bytes)
}

Function DecodeCvmCommandResult {
  param(
    [String]
      $result
  )
  [System.Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($result))
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

Function Get-TcInstanceTypeByRegion {
  <#
    .SYNOPSIS
    Get Tencent Cloud instance types available in a region.

    .DESCRIPTION
    Retrieve available CVM instance types and configurations for a specific region.

    .PARAMETER region
    Specify the region to query. Accepts pipeline input.
    Default: Current default region

    .OUTPUTS
    Instance type configuration objects.

    .EXAMPLE
    PS> Get-TcInstanceTypeByRegion -R 'ap-hongkong'
    Get all instance types available in Hong Kong.

    .EXAMPLE
    PS> Get-TcRegion | Get-TcInstanceTypeByRegion
    Get instance types for all regions via pipeline.
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
    $dic = @{
      Action  = 'DescribeInstanceTypeConfigs'
    }
    $dic = AddApiSignature -d $dic -r $region
    $url = ConvertDic2Url $dic
    $obj = (CallApi $url).InstanceTypeConfigSet
    $objList.AddRange(@($obj))
  }
  end {
    $objList
  }
}

Function Get-TcInstanceTypeByName {
  <#
    .SYNOPSIS
    Get Tencent Cloud instance type by name.

    .DESCRIPTION
    Retrieve detailed information for a specific instance type by name.

    .PARAMETER instanceTypeName
    The instance type name (e.g., 'S6.MEDIUM4'). Accepts pipeline input.

    .PARAMETER region
    Specify the region to query. Default: Current default region

    .OUTPUTS
    Instance type configuration object.

    .EXAMPLE
    PS> Get-TcInstanceTypeByName -N 'S6.MEDIUM4'
    Get details for S6.MEDIUM4 instance type.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [Alias('N')]
    [String]
      $instanceTypeName,

    [Alias('R')]
    [String]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {}
  process {
    $dic = @{
      Action = 'DescribeInstanceTypeConfigs'
      "Filters.0.Name" = 'instance-type'
      "Filters.0.Values.0" = $instanceTypeName.toUpper()
    }
    $dic = AddApiSignature -d $dic -r $region
    $url = ConvertDic2Url $dic
    (CallApi $url).InstanceTypeConfigSet
  }
  end {}
}

Function Get-TcInstanceTypeByFamily {
  <#
    .SYNOPSIS
    Get Tencent Cloud instance types by family.

    .DESCRIPTION
    Retrieve instance type configurations for a specific instance family (e.g., 'S6').

    .PARAMETER instanceTypeFamily
    The instance type family (e.g., 'S6', 'C6'). Accepts pipeline input.

    .PARAMETER region
    Specify the region to query. Default: Current default region

    .OUTPUTS
    Instance type configuration objects.

    .EXAMPLE
    PS> Get-TcInstanceTypeByFamily -F 'S6'
    Get all S6 instance types.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [Alias('F')]
    [String]
      $instanceTypeFamily,

    [Alias('R')]
    [String]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {}
  process {
    $dic = @{
      Action = 'DescribeInstanceTypeConfigs'
      "Filters.0.Name" = 'instance-family'
      "Filters.0.Values.0" = $instanceTypeFamily.toUpper()
    }
    $dic = AddApiSignature -d $dic -r $region
    $url = ConvertDic2Url $dic
    (CallApi $url).InstanceTypeConfigSet
  }
  end {}
}

Function Get-TcInstanceTypePrice {
  <#
    .SYNOPSIS
    Get pricing for a Tencent Cloud instance type.

    .DESCRIPTION
    Inquire about pricing for a specific instance type configuration in a region.

    .PARAMETER instanceType
    The instance type object (from pipeline). Accepts pipeline input.

    .PARAMETER imgId
    The image ID to use for the instance.

    .PARAMETER chargeType
    Billing model: PREPAID, POSTPAID_BY_HOUR, or SPOTPAID. Default: POSTPAID_BY_HOUR

    .PARAMETER chargePeriodInMonth
    Billing period in months for PREPAID instances. Default: 1

    .PARAMETER diskType
    System disk type. Default: CLOUD_SSD

    .PARAMETER diskGb
    System disk size in GB. Default: 50

    .PARAMETER region
    Region for pricing. Derived from instance type zone if not specified.

    .OUTPUTS
    Price information object.

    .EXAMPLE
    PS> Get-TcInstanceTypeByName -N 'S6.MEDIUM4' | Get-TcInstanceTypePrice -I 'img-xxxxx'
    Get pricing for S6.MEDIUM4 instance with specified image.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
      $instanceType,

    [parameter(
      Mandatory = $true
    )]
    [Alias('I')]
    [String]
      $imgId,

    [ValidateSet('PREPAID', 'POSTPAID_BY_HOUR', 'SPOTPAID')]
    [String]
      $chargeType = 'POSTPAID_BY_HOUR',

    [int]
      $chargePeriodInMonth = 1,

    [ValidateSet('LOCAL_BASIC', 'LOCAL_SSD', 'CLOUD_BASIC', 'CLOUD_PREMIUM', 'CLOUD_SSD', 'CLOUD_BSSD', 'CLOUD_HSSD', 'CLOUD_TSSD')]
    [String]
      $diskType = 'CLOUD_SSD',

    [Int]
      $diskGb = 50,

    [Alias('R')]
    [String]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {}
  process {
    $region = GetRegionByZone $instanceType.Zone
    $dic = @{
      Action = 'InquiryPriceRunInstances'
      ImageId = $imgId
      'Placement.Zone' = $instanceType.Zone
      Region = $region
      InstanceType = $instanceType.InstanceType
      InstanceChargeType = $chargeType.toUpper()
      'SystemDisk.DiskSize' = $diskGb
      'SystemDisk.DiskType' = $diskType.toUpper()
    }
    if ($chargeType -eq 'PREPAID') { $dic['InstanceChargePrepaid.Period'] = $chargePeriodInMonth }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    (CallApi $url).Price.InstancePrice | Select-Object *, @{'n'='InstanceType'; 'e'={$instanceType.InstanceType}}, @{'n'='Zone'; 'e'={$instanceType.Zone}}
  }
  end {}
}

Function Get-TcInstanceById {
  <#
    .SYNOPSIS
    Get a Tencent Cloud instance by ID.

    .DESCRIPTION
    Retrieve detailed information about a specific instance using its instance ID.

    .PARAMETER instanceId
    The instance ID. Accepts pipeline input via property name.

    .PARAMETER region
    Specify the region. Default: Current default region

    .OUTPUTS
    Instance object(s).

    .EXAMPLE
    PS> Get-TcInstanceById -I 'ins-xxxxx'
    Get instance details by ID.

    .EXAMPLE
    PS> Get-TcInstanceByRegion | Get-TcInstanceById
    Get instances via pipeline.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [Alias('I')]
    [String]
      $instanceId,

    [Alias('R')]
    [String]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {}
  process {
    $dic = @{
      Action = 'DescribeInstances'
      "InstanceIds.0" = $instanceId
    }
    $dic = AddApiSignature -d $dic -r $region
    $url = ConvertDic2Url $dic
    (CallApi $url).InstanceSet
  }
  end {}
}

Function Get-TcInstanceByName {
  <#
    .SYNOPSIS
    Get a Tencent Cloud instance by name.

    .DESCRIPTION
    Retrieve instance information by searching for a specific instance name.

    .PARAMETER instanceName
    The instance name to search for. Accepts pipeline input via property name.

    .PARAMETER region
    Specify the region. Default: Current default region

    .OUTPUTS
    Instance object(s).

    .EXAMPLE
    PS> Get-TcInstanceByName -N 'my-server'
    Get instance named 'my-server'.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [Alias('N')]
    [String]
      $instanceName,

    [Alias('R')]
    [String]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {}
  process {
    $dic = @{
      Action = 'DescribeInstances'
      "Filters.0.Name" = 'instance-name'
      "Filters.0.Values.0" = $instanceName
    }
    $dic = AddApiSignature -d $dic -r $region
    $url = ConvertDic2Url $dic
    (CallApi $url).InstanceSet
  }
  end {}
}

Function Get-TcInstanceByRegion {
  <#
    .SYNOPSIS
    Get all Tencent Cloud instances in a region.

    .DESCRIPTION
    Retrieve a list of all instances in a specific region.

    .PARAMETER region
    Specify the region. Accepts pipeline input.
    Default: Current default region

    .OUTPUTS
    Instance object array.

    .EXAMPLE
    PS> Get-TcInstanceByRegion -R 'ap-hongkong'
    Get all instances in Hong Kong region.

    .EXAMPLE
    PS> Get-TcRegion | Get-TcInstanceByRegion
    Get instances for all regions.
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
    $obj = GetAllTcObj -a 'DescribeInstances' -p 'InstanceSet' -r $region
    $objList.AddRange(@($obj))
  }
  end {
    $objList
  }
}

Function Stop-TcInstance {
  <#
    .SYNOPSIS
    Stop a Tencent Cloud instance.

    .DESCRIPTION
    Shut down a running instance. Can optionally wait for the operation to complete.

    .PARAMETER instance
    The instance object to stop. Accepts pipeline input.

    .PARAMETER forceStop
    Force stop the instance without graceful shutdown. Default: 'false'

    .PARAMETER stoppedMode
    Charging mode after stop: KEEP_CHARGING or STOP_CHARGING. Default: STOP_CHARGING

    .PARAMETER wait
    Wait for the operation to complete.

    .PARAMETER timeout
    Timeout in seconds for wait operation. Default: 120

    .EXAMPLE
    PS> Get-TcInstanceById -I 'ins-xxxxx' | Stop-TcInstance
    Stop an instance by ID.

    .EXAMPLE
    PS> Stop-TcInstance -I $instance -W
    Stop an instance and wait for completion.

    .LINK
    Start-TcInstance
  #>
  param(
    [Alias('I')]
    [parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
      $instance,
    
    [Alias('F')]
    [string]
      $forceStop = 'false',

    [Alias('M')]
    [ValidateSet('KEEP_CHARGING', 'STOP_CHARGING')]
    [string]
      $stoppedMode = 'STOP_CHARGING',
    
    [Alias('W')]
    [switch]
      $wait,
    
    [Alias('O')]
    [int]
      $timeout = 120
  )
  begin {}
  process {
    if ($instance.InstanceState -eq 'STOPPED') {
      "$($instance.instanceName) is already stopped"
      return
    } else {
      "Shutting down $($instance.instanceName)..."
    }
    $region = GetRegionByZone $instance.Placement.zone
    $dic = @{
      Action = 'StopInstances'
      "InstanceIds.0" = $instance.instanceId
      StoppedMode = $stoppedMode
      ForceStop = $forceStop
    }
    $dic = AddApiSignature AddApiSignature -d $dic -r $region
    $url = ConvertDic2Url $dic
    CallApi $url | write-verbose
    if ($wait) {
      while ($timeout -gt 0) {
        $instance = Get-TcInstanceById -r $region -i $instance.instanceId
        if ($instance.LatestOperation -eq 'StopInstances' -and $instance.LatestOperationState -eq 'SUCCESS') {
          "$($instance.instanceName) has been stopped"
          return
        } else {
          sleep 5
          "`t Waiting ..."
          $timeout -= 5
        }
      }
      "Failed to stop $($instance.instanceName)"
    }
  }
  end {}
}

Function Start-TcInstance {
  <#
    .SYNOPSIS
    Start a Tencent Cloud instance.

    .DESCRIPTION
    Start a stopped instance. Can optionally wait for the operation to complete.

    .PARAMETER instance
    The instance object to start. Accepts pipeline input.

    .PARAMETER wait
    Wait for the operation to complete.

    .PARAMETER timeout
    Timeout in seconds for wait operation. Default: 120

    .EXAMPLE
    PS> Get-TcInstanceById -I 'ins-xxxxx' | Start-TcInstance
    Start an instance by ID.

    .EXAMPLE
    PS> Start-TcInstance -I $instance -W
    Start an instance and wait for completion.

    .LINK
    Stop-TcInstance
  #>
  param(
    [Alias('I')]
    [parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
      $instance,
    
    [Alias('W')]
    [switch]
      $wait,
    
    [Alias('O')]
    [int]
      $timeout = 120
  )
  begin {}
  process {
    if ($instance.InstanceState -eq 'RUNNING') {
      "$($instance.instanceName) is already running"
      return
    } else {
      "Starting $($instance.instanceName)..."
    }
    $region = GetRegionByZone $instance.Placement.zone
    $dic = @{
      Action = 'StartInstances'
      "InstanceIds.0" = $instance.instanceId
    }
    $dic = AddApiSignature AddApiSignature -d $dic -r $region
    $url = ConvertDic2Url $dic
    CallApi $url | write-verbose

    if ($wait) {
      while ($timeout -gt 0) {
        $instance = Get-TcInstanceById -r $region -i $instance.instanceId
        if ($instance.LatestOperation -eq 'StartInstances' -and $instance.LatestOperationState -eq 'SUCCESS') {
          "$($instance.instanceName) has been started"
          return
        } else {
          sleep 5
          "`t Waiting ..."
          $timeout -= 5
        }
      }
      "Failed to start $($instance.instanceName)"
    }
  }
  end {}
}

Function New-TcInstance {
  <#
    .SYNOPSIS
    Create a new Tencent Cloud instance.

    .DESCRIPTION
    Launch a new CVM instance with specified configuration including instance type, image, storage, networking, and more.

    .PARAMETER instanceName
    Name for the new instance. Accepts pipeline input.

    .PARAMETER zone
    The availability zone for the instance.

    .PARAMETER instanceType
    The instance type (e.g., 'S6.MEDIUM4').

    .PARAMETER imageId
    The image ID to use.

    .PARAMETER instanceChargeType
    Billing model: PREPAID or POSTPAID_BY_HOUR. Default: POSTPAID_BY_HOUR

    .PARAMETER systemDiskType
    System disk type. Default: CLOUD_BSSD

    .PARAMETER systemDiskGb
    System disk size in GB.

    .PARAMETER dataDiskCount
    Number of data disks. Default: 0

    .PARAMETER dataDiskGb
    Size of each data disk in GB. Default: 50

    .PARAMETER dataDiskType
    Data disk type. Default: CLOUD_BSSD

    .PARAMETER vpcId
    Virtual Private Cloud ID.

    .PARAMETER subnetId
    Subnet ID.

    .PARAMETER securityGroupId
    Security group ID.

    .PARAMETER publicIpAssigned
    Assign public IP. Default: $false

    .PARAMETER internetChargeType
    Internet billing model. Default: TRAFFIC_POSTPAID_BY_HOUR

    .PARAMETER maxBandwidthOutMb
    Maximum outbound bandwidth in Mbps. Default: 50

    .PARAMETER tag
    Hashtable of tags to apply to instance.

    .OUTPUTS
    Instance ID array.

    .EXAMPLE
    PS> New-TcInstance -InstanceName 'web-server' -Zone 'ap-hongkong-2' -InstanceType 'S6.MEDIUM4' -ImageId 'img-xxxxx'
    Create a new instance with default settings.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [string]
      $instanceName,

    [parameter(Mandatory = $true)]
    [string]
      $zone,

    [parameter(Mandatory = $true)]
    [string]
      $instanceType,
    
    [ValidateSet('PREPAID', 'POSTPAID_BY_HOUR')]
    [string]
      $instanceChargeType = 'POSTPAID_BY_HOUR',

    [parameter(Mandatory = $true)]
    [string]
      $imageId,

    [int]
      $systemDiskGb,

    [ValidateSet('LOCAL_BASIC', 'LOCAL_SSD', 'CLOUD_BASIC', 'CLOUD_PREMIUM', 'CLOUD_SSD', 'CLOUD_BSSD', 'CLOUD_HSSD', 'CLOUD_TSSD')]
    [string]
      $systemDiskType = 'CLOUD_BSSD',

    [int]
      $dataDiskCount = 0,

    [int]
      $dataDiskGb = 50,

    [ValidateSet('LOCAL_BASIC', 'LOCAL_SSD', 'CLOUD_BASIC', 'CLOUD_PREMIUM', 'CLOUD_SSD', 'CLOUD_BSSD', 'CLOUD_HSSD', 'CLOUD_TSSD')]
    [string]
      $dataDiskType = 'CLOUD_BSSD',

    [string]
      $vpcId,
    
    [string]
      $subnetId,

    [string]
      $securityGroupId,

    [bool]
      $publicIpAssigned = $false,

    [ValidateSet('BANDWIDTH_PREPAID', 'TRAFFIC_POSTPAID_BY_HOUR', 'BANDWIDTH_POSTPAID_BY_HOUR', 'BANDWIDTH_PACKAGE')]
    [string]
      $internetChargeType = 'TRAFFIC_POSTPAID_BY_HOUR',
    
    [int]
      $maxBandwidthOutMb = 50,
    
    [Hashtable]
      $tag = @{}
  )
  begin {
    $dic = @{
      Action = 'RunInstances'
      InstanceType = $instanceType
      InstanceChargeType = $instanceChargeType
      ImageId = $imageId
      "SystemDisk.DiskType" = $systemDiskType
      'Placement.Zone' = $zone
    }
    if ($instanceChargeType -eq 'PREPAID') {
      $dic['InstanceChargePrepaid.Period'] = '1'
      $dic['InstanceChargePrepaid.RenewFlag'] = 'NOTIFY_AND_AUTO_RENEW'
    }
    if ($systemDiskGb) {
      $dic['SystemDisk.DiskSize'] = $systemDiskGb
    }
    if ($dataDiskCount -gt 0) {
      for ($i = 0; $i -lt $dataDiskCount; $i++) {
        $dic["DataDisks.$i.DiskType"] = $dataDiskType
        $dic["DataDisks.$i.DiskSize"] = $dataDiskGb
      }
    }
    if ($vpcId) {
      $dic['VirtualPrivateCloud.VpcId'] = $vpcId
    }
    if ($subnetId) {
      $dic['VirtualPrivateCloud.SubnetId'] = $subnetId
    }
    if ($securityGroupId) {
      $dic['SecurityGroupIds.0'] = $securityGroupId
    }
    if ($publicIpAssigned) {
      $dic['InternetAccessible.InternetChargeType'] = $internetChargeType
      $dic['InternetAccessible.InternetMaxBandwidthOut'] = $maxBandwidthOutMb
      $dic['InternetAccessible.PublicIpAssigned'] = 'TRUE'
    }
    if ($tag) {
      $dic["TagSpecification.0.ResourceType"] = 'instance'
      $i = 0
      foreach ($k in $tag.Keys) {
        $dic["TagSpecification.0.Tags.$i.Key"] = $k
        $dic["TagSpecification.0.Tags.$i.Value"] = $tag[$k]
        $i++
      }
    }
    $region = GetRegionByZone $zone
  }
  process {
    $dic['InstanceName'] = $instanceName
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    (CallApi $url).InstanceIdSet
  }
  end {}
}

Function Remove-TcInstance {
  <#
    .SYNOPSIS
    Remove (terminate) a Tencent Cloud instance.

    .DESCRIPTION
    Terminate an instance and release its associated resources (public IP, data disks).

    .PARAMETER instance
    The instance object to remove. Accepts pipeline input.

    .EXAMPLE
    PS> Get-TcInstanceById -I 'ins-xxxxx' | Remove-TcInstance
    Terminate an instance by ID.

    .EXAMPLE
    PS> Get-TcInstanceByName -N 'old-server' | Remove-TcInstance
    Terminate instances by name.

    .LINK
    New-TcInstance
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
      $instance
  )
  begin {}
  process {
    $region = GetRegionByZone $instance.Placement.zone
    $dic = @{
      Action = 'TerminateInstances'
      "InstanceIds.0" = $instance.instanceId
      ReleaseAddress = 'true'
      ReleasePrepaidDataDisks = 'true'
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    CallApi $url
  }
  end {}
}

Function Get-TcCommandInvocation {
  <#
    .SYNOPSIS
    Get command invocation details.

    .DESCRIPTION
    Retrieve information about a command execution invocation including status and task details.

    .PARAMETER invocationId
    The invocation ID returned by Invoke-TcInstanceCommand.

    .PARAMETER region
    Specify the region. Default: Current default region

    .OUTPUTS
    Invocation object.

    .EXAMPLE
    PS> Get-TcCommandInvocation -R 'ap-hongkong' -InvocationId 'ivk-xxxxx'
    Get invocation details.
  #>
  param(    
    [parameter(
      Mandatory = $true
    )]
      $invocationId,

    [Alias('R')]
    [String]
      $region = (Get-TencentCloud).DefaultRegion
  )
  $dic = @{
    Action            = 'DescribeInvocations'
    'InvocationIds.0' = $invocationId
  }
  $dic = AddApiSignature $dic $region
  $url = ConvertDic2Url $dic
  (CallApi $url).InvocationSet
}

Function Get-TcCommandInvocationTask {
  <#
    .SYNOPSIS
    Get command invocation task details.

    .DESCRIPTION
    Retrieve detailed execution results of a specific invocation task on an instance.

    .PARAMETER invocationTaskId
    The invocation task ID.

    .PARAMETER region
    Specify the region. Default: Current default region

    .OUTPUTS
    Invocation task object with execution results.

    .EXAMPLE
    PS> Get-TcCommandInvocationTask -R 'ap-hongkong' -InvocationTaskId 'ivkt-xxxxx'
    Get task execution details.
  #>
  param(
    [parameter(
      Mandatory = $true
    )]
      $invocationTaskId,

    [Alias('R')]
    [String]
      $region = (Get-TencentCloud).DefaultRegion
  )
  $dic = @{
    Action                = 'DescribeInvocationTasks'
    'InvocationTaskIds.0' = $invocationTaskId
    HideOutput            = 'false'
  }
  $dic = AddApiSignature $dic $region
  $url = ConvertDic2Url $dic
  (CallApi $url).InvocationTaskSet
}

Function Invoke-TcInstanceCommand {
  <#
    .SYNOPSIS
    Execute a command on a Tencent Cloud instance.

    .DESCRIPTION
    Run a shell, PowerShell, or batch command on an instance using the Tencent Agent service.

    .PARAMETER instance
    The instance object to execute on. Accepts pipeline input.

    .PARAMETER command
    The command to execute.

    .PARAMETER commandType
    Command type: BAT, POWERSHELL, or SHELL. Default: POWERSHELL

    .PARAMETER wait
    Wait for command completion.

    .PARAMETER timeout
    Timeout in seconds for command execution. Default: 120

    .OUTPUTS
    Invocation ID and command result (if wait is specified).

    .EXAMPLE
    PS> Get-TcInstanceById -I 'ins-xxxxx' | Invoke-TcInstanceCommand -Command 'ipconfig'
    Run a command and return immediately with invocation ID.

    .EXAMPLE
    PS> Get-TcInstanceById -I 'ins-xxxxx' | Invoke-TcInstanceCommand -Command 'systemctl status docker' -CommandType SHELL -Wait
    Run a command and wait for results.

    .LINK
    Get-TcCommandInvocation
    Get-TcCommandInvocationTask
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
      $instance,
    
    [parameter(
      Mandatory = $true
    )]
      $command,
    
    [ValidateSet('BAT', 'POWERSHELL', 'SHELL')]
    [string]
      $commandType = 'POWERSHELL',

    [switch]
      $wait,

    [int]
      $timeout = 120
  )
  begin {}
  process {
    $region = GetRegionByZone $instance.Placement.zone
    $dic = @{
      Action = 'RunCommand'
      CommandType = $commandType.ToUpper()
      Content = "$(EncodeCvmCommand $command)"
      "InstanceIds.0" = $instance.instanceId
      Timeout = $timeout
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    $iid = (CallApi $url).invocationId
    "Running command on $($instance.instanceName)..."
    "Invocation ID: $iid"

    if ($wait -and $iid) {
      while ($timeout -gt 0) {
        $invocationSet = Get-TcCommandInvocation -region $region -invocationId $iid
        if ($invocationSet.InvocationStatus -notin @('PENDING', 'RUNNING')) {
          "Invocation result: {0}" -f $invocationSet.InvocationStatus
          $invocationTask = Get-TcCommandInvocationTask -region $region `
            -invocationTaskId $invocationSet.InvocationTaskBasicInfoSet.InvocationTaskId
          if ($invocationTask.taskstatus -eq 'SUCCESS') {
            DecodeCvmCommandResult $invocationTask.TaskResult.Output
          } else {
             "Invocation task result: {0}" -f $invocationTask.taskstatus
          }
          return
        } else {
          sleep 5
          "`t Waiting ..."
          $timeout -= 5
        }
      }
      "Command timeout on $($instance.instanceName)"
    }
  }
  end {}
}

Function Get-TcImageById {
  <#
    .SYNOPSIS
    Get a Tencent Cloud image by ID.

    .DESCRIPTION
    Retrieve image details by image ID.

    .PARAMETER imageId
    The image ID. Accepts pipeline input via property name.
    
    .PARAMETER region
    Specify the region. Default: Current default region

    .OUTPUTS
    Image object(s).

    .EXAMPLE
    PS> Get-TcImageById -ImageId 'img-xxxxx'
    Get image details by ID.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [string]
      $imageId,
    
    [Alias('R')]
    [String]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {}
  process {
    $dic = @{
      Action = 'DescribeImages'
      "ImageIds.0" = $imageId
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    (CallApi $url).ImageSet
  }
  end {}
}

Function Get-TcImageByName {
  <#
    .SYNOPSIS
    Get Tencent Cloud images by name.

    .DESCRIPTION
    Retrieve images matching a specific image name pattern.

    .PARAMETER imageName
    The image name to search for. Accepts pipeline input via property name.
    
    .PARAMETER region
    Specify the region. Default: Current default region

    .OUTPUTS
    Image object(s).

    .EXAMPLE
    PS> Get-TcImageByName -ImageName 'Ubuntu-20.04'
    Get images with matching name.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [string]
      $imageName,
    
    [Alias('R')]
    [String]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {}
  process {
    $dic = @{
      Action = 'DescribeImages'
      "Filters.0.Name" = 'image-name'
      "Filters.0.Values.0" = $imageName
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    (CallApi $url).ImageSet
  }
  end {}
}

Function Get-TcImageByRegion {
  <#
    .SYNOPSIS
    Get all images in a region.

    .DESCRIPTION
    Retrieve a list of all images available in a Tencent Cloud region.

    .PARAMETER region
    Specify the region. Accepts pipeline input.
    Default: Current default region

    .OUTPUTS
    Image object array.

    .EXAMPLE
    PS> Get-TcImageByRegion -R 'ap-hongkong'
    Get all images in Hong Kong region.
  #>
  param(
    [parameter(
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [string]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {
    $objList = New-Object System.Collections.ArrayList
  }
  process {
    $obj = GetAllTcObj -a 'DescribeImages' -p 'ImageSet' -r $region
    $objList.AddRange(@($obj))
  }
  end {
    $objList
  }
}

Function New-TcImage {
  <#
    .SYNOPSIS
    Create a custom image from an instance.

    .DESCRIPTION
    Create a new image from a running or stopped instance. The image can be used to launch new instances.

    .PARAMETER instance
    The instance to create image from. Accepts pipeline input.

    .PARAMETER imageName
    Name for the new custom image.

    .OUTPUTS
    API response with image creation details.

    .EXAMPLE
    PS> Get-TcInstanceById -I 'ins-xxxxx' | New-TcImage -ImageName 'my-custom-image'
    Create a custom image from an instance.
  #>
  param(
    [parameter(Mandatory = $true)]
      $instance,

    [parameter(Mandatory = $true)]
    [string]
      $imageName
  )
  $dic = @{
    Action     = 'CreateImage'
    InstanceId = $instance.instanceId
    ImageName  = $imageName
  }
  $region = GetRegionByZone $instance.Placement.zone
  $dic = AddApiSignature $dic $region
  $url = ConvertDic2Url $dic
  CallApi $url
}

Function Remove-TcImageById {
  <#
    .SYNOPSIS
    Delete a custom image.

    .DESCRIPTION
    Remove a custom image and optionally delete associated snapshots.

    .PARAMETER imageId
    The image ID to delete. Accepts pipeline input.
    
    .PARAMETER region
    Specify the region. Default: Current default region

    .EXAMPLE
    PS> Remove-TcImageById -ImageId 'img-xxxxx'
    Delete an image.

    .EXAMPLE
    PS> Get-TcImageByName -ImageName 'old-image' | Remove-TcImageById
    Delete images via pipeline.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
      $imageId,
    
    [string]
      $region = (Get-TencentCloud).DefaultRegion
  )

  begin {}
  process {
    $dic = @{
      Action           = 'DeleteImages'
      "ImageIds.0"     = $imageId
      DeleteBindedSnap = 'true'
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    CallApi $url
  }
  end {}
}

Function Get-TcDiskById {
  <#
    .SYNOPSIS
    Get a Tencent Cloud disk by ID.

    .DESCRIPTION
    Retrieve detailed information about a specific disk using its disk ID.

    .PARAMETER diskId
    The disk ID. Accepts pipeline input via property name.

    .PARAMETER region
    Specify the region. Default: Current default region

    .OUTPUTS
    Disk object.

    .EXAMPLE
    PS> Get-TcDiskById -DiskId 'disk-xxxxx'
    Get disk details by ID.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [string]
      $diskId,

    [string]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {}
  process {
    $dic = @{
      Action = 'DescribeDisks'
      "DiskIds.0" = $diskId
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    (CallApi $url).DiskSet
  }
  end {}
}

Function Get-TcDiskByName {
  <#
    .SYNOPSIS
    Get Tencent Cloud disks by name.

    .DESCRIPTION
    Retrieve disk information by searching for a specific disk name.

    .PARAMETER diskName
    The disk name to search for. Accepts pipeline input via property name.
  
    .PARAMETER region
    Specify the region. Default: Current default region

    .OUTPUTS
    Disk object(s).

    .EXAMPLE
    PS> Get-TcDiskByName -DiskName 'data-disk-1'
    Get disks with matching name.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [string]
      $diskName,
  
    [string]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {}
  process {
    $dic = @{
      Action = 'DescribeDisks'
      "Filters.0.Name" = 'disk-name'
      "Filters.0.Values.0" = $diskName
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    (CallApi $url).DiskSet
  }
  end {}
}

Function Get-TcDiskByRegion {
  <#
    .SYNOPSIS
    Get all disks in a region.

    .DESCRIPTION
    Retrieve a list of all disks in a specific Tencent Cloud region.

    .PARAMETER region
    Specify the region. Accepts pipeline input.
    Default: Current default region

    .OUTPUTS
    Disk object array.

    .EXAMPLE
    PS> Get-TcDiskByRegion -R 'ap-hongkong'
    Get all disks in Hong Kong region.
  #>
  param(
    [parameter(
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [string]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {
    $objList = New-Object System.Collections.ArrayList
  }
  process {
    $obj = GetAllTcObj 'DescribeDisks' 'DiskSet' $region
    $objList.AddRange(@($obj))
  }
  end {
    $objList
  }
}

Function Resize-TcDisk {
  <#
    .SYNOPSIS
    Resize a Tencent Cloud disk.

    .DESCRIPTION
    Increase the size of an existing disk (expansion only, reduction not supported).

    .PARAMETER disk
    The disk object to resize. Accepts pipeline input.

    .PARAMETER diskGb
    New disk size in GB.

    .EXAMPLE
    PS> Get-TcDiskById -DiskId 'disk-xxxxx' | Resize-TcDisk -DiskGb 100
    Expand disk to 100 GB.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
      $disk,

    [int]
      $diskGb
  )

  begin {}
  process {
    $region = GetRegionByZone $disk.Placement.zone
    $dic = @{
      Action   = 'ResizeDisk'
      DiskId   = $disk.diskId
      DiskSize = $diskGb
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    CallApi $url
  }
  end {}
}

Function New-TcDisk {
  <#
    .SYNOPSIS
    Create a new Tencent Cloud disk.

    .DESCRIPTION
    Create a new cloud disk with specified configuration including type, size, billing model, and optional snapshot.

    .PARAMETER diskName
    Name for the new disk. Accepts pipeline input.
    
    .PARAMETER diskType
    Disk type (CLOUD_SSD, CLOUD_HSSD, etc.). Default: CLOUD_HSSD

    .PARAMETER diskChargeType
    Billing model (PREPAID, POSTPAID_BY_HOUR, or CDCPAID). Default: POSTPAID_BY_HOUR

    .PARAMETER diskGb
    Disk size in GB.

    .PARAMETER snapshotId
    Optional snapshot ID to create disk from.

    .PARAMETER tag
    Hashtable of tags to apply to disk.

    .PARAMETER zone
    The availability zone for the disk.

    .OUTPUTS
    Disk ID array.

    .EXAMPLE
    PS> New-TcDisk -DiskName 'data-disk' -DiskType 'CLOUD_HSSD' -DiskGb 100 -Zone 'ap-hongkong-2'
    Create a new 100GB SSD disk.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
      $diskName,
    
    [ValidateSet('CLOUD_SSD', 'CLOUD_HSSD', 'CLOUD_PREMIUM', 'CLOUD_BSSD', 'CLOUD_TSSD')]
    [string]
      $diskType = 'CLOUD_HSSD',

    [ValidateSet('PREPAID', 'POSTPAID_BY_HOUR', 'CDCPAID')]
    [string]
      $diskChargeType = 'POSTPAID_BY_HOUR',

    $diskGb,
    $snapshotId,
    $tag = @{},
    
    [parameter(Mandatory = $true)]
    [string]
      $zone
  )
  begin {
     $dic = @{
      Action           = 'CreateDisks'
      DiskType         = $diskType
      DiskChargeType   = $diskChargeType
      'Placement.Zone' = $zone    
    }
    if ($diskChargeType -eq 'PREPAID') {
      $dic['DiskChargePrepaid.Period'] = '1'
      $dic['DiskChargePrepaid.RenewFlag'] = 'NOTIFY_AND_AUTO_RENEW'
    }
    if ($diskGb) {
      $dic['DiskSize'] = $diskGb
    }
    if ($snapshotId) {
      $dic['SnapshotId'] = $snapshotId
    }
    if ($tag) {
      $i = 0
      foreach ($k in $tag.Keys) {
        $dic["Tags.$i.Key"] = $k
        $dic["Tags.$i.Value"] = $tag[$k]
        $i++
      }
    }
    $region = GetRegionByZone $zone
  }
  process {
    $dic['DiskName'] = $diskName
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    (CallApi $url).DiskIdSet
  }
  end {}
}

Function Remove-TcDisk {
  <#
    .SYNOPSIS
    Delete a Tencent Cloud disk.

    .DESCRIPTION
    Terminate and delete a cloud disk. Disk must not be attached to an instance.

    .PARAMETER disk
    The disk object to delete. Accepts pipeline input.

    .EXAMPLE
    PS> Get-TcDiskById -DiskId 'disk-xxxxx' | Remove-TcDisk
    Delete a disk by ID.

    .LINK
    New-TcDisk
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
      $disk
  )

  begin {}
  process {
    $region = GetRegionByZone $disk.Placement.zone
    $dic = @{
      Action      = 'TerminateDisks'
      "DiskIds.0" = $disk.diskId
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    CallApi $url
  }
  end {}
}

Function Get-TcSnapshotById {
  <#
    .SYNOPSIS
    Get a Tencent Cloud snapshot by ID.

    .DESCRIPTION
    Retrieve snapshot details by snapshot ID.

    .PARAMETER snapshotId
    The snapshot ID. Accepts pipeline input via property name.
  
    .PARAMETER region
    Specify the region. Default: Current default region

    .OUTPUTS
    Snapshot object.

    .EXAMPLE
    PS> Get-TcSnapshotById -SnapshotId 'snap-xxxxx'
    Get snapshot details by ID.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [string]
      $snapshotId,
  
    [string]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {}
  process {
    $dic = @{
      Action = 'DescribeSnapshots'
      "SnapshotIds.0" = $snapshotId
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    (CallApi $url).SnapshotSet
  }
  end {}
}

Function Get-TcSnapshotByName {
  <#
    .SYNOPSIS
    Get Tencent Cloud snapshots by name.

    .DESCRIPTION
    Retrieve snapshot information by searching for a specific snapshot name.

    .PARAMETER snapshotName
    The snapshot name to search for. Accepts pipeline input via property name.
    
    .PARAMETER region
    Specify the region. Default: Current default region

    .OUTPUTS
    Snapshot object(s).

    .EXAMPLE
    PS> Get-TcSnapshotByName -SnapshotName 'backup-2024'
    Get snapshots with matching name.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [string]
      $snapshotName,
    
    [string]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {}
  process {
    $dic = @{
      Action = 'DescribeSnapshots'
      "Filters.0.Name" = 'snapshot-name'
      "Filters.0.Values.0" = $snapshotName
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    (CallApi $url).SnapshotSet
  }
  end {}
}

Function Get-TcSnapshotByRegion {
  <#
    .SYNOPSIS
    Get all snapshots in a region.

    .DESCRIPTION
    Retrieve a list of all snapshots in a specific Tencent Cloud region.

    .PARAMETER region
    Specify the region. Accepts pipeline input.
    Default: Current default region

    .OUTPUTS
    Snapshot object array.

    .EXAMPLE
    PS> Get-TcSnapshotByRegion -R 'ap-hongkong'
    Get all snapshots in Hong Kong region.
  #>
  param(
    [parameter(
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [string]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {
    $objList = New-Object System.Collections.ArrayList
  }
  process {
    $obj = GetAllTcObj 'DescribeSnapshots' 'SnapshotSet' $region
    $objList.AddRange(@($obj))
  }
  end {
    $objList
  }
}

Function New-TcSnapshot {
  <#
    .SYNOPSIS
    Create a snapshot of a disk.

    .DESCRIPTION
    Create a snapshot from a cloud disk for backup and recovery purposes. Optionally wait for completion.

    .PARAMETER disk
    The disk object to snapshot. Accepts pipeline input.

    .PARAMETER snapshotName
    Name for the snapshot. Defaults to disk name if not specified.

    .PARAMETER wait
    Wait for snapshot creation to complete.

    .PARAMETER timeout
    Timeout in seconds for wait operation. Default: 180

    .OUTPUTS
    Snapshot ID.

    .EXAMPLE
    PS> Get-TcDiskById -DiskId 'disk-xxxxx' | New-TcSnapshot -SnapshotName 'backup-2024'
    Create a snapshot and wait for completion.

    .EXAMPLE
    PS> New-TcSnapshot -Disk $disk -SnapshotName 'daily-backup' -Wait
    Create a named snapshot with wait.

    .LINK
    Get-TcSnapshotById
  #>
  param(
     [parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
      $disk,

    $snapshotName = $disk.diskName,
    [switch]
      $wait,
    $timeout = 180
  )
  begin {}
  process {
    $dic = @{
      Action = 'CreateSnapshot'
      DiskId = $disk.diskId
      SnapshotName = $snapshotName
    }
    $region = GetRegionByZone $disk.Placement.zone
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    $snapshotId = (CallApi $url).snapshotId
    "Creating snapshot $snapshotId ..."
    if ($wait) {
      while ($timeout -gt 0) {
        $snapshot = Get-TcSnapshotById -region $region -snapshotId $snapshotId
        if ($snapshot.SnapshotState -eq 'CREATING') {
          sleep 10
          "`t Waiting ..."
          $timeout -= 10
        } else {
          "$snapshotId is $($snapshot.SnapshotState)"
          return
        }
      }
      "Timeout creating $snapshotId"
    }
  }
  end {}
}

Function Remove-TcSnapshot {
  <#
    .SYNOPSIS
    Delete a Tencent Cloud snapshot.

    .DESCRIPTION
    Remove a snapshot and optionally delete associated images.

    .PARAMETER snapshot
    The snapshot object to delete. Accepts pipeline input.

    .EXAMPLE
    PS> Get-TcSnapshotById -SnapshotId 'snap-xxxxx' | Remove-TcSnapshot
    Delete a snapshot by ID.

    .LINK
    New-TcSnapshot
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
      $snapshot
  )

  begin {}
  process {
    $region = GetRegionByZone $snapshot.Placement.zone
    $dic = @{
      Action           = 'DeleteSnapshots'
      "SnapshotIds.0"  = $snapshot.snapshotId
      DeleteBindImages = 'true'
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    CallApi $url
  }
  end {}
}

Function Get-TcInstanceDiskUsagePct {
  <#
    .SYNOPSIS
    Get disk usage percentage for an instance.

    .DESCRIPTION
    Retrieve the current disk usage percentage for a specific disk on an instance.

    .PARAMETER instance
    The instance object. Accepts pipeline input.

    .PARAMETER diskName
    The name of the disk to query usage for.

    .OUTPUTS
    Disk usage percentage value.

    .EXAMPLE
    PS> Get-TcInstanceById -I 'ins-xxxxx' | Get-TcInstanceDiskUsagePct -DiskName 'cvm_dev'
    Get disk usage percentage.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
      $instance,
    [parameter(Mandatory = $true)]
    [string]
      $diskName
  )
  begin {}
  process {
    $region = GetRegionByZone $instance.Placement.zone
    $dic = @{
      Action = 'GetMonitorData'
      Namespace = 'QCE/CVM'
      Period = 300
      MetricName = 'DiskUsage'
      'Instances.N.Dimensions.0.Name' = 'InstanceId'
      'Instances.N.Dimensions.0.Value' = $instance.instanceId
      'Instances.N.Dimensions.1.Name' = 'diskname'
      'Instances.N.Dimensions.1.Value' = $diskName
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    (CallApi $url).datapoints.values[-1]
  }
  end {}
}

Function Get-TcInstanceDiskTotalGb {
  <#
    .SYNOPSIS
    Get total disk size for an instance disk.

    .DESCRIPTION
    Retrieve the total disk capacity in GB for a specific disk on an instance.

    .PARAMETER instance
    The instance object. Accepts pipeline input.

    .PARAMETER diskName
    The name of the disk to query total size for.

    .OUTPUTS
    Disk total size in GB.

    .EXAMPLE
    PS> Get-TcInstanceById -I 'ins-xxxxx' | Get-TcInstanceDiskTotalGb -DiskName 'cvm_dev'
    Get disk total size.

    .LINK
    Tencent Cloud API
    English: https://www.tencentcloud.com/document/product/248/33881
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
      $instance,
    [parameter(Mandatory = $true)]
    [string]
      $diskName
  )
  begin {}
  process {
    $region = GetRegionByZone $instance.Placement.zone
    $dic = @{
      Action = 'GetMonitorData'
      Namespace = 'QCE/CVM'
      Period = 300
      MetricName = 'DiskTotal'
      'Instances.N.Dimensions.0.Name' = 'InstanceId'
      'Instances.N.Dimensions.0.Value' = $instance.instanceId
      'Instances.N.Dimensions.1.Name' = 'diskname'
      'Instances.N.Dimensions.1.Value' = $diskName
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    (CallApi $url).datapoints.values[-1] / 1024
  }
  end {}
}

Function Get-TcVpcById {
  <#
    .SYNOPSIS
    Get a Tencent Cloud VPC by ID.

    .DESCRIPTION
    Retrieve VPC details by VPC ID.

    .PARAMETER vpcId
    The VPC ID. Accepts pipeline input via property name.
    
    .PARAMETER region
    Specify the region. Default: Current default region

    .OUTPUTS
    VPC object.

    .EXAMPLE
    PS> Get-TcVpcById -VpcId 'vpc-xxxxx'
    Get VPC details by ID.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [string]
      $vpcId,
    
    [string]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {}
  process {
    $dic = @{
      Action = 'DescribeVpcs'
      "VpcIds.0" = $vpcId
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    (CallApi $url).VpcSet
  }
  end {}
}

Function Get-TcVpcByName {
  <#
    .SYNOPSIS
    Get Tencent Cloud VPCs by name.

    .DESCRIPTION
    Retrieve VPC information by searching for a specific VPC name.

    .PARAMETER vpcName
    The VPC name to search for. Accepts pipeline input via property name.
    
    .PARAMETER region
    Specify the region. Default: Current default region

    .OUTPUTS
    VPC object(s).

    .EXAMPLE
    PS> Get-TcVpcByName -VpcName 'production-vpc'
    Get VPCs with matching name.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [string]
      $vpcName,
    
    [string]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {}
  process {
    $dic = @{
      Action = 'DescribeVpcs'
      "Filters.0.Name" = 'vpc-name'
      "Filters.0.Values.0" = $vpcName
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    (CallApi $url).VpcSet
  }
  end {}
}

Function Get-TcVpcByRegion {
  <#
    .SYNOPSIS
    Get all VPCs in a region.

    .DESCRIPTION
    Retrieve a list of all Virtual Private Clouds (VPCs) in a specific region.

    .PARAMETER region
    Specify the region. Accepts pipeline input.
    Default: Current default region

    .OUTPUTS
    VPC object array.

    .EXAMPLE
    PS> Get-TcVpcByRegion -R 'ap-hongkong'
    Get all VPCs in Hong Kong region.
  #>
  param(
    [parameter(
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [string]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {
    $objList = New-Object System.Collections.ArrayList
  }
  process {
    $obj = GetAllTcObj 'DescribeVpcs' 'VpcSet' $region
    $objList.AddRange(@($obj))
  }
  end {
    $objList
  }
}

Function New-TcVpc {
  <#
    .SYNOPSIS
    Create a new Tencent Cloud VPC.

    .DESCRIPTION
    Create a new Virtual Private Cloud with specified CIDR block and optional tags.

    .PARAMETER vpcName
    Name for the new VPC.
    
    .PARAMETER cidrBlock
    CIDR block for the VPC (e.g., '10.0.0.0/16').

    .PARAMETER tag
    Hashtable of tags to apply to the VPC.

    .PARAMETER region
    Specify the region. Default: Current default region

    .OUTPUTS
    API response with VPC creation details.

    .EXAMPLE
    PS> New-TcVpc -VpcName 'production' -CidrBlock '10.0.0.0/16'
    Create a new VPC.

    .LINK
    Get-TcVpcById
  #>
  param(
    [parameter(Mandatory = $true)]
    [string]
      $vpcName,
    
    [parameter(Mandatory = $true)]
    [string]
      $cidrBlock,

    $tag = @{},
    
    [string]
      $region = (Get-TencentCloud).DefaultRegion
  )
  $dic = @{
    Action = 'CreateVpc'
    VpcName = $vpcName
    CidrBlock = $cidrBlock
  }
  if ($tag) {
      $i = 0
      foreach ($k in $tag.Keys) {
        $dic["Tags.$i.Key"] = $k
        $dic["Tags.$i.Value"] = $tag[$k]
        $i++
      }
    }
  $dic = AddApiSignature $dic $region
  $url = ConvertDic2Url $dic
  CallApi $url
}

Function Remove-TcVpc {
  <#
    .SYNOPSIS
    Delete a Tencent Cloud VPC.

    .DESCRIPTION
    Remove a VPC. VPC must not contain any subnets.

    .PARAMETER vpc
    The VPC object to delete. Accepts pipeline input.

    .EXAMPLE
    PS> Get-TcVpcById -VpcId 'vpc-xxxxx' | Remove-TcVpc
    Delete a VPC by ID.

    .LINK
    New-TcVpc
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
      $vpc
  )
  begin {}
  process {
    $region = $vpc.Region
    $dic = @{
      Action = 'DeleteVpc'
      "VpcId" = $vpc.VpcId
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    CallApi $url
  }
  end {}
}

Function Get-TcSubnetById {
  <#
    .SYNOPSIS
    Get a Tencent Cloud subnet by ID.

    .DESCRIPTION
    Retrieve subnet details by subnet ID.

    .PARAMETER subnetId
    The subnet ID. Accepts pipeline input via property name.
    
    .PARAMETER region
    Specify the region. Default: Current default region

    .OUTPUTS
    Subnet object.

    .EXAMPLE
    PS> Get-TcSubnetById -SubnetId 'subnet-xxxxx'
    Get subnet details by ID.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [string]
      $subnetId,
    
    [string]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {}
  process {
    $dic = @{
      Action = 'DescribeSubnets'
      "SubnetIds.0" = $subnetId
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    (CallApi $url).SubnetSet
  }
  end {}
}

Function Get-TcSubnetByName {
  <#
    .SYNOPSIS
    Get Tencent Cloud subnets by name.

    .DESCRIPTION
    Retrieve subnet information by searching for a specific subnet name.

    .PARAMETER subnetName
    The subnet name to search for. Accepts pipeline input via property name.
    
    .PARAMETER region
    Specify the region. Default: Current default region

    .OUTPUTS
    Subnet object(s).

    .EXAMPLE
    PS> Get-TcSubnetByName -SubnetName 'public-subnet'
    Get subnets with matching name.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [string]
      $subnetName,
    
    [string]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {}
  process {
    $dic = @{
      Action = 'DescribeSubnets'
      "Filters.0.Name" = 'subnet-name'
      "Filters.0.Values.0" = $subnetName
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    (CallApi $url).SubnetSet
  }
  end {}
}

Function Get-TcSubnetByRegion {
  <#
    .SYNOPSIS
    Get all subnets in a region.

    .DESCRIPTION
    Retrieve a list of all subnets in a specific Tencent Cloud region.

    .PARAMETER region
    Specify the region. Accepts pipeline input.
    Default: Current default region

    .OUTPUTS
    Subnet object array.

    .EXAMPLE
    PS> Get-TcSubnetByRegion -R 'ap-hongkong'
    Get all subnets in Hong Kong region.
  #>
  param(
    [parameter(
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [string]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {
    $objList = New-Object System.Collections.ArrayList
  }
  process {
    $obj = GetAllTcObj 'DescribeSubnets' 'SubnetSet' $region
    $objList.AddRange(@($obj))
  }
  end {
    $objList
  }
}

Function New-TcSubnet {
  <#
    .SYNOPSIS
    Create a new Tencent Cloud subnet.

    .DESCRIPTION
    Create a new subnet within a VPC with specified CIDR block and availability zone.

    .PARAMETER subnetName
    Name for the new subnet.
    
    .PARAMETER cidrBlock
    CIDR block for the subnet (e.g., '10.0.1.0/24').

    .PARAMETER vpcId
    The VPC ID to create subnet in.
    
    .PARAMETER zone
    The availability zone for the subnet.

    .PARAMETER tag
    Hashtable of tags to apply to the subnet.

    .OUTPUTS
    API response with subnet creation details.

    .EXAMPLE
    PS> New-TcSubnet -SubnetName 'public-subnet' -CidrBlock '10.0.1.0/24' -VpcId 'vpc-xxxxx' -Zone 'ap-hongkong-2'
    Create a new subnet.

    .LINK
    Get-TcSubnetById
  #>
  param(
    [parameter(Mandatory = $true)]
    [string]
      $subnetName,
    
    [parameter(Mandatory = $true)]
    [string]
      $cidrBlock,

    [parameter(Mandatory = $true)]
    [string]
      $vpcId,
    
    [parameter(Mandatory = $true)]
    [string]
      $zone,

    $tag = @{}
  )
  $dic = @{
    Action = 'CreateSubnet'
    SubnetName = $subnetName
    CidrBlock = $cidrBlock
    VpcId = $vpcId
    Zone = $zone
  }
  if ($tag) {
      $i = 0
      foreach ($k in $tag.Keys) {
        $dic["Tags.$i.Key"] = $k
        $dic["Tags.$i.Value"] = $tag[$k]
        $i++
      }
    }
  $region = GetRegionByZone $zone
  $dic = AddApiSignature $dic $region
  $url = ConvertDic2Url $dic
  CallApi $url
}

Function Remove-TcSubnet {
  <#
    .SYNOPSIS
    Delete a Tencent Cloud subnet.

    .DESCRIPTION
    Remove a subnet. Subnet must be empty (no instances or resources attached).

    .PARAMETER subnet
    The subnet object to delete. Accepts pipeline input.

    .EXAMPLE
    PS> Get-TcSubnetById -SubnetId 'subnet-xxxxx' | Remove-TcSubnet
    Delete a subnet by ID.

    .LINK
    New-TcSubnet
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
      $subnet
  )
  begin {}
  process {
    $region = $subnet.Region
    $dic = @{
      Action = 'DeleteSubnet'
      "SubnetId" = $subnet.SubnetId
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    CallApi $url
  }
  end {}
}

Function Get-TcSecurityGroupById {
  <#
    .SYNOPSIS
    Get a Tencent Cloud security group by ID.

    .DESCRIPTION
    Retrieve security group details by security group ID.

    .PARAMETER securityGroupId
    The security group ID. Accepts pipeline input via property name.

    .PARAMETER region
    Specify the region. Default: Current default region

    .OUTPUTS
    Security group object.

    .EXAMPLE
    PS> Get-TcSecurityGroupById -SecurityGroupId 'sg-xxxxx'
    Get security group details by ID.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [string]
      $securityGroupId,

    [string]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {}
  process {
    $dic = @{
      Action = 'DescribeSecurityGroups'
      "SecurityGroupIds.0" = $securityGroupId
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    (CallApi $url).SecurityGroupSet
  }
  end {}
}

Function Get-TcSecurityGroupByName {
  <#
    .SYNOPSIS
    Get Tencent Cloud security groups by name.

    .DESCRIPTION
    Retrieve security group information by searching for a specific security group name.

    .PARAMETER securityGroupName
    The security group name to search for. Accepts pipeline input via property name.
    
    .PARAMETER region
    Specify the region. Default: Current default region

    .OUTPUTS
    Security group object(s).

    .EXAMPLE
    PS> Get-TcSecurityGroupByName -SecurityGroupName 'web-sg'
    Get security groups with matching name.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [string]
      $securityGroupName,
    
    [string]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {}
  process {
    $dic = @{
      Action = 'DescribeSecurityGroups'
      "Filters.0.Name" = 'security-group-name'
      "Filters.0.Values.0" = $securityGroupName
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    (CallApi $url).SecurityGroupSet
  }
  end {}
}

Function Get-TcSecurityGroupByRegion {
  <#
    .SYNOPSIS
    Get all security groups in a region.

    .DESCRIPTION
    Retrieve a list of all security groups in a specific Tencent Cloud region.

    .PARAMETER region
    Specify the region. Accepts pipeline input.
    Default: Current default region

    .OUTPUTS
    Security group object array.

    .EXAMPLE
    PS> Get-TcSecurityGroupByRegion -R 'ap-hongkong'
    Get all security groups in Hong Kong region.
  #>
  param(
    [parameter(
      ValueFromPipelineByPropertyName = $true,
      ValueFromPipeline = $true
    )]
    [string]
      $region = (Get-TencentCloud).DefaultRegion
  )
  begin {
    $objList = New-Object System.Collections.ArrayList
  }
  process {
    $obj = GetAllTcObj 'DescribeSecurityGroups' 'SecurityGroupSet' $region
    $objList.AddRange(@($obj))
  }
  end {
    $objList
  }
}

Function Get-TcSecurityGroupPolicy {
  <#
    .SYNOPSIS
    Get security group firewall rules.

    .DESCRIPTION
    Retrieve all inbound and outbound rules (policies) for a security group.

    .PARAMETER securityGroup
    The security group object. Accepts pipeline input.

    .OUTPUTS
    Security group policy set including inbound and outbound rules.

    .EXAMPLE
    PS> Get-TcSecurityGroupById -SecurityGroupId 'sg-xxxxx' | Get-TcSecurityGroupPolicy
    Get all policies for a security group.
  #>
  param(
    [parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
      $securityGroup
  )
  begin {}
  process {
    $region = $securityGroup.Region
    $dic = @{
      Action = 'DescribeSecurityGroupPolicies'
      "SecurityGroupId" = $securityGroup.SecurityGroupId
    }
    $dic = AddApiSignature $dic $region
    $url = ConvertDic2Url $dic
    (CallApi $url).SecurityGroupPolicySet
  }
  end {}
}

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