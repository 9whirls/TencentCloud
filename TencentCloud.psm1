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
    { $_ -eq 'GetUserAppId' } {
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
  $dic.Keys | sort | %{$query += $_ + '=' + $dic[$_]}
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

  [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
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
    $res = Invoke-WebRequest -uri $uri -ea Stop | Select -ExpandProperty content
    if ($uri -match 'Action=DescribeImages') { # fix the issue of duplicated keys
      $res = $res -ireplace "isSupportCloudinit", "IsSupportCloudinit"
    }
    $res = $res | ConvertFrom-JSON -ea stop | Select -ExpandProperty response
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
  [Alias('Get-TC')]
  param()
  if ($defaultTc) {
    $defaultTc
  } else {
    throw "No Tencent Cloud is connected. Run Connect-TencentCloud to establish a connection first."
  }
}

Function Connect-TencentCloud {
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

Function Get-TcInstanceById {
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
