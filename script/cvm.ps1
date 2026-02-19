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
