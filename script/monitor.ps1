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
