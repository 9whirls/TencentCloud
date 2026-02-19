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
