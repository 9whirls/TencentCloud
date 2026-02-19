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
