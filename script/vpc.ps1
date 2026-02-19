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