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