# OpenXDR agent 一键安装（Windows，管理员 PowerShell）。在控制台「添加主机」复制命令执行：
#   & ([scriptblock]::Create((irm <控制台>/api/enroll/install.ps1))) <控制台> <令牌>
# 以 SYSTEM 身份的计划任务常驻：开机启动，另每 5 分钟检查一次，进程不在就拉起
# （自动升级后的退出、意外崩溃都靠它恢复）。重复执行即重装。
param([Parameter(Mandatory)][string]$Base, [Parameter(Mandatory)][string]$Token)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '需要管理员权限，请用"以管理员身份运行"的 PowerShell 执行'
}

$dir = Join-Path $env:ProgramData 'OpenXDR'
$bin = Join-Path $dir 'openxdr-agent.exe'
$new = "$bin.new"
$task = 'OpenXDR Agent'

New-Item -ItemType Directory -Force -Path $dir | Out-Null
# 私钥与证书所在目录只留 SYSTEM 与管理员
icacls $dir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null

Write-Host '下载 agent（windows-amd64）'
Invoke-WebRequest -UseBasicParsing -Uri "$Base/api/enroll/agent/windows-amd64" -OutFile $new
& $new version | Out-Null

Write-Host '签发主机证书并接入'
$request = (& $new enroll-request $dir) -join "`n"
if ($LASTEXITCODE -ne 0) { throw '生成接入请求失败' }
$grant = Invoke-WebRequest -UseBasicParsing -Method Post -Uri "$Base/api/enroll/register" `
    -Headers @{ Authorization = "Bearer $Token" } -ContentType 'application/json' -Body $request
$grant.Content | & $new enroll-apply $dir
if ($LASTEXITCODE -ne 0) { throw '写入接入配置失败' }

if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $task -Confirm:$false
}
Get-Process openxdr-agent -ErrorAction SilentlyContinue | Stop-Process -Force
if (Test-Path $bin) { Move-Item -Force $bin "$bin.prev" }
Move-Item -Force $new $bin

$action = New-ScheduledTaskAction -Execute $bin
$watchdog = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
$triggers = @((New-ScheduledTaskTrigger -AtStartup), $watchdog)
# 已在运行时跳过新实例，重复触发只起到"不在就拉起"的作用
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName $task -Action $action -Trigger $triggers -Settings $settings `
    -User 'SYSTEM' -RunLevel Highest | Out-Null
Start-ScheduledTask -TaskName $task
Write-Host "完成：$env:COMPUTERNAME 已接入，几秒后会出现在控制台资产列表"
