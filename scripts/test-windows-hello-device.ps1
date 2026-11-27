param([Parameter(Mandatory)][string]$TestBinary)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
$binary = (Resolve-Path -LiteralPath $TestBinary).Path
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Wormhole | Windows Hello device test'
$form.Width = 520
$form.Height = 180
$form.StartPosition = 'CenterScreen'
$form.TopMost = $true
$label = New-Object System.Windows.Forms.Label
$label.Dock = 'Fill'
$label.TextAlign = 'MiddleCenter'
$label.Text = "Start the test, then confirm the Windows Hello prompts.`r`nOnly a temporary vault slot is used."
$form.Controls.Add($label)
$start = New-Object System.Windows.Forms.Button
$start.Text = 'Avvia / Start Windows Hello test'
$start.Dock = 'Bottom'
$form.Controls.Add($start)
$process = New-Object System.Diagnostics.Process
$process.StartInfo.FileName = $binary
$process.StartInfo.Arguments = '-test.v -test.run=^TestWindowsHelloPhysicalDevice$ -test.timeout=5m'
$process.StartInfo.UseShellExecute = $false
$process.StartInfo.CreateNoWindow = $true
$process.StartInfo.RedirectStandardOutput = $true
$process.StartInfo.RedirectStandardError = $true
$process.StartInfo.EnvironmentVariables['WORMHOLE_TEST_HELLO_OWNER_WINDOW'] = $form.Handle.ToInt64().ToString()
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 250
$state = @{ Started = $false }
$waiting = [Diagnostics.Stopwatch]::StartNew()
$timer.Add_Tick({
    if (($state.Started -and $process.HasExited) -or (-not $state.Started -and $waiting.Elapsed.TotalMinutes -ge 3)) {
        $timer.Stop()
        $form.Close()
    }
})
$start.Add_Click({
    $start.Enabled = $false
    $form.TopMost = $false
    $label.Text = 'Follow the Windows Hello prompts. Use Cancel in the Windows prompt to stop.'
    [void]$process.Start()
    $state.Started = $true
    $state.Output = $process.StandardOutput.ReadToEndAsync()
    $state.Diagnostics = $process.StandardError.ReadToEndAsync()
})
$form.Add_Shown({
    $form.Activate()
    $start.Focus() | Out-Null
    [Console]::Out.WriteLine('Windows OS architecture: ' + [Runtime.InteropServices.RuntimeInformation]::OSArchitecture)
    [Console]::Out.WriteLine('Waiting for Start in the Windows Hello test window.')
    $timer.Start()
})
try {
    [System.Windows.Forms.Application]::Run($form)
    if (-not $state.Started) { exit 2 }
    $process.WaitForExit()
    [Console]::Out.Write($state.Output.GetAwaiter().GetResult())
    [Console]::Error.Write($state.Diagnostics.GetAwaiter().GetResult())
    exit $process.ExitCode
} finally {
    $timer.Dispose()
    $process.Dispose()
    $form.Dispose()
}
