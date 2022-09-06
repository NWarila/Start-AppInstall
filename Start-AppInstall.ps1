<#
    .SYNOPSIS
    .DESCRIPTION
    .PARAMETER Confirm
        [Int] Determine what type of changes should be prompted before executing.
            0 - Confirm both environment and object changes.
            1 - Confirm only object changes. (Default)
            2 - Confirm nothing!
            Object Changes are changes that are permanent such as file modifications, registry changes, etc.
            Environment changes are changes that can normally be restored via restart, such as opening/closing applications.
            Note: This configuration will take priority over Debugger settings for confirm action preference.
    .PARAMETER Debugger
        [Int] Used primarily to quickly apply multiple arguments making script development and debugging easier. Useful only for developers.
            1. Incredibly detailed play-by-play execution of the script. Equivilent to '-Change 0',  '-LogLevel Verbose', script wide 'ErrorAction Stop', 'Set-StrictMode -latest', and lastly 'Set-PSDebug -Trace 1'
            2. Equivilent to '-Change 0', '-LogLevel Verbose', and script wide 'ErrorAction Stop'.
            3. Equivilent to '-Change 1', '-LogLevel Info', and enables verbose on PS commands.
    .PARAMETER LogLevel
        [String] Used to display log output with definitive degrees of verboseness.
            Verbose = Display everything the script is doing with extra verbose messages, helpful for debugging, useless for everything else.
            Debug   = Display all messages at a debug or higher level, useful for debugging.
            Info    = Display all informational messages and higher. (Default)
            Warn    = Display only warning and error messages.
            Error   = Display only error messages.
            None    = Display absolutely nothing.
    .INPUTS
        None
    .OUTPUTS
        None
    .NOTES
    VERSION     DATE			NAME						DESCRIPTION
    ___________________________________________________________________________________________________________
    1.0         28 Sept 2020	Warilia, Nicholas R.		Initial version
    Script tested on the following Powershell Versions
        1.0   2.0   3.0   4.0   5.0   5.1
    ----- ----- ----- ----- ----- -----
        X    X      X     X     ✓    ✓
    Credits:
        (1) Script Template: https://gist.github.com/9to5IT/9620683
        (2) Scipt MultiThreading: https://blog.netnerds.net/2016/12/runspaces-simplified/
    To Do List:
        (1) Get Powershell Path based on version (stock powershell, core, etc.)
    Additional Information:
        #About '#Requires': https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_requires?view=powershell-5.1
        Show-Command Creates GUI window with all parameter; super easy to see what options are available for a command.
        Get-Verb Shows all approved powershell versb
#>

[CmdletBinding(
    ConfirmImpact = 'None',
    DefaultParameterSetName = 'Site',
    HelpURI = '',
    SupportsPaging = $False,
    SupportsShouldProcess = $True,
    PositionalBinding = $True
)] Param (
    [ValidateSet(0, 1, 2)]
    [Int]$Confim = 1,
    [ValidateSet(0, 1, 2)]
    [Int]$Debugger = 3,
    [ValidateSet('Verbose', 'Debug', 'Info', 'Warn', 'Error', 'Fatal', 'Off')]
    [String]$LogLevel = 'Info',
    [ValidateSet('Log', 'Host', 'LogHost', 'Auto')]
    [String]$LogOutput = 'Auto'
)

#region ------ [ AD Domain Controller Query ] ---------------------------------------------------------------------
#endregion --- [ AD Domain Controller Query ] ,#')}]#")}]#'")}] ---------------------------------------------------

#region ------ [ Manual Configuration ] ---------------------------------------------------------------------------
#Require Admin Privilages.
New-Variable -Force -Name:'ScriptConfig' -Value @{
    #Should script enforce running as admin.
    RequireAdmin = $False
    Debug = [Bool]$True
}
#endregion --- [ Manual Configuration ] ,#')}]#")}]#'")}] ---------------------------------------------------------

#region ------ [ Required Functions ] -----------------------------------------------------------------------------
Function Stop-AppProcess {
    [CmdletBinding(
        ConfirmImpact = 'Medium',
        SupportsShouldProcess = $True,
        PositionalBinding = $True,
        DefaultParameterSetName = 'Programs'
    )] Param(
        [Parameter(Mandatory = $True, ParameterSetName = 'Programs')]
        [Parameter(Mandatory = $False, ParameterSetName = 'ProgramDirs')]
        [Parameter(Mandatory = $True, ParameterSetName = 'Both')]
        [Array]$Programs,
        [Parameter(Mandatory = $False, ParameterSetName = 'Programs')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ProgramDirs')]
        [Parameter(Mandatory = $True, ParameterSetName = 'Both')]
        [Array]$ProgramDirs,
        [Switch]$Force
    )

    Write-Verbose -Message:'Initializing Variables.'
    @('Processes', 'TargetProcesses') | ForEach-Object -Process: {
        New-Variable -Name:$_ -Value:$Null -Force -Scope:'Local' -Option:'Private'
    }
    Set-Variable -Name:'Processes' -Value:(Get-Process | Where-Object -FilterScript: {
            [String]::IsNullOrEmpty($_.Path) -ne $True } | Select-Object -Property:'ID', 'Path')
    Set-Variable -Name:'TargetProcesses' -Value:(New-Object -TypeName:'System.Collections.Generic.List[psobject]')

    ForEach ($Program in ($ProgramDirs + $Programs)) {
        If ([String]::IsNullOrEmpty($Program) -eq $False) {
            $Processes.Where({ $_.Path -match [Regex]::Escape($Program) }) |
            ForEach-Object -Process: {
                If ($TargetProcesses.Contains($_) -eq $False) {
                    $TargetProcesses.Add($_)
                }
            }
        }
        Clear-Variable -Name:'Program' -ErrorAction:'SilentlyContinue'
    }

    ForEach ($TargetProcess in $TargetProcesses) {
        Try {
            Stop-Process -Id:$TargetProcess.id -Force:$Force -WhatIf:$WhatIfPreference -Confirm:$ConfirmPreference
            Write-Output -InputObject "[Info] Successfully stopped process: $(([System.IO.FileInfo]$TargetProcess.Path).name)"
        } Catch {
            Write-Output -InputObject "[Error] Unable to stop process. $(([System.IO.FileInfo]$TargetProcess.Path).name)"
        }
        Clear-Variable -Name:'TargetProcess' -ErrorAction:'SilentlyContinue'
    }
}
Function Convert-XMLtoPSObject {
    Param (
        $XML
    )
    New-Variable -Name:'Result' -Value:(New-Object -TypeName:'PSCustomObject')

    $xml | Get-Member -MemberType:'Property' |
    Where-Object {
        $_.MemberType -EQ 'Property'
    } | ForEach-Object -Process:{
        $tXML = $_
        Switch -Regex ($_.Definition) {
                '^\bstring\b.*$' {
                    $Result | Add-Member -MemberType:'NoteProperty' -Name:($tXML.Name) -Value:($XML.($tXML.Name))
                }
                '^\bSystem\.Object\b\[] (?!#comment).*$' {
                    Write-Host "SystemObject Baby!"
                }
                '^\bSystem.Xml.XmlElement\b.*$' {
                    $Result | Add-Member -MemberType:'NoteProperty' -Name:($tXML.Name) -Value:(
                        Convert-XMLtoPSObject -XML:($XML.($tXML.Name))
                    )
                }
                '^\bSystem\.Object\b\[] (#comment).*$' { <# Do Nothing #> }
            Default {
                Write-Host "Unrecognized Type: $($tXML.Name)='$($tXML.Definition)'"
            }
        }
    }
    $Result
}
#endregion --- [ Required Functions ] ,#')}]#")}]#'")}] -----------------------------------------------------------

#region ------ [ Determine Script Environment ] -------------------------------------------------------------------
New-Variable -Name:'nLogInitialize' -Value:$False -Force
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
Trap {
    [String]$ErrLne = '{0:000}' -f $_.InvocationInfo.ScriptLineNumber
    [String]$DbgMsg = 'Failed to execute command: {0}' -f [string]::join('', $_.InvocationInfo.line.split("`n"))
    [String]$ErrMsg = '{0} [{1}]' -f $_.Exception.Message, $_.Exception.GetType().FullName
    If ($nLogInitialize) {
        Write-nLog -Type:'Debug' -Message:$DbgMsg
        Write-nLog -Type:'Error' -Message:$ErrMsg -Line:$ErrLne
    } Else {
        Write-Host -Object:$DbgMsg
        Write-Host -Object:('[{0}] {1}' -f $ErrLne, $ErrMsg)
    }
    Clear-Variable -Name:@('DbgMsg', 'ErrLne', 'ErrTyp') -ErrorAction:'SilentlyContinue'
    Continue
}

New-Variable -Force -Name:'sEnv' -Scope:'Script' -Value @{
    RunMethod   = [String]::Empty
    Process     = [System.Diagnostics.Process]::GetCurrentProcess()
    Interactive = [Bool][Environment]::UserInteractive
    IsAdmin     = [Bool]$False
    Script      = [System.IO.FileInfo]$Null
    PSPath      = [System.IO.FileInfo]$Null
    Variables   = New-Object -TypeName:'System.Collections.Generic.List[String]'
}

Write-Verbose -Message:'Determing if script is running with admin token.'
$sEnv.IsAdmin = (New-Object -TypeName:System.Security.Principal.WindowsPrincipal(
    [System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Verbose -Message:'Checking to see if script is running interactively.'
If ($sEnv.Interactive -eq $True) {
    If ([Regex]::IsMatch($sEnv.Process.CommandLine,' -(?<Arg>c(?:ommand)?|e(?:c|ncodedcommand)?|f(?:ile)?)[: ]')) {
        $sEnv.Interactive = $False
    }
}

Write-Verbose -Message:'Setting PowerShell path.'
$sEnv.PSPath = $sEnv.Process.path

IF (Test-Path -Path Variable:PSise) {
    #Running as PSISE
    [String]$sEnv.RunMethod = 'ISE'
    [System.IO.FileInfo]$sEnv.Script = $psISE.CurrentFile.FullPath
} ElseIF (Test-Path -Path Variable:pseditor) {
    #Running as VSCode
    [String]$sEnv.RunMethod = 'VSCode'
    [System.IO.FileInfo]$sEnv.Script = $pseditor.GetEditorContext().CurrentFile.Path
} Else {
    #Running as AzureDevOps or Powershell
    [String]$sEnv.RunMethod = 'ADPS'
    IF ($Host.Version.Major -GE 3) {
        [System.IO.FileInfo]$sEnv.Script = $PSCommandPath
    } Else {
        [System.IO.FileInfo]$sEnv.Script = $MyInvocation.MyCommand.Definition
    }
}

#endregion --- [ Determine Script Environment ] ,#')}]#")}]#'")}] -------------------------------------------------

#region ------ [ Import Configuration File ] ----------------------------------------------------------------------
@('ConfigFile','Config') |ForEach-Object -Process:{
    New-Variable -Force -Name:$_ -Value:$Null
}
Set-Variable -Name:'Config' -Value:(New-Object -TypeName:'PSCustomObject')

#Loads the configuration file as a XML object.
If ($ScriptConfig.Debug) {
    Set-Variable -Name:'ConfigFile' -Value:"$($sEnv.Script.Directory.fullname)\Test-Application\install.xml"
} Else {
    Set-Variable -Name:'ConfigFile' -Value:"$($sEnv.Script.Directory.fullname)\install.xml"
}

Write-Verbose -Message:'Testing if ConfigFile path is directory.'
If ([System.IO.Directory]::Exists($ConfigFile) -eq $True) {
    Write-Warning -Message:'Configuration file path provided is a directory, appending ''install.xml''.'
    $ConfigFile = Join-Path -Path:$ConfigFile -ChildPath:'\Install.xml'
}

Write-Verbose -Message:'Attempting to load configuration file. '
Try {
    $Config = Convert-XMLtoPSObject -XML:([System.Xml.XmlDocument]((
        New-Object -TypeName 'System.IO.StreamReader' -ArgumentList:@(
            (New-Object -TypeName:'System.IO.FileStream' -ArgumentList:@(
                $ConfigFile,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::Read
            )),
            [Text.Encoding]::UTF8,
            $False,
            "10000"
        )
    ).ReadToEnd())).AppInstall
} Catch {
    Throw $_
    break
}

#endregion --- [ Import Configuration File ] ,#')}]#")}]#'")}] ----------------------------------------------------
