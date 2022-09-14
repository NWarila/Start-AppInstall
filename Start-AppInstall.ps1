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

    .PARAMETER debug
        [Switch]

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
Function Test-FilterScript {
    Param(
        [Parameter(Mandatory)]
        [String]$FilterScript,
        [String]$Object
    )
    Write-Verbose -Message:'Initializing Variables.'
    @('Result') | ForEach-Object -Process: {
        New-Variable -Name:$_ -Value:$Null -Force
    }

    Write-Verbose -Message:"Processing: $Object"
    If ([String]::IsNullOrWhiteSpace($FilterScript) -eq $False) {
        Write-Verbose -Message:"Object $Object has a value; Testing it."
        Write-Debug -Message:"$Object`: $FilterScript"
        Try {
            Set-Variable -Name:Result -Value:(
                [Bool](Invoke-Command -NoNewScope -ScriptBlock:(
                        [ScriptBlock]::Create($FilterScript.Trim())
                    ))
            )
        } Catch {
            Throw $Error[0]
            Return
        }
    } Else {
        Write-Verbose -Message:'Object Config.GlobalConfig.FilterScript is blank.'
    }
    Return $Result
}
Function Start-CimQuery {
    [CmdletBinding(
        ConfirmImpact = 'None',
        DefaultParameterSetName = 'Default',
        HelpURI = '',
        SupportsPaging = $False,
        SupportsShouldProcess = $True,
        PositionalBinding = $True
    )]Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$ClassName,
        [Parameter(Position = 1)]
        [String]$NameSpace = 'root\CIMV2',
        [Parameter(Position = 2)]
        [CimSession]$CimSession,
        [Parameter(Position = 3)]
        [string[]]$Property = '*',
        [Parameter(Position = 4)]
        [Switch]$NewCimSession,
        [Parameter(Position = 0)]
        [HashTable]$QuickSetup
    )

    $Step = [int]1
    $ErrorActionPreference = 'Stop'

    Write-Debug -Message:("Step $Step` Initalizing Variables Variables"); $Step++
    @('Result') | ForEach-Object { New-Variable -Name:$_ -Value:$Null }
    New-Variable -Name:'CimInstSplat' -Value:(@{'Property' = $Property; 'NameSpace' = $NameSpace })
    New-Variable -Name:'CimProperties' -Value:@('ClassName', 'NameSpace', 'CimSession', 'Property')


    Write-Debug -Message:('Step $Step: Quickstep Check.'); $Step++
    If ($QuickSetup) {
        ForEach ($Param in $QuickSetup.GetEnumerator()) {
            Write-Verbose -Message:"ForEach-Param: $($param.Key)"
            If ($Param.Key -in $CimProperties) {
                Write-Verbose -Message:('Adding ''{0}'' key with value ''{1}'' to CimInstSplat.' -f
                    $Param.Key, $Param.Value)
                $CimInstSplat[$Param.Key] = $Param.Value
            } Else {
                Write-Warning -Message:'CimProperty {0} does not match a valid CimSession property.'
            }
        }
        $Null = $PSBoundParameters.Remove('QuickSetup')
    }

    Write-Debug -Message:("Step $Step` Add PSBound Parameters to CimInstSplat."); $Step++
    ForEach ($Param in $PSBoundParameters.GetEnumerator()) {
        If ($Param.Key -in $CimProperties) {
            Write-Debug -Message:"Adding $($Param.Key) ot `$CimInstSplat."
            Write-Verbose -Message:('Adding ''{0}'' key with value ''{1}'' to CimInstSplat.' -f
                $Param.Key, $Param.Value)
            $CimInstSplat[$Param.Key] = $Param.Value
        } Else {
            Write-Debug -Message:"Skipping $($Param.Key); Not in `$CimProperties."
        }
    }


    Write-Debug -Message:("Step $Step` CimSession Check"); $Step++
    If (('CimSession' -NotIn $CimInstSplat.keys) -or $NewCimSession) {
        Write-Verbose -Message:'Attempting to create a DCOM CimSession for LocalHost.'
        $lMSG = 'Creating LocalCimSession: {0}'
        $CimInstSplat['CimSession'] = (
            New-CimSession -ComputerName:'LocalHost' -SessionOption:(
                New-CimSessionOption -Protocol:'Dcom'
            )
        )
        Write-Debug -Message:($lMSG -f 'Success')
    }


    Write-Debug -Message:("Step $Step`: CimSession Check"); $Step++
    $lMSG = 'Get-CimInstance command result: {0}'
    Try {
        Set-Variable -Name:'Result' -Value:(
            Get-CimInstance @CimInstSplat | Select-Object -Property $CimInstSplat.Property)
        Write-Verbose -Message:($lMSG -f 'Success')
    } Catch [Microsoft.Management.Infrastructure.CimException] {
        If ($NewCimSession) {
            Throw $_
        } Else {
            Start-CimQuery -QuickSetup:$CimInstSplat -NewCimSession
        }
    } Catch {
        Throw $_
    }
    Write-Debug -Message:($lMSG -f 'Success')

    Return $Result
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
Set-Variable -Name:'Config' -Value:(New-Object -TypeName:'System.Xml.XmlDocument')

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
    $Config.Load($ConfigFile)
    $Config = $Config.SelectSingleNode('AppInstall')
} Catch {
    Throw $_
    break
}
#endregion --- [ Import Configuration File ] ,#')}]#")}]#'")}] ----------------------------------------------------

#region ------ [ Load System Information ] ------------------------------------------------------------------------
    @('LocalCimSession','OperatingSystem','ComputerSystem','SystemInformation') | ForEach-Object -Process: {
        New-Variable -Force -Name:$_ -Value:$Null
    }

    Write-Verbose -Message:'Loading DCOM CimSession for WMI Queries.'
    Set-Variable -Name:'LocalCimSession' -Value:(
        New-CimSession -ComputerName:'localhost' –SessionOption:(
            New-CimSessionOption –Protocol:'DCOM'
        )
    )

    Write-Verbose -Message:'Loading Operating System information.'
    Set-Variable -Name:'OperatingSystem' -Value:(
        Start-CimQuery -QuickSetup:@{
            ClassName  = 'Win32_OperatingSystem';
            NameSpace  = 'root\CIMV2';
            Property   = 'BuildNumber', 'Caption', 'Description', 'OSArchitecture', 'OSType', 'Version',
            'PortableOperatingSystem', 'ProductType'
            CimSession = $LocalCimSession
        }
    )

    Write-Verbose -Message:'Loading ComputerSystem information.'
    Set-Variable -Name:'ComputerSystem' -Value:(
        Start-CimQuery -QuickSetup:@{
            ClassName  = 'Win32_ComputerSystem';
            NameSpace  = 'root/CIMV2';
            Property   = 'Manufacturer', 'Model'
            CimSession = $LocalCimSession
        }
    )

    Set-Variable -Name:'SystemInformation' -Value:@{
        OSName       = [String]::New($OperatingSystem.Caption)
        OSVersion    = [Version]::Parse($OperatingSystem.Version)
        OSBuild      = [int]::Parse($OperatingSystem.BuildNumber)
        OSArch       = [String]::New(($OperatingSystem.OSArchitecture))
        ProcArch     = [int]::Parse(([IntPtr]::Size * 8))
        Manufacturer = [String]::New($ComputerSystem.Manufacturer)
        Model        = [String]::New($ComputerSystem.Model)
    }

    #Clear-Variable -Name:@('LocalCimSession','OperatingSystem','ComputerSystem') -ErrorAction:'SilentlyContinue'
#endregion --- [ Load System Information ] ,#')}]#")}]#'")}] -----------------------------------------------------

#region ------ [ Processing Installation ] ------------------------------------------------------------------------

    Write-Verbose -Message:'Processing Config.GlobalConfig.FilterScript.'
    If ([String]::IsNullOrEmpty($Config.GlobalConfig.FilterScript) -eq $False) {
        $Config.GlobalConfig.FilterScript = (Test-FilterScript -Object:'$Config.GlobalConfig.FilterScript' `
            -FilterScript:$Config.GlobalConfig.FilterScript
        )
        If ($Config.GlobalConfig.FilterScript -eq $False) {
            Write-Warning -Message:'Computer does not meet GlobalConfig filter script, exiting.'
            Return
        } Else {
            Write-Verbose -Message:'Computer meets the GlobalConfig filterscript requirement.'
        }
    }

    Write-Verbose -Message:'Processing $Config.Installers'
    If ($Config.Installers.GetElementsByTagName('Installer').Count -gt 0) {

        #IWantToRewrite this section, not consistent format with duplicate IDs check.
        Write-Verbose -Message:'Verifying installer IDs are valid Integers.'
        $Config.Installers.Installer.ID |ForEach-Object -Process:{
            If ([int32]::TryParse($_,[ref]$Null)) {
                Write-Debug -Message:"ID '$_' is valid Int: $True"
            } Else {
                Write-Warning -Message:"ID '$_' is not valid."
                break
            }
        }

        Write-Verbose -Message:'Testing for duplicate IDs.'
        $InstallerDuplicates = ($Config.Installers.Installer.ID |Group-Object |
            Where-Object -FilterScript:{$_.count -gt 1})

        If ($InstallerDuplicates.Count -gt 0) {
            Write-Warning -Message:('Installer nodes with non-unique IDs found: {0}' -f `
            ($InstallerDuplicates.Name -Join ','))
            Return
        }

        Write-Verbose -Message:'Calling installers in order of their ID.'
        $Config.Installers.Installer |Sort-Object -Property:'ID' |ForEach-Object -Process:{

            Write-Verbose -Message:'Testing for OS Arch matches.'
            If ($SystemInformation.OSArch -Match @{'x32' = 'Both|86-Bit';'X64'='Both|64-Bit'}[$_.Architecture]) {
                Write-Verbose -Message:"Installer (ID:$($_.ID)) Arch matches OS Arch."
            } Else {
                Write-Verbose -Message:"Installer (ID:$($_.ID)) Arch does not match OS Arch."
                Break
            }

            If ([String]::IsNullOrEmpty($_.FilterScript) -NE $True) {
                If (Test-FilterScript -FilterScript:$_.FilterScript -Object:"$Config.Installers.Installer.$($_.ID)") {
                    Write-Verbose -Message:'FilterScript: Pass'
                } Else {
                    Write-Warning -Message:'FilterScript: Fail'
                    Break
                }
            } Else {
                Write-Verbose 1
            }

        }
    } Else {
        Write-Warning -Message:'No ''installer'' nodes found under the ''Installers'' node.'
    }

#endregion --- [ Processing Installation] ,#')}]#")}]#'")}] -------------------------------------------------------
