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
    [String]$LogOutput = 'Auto',
)

#region ------ [ AD Domain Controller Query ] ---------------------------------------------------------------------
#endregion --- [ AD Domain Controller Query ] ,#')}]#")}]#'")}] ---------------------------------------------------

#region ------ [ Manual Configuration ] ---------------------------------------------------------------------------
#Require Admin Privilages.
New-Variable -Force -Name:'ScriptConfig' -Value @{
    #Should script enforce running as admin.
    RequireAdmin = $False
}
#endregion --- [ Manual Configuration ] ,#')}]#")}]#'")}] ---------------------------------------------------------

#region ------ [ Required Functions ] -----------------------------------------------------------------------------
Function Stop-AppProcess {
    
}
#endregion --- [ Required Functions ] ,#')}]#")}]#'")}] -----------------------------------------------------------
