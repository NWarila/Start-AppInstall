Function Stop-AppProcess {
    Param(
        [Array]$Programs,
        [Array]$ProgramDirs
    )

    #Initalize needed variables
    @('Processes','TargetProcesses') | ForEach-Object -Process:{
        New-Variable -Name:$_ -Value:$Null -Force -Scope:'Local' -Option:'Private'
    }
    Set-Variable -Name:'Processes' -Value:(Get-Process |Where-object -FilterScript:{
        [String]::IsNullOrEmpty($_.Path) -ne $True} |Select-Object -Property:'ID','Path')
    Set-Variable -Name:'TargetProcesses' -Value:(New-Object -TypeName:'System.Collections.Generic.List[psobject]')

    ForEach ($Program in ($ProgramDirs + $Programs)) {
        If ([String]::IsNullOrEmpty($Program) -eq $False) {
            $Processes |
            Where-Object -FilterScript:{$_.Path -match [Regex]::Escape($Program)} |
            ForEach-Object -Process:{
                If ($TargetProcesses.Contains($_) -eq $False) {
                    $TargetProcesses.Add($_)
                }
            }
        }
        Clear-Variable -Name:'Program' -ErrorAction:'SilentlyContinue'
    }

    ForEach ($TargetProcess in $TargetProcesses) {
        Try {
            #Stop-Process -id:$TargetProcess.id -Force -ErrorAction Stop
            Write-Output -InputObject "[Info] Successfully stopped process: $(([System.IO.FileInfo]$TargetProcess.Path).name)"
        } Catch {
            Write-Output -InputObject "[Error] Unable to stop process. $(([System.IO.FileInfo]$TargetProcess.Path).name)"
        }
        Clear-Variable -Name:'TargetProcess' -ErrorAction:'SilentlyContinue'
    }

}
