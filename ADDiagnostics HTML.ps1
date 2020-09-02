
param(
    $Report = ".\ADDiag.htm"  # Report file name
    ,$Timeout = "120"         # DCDIAG timeout in seconds for each test. Minimum recommended: 120
    ,$DCDIAGTests = @("Advertising","CheckSDRefDom","CheckSecurityError","CrossRefValidation","CutoffServers","DNS","FRSEvent","DFSREvent","SysVolCheck","LocatorCheck","InterSite","KCCEvent","KnowsOfRoleHolders","MachineAccount","NCSecDesc","NetLogons","ObjectsReplicated","OutboundSecureChannels","RegisterInDNS","Replications","RIDManager","Services","SystemLog","Topology","VerifyEnterpriseReferences","VerifyReferences","VerifyReplicas")
    ,$MinFreeSpace = "15"     # Minimum free space considered as good
    ,[switch]$NoOpenReport  # Will not open the HTML report on finish
)

#region =[ Config ]=========================================================================================================================
$HtmlLineFormat = "<td colspan='8' bgcolor= '{0}' align=center><font face='Arial' color='Black' size='2'>{1}</font></td>{2}"
$SvcCount = "0"
Clear-Host
Write-Host " "
Write-Host "The report will be saved as" $Report
Write-Host "The configured timeout for each test is $Timeout seconds"
if ($NoOpenReport){
    Write-Host "As configured, the report will be saved but not will be opened after finishing all the tests"
} else {
    Write-Host "The report will be opened after finishing all the tests because NoOpenReport parameter was not found"
}
Write-Host " "
Write-Host "- - - - - - - - - - - - - - - -"

#endregion =[ Config ]=======================================================================================================================

#region =[ Helper Functions ]================================================================================================================
function AddToLog {
    param(
        $Message,
        [ValidateSet('Success','Failed','TimeOut')]$Status = 'Success',
        $Prefix = '',
        [switch]$NoCloseTR
    )
    $append = if($NoCloseTR) { '' } else { '</tr>' }
    $ConsoleColors = @{Success = 'Green'; Failed = 'Red'; TimeOut = 'Yellow'}
    $HtmlColors = @{Success = '#00cc33'; Failed = '#ff3333'; TimeOut = '#F7FE2E'}
    Write-Host -Object $Message -ForegroundColor $ConsoleColors[$Status]
    $Prefix + ($HtmlLineFormat -f  $HtmlColors[$Status], $Message, $append) | Out-File -FilePath $Report -Append
}
#endregion =[ Helper Functions ]================================================================================================================

#region =[ HTML 1/2 ]======================================================================================================================
$Now = Get-Date
@"
<html>
    <head>
        <meta http-equiv='Content-Type' content='text/html; charset=iso-8859-1'>
        <title>ADDS report</title>
        <STYLE TYPE='text/css'>
            <!--
            td {font-family: Arial; font-size: 12px; border: 0px; padding-top: 5px; padding-right: 5px; padding-bottom: 5px; padding-left: 5px;} 
            body { margin-left: 5px; margin-top: 5px; margin-right: 5px; margin-bottom: 5px; table {border: thin solid #000000;}
            --> 
        </style> 
    </head>
    <body> 
        <table width='100%'>
            <tr bgcolor='#000099'>
                <td colspan='10' height='25' align='center'>
                    <font face='Arial' color='White' size='4'><strong>Active Directory Services diagnosis report for ESB, $Now</strong></font>
                </td>
            </tr>
            </table>
    <table width='100%'>
        <tr bgcolor='Blue'>
            <td width='10%' align='center'><font face='Arial' color='White' size='2'>Name</td>
            <td width='20%' align='center'><font face='Arial' color='White' size='2'>Test name</td>
            <td colspan='8' width='70%' align='center'><font face='Arial' color='White' size='2'>Result</td>
        </tr>
"@ | Out-File -FilePath $Report -Force
#endregion =[ HTML 1/2 ]=======================================================================================================================

#region =[ Forest checks ]=====================================================================================================================
If (-not (Get-module ActiveDirectory)) {
    Import-Module ActiveDirectory -ErrorAction Stop
}
Write-Host " "
Write-Host "Starting general checks"
Write-Host "- - - - - - - - - - - - - - - -"
$Domain = Get-ADForest | Select-Object *
$Domains = Get-ADForest | Select-Object -ExpandProperty Domains  | Sort-Object -Property Name
$DomMode = $Domain.ForestMode
$Domain = $Domain.Name
@"
    <tr>
        <td bgcolor='#808080' align=center><font face='Arial' color='White' size='2'>$Domain</td>
        <td bgcolor= '#E0E0F8' align=center><font face='Arial' color='Black' size='2'>Forest functional level</td>
        <td colspan='8' bgcolor= '#E0E0F8' align=center><font face='Arial' color='Black' size='2'>$DomMode</td>
    </tr>
    <tr>
        <td></td>
        <td bgcolor='#5882FA' align=center><font face='Arial' color='White' size='2'>Tombstone</td>
"@ | Out-File -FilePath $Report -Append

#region =[ Tombstone check ]====================================================================================================================
$Domain = Get-ADDomain $Domain
$ADObj =  �CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,"+$Domain.DistinguishedName 
$ADObj =  Get-ADObject -Identity $ADObj -Properties tombstonelifetime
$ADTombstone = $ADObj.tombstonelifetime
if ($ADTombstone -ge 180){
    AddToLog -Message $ADTombstone -Status Success
} else {
    AddToLog -Message $ADTombstone -Status Failed
}
#endregion =[ Tombstone check ]================================================================================================================

#region =[ AD recycleBin check ]===============================================================================================================
Write-Host "Checking AD recycleBin status"
@"
    <tr colspan='8'>
        <td ></td>
        <td bgcolor='#5882FA' align=center><font face='Arial' color='White' size='2'>AD recycleBin</td>
"@ | Out-File -FilePath $Report -Append
$ADRecBin = (Get-ADOptionalFeature -Filter "Name -like 'Recycle Bin Feature'").EnabledScopes
if ($ADRecBin.Count -gt 0){
    AddToLog -Message "AD recycleBin is enabled" -Status Success
} else {
    AddToLog -Message "AD recycleBin was not yet enabled" -Status Failed
}
#endregion =[ AD recycleBin check ]============================================================================================================

#region =[ Groups check ]======================================================================================================================
Write-Host "Checking groups membership"
@"
    <tr colspan='8'>
        <td ></td>
        <td bgcolor='#5882FA' align=center><font face='Arial' color='White' size='2'>Schema admins count</td>
"@ | Out-File -FilePath $Report -Append
$GroupCheck = (Get-ADGroupMember "schema admins").Count
if ($GroupCheck -eq 0){
    AddToLog -Message "Schema admins group is empty" -Status Success
} else {
    AddToLog -Message "Schema admins group is not empty" -Status Failed
}
@"
    <tr colspan='8'>
        <td ></td>
        <td bgcolor='#5882FA' align=center><font face='Arial' color='White' size='2'>Enterprise admins count</td>
"@ | Out-File -FilePath $Report -Append
$GroupCheck = (Get-ADGroupMember "enterprise admins").Count
if ($GroupCheck -eq 0){
    AddToLog -Message "Enterprise admins group is empty" -Status Success
} else {
    AddToLog -Message "Enterprise admins group is not empty" -Status Failed
}
#endregion =[ Groups check ]===================================================================================================================

#region =[ SPN check ]=========================================================================================================================
Write-Host "Checking SPN consistency"
@"
    <tr colspan='8'>
        <td ></td>
        <td bgcolor='#5882FA' align=center><font face='Arial' color='White' size='2'>SPN consistency</td>
"@ | Out-File -FilePath $Report -Append
$ReadResults = & setspn.exe -F -X
    if ($ReadResults -like "found 0 group of duplicate SPNs."){
        AddToLog -Message "No duplicate SPNs were found" -Status Success
    } else {
        AddToLog -Message "Duplicate SPNs were found, consider running setspn.exe -X" -Status Failed
    }
#endregion =[ SPN check ]======================================================================================================================

#region =[ Repadmin showbackup check ]=====================================================================================================
Write-Host "Checking last succesfully backup registered"
@"
    <tr colspan='8'>
        <td ></td>
        <td bgcolor='#5882FA' align=center><font face='Arial' color='White' size='2'>Last registered backup</td>
        <td colspan='8' bgcolor='#E0E0F8' align=center><font face='Arial' color='Black' size='2'> repadmin.exe /showbackup</td>
    </tr>
"@ | Out-File -FilePath $Report -Append
$Count = 0
$ReadResults = & repadmin.exe /showbackup
foreach ($ReadResult in $ReadResults){
    $Count++
    if ($Count -gt 10){
        if ($ReadResult.Length -gt 1){
            $ReadResult = $ReadResult -replace "dSASignature"," "
            $ReadResult = $ReadResult -replace "\s+","</td><td>"
            $ReadResult = $ReadResult -replace "<td>1</td>"," "
            $ReadResult = $ReadResult -replace "<td></td>"," "
            @"
                <tr>
                    <td></td>
                    <td></td>
                    <td width='10%'>$ReadResult</td>
                </tr>
"@ | Out-File -FilePath $Report -Append
        }
    }
}
#endregion =[ Repadmin showbackup check ]====================================================================================================

#region =[ Replication checks ]============================================================================================================
Write-Host "Checking replication information"
@"
    <tr colspan='8'>
        <td ></td>
        <td bgcolor='#5882FA' align=center><font face='Arial' color='White' size='2'>Replication information</td>
        <td colspan='8' bgcolor='#E0E0F8' align=center><font face='Arial' color='Black' size='2'> repadmin.exe /replsum</td>
    </tr>
"@ | Out-File -FilePath $Report -Append
$Count = 0
$ReadResults = & repadmin.exe /replsum
foreach ($ReadResult in $ReadResults){
    $Count++
    if ($Count -gt 9){
        if ($ReadResult.Length -gt 1){
            $ReadResult = $ReadResult -replace "/"," "
            $ReadResult = $ReadResult -replace "\s+","</td><td>"
            $ReadResult = $ReadResult -replace "<td></td>"," "
            $ReadResult = $ReadResult -replace "largest</td><td>delta","Largest delta"
            $ReadResult = $ReadResult -replace "Source</td><td>DSA","<td>Source DSA"
            $ReadResult = $ReadResult -replace "Destination</td><td>DSA","<td>Destination DSA"
            @"
                <tr>
                    <td></td>
                    <td></td>
                    $ReadResult
                </tr>
"@ | Out-File -FilePath $Report -Append
        }
    }
}
#endregion =[ Replication checks ]===========================================================================================================
#endregion =[ Forest check ]=================================================================================================================

#region =[ Domains checks ]==================================================================================================================
foreach ($Domain in $Domains){
    Write-Host "Starting checks on $Domain"
    $ADDomain = Get-ADDomain
    $DomMode = $ADDomain.DomainMode
    $DomSID = $ADDomain.DomainSID
    $NetBIOS = $ADDomain.NetBIOSName
    @"
        <tr>
            <td bgcolor='#808080' align=center><font face='Arial' color='White' size='2'>$Domain</td>
            <td bgcolor= '#E0E0F8' align=center><font face='Arial' color='Black' size='2'>Domain functional level</td>
            <td colspan='8' bgcolor= '#E0E0F8' align=center><font face='Arial' color='Black' size='2'>$DomMode</td>
        </tr>
        <tr>
            <td></td>
            <td bgcolor= '#E0E0F8' align=center><font face='Arial' color='Black' size='2'>Domain SID</td>
            <td colspan='8' bgcolor= '#E0E0F8' align=center><font face='Arial' color='Black' size='2'>$DomSID</td>
        </tr>
        <tr>
            <td></td>
            <td bgcolor= '#E0E0F8' align=center><font face='Arial' color='Black' size='2'>NetBIOS name</td>
            <td colspan='8' bgcolor= '#E0E0F8' align=center><font face='Arial' color='Black' size='2'>$NetBIOS</td>
        </tr>
        <tr>
            <td></td>
            <td bgcolor='#5882FA' align=center><font face='Arial' color='White' size='2'>Replication failures</td>
"@ | Out-File -FilePath $Report -Append
    if ((Get-command "Get-ADReplicationFailure" -ErrorAction SilentlyContinue).Length -ge 1){
        $ReplFails = (Get-ADReplicationFailure -Target $Domain -ErrorAction SilentlyContinue).failureCount
        Write-Host "Checking replication errors"
        if ($ReplFails -eq 0){
            AddToLog -Message "No replication errors found" -Status Success
        } else {
            AddToLog -Message "The replication errors counter is not 0, consider running Powershell Get-ADReplicationFailure" -Status TimeOut
        }
    } else {
        AddToLog -Message "Unable to Get-ADReplicationFailure because it needs at least Windows Server 2012R2" -Status TimeOut
    }
}

#region =[ FSMO roles holders ]==============================================================================================================
Write-Host "Checking Forest FSMO holders"
@"
    <tr colspan='8'>
        <td ></td>
        <td bgcolor='#5882FA' align=center><font face='Arial' color='White' size='2'>FSMO roles holders</td>
        <td colspan='8' bgcolor='#E0E0F8' align=center><font face='Arial' color='Black' size='2'> netdom.exe query FSMO</td>
    </tr>
"@ | Out-File -FilePath $Report -Append
$Count = 0
$ReadResults = & netdom.exe query FSMO
foreach ($ReadResult in $ReadResults){
    $Count++
    if ($Count -lt 7){
        if ($Count -eq 6){
            if ($ReadResult -like "The command completed successfully."){
                #AddToLog -Message "Netdom query FSMO completed successfully" -Status Success
            } else {
                @"
                <tr>
                    <td></td>
                    <td></td>
"@ | Out-File -FilePath $Report -Append
                AddToLog -Message "Netdom query FSMO failed" -Status Failed
            }
        } else {
            if ($ReadResult.Length -gt 1){
                $ReadResult = $ReadResult -replace "\s+"," "
                $ReadResult = $ReadResult -replace "<td></td>"," "
                @"
                    <tr>
                        <td></td>
                        <td></td>
                        <td>$ReadResult</td>
                    </tr>
"@ | Out-File -FilePath $Report -Append
            }
        }
    }
}
#endregion =[ FSMO roles holders ]=============================================================================================================

#region =[ Sysvol mode check ]=================================================================================================================
Write-Host "Checking Sysvol mode"
@"
    <tr colspan='8'>
        <td ></td>
        <td bgcolor='#5882FA' align=center><font face='Arial' color='White' size='2'>Sysvol mode</td>
"@ | Out-File -FilePath $Report -Append
$ADObj = "CN=DFSR-GlobalSettings,CN=System,"+$ADDomain.DistinguishedName 
$ADObj = Get-ADObject -Identity $ADObj -Properties *
if ($ADObj.'msDFSR-Flags' -gt 47){
    AddToLog -Message "Sysvol mode is DFS-R" -Status Success
} else {
    AddToLog -Message "Sysvol mode is not DFS-R" -Status Failed
}
#endregion =[ Sysvol mode check ]==============================================================================================================
#endregion =[ Domains checks ]=================================================================================================================

#region =[ DCs Checks ]========================================================================================================================
$DCs = (Get-ADForest).Domains | %{ Get-ADDomainController -Filter * -Server $_ } | Sort-Object -Property hostname
foreach ($DC in $DCs){
    $DCName = $DC.HostName.ToString()
    Write-Host " "
    Write-Host "Starting checks on $DC.hostname"
    Write-Host "- - - - - - - - - - - - - - - -"
    @"
    <tr>
        <td bgcolor='#808080' align=center><font face='Arial' color='White' size='2'>$DCName</td>
"@ | Out-File -FilePath $Report -Append
    
    #region =[ Connectivity check ]=========================================================================================================
    if (Test-Connection -ComputerName $DC.hostname -Count 1 -ErrorAction SilentlyContinue) {
        Write-Host `t Connectivity check passed -ForegroundColor Green
        $OS = Get-WmiObject -Class win32_OperatingSystem -ComputerName $DC.hostname -ErrorAction SilentlyContinue
        $Lastboot = $OS.ConvertToDateTime($os.LastBootUpTime)
        $OS = $OS.Caption
        AddToLog -Message 'Ping is ok' -Status Success -Prefix @"
                <td bgcolor='#E0E0F8' align=center><font face='Arial' color='Black' size='2'>Operating system</td>
                <td colspan='8' bgcolor= '#E0E0F8' align=center><font face='Arial' color='Black' size='2'>$OS</td>
            </tr>
            <tr>
                <td></td>
                <td bgcolor='#E0E0F8' align=center><font face='Arial' color='Black' size='2'>Last boot time</td>
                <td colspan='8' bgcolor= '#E0E0F8' align=center><font face='Arial' color='Black' size='2'>$Lastboot</td>
            </tr>
            <tr>
                <td></td>
                <td bgcolor='#5882FA' align=center><font face='Arial' color='White' size='2'>Ping check</td>
"@ 
    #endregion =[ Connectivity check ]========================================================================================================

        #region =[ Logical disks check ]====================================================================================================
        $Disks = Get-WmiObject -Class win32_logicaldisk -ComputerName $DC.hostname -Filter 'DriveType=3' -ErrorAction SilentlyContinue
        foreach ($Disk in $Disks){
            $DiskDrive = $Disk.DeviceID.ToString()
            @"
                <tr>
                <td></td>
                <td bgcolor='#5882FA' align=center><font face='Arial' color='White' size='2'>Drive $DiskDrive</td>
"@ | Out-File -FilePath $Report -Append
            $DiskFreeSpace = $Disk.FreeSpace/1GB
            if ($DiskFreeSpace -gt $MinFreeSpace){
                AddToLog -Message $DiskFreeSpace -Status Success
            } else {
                AddToLog -Message $DiskFreeSpace -Status Failed
            }
        }
        #endregion =[ Logical disks check ]====================================================================================================

        #region =[ Services check ]==========================================================================================================
        $Services = Get-WMIObject -Class Win32_Service -Filter "State='Stopped'" -ComputerName $DC.hostname -ErrorAction SilentlyContinue
        foreach($service in $Services) {
            $Log = "
                <tr>
                    <td></td>
                    <td bgcolor='#5882FA' align=center><font face='Arial' color='White' size='2'>Services check</td>"
            if(-not (($Service.exitcode -eq 0) -or ($Service.exitcode -eq 1077))){
                $SvcCount = "1"
                $Svc = ($service.Displayname).tostring()
                AddToLog -Message $Svc -Status Failed -Prefix $Log
            }
        }
        if ($SvcCount -lt 1){

            AddToLog -Message 'No services with error exit codes where found' -Status Success -Prefix $Log
        }
        $SvcCount = "0"
        #endregion =[ Services check ]========================================================================================================

        #region =[ DCDIAG check ]===========================================================================================================
        foreach ($DCDIAGTest in $DCDIAGTests){
            write-host "Running $DCDIAGTest test on"$DC.HostName
            if ($DCDIAGTest -like "DNS"){
                Write-Host "Usually DNS test takes more time than other tests. Please wait and/ or consider reviewing 'Timeout' configuration in 'param section'"
            }
            $Job = start-job -Name ADdiag -scriptblock {dcdiag.exe /s:$($args[0]) /test:$($args[1])} -ArgumentList $DC.hostname,$DCDIAGTest
            Wait-Job -Name ADdiag -Timeout $Timeout | Out-Null
            $Log = "
                <tr>
                <td></td>
                <td bgcolor='#5882FA' align=center><font face='Arial' color='White' size='2'>DCDIAG $DCDIAGTest</td>"
            if($Job.State -eq 'Running'){
                AddToLog -Message "$DCDIAGTest timeout, consider running: dcdiag.exe /test:$DCDIAGtest" -Status TimeOut -Prefix $Log
                Stop-Job -Name ADdiag -ErrorAction SilentlyContinue
            } else {
                $ReadResults = (Receive-Job -Name ADdiag -Keep) -match "test $DCDIAGTest"
                foreach ($ReadResult in $ReadResults){
                    if ($ReadResult -match '\.+\s(?<DomainName>.*)\spassed\stest\s(?<TestName>.*)'){
                        AddToLog -Message $DCDIAGTest -Status Success -Prefix $Log
                    } else {
                        AddToLog -Message "$DCDIAGTest failed, consider running: dcdiag.exe /test:$DCDIAGtest" -Status Failed -Prefix $Log
                    }
                }
            }
            Remove-Job -Name ADdiag -Force -ErrorAction SilentlyContinue
        }
        #endregion =[ DCDIAG check ]==============================================================================================================

    } else {
        AddToLog -Message 'No ping' -Status Failed -Prefix @"
                <td></td>
                <td></td>
            </tr>
            <tr>
                <td></td>
                <td bgcolor='#5882FA' align=center><font face='Arial' color='White' size='2'>Ping check</td>
"@
    }
}
#endregion =[ DCs Checks ]==============================================================================================================================

#region =[ HTML 2/2 ]============================================================================================================================
@"
            <tr>
                <td colspan='10' height='25' align='center'>
                    <font face='Arial' color='Black' size='2'>Author Bilel Graine</font>
                </td>
            </tr>
            <tr>
            </tr>
        </table>
    </body>
</html>
"@ | Out-File -FilePath $Report -Append
#endregion =[ HTML 2/2 ]============================================================================================================================

#region =[ End section ]==========================================================================================================================
Get-Job -Name ADdiag -ErrorAction SilentlyContinue | Remove-Job -Force -ErrorAction SilentlyContinue
Write-Host "Finished" -ForegroundColor Blue
if (-not($NoOpenReport)){
    Invoke-Item $Report
    }
$Report = ""
$Log = ""
#endregion =[ End section ]=========================================================================================================================
