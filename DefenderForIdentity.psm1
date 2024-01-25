<#
Copyright (c) Microsoft Corporation.
MIT License
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#>

#requires -Version 4.0
#requires -Modules ActiveDirectory, GroupPolicy

#region General settings

$script:settings = @{

    gpoNamePrefix                  = 'Microsoft Defender for Identity'

    gpoExtensions                  = @{
        'Core GPO Engine'                                = '00000000-0000-0000-0000-000000000000'
        'Tool Extension GUID (Computer Policy Settings)' = '0F6B957D-509E-11D1-A7CC-0000F87571E3'
        'Security'                                       = '827D319E-6EAC-11D2-A4EA-00C04F79F83A'
        'Computer Restricted Groups'                     = '803E14A0-B4FB-11D0-A0D0-00A0C90F574B'
        'Preference Tool CSE GUID Registry'              = 'BEE07A6A-EC9F-4659-B8C9-0B1937907C83'
        'Preference CSE GUID Registry'                   = 'B087BE9D-ED37-454F-AF9C-04291E351182'
        'Audit Configuration Extension'                  = '0F3F3735-573D-9804-99E4-AB2A69BA5FD4'
        'Audit Policy Configuration'                     = 'F3CCC681-B74C-4060-9F26-CD84525DCA2A'
    }

    ProcessorPerformance           = @{
        GpoName    = '{0} - Processor Performance'
        SchemeGuid = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
        Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings'
        ValueName  = 'ActivePowerScheme'
    }

    NTLMAuditing                   = @{
        GpoName     = '{0} - NTLM Auditing for DCs'
        RegistrySet = @{
            'System\CurrentControlSet\Control\Lsa\MSV1_0\AuditReceivingNTLMTraffic'   = '2'
            'System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic'  = '1|2'
            'System\CurrentControlSet\Services\Netlogon\Parameters\AuditNTLMInDomain' = '7'
        }
    }

    CAAuditing                     = @{
        GpoName       = '{0} - Auditing for CAs'
        GpoVal        = @{ 'AuditFilter' = 127 }
        GpoReg        = 'System\CurrentControlSet\Services\CertSvc\Configuration\%DomainName%-%ComputerName%-CA'
        RegPathActive = 'System\CurrentControlSet\Services\CertSvc\Configuration\Active'
        RegistrySet   = @{
            'System\CurrentControlSet\Services\CertSvc\Configuration\{0}\AuditFilter' = 127
        }
        GPPermissions = [ordered]@{
            'Cert Publishers'     = 'GpoApply'
            'Domain Controllers'  = 'GpoRead'
            'Authenticated Users' = 'GpoRead'
        }
    }

    AdvancedAuditPolicyDCs         = @{
        GpoName        = '{0} - Advanced Audit Policy for DCs'
        PolicySettings = @'
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
,System,Security System Extension,{0CCE9211-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Distribution Group Management,{0CCE9238-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Security Group Management,{0CCE9237-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Computer Account Management,{0CCE9236-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,User Account Management,{0CCE9235-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Directory Service Access,{0CCE923B-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Directory Service Changes,{0CCE923C-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success and Failure,,3
'@
    }

    AdvancedAuditPolicyCAs         = @{
        GpoName        = '{0} - Advanced Audit Policy for CAs'
        PolicySettings = @'
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
,System,Audit Certification Services,{0cce9221-69ae-11d9-bed3-505054503030},Success and Failure,,3
'@
        GPPermissions  = [ordered]@{
            'Cert Publishers'     = 'GpoApply'
            'Domain Controllers'  = 'GpoRead'
            'Authenticated Users' = 'GpoRead'
        }
    }

    ObjectAuditing                 = @{
        Path     = 'AD:\{0}'
        Auditing = @'
SecurityIdentifier,AccessMask,AuditFlagsValue,InheritedObjectAceType,Description,InheritanceType,PropagationFlags
S-1-1-0,852331,1,bf967aba-0de6-11d0-a285-00aa003049e2,Descendant User Objects,2,2
S-1-1-0,852331,1,bf967a9c-0de6-11d0-a285-00aa003049e2,Descendant Group Objects,2,2
S-1-1-0,852331,1,bf967a86-0de6-11d0-a285-00aa003049e2,Descendant Computer Objects,2,2
S-1-1-0,852331,1,ce206244-5827-4a86-ba1c-1c0c386c1b64,Descendant msDS-ManagedServiceAccount Objects,2,2
S-1-1-0,852075,1,7b8b558a-93a5-4af7-adca-c017e67f1057,Descendant msDS-GroupManagedServiceAccount Objects,2,2
'@ | ConvertFrom-Csv
    }

    ConfigurationContainerAuditing = @{
        Validate = 'LDAP://CN=Microsoft Exchange,CN=Services,CN=Configuration,{0}'
        Path     = 'AD:\CN=Configuration,{0}'
        Auditing = @'
SecurityIdentifier,AccessMask,AuditFlagsValue,AceFlagsValue,InheritedObjectAceType,InheritanceType,PropagationFlags
S-1-1-0,32,3,194,00000000-0000-0000-0000-000000000000,1,0
'@ | ConvertFrom-Csv
    }

    AdfsAuditing                   = @{
        Validate = 'LDAP://CN=ADFS,CN=Microsoft,CN=Program Data,{0}'
        Path     = 'AD:\CN=ADFS,CN=Microsoft,CN=Program Data,{0}'
        Auditing = @'
SecurityIdentifier,AccessMask,AuditFlagsValue,AceFlagsValue,InheritedObjectAceType,InheritanceType,PropagationFlags
S-1-1-0,48,3,194,00000000-0000-0000-0000-000000000000,1,0
'@ | ConvertFrom-Csv
    }

    SensitiveGroups                = @{
        'Administrators'              = 'S-1-5-32-544'
        'Account Operators'           = 'S-1-5-32-548'
        'Backup Operators'            = 'S-1-5-32-551'
        'Domain Admins'               = '{0}-512'
        'Domain Controllers'          = '{0}-516'
        'Enterprise Admins'           = '{0}-519'
        'Group Policy Creator Owners' = '{0}-520'
        'Print Operators'             = 'S-1-5-32-550'
        'Replicators'                 = 'S-1-5-32-552'
        'Schema Admins'               = '{0}-518'
        'Server Operators'            = 'S-1-5-32-549'
        'Cert Publishers'             = '{0}-517'
    }

}

if (Test-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath ($PSUICulture))) {
    Import-LocalizedData -BindingVariable strings
} else {
    Import-LocalizedData -BindingVariable strings -UICulture en-US
}

#endregion

#region General helper functions

function Get-MDIValidationMessage {
    param($Result)
    if ($Result) {
        $strings['Validation_Passed']
    } else {
        $strings['Validation_Failed']
    }
}

function Resolve-MDIPath {
    param(
        [parameter(Mandatory)] $Path
    )
    $return = Resolve-Path -Path $Path -ErrorAction SilentlyContinue -ErrorVariable resolveError
    if ($return.Path) { $return.Path }
    else { $resolveError[0].TargetObject }
}

function Format-Json {
    param(
        [Parameter(Mandatory, ValueFromPipeline)] [String] $json
    )
    $indent = 0;
    ($json -Split '\n' | ForEach-Object {
        if ($_ -match '[\}\]]') {
            $indent--
        }
        $line = (' ' * $indent * 2) + $_.TrimStart().Replace(':  ', ': ')
        if ($_ -match '[\{\[]') {
            $indent++
        }
        $line
    }) -join "`n"
}

function Test-MDICAServer {
    [CmdletBinding()]
    param()
    [bool](Get-Service CertSvc -ErrorAction SilentlyContinue)
}

#endregion

#region Sensor service helper functions

function Get-MDISensorBinPath {
    [CmdletBinding()]
    param()
    $wmiParams = @{
        Namespace   = 'root\cimv2'
        ClassName   = 'Win32_Service'
        Property    = 'PathName'
        Filter      = 'Name="AATPSensor"'
        ErrorAction = 'Stop'
    }
    Write-Verbose -Message $strings['Sensor_LocateConfigurationFile']
    try {
        $return = (Get-CimInstance @wmiParams | Select-Object -ExpandProperty PathName) -replace '"|Microsoft\.Tri\.Sensor\.exe', ''
    } catch {
        $return = $null
    }
    if ([string]::IsNullOrEmpty($return)) {
        Write-Warning $strings['Sensor_ServiceNotFound']
    }
    $return
}

function Stop-MDISensor {
    [CmdletBinding()]
    param()
    Stop-Service -Name AATPSensorUpdater -Force
}

function Start-MDISensor {
    [CmdletBinding()]
    param()
    Start-Service -Name AATPSensorUpdater
}

#endregion

#region Sensor configuration helper functions

function Get-MDISensorConfiguration {
    [CmdletBinding()]
    param()
    $sensorBinPath = Get-MDISensorBinPath
    if ($null -eq $sensorBinPath) {
        $sensorConfiguration = $null
    } else {
        Write-Verbose -Message $strings['Sensor_ReadConfigurationFile']
        $sensorConfigurationPath = Join-Path -Path $sensorBinPath -ChildPath 'SensorConfiguration.json'
        $sensorConfiguration = Get-Content -Path $sensorConfigurationPath -Raw | ConvertFrom-Json
    }

    if ($null -ne $sensorConfiguration.SensorProxyConfiguration) {
        $SensorProxyConfiguration = [PSCustomObject]@{
            IsProxyEnabled               = -not [string]::IsNullOrEmpty($sensorConfiguration.SensorProxyConfiguration.Url)
            IsAuthenticationProxyEnabled = -not [string]::IsNullOrEmpty($sensorConfiguration.SensorProxyConfiguration.UserName)
            Url                          = $sensorConfiguration.SensorProxyConfiguration.Url
            UserName                     = $sensorConfiguration.SensorProxyConfiguration.UserName
            EncryptedUserPasswordData    = $sensorConfiguration.SensorProxyConfiguration.EncryptedUserPasswordData.EncryptedBytes
            CertificateThumbprint        = $sensorConfiguration.SensorProxyConfiguration.EncryptedUserPasswordData.CertificateThumbprint

        }
        $sensorConfiguration.SensorProxyConfiguration = $SensorProxyConfiguration
    }
    $sensorConfiguration
}

function Get-MDIEncryptedPassword {
    param(
        [Parameter(Mandatory = $true)] [string] $CertificateThumbprint,
        [Parameter(Mandatory = $true)] [PSCredential] $Credential
    )
    $store = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList @(
        [System.Security.Cryptography.X509Certificates.StoreName]::My,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    )
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2] $store.Certificates.Find(
        [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $CertificateThumbprint, $false)[0]

    $rsaPublicKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    $bytes = [System.Text.Encoding]::Unicode.GetBytes(
        $Credential.GetNetworkCredential().Password
    )
    $encrypted = $rsaPublicKey.Encrypt($bytes, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    $encryptedPassword = [System.Convert]::ToBase64String($encrypted)

    $store.Close()
    $encryptedPassword
}

function Get-MDIDecryptedPassword {
    param(
        [Parameter(Mandatory = $true)] [string] $CertificateThumbprint,
        [Parameter(Mandatory = $true)] [string] $EncryptedString
    )
    $store = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList @(
        [System.Security.Cryptography.X509Certificates.StoreName]::My,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    )
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2] $store.Certificates.Find(
        [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $CertificateThumbprint, $false)[0]

    $rsaPublicKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)

    $encrypted = [System.Convert]::FromBase64String($EncryptedString)
    $bytes = $rsaPublicKey.Decrypt($encrypted, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    $decryptedPassword = [System.Text.Encoding]::Unicode.GetString($bytes)

    $store.Close()
    $decryptedPassword
}

function Get-MDISensorProxyConfiguration {
    [CmdletBinding()]
    param()
    $sensorConfiguration = Get-MDISensorConfiguration
    if ($null -eq $sensorConfiguration) {
        $proxyConfiguration = $null
    } else {
        $proxyConfiguration = $sensorConfiguration.SensorProxyConfiguration
    }
    $proxyConfiguration
}

function Set-MDISensorProxyConfiguration {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $false)] [string] $ProxyUrl,
        [Parameter(Mandatory = $false)] [PSCredential] $ProxyCredential
    )
    $operation = if ([string]::IsNullOrEmpty($ProxyUrl)) { 'Clear' } else { 'Set' }
    if ($PSCmdlet.ShouldProcess($strings['Sensor_ProxyConfigurationAction'], $operation)) {
        $sensorConfiguration = Get-MDISensorConfiguration
        if ($null -eq $sensorConfiguration) {
            Write-Error $strings['Sensor_ErrorReadingSensorConfiguration'] -ErrorAction Stop
        }
        if ([string]::IsNullOrEmpty($ProxyUrl)) {
            $sensorConfiguration.SensorProxyConfiguration = $null
        } else {
            if ($ProxyCredential) {
                $thumbprint = $sensorConfiguration.SecretManagerConfigurationCertificateThumbprint
                $sensorConfiguration.SensorProxyConfiguration = [PSCustomObject]@{
                    '$type'                   = 'SensorProxyConfiguration'
                    Url                       = $ProxyUrl
                    UserName                  = $ProxyCredential.UserName
                    EncryptedUserPasswordData = [PSCustomObject]@{
                        '$type'               = 'EncryptedData'
                        EncryptedBytes        = Get-MDIEncryptedPassword -CertificateThumbprint $thumbprint -Credential $ProxyCredential
                        SecretVersion         = $null
                        CertificateThumbprint = $sensorConfiguration.SecretManagerConfigurationCertificateThumbprint
                    }
                }
            } else {
                $sensorConfiguration.SensorProxyConfiguration = [PSCustomObject]@{
                    '$type' = 'SensorProxyConfiguration'
                    Url     = $ProxyUrl
                }
            }
        }
        Stop-MDISensor
        Write-Verbose -Message $strings['Sensor_WriteSensorConfigurationFile']
        $sensorConfiguration | ConvertTo-Json | Format-Json |
            Set-Content -Path (Join-Path -Path (Get-MDISensorBinPath) -ChildPath 'SensorConfiguration.json')
        Start-MDISensor
    }
}

function Clear-MDISensorProxyConfiguration {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    if ($PSCmdlet.ShouldProcess($strings['Sensor_ProxyConfigurationAction'], 'Clear')) {
        Set-MDISensorProxyConfiguration -ProxyUrl $null
    }
}

#endregion

#region GPO helper functions

function Get-MDIGPOName {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory = $false)] [string] $GpoNamePrefix
    )
    if ([string]::IsNullOrEmpty($GpoNamePrefix)) {
        $Name -f $script:settings['gpoNamePrefix']
    } else {
        $Name -f $GpoNamePrefix
    }
}

function New-MDIGPO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory = $false)] [switch] $CreateGpoDisabled
    )
    Write-Verbose -Message ($strings['GPO_Create'] -f $Name)
    $gpo = New-GPO -Name $Name
    if ($gpo) {
        Start-Sleep -Milliseconds 500
        $gPCFileSysPath = (Get-ADObject -Identity $gpo.Path -Properties gPCFileSysPath).gPCFileSysPath
        $maxWaitTime = (Get-Date).AddSeconds(3)
        do {
            Start-Sleep -Milliseconds 500
        } while (-not ((Test-Path -Path $gPCFileSysPath) -or ($maxWaitTime -lt (Get-Date))))
        if ($CreateGpoDisabled) {
            $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::AllSettingsDisabled
        } else {
            $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled
        }
        $gpo | Add-Member -MemberType NoteProperty -Name gPCFileSysPath -Value $gPCFileSysPath -PassThru -Force
    }
}

function Get-MDIGPO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name
    )
    $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $gpo) {
        Write-Verbose -Message ("'{0}' - {1}" -f $Name, $strings['GPO_NotFound'])
    }
    $gpo
}

function Get-MDIGPOLink {
    param(
        [guid] $Guid
    )
    Write-Verbose -Message $strings['GPO_GetLinks']
    $xml = [xml](Get-GPOReport -Guid $Guid -ReportType Xml)
    @($xml.GPO.LinksTo)
}

function Test-MDIGPOLink {
    [CmdletBinding()]
    param(
        [guid] $Guid
    )
    $return = $false
    $enabledLinks = @(Get-MDIGPOLink -Guid $Guid | Where-Object { $_.Enabled -eq 'true' })
    if ($enabledLinks.Count -lt 1) {
        Write-Verbose -Message ($strings['GPO_NotLinkedOrEnabled'])
    } else {
        $return = $true
        $enabledLinks | ForEach-Object {
            Write-Verbose -Message ($strings['GPO_LinkedAndEnabled'] -f $_.SOMPath)
        }
    }
    $return
}

function Set-MDIGPOLink {
    param(
        [Parameter(Mandatory)] [guid] $Guid,
        [Parameter(Mandatory)] [string] $Target,
        [Microsoft.GroupPolicy.EnableLink] $LinkEnabled = [Microsoft.GroupPolicy.EnableLink]::Yes,
        [Microsoft.GroupPolicy.EnforceLink] $Enforced = [Microsoft.GroupPolicy.EnforceLink]::Yes
    )
    Write-Verbose -Message $strings['GPO_SetLink']
    $gpLink = @{
        Guid        = $Guid
        LinkEnabled = $LinkEnabled
        Enforced    = $Enforced
        Target      = $Target
    }
    $link = New-GPLink @gpLink -ErrorAction SilentlyContinue
    if ($null -eq $link) {
        $link = Set-GPLink @gpLink -ErrorAction SilentlyContinue
    }
    if ($null -eq $link) {
        throw $strings['GPO_UnableToUpdateLink']
    }
}

function Get-MDIGPOMachineVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [guid] $Guid
    )
    (Get-GPO -Guid $Guid).Computer | Select-Object -Property *Version
}

function Set-MDIGPOMachineVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [guid] $Guid,
        [Parameter(Mandatory)] [int] $Version,
        [Parameter(Mandatory = $false)] [ValidateSet('Sysvol', 'DS', 'All')] [string] $Mode = 'Sysvol'
    )
    Write-Verbose -Message $strings['GPO_UpdateVersion']
    if ($Mode -match 'ALL|DS') {
        $gpoAdObjectPath = 'CN={0},{1}' -f "{$Guid}", (Get-MDIAdPath 'CN=Policies,CN=System,{0}')
        Set-ADObject -Identity $gpoAdObjectPath -Replace @{versionNumber = $Version } | Out-Null
    }
    if ($Mode -match 'ALL|Sysvol') {
        $filePath = '\\{0}\SYSVOL\{0}\Policies\{1}\GPT.INI' -f $env:USERDNSDOMAIN, "{$guid}"
        $newContent = ((Get-Content $filePath) -join [environment]::NewLine) -replace 'Version=\d+', ('Version={0}' -f $version)
        Set-Content -Path $filePath -Encoding ASCII -Value $newContent
    }
}

function Get-MDIGPOMachineExtension {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [guid] $Guid
    )
    Write-Verbose -Message $strings['GPO_GetExtension']
    $gpoAdObjectPath = 'CN={0},{1}' -f "{$Guid}", (Get-MDIAdPath 'CN=Policies,CN=System,{0}')
    Get-ADObject -Identity $gpoAdObjectPath -Properties gPCMachineExtensionNames, VersionNumber
}

function Set-MDIGPOMachineExtension {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [guid] $Guid,
        [Parameter(Mandatory)] [string[]] $Extension
    )
    Write-Verbose -Message $strings['GPO_SetExtension']
    $return = $null

    $extensions = $Extension | ForEach-Object { "{$_}" }
    $extensionGuids = '[{0}]' -f [string]::Join('', $extensions, 0, 2)
    $Replace = @{gPCMachineExtensionNames = $extensionGuids }

    $gpoAdObjectPath = 'CN={0},{1}' -f "{$Guid}", (Get-MDIAdPath 'CN=Policies,CN=System,{0}')
    $gpoUpdated = Set-ADObject -Identity $gpoAdObjectPath -Replace $Replace -PassThru

    if ($gpoUpdated) {
        try {
            $gpoComputerDSVersion = (Get-MDIGPOMachineVersion -Guid $Guid).DSVersion
            if ($gpoComputerDSVersion -lt 2) { $gpoComputerDSVersion = 3 } else { $gpoComputerDSVersion++ }
            Set-MDIGPOMachineVersion -Guid $Guid -Version $gpoComputerDSVersion -Mode All
            $return = $gpoComputerDSVersion
        } catch {
            Write-Verbose -Message $_.Exception.Message
        }
    }
    $return
}

function Test-MDIGPOEnabledAndLink {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $GPO
    )
    $state = $false
    if (-not ($GPO.GpoStatus -ne [Microsoft.GroupPolicy.GpoStatus]::AllSettingsDisabled)) {
        Write-Verbose -Message $strings['GPO_SettingsDisabled']
    } else {
        if (-not (Test-MDIGPOLink -Guid $GPO.Id.Guid)) {
            Write-Verbose -Message $strings['GPO_LinkNotFound']
        } else {
            $state = $true
        }
    }
    $state
}

#endregion

#region Processor Performance helper functions

function Get-MDIProcessorPerformance {
    & "$($env:SystemRoot)\system32\powercfg.exe" @('/GETACTIVESCHEME')
}

function Test-MDIProcessorPerformance {
    [CmdletBinding()]
    param(
        [switch] $Detailed
    )
    Write-Verbose -Message $strings['ProcessorPerformance_Validate']
    $result = $false
    $activeScheme = Get-MDIProcessorPerformance
    if ($activeScheme -match ':\s+(?<guid>[a-fA-F0-9]{8}[-]?([a-fA-F0-9]{4}[-]?){3}[a-fA-F0-9]{12})\s+\((?<name>.*)\)') {
        $result = $Matches.guid -eq '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
    }
    Write-Verbose -Message (Get-MDIValidationMessage $result)
    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $result
                Details = $activeScheme
            })
    } else {
        $result
    }
}

function Set-MDIProcessorPerformance {
    & "$($env:SystemRoot)\system32\powercfg.exe" @('/SETACTIVE', '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c')
}

function Get-MDIProcessorPerformanceGPO {
    [CmdletBinding()]
    param(
        [string] $GpoNamePrefix
    )
    $gpoName = Get-MDIGPOName -Name $settings.ProcessorPerformance.GpoName -GpoNamePrefix $GpoNamePrefix
    $gpo = Get-MDIGPO -Name $gpoName
    if ($gpo) {
        $gpo | Select-Object -Property *,
        @{N = 'GPRegistryValue'; E = { Get-GPRegistryValue -Guid $gpo.Id.Guid -Key $settings.ProcessorPerformance.Key } }
    }
}

function Test-MDIProcessorPerformanceGPO {
    [CmdletBinding()]
    param(
        [switch] $Detailed,
        [string] $GpoNamePrefix
    )
    $gpoName = Get-MDIGPOName -Name $settings.ProcessorPerformance.GpoName -GpoNamePrefix $GpoNamePrefix
    Write-Verbose -Message ($strings['GPO_Validate'] -f $gpoName)

    $state = $false
    $gpo = Get-MDIProcessorPerformanceGPO -GpoNamePrefix $GpoNamePrefix

    if ($gpo) {
        $gpSetOk = $gpo.GPRegistryValue.ValueName -eq $settings.ProcessorPerformance.ValueName -and
        $gpo.GPRegistryValue.Value -eq $settings.ProcessorPerformance.SchemeGuid -and
        $gpo.GPRegistryValue.PolicyState -eq [Microsoft.GroupPolicy.PolicyState]::Set

        if ($gpSetOk) {
            $state = Test-MDIGPOEnabledAndLink -GPO $gpo
        } else {
            Write-Verbose -Message $strings['GPO_SettingsMismatch']
        }
    }
    Write-Verbose -Message (Get-MDIValidationMessage $state)
    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $state
                Details = if ($gpo) { $gpo | Select-Object DisplayName, Id, GpoStatus, GPRegistryValue }
                else { "'{0}' - {1}" -f $gpoName, $strings['GPO_NotFound'] }
            })
    } else {
        $state
    }
}

function Set-MDIProcessorPerformanceGPO {
    [CmdletBinding()]
    param(
        [switch] $SkipGpoLink,
        [switch] $CreateGpoDisabled,
        [string] $GpoNamePrefix
    )
    $gpoName = Get-MDIGPOName -Name $settings.ProcessorPerformance.GpoName -GpoNamePrefix $GpoNamePrefix
    $gpo = Get-MDIProcessorPerformanceGPO -GpoNamePrefix $GpoNamePrefix
    if ($null -eq $gpo) {
        $gpo = New-MDIGPO -Name $gpoName -CreateGpoDisabled:$CreateGpoDisabled
    }
    if ($gpo) {
        $gppParams = @{
            Guid      = $gpo.Id.Guid
            Type      = 'String'
            Key       = $settings.ProcessorPerformance.Key
            ValueName = $settings.ProcessorPerformance.ValueName
            Value     = $settings.ProcessorPerformance.SchemeGuid
        }
        $gpoUpdated = Set-GPRegistryValue @gppParams
        if (-not ($CreateGpoDisabled)) { $gpoUpdated.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled }
        $gpoUpdated.MakeAclConsistent()

        if (-not $SkipGpoLink) {
            $gpLinkParams = @{
                Guid        = $gpo.Id.Guid
                LinkEnabled = [Microsoft.GroupPolicy.EnableLink]::Yes
                Enforced    = [Microsoft.GroupPolicy.EnforceLink]::Yes
                Target      = 'OU=Domain Controllers,{0}' -f ([adsi]'').distinguishedName.Value
            }
            Set-MDIGPOLink @gpLinkParams
        }
    } else {
        throw $strings['GPO_UnableToUpdate']
    }
}

#endregion

#region Directory Services Auditing helper functions

function Get-MDIAdPath {
    param(
        [Parameter(Mandatory)] $Path
    )
    $DefaultNamingContext = ([adsi]('LDAP://{0}/RootDSE' -f $env:USERDNSDOMAIN)).defaultNamingContext.Value
    $Path -f $DefaultNamingContext
}

function Get-MDISAcl {
    param(
        [Parameter(Mandatory)] $Path
    )
    $acls = Get-Acl -Path $Path -Audit -ErrorAction Stop
    if ($acls) {
        foreach ($acl in $acls.Audit) {
            [PSCustomObject]@{
                Account                = $acl.IdentityReference.Value
                SecurityIdentifier     = $acl.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                AccessMask             = [int]$acl.ActiveDirectoryRights
                AccessMaskDetails      = $acl.ActiveDirectoryRights
                AuditFlags             = $acl.AuditFlags
                AuditFlagsValue        = [int]$acl.AuditFlags
                InheritedObjectAceType = $acl.InheritedObjectType
                InheritanceType        = [int]$acl.InheritanceType
                PropagationFlags       = [int]$acl.PropagationFlags
            }
        }
    }
}

function Set-MDISAcl {
    param(
        [Parameter(Mandatory)] $Auditing
    )
    $Path = Get-MDIAdPath -Path $Auditing.Path
    $acls = Get-Acl -Path $Path -Audit -ErrorAction SilentlyContinue
    if ($acls) {
        Write-Verbose -Message ('Setting System Access Control Lists')
        foreach ($audit in $Auditing.Auditing) {
            $account = (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList @(
                    $audit.SecurityIdentifier)).Translate([System.Security.Principal.NTAccount]).Value
            $argumentList = @(
                [Security.Principal.NTAccount] $account,
                [System.DirectoryServices.ActiveDirectoryRights] $audit.AccessMask,
                [System.Security.AccessControl.AuditFlags] $audit.AuditFlagsValue,
                [guid]::Empty.Guid.ToString(),
                [System.DirectoryServices.ActiveDirectorySecurityInheritance] $audit.InheritanceType,
                [guid] $audit.InheritedObjectAceType
            )
            $rule = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $argumentList
            $acls.AddAuditRule($rule)
        }
        Set-Acl -Path $Path -AclObject $acls
    }
}

function Get-MDIDomainObjectAuditing {
    try {
        Get-MDISAcl -Path (Get-MDIAdPath -Path $settings.ObjectAuditing.Path)
    } catch [System.Management.Automation.ActionPreferenceStopException] {
        if ('ObjectNotFound' -eq $_.Exception.ErrorRecord.CategoryInfo.Category) {
            Write-Warning $_.Exception.Message
        } else {
            throw $_
        }
    }
}

function Get-MDIAdfsAuditing {
    try {
        Get-MDISAcl -Path (Get-MDIAdPath -Path $settings.AdfsAuditing.Path)
    } catch [System.Management.Automation.ActionPreferenceStopException] {
        if ('ObjectNotFound' -eq $_.Exception.ErrorRecord.CategoryInfo.Category) {
            Write-Warning $_.Exception.Message
        } else {
            throw $_
        }
    }
}

function Get-MDIConfigurationContainerAuditing {
    try {
        Get-MDISAcl -Path (Get-MDIAdPath -Path $settings.ConfigurationContainerAuditing.Path)
    } catch [System.Management.Automation.ActionPreferenceStopException] {
        if ('ObjectNotFound' -eq $_.Exception.ErrorRecord.CategoryInfo.Category) {
            Write-Warning $_.Exception.Message
        } else {
            throw $_
        }
    }
}

function Test-MDIAuditing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [object[]] $ExpectedAuditing,
        [switch] $Detailed
    )
    try {
        $AppliedAuditing = Get-MDISAcl -Path (Get-MDIAdPath -Path $Path)
        $isAuditingOk = @(foreach ($applied in $AppliedAuditing) {
                $ExpectedAuditing | Where-Object { ($_.SecurityIdentifier -eq $applied.SecurityIdentifier) -and
                ($_.AuditFlagsValue -eq $applied.AuditFlagsValue) -and
                ($_.InheritedObjectAceType -eq $applied.InheritedObjectAceType) -and
                ($_.InheritanceType -eq $applied.InheritanceType) -and
                ($_.PropagationFlags -eq $applied.PropagationFlags) -and
                (([System.DirectoryServices.ActiveDirectoryRights]$applied.AccessMask).HasFlag(([System.DirectoryServices.ActiveDirectoryRights]($_.AccessMask)))) }
            }).Count -ge $ExpectedAuditing.Count

    } catch [System.Management.Automation.ActionPreferenceStopException] {
        if ('ObjectNotFound' -eq $_.Exception.ErrorRecord.CategoryInfo.Category) {
            $isAuditingOk = $true
        } else {
            $isAuditingOk = $false
        }
    }
    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $isAuditingOk
                Details = $AppliedAuditing
            })
    } else {
        $isAuditingOk
    }
}

function Test-MDIDomainObjectAuditing {
    [CmdletBinding()]
    param(
        [switch] $Detailed
    )
    Write-Verbose -Message $strings['DomainObject_ValidateAuditing']
    $result = Test-MDIAuditing -Path $settings.ObjectAuditing.Path -ExpectedAuditing $settings.ObjectAuditing.Auditing -Detailed:$Detailed
    if ($Detailed) {
        Write-Verbose -Message (Get-MDIValidationMessage $result.Status)
    } else {
        Write-Verbose -Message (Get-MDIValidationMessage $result)
    }
    $result
}

function Test-MDIAdfsAuditing {
    [CmdletBinding()]
    param(
        [switch] $Detailed
    )
    $result = [PSCustomObject]@{
        Status  = $true
        Details = $strings['ADFS_ContainerNotFound']
    }
    Write-Verbose -Message $strings['ADFS_ValidateAuditing']
    if ([System.DirectoryServices.DirectoryEntry]::Exists((Get-MDIAdPath -Path $settings.AdfsAuditing.Validate))) {
        $result = Test-MDIAuditing -Path $settings.AdfsAuditing.Path -ExpectedAuditing $settings.AdfsAuditing.Auditing -Detailed:$Detailed
    } elseif (-not $Detailed) {
        $result = $true
    }
    if ($Detailed) {
        Write-Verbose -Message (Get-MDIValidationMessage $result.Status)
    } else {
        Write-Verbose -Message (Get-MDIValidationMessage $result)
    }
    $result
}

function Test-MDIConfigurationContainerAuditing {
    [CmdletBinding()]
    param(
        [switch] $Detailed
    )
    $result = [PSCustomObject]@{
        Status  = $true
        Details = $strings['Exchange_ContainerNotFound']
    }
    Write-Verbose -Message $strings['Exchange_ValidateAuditing']
    if ([System.DirectoryServices.DirectoryEntry]::Exists((Get-MDIAdPath -Path $settings.ConfigurationContainerAuditing.Validate))) {
        $result = Test-MDIAuditing -Path $settings.ConfigurationContainerAuditing.Path -ExpectedAuditing $settings.ConfigurationContainerAuditing.Auditing -Detailed:$Detailed
    } elseif (-not $Detailed) {
        $result = $true
    }
    if ($Detailed) {
        Write-Verbose -Message (Get-MDIValidationMessage $result.Status)
    } else {
        Write-Verbose -Message (Get-MDIValidationMessage $result)
    }
    $result
}

function Set-MDIDomainObjectAuditing {
    Set-MDISAcl -Auditing $settings.ObjectAuditing
}

function Set-MDIAdfsAuditing {
    if ([System.DirectoryServices.DirectoryEntry]::Exists((Get-MDIAdPath -Path $settings.AdfsAuditing.Validate))) {
        Set-MDISAcl -Auditing $settings.AdfsAuditing
    } else {
        Write-Warning $strings['ADFS_ContainerNotFound']
    }
}

function Set-MDIConfigurationContainerAuditing {
    [CmdletBinding()]
    param(
        [switch] $Force
    )
    if ($Force -or [System.DirectoryServices.DirectoryEntry]::Exists((Get-MDIAdPath -Path $settings.ConfigurationContainerAuditing.Validate))) {
        Set-MDISAcl -Auditing $settings.ConfigurationContainerAuditing
    } else {
        Write-Warning $strings['Exchange_ContainerNotFound']
    }
}

#endregion

#region NTLM Auditing helper functions

function Get-MDINTLMAuditing {
    [CmdletBinding()]
    param()
    $settings.NTLMAuditing.RegistrySet.GetEnumerator() | ForEach-Object {
        $name = ($_.Name -split '\\')[-1]
        $path = 'HKLM:\{0}' -f ($_.Name -replace $name)
        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $name
        $expected = $_.Value
        [PSCustomObject]@{
            Path          = $path
            Name          = $name
            ActualValue   = $value
            ExpectedValue = $expected
        }
    }
}

function Test-MDINTLMAuditing {
    [CmdletBinding()]
    param(
        [switch] $Detailed
    )
    Write-Verbose -Message $strings['NTLM_ValidateAuditing']
    $ntlmAuditing = Get-MDINTLMAuditing
    $status = @($ntlmAuditing | Where-Object { $_.ActualValue -match $_.ExpectedValue }).Count -eq $settings.NTLMAuditing.RegistrySet.Count
    Write-Verbose (Get-MDIValidationMessage $status)
    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $status
                Details = $ntlmAuditing
            })
    } else {
        $status
    }
}

function Set-MDINTLMAuditing {
    [CmdletBinding()]
    param()
    $settings.NTLMAuditing.RegistrySet.GetEnumerator() | ForEach-Object {
        $name = ($_.Name -split '\\')[-1]
        $path = 'HKLM:\{0}' -f ($_.Name -replace $name)
        $value = ($_.Value -split '\|')[0]
        Set-ItemProperty -Path $path -Name $name -Value $value -ErrorAction Stop
    }
}

function Get-MDINTLMAuditingGPO {
    [CmdletBinding()]
    param(
        [string] $GpoNamePrefix
    )
    $gpoName = Get-MDIGPOName -Name $settings.NTLMAuditing.GpoName -GpoNamePrefix $GpoNamePrefix
    $gpo = Get-MDIGPO -Name $gpoName
    if ($gpo) {
        $report = [xml](Get-GPOReport -Guid $gpo.Id -ReportType Xml)
        $options = $report.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'AuditReceivingNTLMTraffic|RestrictSendingNTLMTraffic|AuditNTLMInDomain' }
        $RegistryValue = foreach ($opt in $options) {
            $valueName = ($opt.KeyName -split '\\')[-1]
            $path = $opt.KeyName -replace '(.*)\\(\w+)', '$1'
            [PSCustomObject]@{
                KeyName       = $path
                valueName     = $valueName
                Value         = $opt.SettingNumber
                valueDisplay  = $opt.Display.DisplayString
                ExpectedValue = ($settings.NTLMAuditing.RegistrySet.GetEnumerator() |
                        Where-Object { ('MACHINE\{0}' -f $_.Name) -eq (Join-Path -Path $path -ChildPath $valueName) }).Value
            }
        }
        $gpo | Select-Object -Property *, @{N = 'RegistryValue'; E = { $RegistryValue } }
    }
}

function Test-MDINTLMAuditingGPO {
    [CmdletBinding()]
    param(
        [switch] $Detailed,
        [string] $GpoNamePrefix
    )
    $gpoName = Get-MDIGPOName -Name $settings.NTLMAuditing.GpoName -GpoNamePrefix $GpoNamePrefix
    Write-Verbose -Message ($strings['GPO_Validate'] -f $gpoName)

    $state = $false
    $gpo = Get-MDINTLMAuditingGPO -GpoNamePrefix $GpoNamePrefix

    if ($gpo) {
        $gpSetOk = @($gpo.RegistryValue | Where-Object {
                $_.Value -match $_.ExpectedValue
            }).Count -eq $settings.NTLMAuditing.RegistrySet.Count

        if ($gpSetOk) {
            $state = Test-MDIGPOEnabledAndLink -GPO $gpo
        } else {
            Write-Verbose -Message $strings['GPO_SettingsMismatch']
        }
    }
    Write-Verbose -Message (Get-MDIValidationMessage $state)
    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $state
                Details = if ($gpo) { $gpo | Select-Object DisplayName, Id, GpoStatus, RegistryValue }
                else { "'{0}' - {1}" -f $gpoName, $strings['GPO_NotFound'] }
            })
    } else {
        $state
    }
}

function Set-MDINTLMAuditingGPO {
    [CmdletBinding()]
    param(
        [switch] $SkipGpoLink,
        [switch] $CreateGpoDisabled,
        [string] $GpoNamePrefix
    )
    $gpoName = Get-MDIGPOName -Name $settings.NTLMAuditing.GpoName -GpoNamePrefix $GpoNamePrefix
    $gpo = Get-MDIGPO -Name $gpoName
    if ($null -eq $gpo) {
        $gpo = New-MDIGPO -Name $gpoName -CreateGpoDisabled:$CreateGpoDisabled
    }

    $filePath = '{0}\Machine\Microsoft\Windows NT\SecEdit' -f $gpo.gPCFileSysPath
    if (-not (Test-Path $filePath)) { New-Item -Path $filePath -ItemType Directory -Force | Out-Null }

    $fileContent = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Registry Values]
'@

    $settings.NTLMAuditing.RegistrySet.GetEnumerator() | ForEach-Object {
        $value = ($_.Value -split '\|')[0]
        $fileContent += '{2}MACHINE\{0}=4,{1}' -f $_.Name, $Value, [System.Environment]::NewLine
    }
    Set-Content -Path (Join-Path -Path $filePath -ChildPath 'GptTmpl.inf') -Encoding Unicode -Value $fileContent

    if (-not ($CreateGpoDisabled)) { $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled }
    $gpo.MakeAclConsistent()
    $gpoUpdated = Set-MDIGPOMachineExtension -Guid $gpo.Id.Guid -Extension @(
        $settings.gpoExtensions['Security'], $settings.gpoExtensions['Computer Restricted Groups'])

    if ($null -ne $gpoUpdated) {
        if (-not $SkipGpoLink) {
            $gpLinkParams = @{
                Guid        = $gpo.Id.Guid
                LinkEnabled = [Microsoft.GroupPolicy.EnableLink]::Yes
                Enforced    = [Microsoft.GroupPolicy.EnforceLink]::Yes
                Target      = 'OU=Domain Controllers,{0}' -f ([adsi]'').distinguishedName.Value
            }
            Set-MDIGPOLink @gpLinkParams
        }
    } else {
        Write-Warning $strings['GPO_UnableToSetExtension']
    }
}

#endregion

#region Advanced Auditing Policy helper functions

function Get-MDIAdvAuditPolicy {
    [CmdletBinding()]
    param()
    & "$($env:SystemRoot)\system32\auditpol.exe" @('/get', '/category:*', '/r') | ConvertFrom-Csv |
        Select-Object *, @{N = 'Setting Value'; E = {
                $setting = 0
                if ($_.'Inclusion Setting' -match 'Success') { $setting += 1 }
                if ($_.'Inclusion Setting' -match 'Failure') { $setting += 2 }
                if ($_.'Exclusion Setting' -match 'Success') { $setting += 4 }
                if ($_.'Exclusion Setting' -match 'Failure') { $setting += 8 }
                $setting
            }
        }
}

function Test-MDIAdvAuditPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]] $ExpectedAuditing,
        [switch] $Detailed
    )
    $AppliedAuditing = Get-MDIAdvAuditPolicy
    $status = @(foreach ($applied in $AppliedAuditing) {
            $ExpectedAuditing | Where-Object {
            ($applied.'Policy Target') -eq ($_.'Policy Target') -and
            ($applied.'Subcategory GUID').ToUpper() -eq ($_.'Subcategory Guid').ToUpper() -and
            ($applied.'Setting Value') -eq ($_.'Setting Value')
            }
        }).Count -ge $ExpectedAuditing.Count
    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $status
                Details = $AppliedAuditing
            })
    } else {
        $status
    }
}

function Set-MDIAdvAuditPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $SubcategoryGUID,
        [string] $InclusionSetting
    )
    if ($SubcategoryGUID -notmatch '^{.*}$') { $SubcategoryGUID = "{$SubcategoryGUID}" }
    $success = if ($InclusionSetting -match 'Success') { 'enable' } else { 'disable' }
    $failure = if ($InclusionSetting -match 'Failure') { 'enable' } else { 'disable' }
    $null = & "$($env:SystemRoot)\system32\auditpol.exe" @('/set', "/subcategory:$SubcategoryGUID", "/success:$success", "/failure:$failure")
}

#endregion

#region Advanced Auditing Policy for DCs Settings

function Get-MDIAdvancedAuditPolicyDCsGPO {
    [CmdletBinding()]
    param(
        [string] $GpoNamePrefix
    )
    $gpoName = Get-MDIGPOName -Name $settings.AdvancedAuditPolicyDCs.GpoName -GpoNamePrefix $GpoNamePrefix
    $gpo = Get-MDIGPO -Name $gpoName
    if ($gpo) {
        $report = [xml](Get-GPOReport -Guid $gpo.Id -ReportType Xml)
        $currentSettings = $report.GPO.Computer.ExtensionData.Extension.AuditSetting
        $expectedSettings = $settings.AdvancedAuditPolicyDCs.PolicySettings | ConvertFrom-Csv
        $AuditSettings = foreach ($audit in $expectedSettings) {
            [PSCustomObject]@{
                PolicyTarget    = $audit.'Policy Target'
                SubcategoryName = $audit.'Subcategory'
                SubcategoryGuid = $audit.'Subcategory GUID'
                SettingValue    = $audit.'Setting Value'
                ExpectedValue   = ($currentSettings | Where-Object { -not [string]::IsNullOrEmpty($_) } | Where-Object {
                    ($_.SubcategoryGuid).ToUpper() -eq ($audit.'Subcategory GUID').ToUpper() -and
                        $_.PolicyTarget -eq $audit.'Policy Target' }).SettingValue
            }
        }
        $gpo | Select-Object -Property *, @{N = 'AuditSettings'; E = { $AuditSettings } }
    }
}

function Test-MDIAdvancedAuditPolicyDCsGPO {
    [CmdletBinding()]
    param(
        [switch] $Detailed,
        [string] $GpoNamePrefix
    )
    $gpoName = Get-MDIGPOName -Name $settings.AdvancedAuditPolicyDCs.GpoName -GpoNamePrefix $GpoNamePrefix
    Write-Verbose -Message ($strings['GPO_Validate'] -f $gpoName)

    $state = $false
    $gpo = Get-MDIAdvancedAuditPolicyDCsGPO -GpoNamePrefix $GpoNamePrefix

    if ($gpo) {
        $expectedSettings = @($settings.AdvancedAuditPolicyDCs.PolicySettings | ConvertFrom-Csv)
        $gpSetOk = @($gpo.AuditSettings | Where-Object {
                $_.SettingValue -match $_.ExpectedValue
            }).Count -eq $expectedSettings.Count

        if ($gpSetOk) {
            $state = Test-MDIGPOEnabledAndLink -GPO $gpo
        } else {
            Write-Verbose -Message $strings['GPO_SettingsMismatch']
        }
    }
    Write-Verbose -Message (Get-MDIValidationMessage $state)
    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $state
                Details = if ($gpo) { $gpo | Select-Object DisplayName, Id, GpoStatus, AuditSettings }
                else { "'{0}' - {1}" -f $gpoName, $strings['GPO_NotFound'] }
            })
    } else {
        $state
    }
}

function Set-MDIAdvancedAuditPolicyDCsGPO {
    [CmdletBinding()]
    param(
        [switch] $SkipGpoLink,
        [switch] $CreateGpoDisabled,
        [string] $GpoNamePrefix
    )
    $gpoName = Get-MDIGPOName -Name $settings.AdvancedAuditPolicyDCs.GpoName -GpoNamePrefix $GpoNamePrefix
    $gpo = Get-MDIGPO -Name $gpoName
    if ($null -eq $gpo) {
        $gpo = New-MDIGPO -Name $gpoName -CreateGpoDisabled:$CreateGpoDisabled
    }

    $filePath = '{0}\Machine\Microsoft\Windows NT\Audit' -f $gpo.gPCFileSysPath
    if (-not (Test-Path $filePath)) { New-Item -Path $filePath -ItemType Directory -Force | Out-Null }
    Set-Content -Path (Join-Path -Path $filePath -ChildPath 'audit.csv') -Encoding ASCII -Value $settings.AdvancedAuditPolicyDCs.PolicySettings

    if (-not ($CreateGpoDisabled)) { $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled }
    $gpo.MakeAclConsistent()
    $gpoUpdated = Set-MDIGPOMachineExtension -Guid $gpo.Id.Guid -Extension @(
        $settings.gpoExtensions['Audit Policy Configuration'], $settings.gpoExtensions['Audit Configuration Extension'])

    if ($null -ne $gpoUpdated) {
        if (-not $SkipGpoLink) {
            $gpLinkParams = @{
                Guid        = $gpo.Id.Guid
                LinkEnabled = [Microsoft.GroupPolicy.EnableLink]::Yes
                Enforced    = [Microsoft.GroupPolicy.EnforceLink]::Yes
                Target      = 'OU=Domain Controllers,{0}' -f ([adsi]'').distinguishedName.Value
            }
            Set-MDIGPOLink @gpLinkParams
        }
    } else {
        Write-Warning $strings['GPO_UnableToSetExtension']
    }
}

function Get-MDIAdvancedAuditPolicyDCs {
    [CmdletBinding()]
    param()
    $relevantGUIDs = @($settings.AdvancedAuditPolicyDCs.PolicySettings | ConvertFrom-Csv) | Select-Object -ExpandProperty 'Subcategory GUID' -Unique
    Get-MDIAdvAuditPolicy | Where-Object { $_.'Subcategory GUID' -in $relevantGUIDs }
}

function Test-MDIAdvancedAuditPolicyDCs {
    [CmdletBinding()]
    param(
        [switch] $Detailed
    )
    Write-Verbose -Message $strings['AdvancedPolicyDCs_Validate']
    $result = Test-MDIAdvAuditPolicy -ExpectedAuditing @($settings.AdvancedAuditPolicyDCs.PolicySettings | ConvertFrom-Csv) -Detailed:$Detailed
    if ($Detailed) {
        Write-Verbose -Message (Get-MDIValidationMessage $result.Status)
    } else {
        Write-Verbose -Message (Get-MDIValidationMessage $result)
    }
    $result
}

function Set-MDIAdvancedAuditPolicyDCs {
    Write-Verbose -Message $strings['AdvancedPolicyDCs_Set']
    $settings.AdvancedAuditPolicyDCs.PolicySettings | ConvertFrom-Csv | ForEach-Object {
        $param = @{
            SubcategoryGUID  = $_.'Subcategory GUID'
            InclusionSetting = $_.'Inclusion Setting'
        }
        Set-MDIAdvAuditPolicy @param
    }
}

#endregion

#region Advanced Auditing Policy for CAs Settings

function Get-MDIAdvancedAuditPolicyCAsGPO {
    [CmdletBinding()]
    param(
        [string] $GpoNamePrefix
    )
    $gpoName = Get-MDIGPOName -Name $settings.AdvancedAuditPolicyCAs.GpoName -GpoNamePrefix $GpoNamePrefix
    $gpo = Get-MDIGPO -Name $gpoName
    if ($gpo) {
        $report = [xml](Get-GPOReport -Guid $gpo.Id -ReportType Xml)
        $currentSettings = $report.GPO.Computer.ExtensionData.Extension.AuditSetting
        $expectedSettings = $settings.AdvancedAuditPolicyCAs.PolicySettings | ConvertFrom-Csv
        $AuditSettings = foreach ($audit in $expectedSettings) {
            [PSCustomObject]@{
                PolicyTarget    = $audit.'Policy Target'
                SubcategoryName = $audit.'Subcategory'
                SubcategoryGuid = $audit.'Subcategory GUID'
                SettingValue    = $audit.'Setting Value'
                ExpectedValue   = ($currentSettings | Where-Object {
                        $_.SubcategoryName -eq ($audit.Subcategory) -and
                        ($_.SubcategoryGuid).ToUpper() -eq ($audit.'Subcategory GUID').ToUpper() -and
                        $_.PolicyTarget -eq $audit.'Policy Target' }).SettingValue
            }
        }
        $delegation = $settings.AdvancedAuditPolicyCAs.GPPermissions.GetEnumerator() | ForEach-Object {
            Get-GPPermission -Guid $gpo.Id.Guid -TargetType Group -TargetName $_.Key
        }
        $gpo = $gpo | Select-Object -Property *, @{N = 'AuditSettings'; E = { $AuditSettings } }, @{N = 'Delegation'; E = { $delegation } }
    }
    $gpo
}

function Test-MDIAdvancedAuditPolicyCAsGPO {
    [CmdletBinding()]
    param(
        [switch] $Detailed,
        [string] $GpoNamePrefix
    )
    $gpoName = Get-MDIGPOName -Name $settings.AdvancedAuditPolicyCAs.GpoName -GpoNamePrefix $GpoNamePrefix
    Write-Verbose -Message ($strings['GPO_Validate'] -f $gpoName)

    $state = $false
    $gpo = Get-MDIAdvancedAuditPolicyCAsGPO -GpoNamePrefix $GpoNamePrefix

    if ($gpo) {
        $expectedSettings = @($settings.AdvancedAuditPolicyCAs.PolicySettings | ConvertFrom-Csv)
        $gpSetOk = @($gpo.AuditSettings | Where-Object {
                $_.SettingValue -match $_.ExpectedValue
            }).Count -eq $expectedSettings.Count

        if ($gpSetOk) {
            $gpDelegationOk = @($gpo.Delegation | Where-Object {
                    $settings.AdvancedAuditPolicyCAs.GPPermissions[$_.Trustee.Name] -eq $_.Permission
                }).Count -eq $settings.AdvancedAuditPolicyCAs.GPPermissions.Count

            if (-not $gpDelegationOk) {
                Write-Verbose -Message $strings['GPO_DelegationMismatch']
            } else {
                $state = Test-MDIGPOEnabledAndLink -GPO $gpo
            }

        } else {
            Write-Verbose -Message $strings['GPO_SettingsMismatch']
        }
    }
    Write-Verbose -Message (Get-MDIValidationMessage $state)
    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $state
                Details = if ($gpo) { $gpo | Select-Object DisplayName, Id, GpoStatus, AuditSettings }
                else { "'{0}' - {1}" -f $gpoName, $strings['GPO_NotFound'] }
            })
    } else {
        $state
    }
}

function Set-MDIAdvancedAuditPolicyCAsGPO {
    [CmdletBinding()]
    param(
        [switch] $SkipGpoLink,
        [switch] $CreateGpoDisabled,
        [string] $GpoNamePrefix
    )
    $gpoName = Get-MDIGPOName -Name $settings.AdvancedAuditPolicyCAs.GpoName -GpoNamePrefix $GpoNamePrefix
    $gpo = Get-MDIGPO -Name $gpoName
    if ($null -eq $gpo) {
        $gpo = New-MDIGPO -Name $gpoName -CreateGpoDisabled:$CreateGpoDisabled
    }

    $filePath = '{0}\Machine\Microsoft\Windows NT\Audit' -f $gpo.gPCFileSysPath
    if (-not (Test-Path $filePath)) { New-Item -Path $filePath -ItemType Directory -Force | Out-Null }
    Set-Content -Path (Join-Path -Path $filePath -ChildPath 'audit.csv') -Encoding ASCII -Value $settings.AdvancedAuditPolicyCAs.PolicySettings

    if (-not ($CreateGpoDisabled)) { $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled }
    $gpo.MakeAclConsistent()
    $gpoUpdated = Set-MDIGPOMachineExtension -Guid $gpo.Id.Guid -Extension @(
        $settings.gpoExtensions['Audit Policy Configuration'], $settings.gpoExtensions['Audit Configuration Extension'])

    Write-Verbose -Message $strings['GPO_SetDelegation']
    $settings.AdvancedAuditPolicyCAs.GPPermissions.GetEnumerator() | ForEach-Object {
        Set-GPPermission -Guid $gpo.Id.Guid -TargetType Group -TargetName $_.Key -PermissionLevel $_.Value -Replace | Out-Null
    }

    if ($null -ne $gpoUpdated) {
        if (-not $SkipGpoLink) {
            $gpLinkParams = @{
                Guid        = $gpo.Id.Guid
                LinkEnabled = [Microsoft.GroupPolicy.EnableLink]::Yes
                Enforced    = [Microsoft.GroupPolicy.EnforceLink]::Yes
                Target      = ([adsi]'').distinguishedName.Value
            }
            Set-MDIGPOLink @gpLinkParams
        }
    } else {
        Write-Warning $strings['GPO_UnableToSetExtension']
    }
}

function Get-MDIAdvancedAuditPolicyCAs {
    [CmdletBinding()]
    param()
    $relevantGUIDs = @($settings.AdvancedAuditPolicyCAs.PolicySettings | ConvertFrom-Csv) | Select-Object -ExpandProperty 'Subcategory GUID' -Unique
    Get-MDIAdvAuditPolicy | Where-Object { $_.'Subcategory GUID' -in $relevantGUIDs }
}

function Test-MDIAdvancedAuditPolicyCAs {
    [CmdletBinding()]
    param(
        [switch] $Detailed
    )
    Write-Verbose -Message $strings['AdvancedPolicyCAs_Validate']
    if (Test-MDICAServer) {
        $result = Test-MDIAdvAuditPolicy -ExpectedAuditing @($settings.AdvancedAuditPolicyCAs.PolicySettings | ConvertFrom-Csv) -Detailed:$Detailed
    } else {
        Write-Verbose -Message $strings['CAAuditing_NotCAServer']
        $result = [PSCustomObject]([ordered]@{
                Status  = $true
                Details = $strings['CAAuditing_NotCAServer']
            })
    }

    if ($Detailed) {
        Write-Verbose -Message (Get-MDIValidationMessage $result.Status)
    } else {
        Write-Verbose -Message (Get-MDIValidationMessage $result)
    }
    $result
}

function Set-MDIAdvancedAuditPolicyCAs {
    Write-Verbose -Message $strings['AdvancedPolicyCAs_Set']
    $settings.AdvancedAuditPolicyCAs.PolicySettings | ConvertFrom-Csv | ForEach-Object {
        $param = @{
            SubcategoryGUID  = $_.'Subcategory GUID'
            InclusionSetting = $_.'Inclusion Setting'
        }
        Set-MDIAdvAuditPolicy @param
    }
}

#endregion

#region CA Audit configuration helper functions

function Get-MDICAAuditing {
    [CmdletBinding()]
    param()
    $certSvcConfigPath = $settings.CAAuditing.RegPathActive
    $name = ($certSvcConfigPath -split '\\')[-1]
    $activePath = 'HKLM:\{0}' -f ($certSvcConfigPath -replace $name)
    $activeValue = Get-ItemProperty -Path $activePath -Name $name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $name

    $settings.CAAuditing.RegistrySet.GetEnumerator() | ForEach-Object {
        $name = ($_.Name -split '\\')[-1]
        $path = 'HKLM:\{0}' -f (($_.Name -replace $name) -f $activeValue)
        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $name
        $expected = $_.Value
        [PSCustomObject]@{
            Path          = $path
            Name          = $name
            ActualValue   = $value
            ExpectedValue = $expected
        }
    }
}

function Test-MDICAAuditing {
    [CmdletBinding()]
    param(
        [switch] $Detailed
    )
    Write-Verbose -Message $strings['CAAuditing_Validate']
    if (Test-MDICAServer) {
        $caAuditing = Get-MDICAAuditing
        $caAuditingOk = @($caAuditing | Where-Object { $_.ActualValue -match $_.ExpectedValue }).Count -eq $settings.CAAuditing.RegistrySet.Count
    } else {
        Write-Verbose -Message $strings['CAAuditing_NotCAServer']
        $caAuditing = $strings['CAAuditing_NotCAServer']
        $caAuditingOk = $true
    }
    Write-Verbose -Message (Get-MDIValidationMessage $caAuditingOk)

    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $caAuditingOk
                Details = $caAuditing
            })
    } else {
        $caAuditingOk
    }
}

function Set-MDICAAuditing {
    [CmdletBinding()]
    param(
        [switch] $SkipServiceRestart
    )
    if (Get-Service CertSvc -ErrorAction SilentlyContinue) {
        $certSvcConfigPath = $settings.CAAuditing.RegPathActive
        $name = ($certSvcConfigPath -split '\\')[-1]
        $activePath = 'HKLM:\{0}' -f ($certSvcConfigPath -replace $name)
        $activeValue = Get-ItemProperty -Path $activePath -Name $name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $name

        $settings.CAAuditing.RegistrySet.GetEnumerator() | ForEach-Object {
            $name = ($_.Name -split '\\')[-1]
            $path = 'HKLM:\{0}' -f (($_.Name -replace $name) -f $activeValue)
            $value = ($_.Value -split '\|')[0]
            Write-Verbose -Message ('Setting {0}{1} to {2}' -f $path, $name, $value)
            Set-ItemProperty -Path $path -Name $name -Value $value -ErrorAction Stop
        }
        if (-not $SkipServiceRestart) { Restart-Service -Name CertSvc -Force -Verbose:$VerbosePreference }
    } else {
        Write-Warning $strings['CAAuditing_NotCAServer']
    }
}

function Get-MDICAAuditingGPO {
    [CmdletBinding()]
    param(
        [string] $GpoNamePrefix
    )
    $gpoName = Get-MDIGPOName -Name $settings.CAAuditing.GpoName -GpoNamePrefix $GpoNamePrefix
    $gpo = Get-MDIGPO -Name $gpoName
    if ($gpo) {
        $params = @{
            Guid      = $gpo.Id
            Context   = 'Computer'
            Key       = 'HKEY_LOCAL_MACHINE\{0}' -f $settings.CAAuditing.GpoReg
            ValueName = ($settings.CAAuditing.GpoVal).Keys[0]
        }; $GPPrefRegistryValue = Get-GPPrefRegistryValue @params -ErrorAction SilentlyContinue
        $delegation = $settings.CAAuditing.GPPermissions.GetEnumerator() | ForEach-Object {
            Get-GPPermission -Guid $gpo.Id.Guid -TargetType Group -TargetName $_.Key
        }
        $gpo = $gpo | Select-Object -Property *, @{N = 'GPPrefRegistryValue'; E = { $GPPrefRegistryValue } }, @{N = 'Delegation'; E = { $delegation } }
    }
    $gpo
}

function Test-MDICAAuditingGPO {
    [CmdletBinding()]
    param(
        [switch] $Detailed,
        [string] $GpoNamePrefix
    )
    $gpoName = Get-MDIGPOName -Name $settings.CAAuditing.GpoName -GpoNamePrefix $GpoNamePrefix
    Write-Verbose -Message ($strings['GPO_Validate'] -f $gpoName)

    $state = $false
    $gpo = Get-MDICAAuditingGPO -GpoNamePrefix $GpoNamePrefix
    $gpSetOk = @()

    if ($gpo -and $gpo.GPPrefRegistryValue) {
        $settings.CAAuditing.GpoVal.GetEnumerator() | ForEach-Object {
            $expected = [PSCustomObject]@{
                DisabledDirectly = $false
                Type             = 'DWord'
                Action           = 'Update'
                Hive             = 'LocalMachine'
                FullKeyPath      = 'HKEY_LOCAL_MACHINE\{0}' -f $settings.CAAuditing.GpoReg
                ValueName        = $_.Key
                Value            = $_.Value
            }
            $properties = $expected | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
            $applied = $gpo.GPPrefRegistryValue | Select-Object -Property $properties
            $gpSetOk += ($null -ne (Compare-Object -ReferenceObject $applied -DifferenceObject $expected -Property $properties -IncludeEqual -ExcludeDifferent))
        }

        if (($gpSetOk -eq $false).Count -eq 0) {
            $gpDelegationOk = @($gpo.Delegation | Where-Object {
                    $settings.CAAuditing.GPPermissions[$_.Trustee.Name] -eq $_.Permission
                }).Count -eq $settings.CAAuditing.GPPermissions.Count

            if (-not $gpDelegationOk) {
                Write-Verbose -Message $strings['GPO_DelegationMismatch']
            } else {
                $state = Test-MDIGPOEnabledAndLink -GPO $gpo
            }

        } else {
            Write-Verbose -Message $strings['GPO_SettingsMismatch']
        }
    }
    Write-Verbose -Message (Get-MDIValidationMessage $state)
    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $state
                Details = if ($gpo) { $gpo | Select-Object DisplayName, Id, GpoStatus, GPPrefRegistryValue }
                else { "'{0}' - {1}" -f $gpoName, $strings['GPO_NotFound'] }
            })
    } else {
        $state
    }
}

function Set-MDICAAuditingGPO {
    [CmdletBinding()]
    param(
        [switch] $SkipGpoLink,
        [switch] $CreateGpoDisabled,
        [string] $GpoNamePrefix
    )
    $gpoName = Get-MDIGPOName -Name $settings.CAAuditing.GpoName -GpoNamePrefix $GpoNamePrefix
    $gpo = Get-MDIGPO -Name $gpoName
    if ($null -eq $gpo) {
        $gpo = New-MDIGPO -Name $gpoName -CreateGpoDisabled:$CreateGpoDisabled
    }

    $settings.CAAuditing.GpoVal.GetEnumerator() | ForEach-Object {
        $params = @{
            Guid      = $gpo.Id
            Context   = 'Computer'
            Key       = 'HKEY_LOCAL_MACHINE\{0}' -f $settings.CAAuditing.GpoReg
            ValueName = $_.Name
            Order     = -1
        }; if (Get-GPPrefRegistryValue @params -ErrorAction SilentlyContinue) { $gpo = Remove-GPPrefRegistryValue @params }

        $params += @{
            Value  = [int]$_.Value
            Type   = 'DWord'
            Action = 'Update'
        }
        Set-GPPrefRegistryValue @params | Out-Null
    }

    if (-not ($CreateGpoDisabled)) { $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled }
    $gpo.MakeAclConsistent()
    $gpoUpdated = Set-MDIGPOMachineExtension -Guid $gpo.Id.Guid -Extension @(
        $settings.gpoExtensions['Preference CSE GUID Registry'], $settings.gpoExtensions['Preference Tool CSE GUID Registry'])

    Write-Verbose -Message $strings['GPO_SetDelegation']
    $settings.CAAuditing.GPPermissions.GetEnumerator() | ForEach-Object {
        Set-GPPermission -Guid $gpo.Id.Guid -TargetType Group -TargetName $_.Key -PermissionLevel $_.Value -Replace | Out-Null
    }

    if ($null -ne $gpoUpdated) {
        if (-not $SkipGpoLink) {
            $gpLinkParams = @{
                Guid        = $gpo.Id.Guid
                LinkEnabled = [Microsoft.GroupPolicy.EnableLink]::Yes
                Enforced    = [Microsoft.GroupPolicy.EnforceLink]::Yes
                Target      = ([adsi]'').distinguishedName.Value
            }
            Set-MDIGPOLink @gpLinkParams
        }
    } else {
        Write-Warning $strings['GPO_UnableToSetExtension']
    }
}

#endregion

#region Domain helper functions

function Get-MDIDomainSchemaVersion {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)] [string] $Domain = $env:USERDNSDOMAIN
    )
    $schemaVersions = @{
        13 = 'Windows 2000 Server'
        30 = 'Windows Server 2003'
        31 = 'Windows Server 2003 R2'
        44 = 'Windows Server 2008'
        47 = 'Windows Server 2008 R2'
        56 = 'Windows Server 2012'
        69 = 'Windows Server 2012 R2'
        87 = 'Windows Server 2016'
        88 = 'Windows Server 2019 / 2022'
        90 = 'Windows Server vNext'
    }

    Write-Verbose -Message 'Getting AD Schema Version'
    $schema = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList (
        'LDAP://{0}' -f ([adsi]'LDAP://rootDSE').Properties['schemaNamingContext'].Value
    )
    $schemaVersion = $schema.Properties['objectVersion'].Value

    $return = @{
        schemaVersion = $schemaVersion
        details       = $schemaVersions[$schemaVersion]
    }
    $return
}

#endregion

#region DSA helper functions

function Get-MDIDeletedObjectsContainerPermission {
    [CmdletBinding()]
    param ()
    $deletedObjectsDN = 'CN=Deleted Objects,{0}' -f ([adsi]'').distinguishedName.Value
    $output = & "$($env:SystemRoot)\system32\dsacls.exe" @($deletedObjectsDN)
    ($output -join [System.Environment]::NewLine) -split '(?=Allow\s)' | Where-Object { $_ -match 'Allow' } | ForEach-Object {
        if ($_ -match 'Allow\s(?<Identity>(NT AUTHORITY\\\w+)|([^\s]+))\s+(?<Permissions>.*(?:\n\s+.*)*)') {
            [PSCustomObject]@{
                Identity    = $Matches.Identity
                Permissions = $Matches.Permissions -split '\s{2,}' | ForEach-Object { $_.Trim() }
            }
        }
    }
}

function Test-MDIDSA {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Identity,
        [switch] $Detailed
    )
    $return = @()
    $account = try {
        Get-ADUser -Identity $Identity -Properties msDS-PrincipalName
    } catch { try { Get-ADServiceAccount -Identity $Identity -Properties msDS-PrincipalName } catch { $null } }

    if ($null -eq $account) {
        $false
        Write-Error $strings['DSA_CannotFindIdentity'] -ErrorAction Stop
    } else {

        Write-Verbose -Message $strings['DSA_TestGroupMembership']
        $memberOf = @{}
        $filter = '(&(objectCategory=group)(objectClass=group)(member:1.2.840.113556.1.4.1941:={0}))' -f $account.DistinguishedName
        $searcher = [adsisearcher]$filter
        'objectSid', 'distinguishedName', 'msDS-PrincipalName' | ForEach-Object { [void]($searcher.PropertiesToLoad.Add($_)) }
        $searcher.FindAll() | ForEach-Object {
            $memberOf.Add($_.Properties['distinguishedname'][0],
                [PSCustomObject]@{
                    'objectSid'          = (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList @($_.Properties['objectSid'][0], 0)).Value
                    'msDS-PrincipalName' = $_.Properties['msDS-PrincipalName'][0]
                })
        }

        $domainSid = (Get-ADDomain).DomainSID.Value
        $sensitiveGroups = @{}
        $settings.SensitiveGroups.GetEnumerator() | ForEach-Object {
            $sensitiveGroups.Add(($_.Value -f $domainSid), $_.Key)
        }

        $sensitiveGroupsMembership = @(
            $memberOf.GetEnumerator() | Where-Object {
                $sensitiveGroups.ContainsKey($_.Value.objectSid)
            } | Select-Object -ExpandProperty Name
        )
        $return += [PSCustomObject][ordered]@{
            Test    = 'SensitiveGroupsMembership'
            Status  = $sensitiveGroupsMembership.Count -eq 0
            Details = $sensitiveGroupsMembership
        }

        Write-Verbose -Message $strings['DSA_TestDelegation']
        $sidsToCheck = @($account.SID.Value)
        $sidsToCheck += ($memberOf.GetEnumerator() | Where-Object {
                $sensitiveGroupsMembership -notcontains $_.Key }).Value.Value

        $filter = '(|(objectClass=domain)(objectClass=organizationalUnit)(objectClass=group))'
        $searcher = [adsisearcher]$filter
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $delegatedObjects = $searcher.FindAll() | ForEach-Object {
            $de = $_.GetDirectoryEntry()
            $permissions = $de.PsBase.ObjectSecurity.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
            if ($permissions | Where-Object { ($_.AccessControlType -eq 'Allow') -and ($sidsToCheck -contains $_.IdentityReference.Value) }) {
                $de.distinguishedName.Value
            }
        }
        $return += [PSCustomObject][ordered]@{
            Test    = 'ExplicitDelegation'
            Status  = $delegatedObjects.Count -eq 0
            Details = @($delegatedObjects | Select-Object -Unique)
        }

        Write-Verbose -Message $strings['DSA_TestDeletedObjectsAccess']
        $appliedAsExpected = $false
        $msDSPrincipalNamesToCheck = @($memberOf.GetEnumerator() | ForEach-Object { $_.Value.'msDS-PrincipalName' })
        $msDSPrincipalNamesToCheck += $account.'msDS-PrincipalName'
        $expectedDsacls = @('SPECIAL ACCESS', 'LIST CONTENTS', 'READ PROPERTY')
        $appliedDsacls = Get-MDIDeletedObjectsContainerPermission
        if ([string]::IsNullOrEmpty($appliedDsacls)) {
            Write-Warning -Message $strings['DSA_CannotReadDeletedObjectsContainer']
        } else {
            $dsaDsacls = $appliedDsacls | Where-Object { $msDSPrincipalNamesToCheck -contains $_.Identity } | Select-Object -ExpandProperty Permissions
            if ($null -eq $dsaDsacls) {
                $dsaDsacls = 'NONE'
            } else {
                $dsaDsacls = $dsaDsacls | Select-Object -Unique
                $appliedAsExpected = (Compare-Object -ReferenceObject $dsaDsacls -DifferenceObject $expectedDsacls -IncludeEqual -ExcludeDifferent).Count -eq $expectedDsacls.Count
            }
        }
        $return += [PSCustomObject][ordered]@{
            Test    = 'DeletedObjectsContainerPermission'
            Status  = $appliedAsExpected
            Details = $dsaDsacls
        }

        if ($account.ObjectClass -eq 'user') {
            Write-Verbose -Message $strings['DSA_TestManager']
            $filter = '(|(managedBy={0})(manager={0}))' -f ($account.DistinguishedName -replace '\s', '\20')
            $searcher = [adsisearcher]$filter
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $managerOf = $searcher.FindAll()
            $return += [PSCustomObject][ordered]@{
                Test    = 'ManagerOf'
                Status  = $managerOf.Count -eq 0
                Details = @($managerOf | ForEach-Object { $_.Properties['distinguishedname'] })
            }
        } else {
            Write-Warning $strings['DSA_SkipGmsaTests']
        }

        $overallStatus = ($return.Status -eq $false).Count -eq 0
        if (-not $Detailed) { $overallStatus }
        else { $return }
        Write-Verbose -Message (Get-MDIValidationMessage $overallStatus)
    }
}

#endregion

#region Connectivity helper functions

function Test-MDISensorApiConnection {
    [CmdletBinding(DefaultParameterSetName = 'UseCurrentConfiguration')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'BypassConfiguration')]
        [switch] $BypassConfiguration,

        [Parameter(Mandatory = $true, ParameterSetName = 'BypassConfiguration')]
        [string] $SensorApiUrl,

        [Parameter(Mandatory = $false, ParameterSetName = 'BypassConfiguration')]
        [string] $ProxyUrl,

        [Parameter(Mandatory = $false, ParameterSetName = 'BypassConfiguration')]
        [PSCredential] $ProxyCredential
    )

    $sensorApiPath = 'tri/sensor/api/ping'
    $protocol = @{
        80  = 'http'
        443 = 'https'
    }

    if ($PSCmdlet.ParameterSetName -eq 'BypassConfiguration') {

        $params = @{ URI = $SensorApiUrl }
        if ($ProxyUrl) { $params.Add('Proxy', $ProxyUrl) }
        if ($ProxyCredential) { $params.Add('ProxyCredential', $ProxyCredential) }

    } else {
        $sensorConfiguration = Get-MDISensorConfiguration
        if ([string]::IsNullOrEmpty($sensorConfiguration)) {
            Write-Error $strings['Sensor_ErrorReadingSensorConfiguration'] -ErrorAction Stop
        } else {
            $params = @{
                URI = '{0}://{1}' -f $protocol[$sensorConfiguration.WorkspaceApplicationSensorApiWebClientConfigurationServiceEndpoint.Port],
                $sensorConfiguration.WorkspaceApplicationSensorApiWebClientConfigurationServiceEndpoint.Address
            }
            if ($sensorConfiguration.SensorProxyConfiguration.IsProxyEnabled) {
                $params.Add('Proxy', $sensorConfiguration.SensorProxyConfiguration.Url)

                if ($sensorConfiguration.SensorProxyConfiguration.IsAuthenticationProxyEnabled) {
                    $decryptParams = @{
                        CertificateThumbprint = $sensorConfiguration.SensorProxyConfiguration.CertificateThumbprint
                        EncryptedString       = $sensorConfiguration.SensorProxyConfiguration.EncryptedUserPasswordData
                    }
                    $passwd = Get-MDIDecryptedPassword @decryptParams
                    $proxyCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @(
                        $sensorConfiguration.SensorProxyConfiguration.UserName,
                        ($passwd | ConvertTo-SecureString -AsPlainText -Force)
                    )
                    $params.Add('ProxyCredential', $proxyCredential)
                }
            }
        }
    }
    try {
        if ($params.URI -notmatch "$sensorApiPath`$") {
            $params.URI = '{0}/{1}' -f $params.URI, $sensorApiPath
        }
        $response = Invoke-WebRequest @params
        (200 -eq $response.StatusCode)
    } catch {
        Write-Verbose -Message $_.Exception.Message
        $false
    }
}

#endregion

#region Post deployment configuration helper functions

function Use-MDIConfigName {
    param(
        [Parameter(Mandatory)] [string[]] $Configuration,
        [Parameter(Mandatory)] [string[]] $ActionItem
    )
    $ActionItem += 'All'
    @(Compare-Object -ReferenceObject $Configuration -DifferenceObject $ActionItem -ExcludeDifferent -IncludeEqual).Count -gt 0
}

function Get-MDIConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [ValidateSet('Domain', 'LocalMachine')] [string] $Mode,
        [Parameter(Mandatory = $true)] [ValidateSet('AdfsAuditing', 'AdvancedAuditPolicyCAs', 'AdvancedAuditPolicyDCs',
            'CAAuditing', 'ConfigurationContainerAuditing', 'DomainObjectAuditing', 'NTLMAuditing', 'ProcessorPerformance', 'All')] [string[]] $Configuration,
        [Parameter(Mandatory = $false)] [string] $GpoNamePrefix
    )

    $results = @{}
    if (Use-MDIConfigName $Configuration 'AdfsAuditing') {
        $results.Add('AdfsAuditing', (Test-MDIAdfsAuditing -Detailed))
    }
    if (Use-MDIConfigName $Configuration 'AdvancedAuditPolicyCAs') {
        if ($Mode -eq 'LocalMachine') {
            $results.Add('AdvancedAuditPolicyCAs', (Test-MDIAdvancedAuditPolicyCAs -Detailed))
        } else {
            $results.Add('AdvancedAuditPolicyCAs', (Test-MDIAdvancedAuditPolicyCAsGPO -Detailed -GpoNamePrefix $GpoNamePrefix))
        }
    }
    if (Use-MDIConfigName $Configuration 'AdvancedAuditPolicyDCs') {
        if ($Mode -eq 'LocalMachine') {
            $results.Add('AdvancedAuditPolicyDCs', (Test-MDIAdvancedAuditPolicyDCs -Detailed))
        } else {
            $results.Add('AdvancedAuditPolicyDCs', (Test-MDIAdvancedAuditPolicyDCsGPO -Detailed -GpoNamePrefix $GpoNamePrefix))
        }
    }
    if (Use-MDIConfigName $Configuration 'CAAuditing') {
        if ($Mode -eq 'LocalMachine') {
            $results.Add('CAAuditing', (Test-MDICAAuditing -Detailed))
        } else {
            $results.Add('CAAuditing', (Test-MDICAAuditingGPO -Detailed -GpoNamePrefix $GpoNamePrefix))
        }
    }
    if (Use-MDIConfigName $Configuration 'ConfigurationContainerAuditing') {
        $results.Add('ConfigurationContainerAuditing', (Test-MDIConfigurationContainerAuditing -Detailed))
    }
    if (Use-MDIConfigName $Configuration 'DomainObjectAuditing') {
        $results.Add('DomainObjectAuditing', (Test-MDIDomainObjectAuditing -Detailed))
    }
    if (Use-MDIConfigName $Configuration 'NTLMAuditing') {
        if ($Mode -eq 'LocalMachine') {
            $results.Add('NTLMAuditing', (Test-MDINTLMAuditing -Detailed))
        } else {
            $results.Add('NTLMAuditing', (Test-MDINTLMAuditingGPO -Detailed -GpoNamePrefix $GpoNamePrefix))
        }
    }
    if (Use-MDIConfigName $Configuration 'ProcessorPerformance') {
        if ($Mode -eq 'LocalMachine') {
            $results.Add('ProcessorPerformance', (Test-MDIProcessorPerformance -Detailed))
        } else {
            $results.Add('ProcessorPerformance', (Test-MDIProcessorPerformanceGPO -Detailed -GpoNamePrefix $GpoNamePrefix))
        }
    }

    if ($Configuration -contains 'All') {
        $Configuration += $results.GetEnumerator() | Select-Object -ExpandProperty Name
    }
    $Configuration | Select-Object -Unique | Where-Object { $_ -ne 'All' } | ForEach-Object {
        [PSCustomObject]@{
            Configuration = $_
            Mode          = $Mode
            Status        = $results[$_].Status
            Details       = $results[$_].Details
        }
    }
}

function Test-MDIConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [ValidateSet('Domain', 'LocalMachine')] [string] $Mode,
        [Parameter(Mandatory = $true)] [ValidateSet('AdfsAuditing', 'AdvancedAuditPolicyCAs', 'AdvancedAuditPolicyDCs',
            'CAAuditing', 'ConfigurationContainerAuditing', 'DomainObjectAuditing', 'NTLMAuditing', 'ProcessorPerformance', 'All')] [string[]] $Configuration,
        [Parameter(Mandatory = $false)] [string] $GpoNamePrefix
    )

    $results = if ($Mode -eq 'Domain') {
        Get-MDIConfiguration -Configuration $Configuration -Mode Domain -GpoNamePrefix $GpoNamePrefix
    } else {
        Get-MDIConfiguration -Configuration $Configuration -Mode LocalMachine
    }

    if ('All' -eq $Configuration) {
        @($results | Where-Object { $_.Status -eq $false }).Count -eq 0
    } else {
        $results.Status
    }
}

function Set-MDIConfiguration {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)] [ValidateSet('Domain', 'LocalMachine')] [string] $Mode,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)] [ValidateSet('AdfsAuditing', 'AdvancedAuditPolicyCAs', 'AdvancedAuditPolicyDCs',
            'CAAuditing', 'ConfigurationContainerAuditing', 'DomainObjectAuditing', 'NTLMAuditing', 'ProcessorPerformance', 'All')] [string[]] $Configuration,
        [Parameter(Mandatory = $false)] [string] $GpoNamePrefix,
        [Parameter(Mandatory = $false)] [switch] $CreateGpoDisabled,
        [Parameter(Mandatory = $false)] [switch] $SkipGpoLink,
        [Parameter(Mandatory = $false)] [switch] $Force
    )

    Process {
        foreach ($config in $Configuration) {

            Write-Verbose ($strings['Configuration_Set'] -f $config)
            if (Use-MDIConfigName $config 'AdfsAuditing') { Set-MDIAdfsAuditing }

            if (Use-MDIConfigName $config 'AdvancedAuditPolicyCAs') {
                if ($Mode -eq 'LocalMachine') {
                    Set-MDIAdvancedAuditPolicyCAs
                } else {
                    Set-MDIAdvancedAuditPolicyCAsGPO -CreateGpoDisabled:$CreateGpoDisabled -SkipGpoLink:$SkipGpoLink -GpoNamePrefix $GpoNamePrefix
                }
            }

            if (Use-MDIConfigName $config 'AdvancedAuditPolicyDCs') {
                if ($Mode -eq 'LocalMachine') {
                    Set-MDIAdvancedAuditPolicyDCs
                } else {
                    Set-MDIAdvancedAuditPolicyDCsGPO -CreateGpoDisabled:$CreateGpoDisabled -SkipGpoLink:$SkipGpoLink -GpoNamePrefix $GpoNamePrefix
                }
            }

            if (Use-MDIConfigName $config 'CAAuditing') {
                if ($Mode -eq 'LocalMachine') {
                    Set-MDICAAuditing
                } else {
                    Set-MDICAAuditingGPO -CreateGpoDisabled:$CreateGpoDisabled -SkipGpoLink:$SkipGpoLink -GpoNamePrefix $GpoNamePrefix
                }
            }

            if (Use-MDIConfigName $config 'ConfigurationContainerAuditing') { Set-MDIConfigurationContainerAuditing -Force:$Force }

            if (Use-MDIConfigName $config 'DomainObjectAuditing') { Set-MDIDomainObjectAuditing }

            if (Use-MDIConfigName $config 'NTLMAuditing') {
                if ($Mode -eq 'LocalMachine') {
                    Set-MDINTLMAuditing
                } else {
                    Set-MDINTLMAuditingGPO -CreateGpoDisabled:$CreateGpoDisabled -SkipGpoLink:$SkipGpoLink -GpoNamePrefix $GpoNamePrefix
                }
            }

            if (Use-MDIConfigName $config 'ProcessorPerformance') {
                if ($Mode -eq 'LocalMachine') {
                    Set-MDIProcessorPerformance
                } else {
                    Set-MDIProcessorPerformanceGPO -CreateGpoDisabled:$CreateGpoDisabled -SkipGpoLink:$SkipGpoLink -GpoNamePrefix $GpoNamePrefix
                }
            }
        }
    }
}

function New-MDIConfigurationReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory = $false)] [ValidateSet('Domain', 'LocalMachine')] [string] $Mode = 'Domain',
        [Parameter(Mandatory = $false)] [string] $GpoNamePrefix,
        [switch] $OpenHtmlReport
    )
    if (-not(Test-Path -Path $Path)) { [void](New-Item -Path $Path -ItemType Directory -Force -ErrorAction SilentlyContinue) }

    $reportTarget = if ($Mode -eq 'Domain') { $env:USERDNSDOMAIN } else { '{0}.{1}' -f $env:COMPUTERNAME, $env:USERDNSDOMAIN }
    $configurations = Get-MDIConfiguration -Configuration All -Mode $Mode -GpoNamePrefix $GpoNamePrefix

    $jsonReportFile = Resolve-MDIPath -Path (
        Join-Path -Path $Path -ChildPath ('MDI-configuration-report-{0}.json' -f $reportTarget))
    $htmlReportFile = Resolve-MDIPath -Path (
        Join-Path -Path $Path -ChildPath ('MDI-configuration-report-{0}.html' -f $reportTarget))

    $css = @'
<style>
body { font-family: Arial, sans-serif, 'Open Sans'; }
table { border-collapse: collapse; }
td, th { border: 1px solid #aeb0b5; padding: 5px; text-align: left; vertical-align: middle; }
tr:nth-child(even) { background-color: #f2f2f2; }
th { padding: 8px; text-align: left; background-color: #e4e2e0; color: #212121; }
.red    {background-color: #cd2026; color: #ffffff; }
.green  {background-color: #4aa564; color: #212121; }
ul { list-style: none; padding-left: 0.5em;}
</style>
'@
    $colors = @{$true = 'green'; $false = 'red' }
    $status = @{$true = $strings['DomainReport_StatusPass']; $false = $strings['DomainReport_StatusFail'] }
    $tblHeader = '<tr><th>{0}</th><th>{1}</th><th>{2}</th></tr>' -f $strings['DomainReport_Configuration'],
    $strings['DomainReport_Status'], $strings['DomainReport_CommandToFix']
    $tblContent = @($configurations | Sort-Object Configuration | ForEach-Object {
            $gpoPrefixIfUsed = if ([string]::IsNullOrEmpty($GpoNamePrefix)) { '' } else { " -GpoNamePrefix $GpoNamePrefix" }
            "<tr><td><a href='https://aka.ms/mdi/{0}'>{0}</a></td><td class='{1}'>{2}</td><td>{3}{0}{4}</td></tr>" -f `
                $_.Configuration, $colors[$_.Status], $status[$_.Status], 'Set-MDIConfiguration -Mode Domain -Configuration ', $gpoPrefixIfUsed
        }) -join [environment]::NewLine

    $htmlContent = @'
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>{0}</head><body>
<h2>{1}</h2>
{2}
<br/><br/>
<table>
{3}
{4}
</table>
<br/>
<hr>
<ul>
<li>{5}</li>
</ul>
<hr>
<br/>{6} <a href='{7}'>{7}</a><br/>
<br/>{8}
'@ -f $css, ($strings['DomainReport_Title'] -f $reportTarget), $strings['DomainReport_Subtitle'],
    $tblHeader, $tblContent, $strings['DomainReport_NoteMessage'], $strings['DomainReport_DetailsMessage'],
    $jsonReportFile, ($strings['DomainReport_CreatedBy'] -f "<a href='https://aka.ms/mdi/psmodule'>DefenderForIdentity</a>")

    Write-Verbose ('{0}: {1}' -f $strings['DomainReport_JsonMessage'], $jsonReportFile)
    $configurations | ConvertTo-Json -Depth 5 | Format-Json | Out-File -FilePath $jsonReportFile -Force -Encoding utf8

    Write-Verbose ('{0}: {1}' -f $strings['DomainReport_HtmlMessage'], $htmlReportFile)
    $htmlContent | Out-File -FilePath $htmlReportFile -Force -Encoding utf8

    $reportPath = (Resolve-Path -Path $htmlReportFile).Path
    if ($OpenHtmlReport) { Invoke-Item -Path $reportPath }
}

#endregion
# SIG # Begin signature block
# MIInwgYJKoZIhvcNAQcCoIInszCCJ68CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCa0by0+BLeQfLB
# ShK29MiB+JJ3IBsqOIPE1R1OgmvWqqCCDXYwggX0MIID3KADAgECAhMzAAADrzBA
# DkyjTQVBAAAAAAOvMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMxMTE2MTkwOTAwWhcNMjQxMTE0MTkwOTAwWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDOS8s1ra6f0YGtg0OhEaQa/t3Q+q1MEHhWJhqQVuO5amYXQpy8MDPNoJYk+FWA
# hePP5LxwcSge5aen+f5Q6WNPd6EDxGzotvVpNi5ve0H97S3F7C/axDfKxyNh21MG
# 0W8Sb0vxi/vorcLHOL9i+t2D6yvvDzLlEefUCbQV/zGCBjXGlYJcUj6RAzXyeNAN
# xSpKXAGd7Fh+ocGHPPphcD9LQTOJgG7Y7aYztHqBLJiQQ4eAgZNU4ac6+8LnEGAL
# go1ydC5BJEuJQjYKbNTy959HrKSu7LO3Ws0w8jw6pYdC1IMpdTkk2puTgY2PDNzB
# tLM4evG7FYer3WX+8t1UMYNTAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQURxxxNPIEPGSO8kqz+bgCAQWGXsEw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMTgyNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAISxFt/zR2frTFPB45Yd
# mhZpB2nNJoOoi+qlgcTlnO4QwlYN1w/vYwbDy/oFJolD5r6FMJd0RGcgEM8q9TgQ
# 2OC7gQEmhweVJ7yuKJlQBH7P7Pg5RiqgV3cSonJ+OM4kFHbP3gPLiyzssSQdRuPY
# 1mIWoGg9i7Y4ZC8ST7WhpSyc0pns2XsUe1XsIjaUcGu7zd7gg97eCUiLRdVklPmp
# XobH9CEAWakRUGNICYN2AgjhRTC4j3KJfqMkU04R6Toyh4/Toswm1uoDcGr5laYn
# TfcX3u5WnJqJLhuPe8Uj9kGAOcyo0O1mNwDa+LhFEzB6CB32+wfJMumfr6degvLT
# e8x55urQLeTjimBQgS49BSUkhFN7ois3cZyNpnrMca5AZaC7pLI72vuqSsSlLalG
# OcZmPHZGYJqZ0BacN274OZ80Q8B11iNokns9Od348bMb5Z4fihxaBWebl8kWEi2O
# PvQImOAeq3nt7UWJBzJYLAGEpfasaA3ZQgIcEXdD+uwo6ymMzDY6UamFOfYqYWXk
# ntxDGu7ngD2ugKUuccYKJJRiiz+LAUcj90BVcSHRLQop9N8zoALr/1sJuwPrVAtx
# HNEgSW+AKBqIxYWM4Ev32l6agSUAezLMbq5f3d8x9qzT031jMDT+sUAoCw0M5wVt
# CUQcqINPuYjbS1WgJyZIiEkBMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGaIwghmeAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAAOvMEAOTKNNBUEAAAAAA68wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINCWB+Ip8dUfgSroJkCwRkPk
# rsC07J+gw7qh2Clg4CzeMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAg0TtQQ5HDnyG6z+tz0ehqP4diSk/8/WfWUde4MvdoLxxLo2Zr2PcVHxI
# pNAuh+Z74E9WPt2OZA+jDDYjt7ThdQvh4vqni21Th4aTyCeTbrCasIekEMLVW0tb
# 82Q/FcAyySAktvYtl81E36/7ampw1rRk1FwOC7LtAIli4tULtRn23DhJlaSjCx5P
# +sEMjpSiAvzSnkBF6/8R11XZJikwtu34SPGXeL783Q9KsDbnG1EoUY2lDBP+LuMV
# e4yr9H83iQoqCX9/Q89iZeUUdM8UMjkTNtUIHBPuQr2i6/JGI4trzYKAaPZFKPJG
# VIQvLDRMgGHjSWR0iBd9ZykFoAwNZqGCFywwghcoBgorBgEEAYI3AwMBMYIXGDCC
# FxQGCSqGSIb3DQEHAqCCFwUwghcBAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsq
# hkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCA97exOaQX+q/wrHHHiO3oaOO0ITW5DmiSwcTjhtHcxNAIGZYM0bihF
# GBMyMDI0MDExNjE2Mjc1OS43NThaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OkZDNDEtNEJENC1EMjIwMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloIIRezCCBycwggUPoAMCAQICEzMAAAHimZmV8dzjIOsAAQAAAeIwDQYJ
# KoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjMx
# MDEyMTkwNzI1WhcNMjUwMTEwMTkwNzI1WjCB0jELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3Bl
# cmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpGQzQxLTRC
# RDQtRDIyMDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALVjtZhV+kFmb8cKQpg2mzis
# DlRI978Gb2amGvbAmCd04JVGeTe/QGzM8KbQrMDol7DC7jS03JkcrPsWi9WpVwsI
# ckRQ8AkX1idBG9HhyCspAavfuvz55khl7brPQx7H99UJbsE3wMmpmJasPWpgF05z
# ZlvpWQDULDcIYyl5lXI4HVZ5N6MSxWO8zwWr4r9xkMmUXs7ICxDJr5a39SSePAJR
# IyznaIc0WzZ6MFcTRzLLNyPBE4KrVv1LFd96FNxAzwnetSePg88EmRezr2T3HTFE
# lneJXyQYd6YQ7eCIc7yllWoY03CEg9ghorp9qUKcBUfFcS4XElf3GSERnlzJsK7s
# /ZGPU4daHT2jWGoYha2QCOmkgjOmBFCqQFFwFmsPrZj4eQszYxq4c4HqPnUu4hT4
# aqpvUZ3qIOXbdyU42pNL93cn0rPTTleOUsOQbgvlRdthFCBepxfb6nbsp3fcZaPB
# fTbtXVa8nLQuMCBqyfsebuqnbwj+lHQfqKpivpyd7KCWACoj78XUwYqy1HyYnStT
# me4T9vK6u2O/KThfROeJHiSg44ymFj+34IcFEhPogaKvNNsTVm4QbqphCyknrwBy
# qorBCLH6bllRtJMJwmu7GRdTQsIx2HMKqphEtpSm1z3ufASdPrgPhsQIRFkHZGui
# hL1Jjj4Lu3CbAmha0lOrAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQURIQOEdq+7Qds
# lptJiCRNpXgJ2gUwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYD
# VR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# cmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwG
# CCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIw
# MjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcD
# CDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBAORURDGrVRTbnulf
# sg2cTsyyh7YXvhVU7NZMkITAQYsFEPVgvSviCylr5ap3ka76Yz0t/6lxuczI6w7t
# Xq8n4WxUUgcj5wAhnNorhnD8ljYqbck37fggYK3+wEwLhP1PGC5tvXK0xYomU1nU
# +lXOy9ZRnShI/HZdFrw2srgtsbWow9OMuADS5lg7okrXa2daCOGnxuaD1IO+65E7
# qv2O0W0sGj7AWdOjNdpexPrspL2KEcOMeJVmkk/O0ganhFzzHAnWjtNWneU11WQ6
# Bxv8OpN1fY9wzQoiycgvOOJM93od55EGeXxfF8bofLVlUE3zIikoSed+8s61NDP+
# x9RMya2mwK/Ys1xdvDlZTHndIKssfmu3vu/a+BFf2uIoycVTvBQpv/drRJD68eo4
# 01mkCRFkmy/+BmQlRrx2rapqAu5k0Nev+iUdBUKmX/iOaKZ75vuQg7hCiBA5xIm5
# ZIXDSlX47wwFar3/BgTwntMq9ra6QRAeS/o/uYWkmvqvE8Aq38QmKgTiBnWSS/uV
# PcaHEyArnyFh5G+qeCGmL44MfEnFEhxc3saPmXhe6MhSgCIGJUZDA7336nQD8fn4
# y6534Lel+LuT5F5bFt0mLwd+H5GxGzObZmm/c3pEWtHv1ug7dS/Dfrcd1sn2E4gk
# 4W1L1jdRBbK9xwkMmwY+CHZeMSvBMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJ
# mQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNh
# dGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1
# WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjK
# NVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhg
# fWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJp
# rx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/d
# vI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka9
# 7aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKR
# Hh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9itu
# qBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyO
# ArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItb
# oKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6
# bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6t
# AgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQW
# BBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacb
# UzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYz
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnku
# aHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIA
# QwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2
# VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwu
# bWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEw
# LTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYt
# MjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/q
# XBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6
# U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVt
# I1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis
# 9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTp
# kbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0
# sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138e
# W0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJ
# sWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7
# Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0
# dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQ
# tB1VM1izoXBm8qGCAtcwggJAAgEBMIIBAKGB2KSB1TCB0jELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxh
# bmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpG
# QzQxLTRCRDQtRDIyMDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaIjCgEBMAcGBSsOAwIaAxUAFpuZafp0bnpJdIhfiB1d8pTohm+ggYMwgYCk
# fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIF
# AOlQoEIwIhgPMjAyNDAxMTYxNDI3MTRaGA8yMDI0MDExNzE0MjcxNFowdzA9Bgor
# BgEEAYRZCgQBMS8wLTAKAgUA6VCgQgIBADAKAgEAAgIKLAIB/zAHAgEAAgIRyDAK
# AgUA6VHxwgIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIB
# AAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAIBj2sMdZAA/09lo
# V3xOBfIdoW9QMJK5wCyKpO60cg3tVApa1jRDYSAxVB0t2L8w5Tkipzjvulxeqbwu
# R96pBGWzY9BhXrYt0hMJbpUPH5ZCjKrNCRgvtKy0ULFDynD6R25sMxDrRsxF6Kwk
# o43UOuft5pZ0EM9hJ3awZRxlvjflMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTACEzMAAAHimZmV8dzjIOsAAQAAAeIwDQYJYIZIAWUD
# BAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0B
# CQQxIgQgEYgQ2jMSCMcTNgZoZNYhyn0XEJWjb58YEtWxBC54GyswgfoGCyqGSIb3
# DQEJEAIvMYHqMIHnMIHkMIG9BCAriSpKEP0muMbBUETODoL4d5LU6I/bjucIZkOJ
# CI9//zCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB
# 4pmZlfHc4yDrAAEAAAHiMCIEIAaqhv1DLSsM/NeHlcOS4Olpo7LvVZMWkAvWmOTb
# aw50MA0GCSqGSIb3DQEBCwUABIICAHd/iL9+cVOc4YJcKLJx836AHpyoH+VX0IAW
# BSGI1Pu/P1RMFWq/Pxcb3FrpUJmuVJCaDoEGSt+WhLl7WLUOGk8aBtcqPIjPNaUe
# TEeTPiAZOYvDvvLvRk5+qP54S1DPz2T5fxJY3kdzUeQ3bsF1jV5mFBpQDShrCnXj
# riuIajReflIKsv6t4WuayfvlZvB5kUjKrvE9z6zFWkFUuOSBIsFhK1flHXSQqd0G
# JaJMInulSIq9/8IOGezGxr1KPu/4aVbcrPHO1b96EKkCAZDUsO+3y3rIB7jTkIlY
# Hs7VnwuWe1Y+62PFpW1JVYpqHi7yLSSgOThlYeE5otRWkaNUH3CuwSTyyXnezlwy
# pyDT45haLSdADtsB7nQs/8DvkHI0o1hDf+FZ2pPPdWQ92iVJhIWgyfgZQLkCDlaX
# nP3Yu8DwAFodzpXHfWW1TvOQp1Jlc5y5QfMA5YDJdoqjwR7IMazRPv8sQDsZI18Y
# UrOxaRrmqoaxKrT+7ZL3cRIQsrcxM+E3jn/aWjt0i/B5J6DKhx945+z+calc9OZq
# pUv/CRju1WZKzvFc21D1A179qRgrNsUFEvI0j3evUGLVsZ44dyphuf+e+iI+UGst
# oAwD5IG99QuQTirt8wMPbCaFjbADKSillcfg2gsM+unFbV0H8g561Hn0oo1GkO/H
# tyUKUW5J
# SIG # End signature block
