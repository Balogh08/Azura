param (        
     [string]$sqlPackageArguments     
    )

$ErrorActionPreference = 'Stop'
Write-Verbose "Entering script Microsoft.TeamFoundation.DistributedTask.Task.Deployment.Sql.ps1" -Verbose

function Get-SqlPackageOnTargetMachine
{
    try
    {
        $sqlDacPath, $sqlVersion = Locate-HighestVersionSqlPackageWithSql
        $sqlVersionNumber = [decimal] $sqlVersion
    }
    catch [System.Exception]
    {
        Write-Verbose ("Failed to get Dac Framework (installed with SQL Server) location with exception: " + $_.Exception.Message) -verbose
        $sqlVersionNumber = 0
    }

	try
    {
        $sqlMsiDacPath, $sqlMsiVersion = Locate-HighestVersionSqlPackageWithDacMsi
        $sqlMsiVersionNumber = [decimal] $sqlMsiVersion
    }
    catch [System.Exception]
    {
        Write-Verbose ("Failed to get Dac Framework (installed with DAC Framework) location with exception: " + $_.Exception.Message) -verbose
        $sqlMsiVersionNumber = 0
    }

    try
    {
        $vsDacPath, $vsVersion = Locate-HighestVersionSqlPackageInVS
        $vsVersionNumber = [decimal] $vsVersion
    }
    catch [System.Exception]
    {
        Write-Verbose ("Failed to get Dac Framework (installed with Visual Studio) location with exception: " + $_.Exception.Message) -verbose
        $vsVersionNumber = 0
    }

    if (($vsVersionNumber -ge $sqlVersionNumber) -and ($vsVersionNumber -ge $sqlMsiVersionNumber))
    {
        $dacPath = $vsDacPath
    }
	elseif ($sqlVersionNumber -ge $sqlMsiVersionNumber)
    {
        $dacPath = $sqlDacPath
    }
    else
    {
        $dacPath = $sqlMsiDacPath
    }

    if ($dacPath -eq $null)
    {
        throw  "Unable to find the location of Dac Framework (SqlPackage.exe) from registry on machine $env:COMPUTERNAME"
    }
    else
    {
        return $dacPath
    }
}

function Get-RegistryValueIgnoreError
{
    param
    (
        [parameter(Mandatory = $true)]
        [Microsoft.Win32.RegistryHive]
        $RegistryHive,

        [parameter(Mandatory = $true)]
        [System.String]
        $Key,

        [parameter(Mandatory = $true)]
        [System.String]
        $Value,

        [parameter(Mandatory = $true)]
        [Microsoft.Win32.RegistryView]
        $RegistryView
    )

    try
    {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($RegistryHive, $RegistryView)
        $subKey =  $baseKey.OpenSubKey($Key)
        if($subKey -ne $null)
        {
            return $subKey.GetValue($Value)
        }
    }
    catch
    {
    }
    return $null
}

function Get-SubKeysInFloatFormat($keys)
{
    $targetKeys = @() 
        foreach ($key in $keys) 
        {		  
            try {
                $targetKeys += [decimal] $key
            }
            catch {}
        }
   
    $targetKeys    
}

function Get-SqlPackageForSqlVersion([int] $majorVersion, [bool] $wow6432Node)
{
    $sqlInstallRootRegKey = "SOFTWARE", "Microsoft", "Microsoft SQL Server", "$majorVersion" -join [System.IO.Path]::DirectorySeparatorChar

    if ($wow6432Node -eq $true)
    {
        $sqlInstallRootPath = Get-RegistryValueIgnoreError LocalMachine "$sqlInstallRootRegKey" "VerSpecificRootDir" Registry64
    }
    else
    {        
        $sqlInstallRootPath = Get-RegistryValueIgnoreError LocalMachine "$sqlInstallRootRegKey" "VerSpecificRootDir" Registry32
    }
    
    if ($sqlInstallRootPath -eq $null)
    {
        return $null
    }
    
    Write-Verbose -verbose "Sql Version Specific Root Dir for version $majorVersion as read from registry: $sqlInstallRootPath"    
        
    $DacInstallPath = [System.IO.Path]::Combine($sqlInstallRootPath, "Dac", "bin", "SqlPackage.exe")

    if (Test-Path $DacInstallPath)
    {
        Write-Verbose -verbose "Dac Framework installed with SQL Version $majorVersion found at $DacInstallPath on machine $env:COMPUTERNAME"
        return $DacInstallPath
    }
    else
    {
        return $null
    }
}

function Locate-HighestVersionSqlPackageWithSql()
{
    $sqlRegKey = "HKLM:", "SOFTWARE", "Wow6432Node", "Microsoft", "Microsoft SQL Server"-join [System.IO.Path]::DirectorySeparatorChar
    $sqlRegKey64 = "HKLM:", "SOFTWARE", "Microsoft", "Microsoft SQL Server"-join [System.IO.Path]::DirectorySeparatorChar

    if (-not (Test-Path $sqlRegKey))
    {
        $sqlRegKey = $sqlRegKey64
    }

    if (-not (Test-Path $sqlRegKey))
    {
        return $null, 0
    }

    $keys = Get-Item $sqlRegKey | %{$_.GetSubKeyNames()} 
    $versions = Get-SubKeysInFloatFormat $keys | Sort-Object -Descending

    Write-Verbose -verbose "Sql Versions installed on machine $env:COMPUTERNAME as read from registry: $versions"        

    foreach ($majorVersion in $versions) 
    {
        $DacInstallPathWow6432Node = Get-SqlPackageForSqlVersion $majorVersion $true
        $DacInstallPath = Get-SqlPackageForSqlVersion $majorVersion $false

        if ($DacInstallPathWow6432Node -ne $null)
        {            
            return $DacInstallPathWow6432Node, $majorVersion
        }
        elseif ($DacInstallPath -ne $null)
        {
            return $DacInstallPath, $majorVersion
        }
    }

    Write-Verbose -verbose "Dac Framework (installed with SQL) not found on machine $env:COMPUTERNAME"      

    return $null, 0
}

function Locate-HighestVersionSqlPackageWithDacMsi()
{
    $sqlRegKeyWow = "HKLM:", "SOFTWARE", "Wow6432Node", "Microsoft", "Microsoft SQL Server", "DACFramework", "CurrentVersion" -join [System.IO.Path]::DirectorySeparatorChar
    $sqlRegKey = "HKLM:", "SOFTWARE", "Microsoft", "Microsoft SQL Server", "DACFramework", "CurrentVersion" -join [System.IO.Path]::DirectorySeparatorChar

	$sqlKey = "SOFTWARE", "Microsoft", "Microsoft SQL Server", "DACFramework", "CurrentVersion" -join [System.IO.Path]::DirectorySeparatorChar
	
    if (Test-Path $sqlRegKey)
    {
        $dacVersion = Get-RegistryValueIgnoreError LocalMachine "$sqlKey" "Version" Registry64
        $majorVersion = $dacVersion.Substring(0, $dacVersion.IndexOf(".")) + "0"
    }
    
    if (Test-Path $sqlRegKeyWow)
    {
        $dacVersionX86 = Get-RegistryValueIgnoreError LocalMachine "$sqlKey" "Version" Registry32
        $majorVersionX86 = $dacVersionX86.Substring(0, $dacVersionX86.IndexOf(".")) + "0"
    }

	if ((-not($dacVersion)) -and (-not($dacVersionX86)))
	{
	    Write-Verbose -verbose "Dac Framework (installed with DAC Framework) not found on machine $env:COMPUTERNAME"   
	    return $null, 0
	}    

    if ($majorVersionX86 -gt $majorVersion)
    {
        $majorVersion = $majorVersionX86
    }

	$dacRelativePath = "Microsoft SQL Server", "$majorVersion", "DAC", "bin", "SqlPackage.exe" -join [System.IO.Path]::DirectorySeparatorChar
	$programFiles = $env:ProgramFiles
	$programFilesX86 = "${env:ProgramFiles(x86)}"

	if (-not ($programFilesX86 -eq $null))
	{
	    $dacPath = $programFilesX86, $dacRelativePath -join [System.IO.Path]::DirectorySeparatorChar

		if (Test-Path("$dacPath"))
		{
            Write-Verbose -verbose "Dac Framework (installed with DAC Framework Msi) found on machine $env:COMPUTERNAME at $dacPath"  
            return $dacPath, $majorVersion
		}		
	}

	if (-not ($programFiles -eq $null))
	{
	    $dacPath = $programFiles, $dacRelativePath -join [System.IO.Path]::DirectorySeparatorChar

		if (Test-Path($dacPath))
		{
            Write-Verbose -verbose "Dac Framework (installed with DAC Framework Msi) found on machine $env:COMPUTERNAME at $dacPath"  
            return $dacPath, $majorVersion
		}		
	}
    
    return $null, 0
}

function Locate-SqlPackageInVS([string] $version)
{
    $vsRegKeyForVersion = "SOFTWARE", "Microsoft", "VisualStudio", $version -join [System.IO.Path]::DirectorySeparatorChar

    $vsInstallDir = Get-RegistryValueIgnoreError LocalMachine "$vsRegKeyForVersion" "InstallDir" Registry64

    if ($vsInstallDir -eq $null)
    {
        $vsInstallDir = Get-RegistryValueIgnoreError LocalMachine "$vsRegKeyForVersion"  "InstallDir" Registry32
    } 

    if ($vsInstallDir)
    {
        Write-Verbose -verbose "Visual Studio install location: $vsInstallDir" 

        $dacExtensionPath = [System.IO.Path]::Combine("Extensions", "Microsoft", "SQLDB", "DAC")
        $dacParentDir = [System.IO.Path]::Combine($vsInstallDir, $dacExtensionPath)

        if (Test-Path $dacParentDir)
        {
            $dacVersionDirs = Get-ChildItem $dacParentDir | Sort-Object @{e={$_.Name -as [int]}} -Descending

            foreach ($dacVersionDir in $dacVersionDirs) 
            {
                $dacVersion = $dacVersionDir.Name
                $dacFullPath = [System.IO.Path]::Combine($dacVersionDir.FullName, "SqlPackage.exe")

                if(Test-Path $dacFullPath -pathtype leaf)
                {
                    Write-Verbose -verbose "Dac Framework installed with Visual Studio found at $dacFullPath on machine $env:COMPUTERNAME"
                    return $dacFullPath, $dacVersion
                }
                else
                {
                    Write-Verbose -verbose "Unable to find Dac framework installed with Visual Studio at $($dacVersionDir.FullName) on machine $env:COMPUTERNAME"
                }
            }
        }
    }

    return $null, 0
}

function Locate-HighestVersionSqlPackageInVS()
{
    $vsRegKey = "HKLM:", "SOFTWARE", "Wow6432Node", "Microsoft", "VisualStudio" -join [System.IO.Path]::DirectorySeparatorChar
    $vsRegKey64 = "HKLM:", "SOFTWARE", "Microsoft", "VisualStudio" -join [System.IO.Path]::DirectorySeparatorChar

    if (-not (Test-Path $vsRegKey))
    {
        $vsRegKey = $vsRegKey64
    }

    if (-not (Test-Path $vsRegKey))
    {
        Write-Verbose -verbose "Visual Studio not found on machine $env:COMPUTERNAME"     
        return $null, 0
    }

    $keys = Get-Item $vsRegKey | %{$_.GetSubKeyNames()} 
    $versions = Get-SubKeysInFloatFormat $keys | Sort-Object -Descending 

    Write-Verbose -verbose "Visual Studio versions found on machine $env:COMPUTERNAME as read from registry: $versions"        

    foreach ($majorVersion in $versions)
    {
        $dacFullPath, $dacVersion = Locate-SqlPackageInVS $majorVersion

        if ($dacFullPath -ne $null)
        {
            return $dacFullPath, $dacVersion
        }
    }

    Write-Verbose -verbose "Dac Framework (installed with Visual Studio) not found on machine $env:COMPUTERNAME"    

    return $null, 0
}

$ASTERISK_PASSWORD = "********"

$indexOfTargetPassword = $sqlPackageArguments.IndexOf("/TargetPassword");
if( $indexOfTargetPassword -ge 0 )
{
    $indexOfFirstQuote = $sqlPackageArguments.IndexOf("'",$indexOfTargetPassword);
    $indexOfSecondQuote = $sqlPackageArguments.IndexOf("'",$indexOfFirstQuote+1);
    $sqlPackageArgumentsToBeLogged = $sqlPackageArguments.Substring(0,$indexOfFirstQuote+1) + $ASTERISK_PASSWORD + $sqlPackageArguments.Substring($indexOfSecondQuote) 
}
else
{
    $sqlPackageArgumentsToBeLogged = $sqlPackageArguments
}
Write-Verbose "sqlPackageArguments = $sqlPackageArgumentsToBeLogged" -Verbose

$sqlPackage = Get-SqlPackageOnTargetMachine

$sqlPackageArguments = $sqlPackageArguments.Trim('"', ' ')

$command = "`"$sqlPackage`" $sqlPackageArguments"

$command = $command.Replace("'", "`"")

$indexOfTargetPassword = $command.IndexOf("/TargetPassword");
if( $indexOfTargetPassword -ge 0 )
{
    $indexOfFirstQuote = $command.IndexOf('"',$indexOfTargetPassword);
    $indexOfSecondQuote = $command.IndexOf('"',$indexOfFirstQuote+1);
    $commandToBeLogged = $command.Substring(0,$indexOfFirstQuote+1) + $ASTERISK_PASSWORD + $command.Substring($indexOfSecondQuote) 
}
else
{
    $commandToBeLogged = $command
}
Write-Verbose "Executing : $commandToBeLogged" -Verbose

$PowershellVersion5 = "5"
$ErrorActionPreference = 'Continue'

if ($PSVersionTable.PSVersion.Major -ge $PowershellVersion5)
{
    cmd.exe /c "$command"
}
else
{
    cmd.exe /c "`"$command`""
}

$ErrorActionPreference = 'Stop'

# SIG # Begin signature block
# MIIjhgYJKoZIhvcNAQcCoIIjdzCCI3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCASfteqeV7jt1Fl
# qrQmDCdwFY9iW8VvbialeekQtAqBEKCCDYEwggX/MIID56ADAgECAhMzAAABA14l
# HJkfox64AAAAAAEDMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMTgwNzEyMjAwODQ4WhcNMTkwNzI2MjAwODQ4WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDRlHY25oarNv5p+UZ8i4hQy5Bwf7BVqSQdfjnnBZ8PrHuXss5zCvvUmyRcFrU5
# 3Rt+M2wR/Dsm85iqXVNrqsPsE7jS789Xf8xly69NLjKxVitONAeJ/mkhvT5E+94S
# nYW/fHaGfXKxdpth5opkTEbOttU6jHeTd2chnLZaBl5HhvU80QnKDT3NsumhUHjR
# hIjiATwi/K+WCMxdmcDt66VamJL1yEBOanOv3uN0etNfRpe84mcod5mswQ4xFo8A
# DwH+S15UD8rEZT8K46NG2/YsAzoZvmgFFpzmfzS/p4eNZTkmyWPU78XdvSX+/Sj0
# NIZ5rCrVXzCRO+QUauuxygQjAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUR77Ay+GmP/1l1jjyA123r3f3QP8w
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDM3OTY1MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAn/XJ
# Uw0/DSbsokTYDdGfY5YGSz8eXMUzo6TDbK8fwAG662XsnjMQD6esW9S9kGEX5zHn
# wya0rPUn00iThoj+EjWRZCLRay07qCwVlCnSN5bmNf8MzsgGFhaeJLHiOfluDnjY
# DBu2KWAndjQkm925l3XLATutghIWIoCJFYS7mFAgsBcmhkmvzn1FFUM0ls+BXBgs
# 1JPyZ6vic8g9o838Mh5gHOmwGzD7LLsHLpaEk0UoVFzNlv2g24HYtjDKQ7HzSMCy
# RhxdXnYqWJ/U7vL0+khMtWGLsIxB6aq4nZD0/2pCD7k+6Q7slPyNgLt44yOneFuy
# bR/5WcF9ttE5yXnggxxgCto9sNHtNr9FB+kbNm7lPTsFA6fUpyUSj+Z2oxOzRVpD
# MYLa2ISuubAfdfX2HX1RETcn6LU1hHH3V6qu+olxyZjSnlpkdr6Mw30VapHxFPTy
# 2TUxuNty+rR1yIibar+YRcdmstf/zpKQdeTr5obSyBvbJ8BblW9Jb1hdaSreU0v4
# 6Mp79mwV+QMZDxGFqk+av6pX3WDG9XEg9FGomsrp0es0Rz11+iLsVT9qGTlrEOla
# P470I3gwsvKmOMs1jaqYWSRAuDpnpAdfoP7YO0kT+wzh7Qttg1DO8H8+4NkI6Iwh
# SkHC3uuOW+4Dwx1ubuZUNWZncnwa6lL2IsRyP64wggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVWzCCFVcCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAQNeJRyZH6MeuAAAAAABAzAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgk+0i4u7t
# lVNENchkNwonv+nMLJrr66liJU0hd8m9nQQwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQA0zRtxXxO2hfZs9W8SEAEbyD/R3yIL6rY+PiG1cqtc
# 6a5In9Ejf9o7NGvWG9mb727fE0IV9PFhRe8j9Ax4tCeccKz7KdbI7P9vKDErdmCu
# EWQTL3cl8bhTXY4kgbBN4Zd3VaoP/GCFrHDiKuEB4hSCHc2Tab5jBPRZiAtg9/TC
# J1NQc6+0MR+i7bnZJgdKL7wfKQde7dAoBkT8/j8OgyMI/UsjywsnpPbW9PAmmIfi
# SHO9ITb11toO7YoPVSxd7zprcrX1yn5DaAVSIerP2+7BThu37okRTmQ9dKM8Mx3r
# gTOy4rzIlOKAZAFb9tSou0s4VEJ6cVc28ItSm2DL+wCFoYIS5TCCEuEGCisGAQQB
# gjcDAwExghLRMIISzQYJKoZIhvcNAQcCoIISvjCCEroCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEINlLJNxfx+VpMvaWqIRy1W1wjs3sa4/yfCC0Uasn
# j9oLAgZctG58cn4YEzIwMTkwNDMwMjI0NDMwLjE4OFowBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjdCRjEtRTNFQS1CODA4MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIOPDCCBPEwggPZoAMCAQICEzMAAAD2rM92KnN0mtoAAAAAAPYw
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MTgxMDI0MjExNDI3WhcNMjAwMTEwMjExNDI3WjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046N0JGMS1FM0VBLUI4
# MDgxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCUmrVAwDHtx3rsVppuWDzC8TXEAXtm
# AUD6639Of0V6AYaoHuLpUKSE96VNJ8lHfIV6QX0TdLD5k/Yhx7Mq9uvk9e3RK+2f
# kGoEatgrb5cWSOyMg3NfOwTX5J5gmRPTiGQzCYXxdGmF6zEIwxRNuWb4tUQkWtir
# kggkKajWSf1s4NLZaq18z9P5P6tUoBF5gdXdhCNClVbmvH/o76zezFAUo3vs7yT6
# 78j+lY6dXAvgAkHhaicuJWVFIWwPxLiZNu2erW8xSL7GWlnn/j2mGLPLu+vlwRyW
# vKANsOut8LRLU/KigOH22aXUNRhtqj8mfZ4IkUeg3Q0EfOAR5+lsbQdVAgMBAAGj
# ggEbMIIBFzAdBgNVHQ4EFgQUHYdig5QfaIJJSNNs7plkg+wm80owHwYDVR0jBBgw
# FoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENB
# XzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAx
# MC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDAN
# BgkqhkiG9w0BAQsFAAOCAQEAMBX2zuIcVxbQmJHV8h7Z3bvtyG8D8Zio+fgvABOb
# makrTpAwGqdIN1Bnow0JAz4cxyiLjnlq1KFxJyEyCIgduOGmFeP/QG1S5o9CJZuT
# Tsn+weLs77yNB7dXe8Mew9Pf0nkuQGan+NZ2s5A02FCy1Q3wK3KIQZ6QXIjsFLoL
# 2RhJ522sZNgUI9bk4lyfMJejDMgnyiWY4rxZHjWkxGNoP8KeuJ/OJzVpH9gfB86Z
# 73KwZ4jLdpzF3/wl2nu/iIU31NVboafPtcngDhU0qKI6PD+VEP+Hcmauhf4CTv0s
# Dk0kQBqqQsieIYKp1Qjfygju47ippO3YEvZVnvn228IO1jCCBnEwggRZoAMCAQIC
# CmEJgSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRp
# ZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1MDcwMTIx
# NDY1NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ1aUKAIKF
# ++18aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP8WCIhFRD
# DNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRhZ5FfgVSx
# z5NMksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39dx898Fd1
# rL2KQk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2iAg16Hgc
# sOmZzTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGjggHmMIIB
# 4jAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xGG8UzaFqF
# bVUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1Ud
# EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYD
# VR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwv
# cHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEB
# BE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB/wSBlTCB
# kjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUFBwICMDQe
# MiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0AZQBuAHQA
# LiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFvs+umzPUx
# vs8F4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5U4zM9GAS
# inbMQEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFSAK84Dxf1
# L3mBZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1Vry/+tuWO
# M7tiX5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6f32WapB4
# pm3S4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35jWSUPei45
# V3aicaoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHasFAeb73x
# 4QDf5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLNHfS4hQEe
# gPsbiSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4sanblrKn
# QqLJzxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHXodLFVeNp
# 3lfB0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUeCLraNtvT
# X4/edIhJEqGCAs4wggI3AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBP
# cGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo3QkYxLUUzRUEtQjgw
# ODElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcG
# BSsOAwIaAxUADxdHwnvWAzfCWtOb88hbm/VWmpGggYMwgYCkfjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOByszQwIhgPMjAx
# OTA0MzAxOTQyNDRaGA8yMDE5MDUwMTE5NDI0NFowdzA9BgorBgEEAYRZCgQBMS8w
# LTAKAgUA4HKzNAIBADAKAgEAAgInrgIB/zAHAgEAAgIRqjAKAgUA4HQEtAIBADA2
# BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIB
# AAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAMt/XHztE/BY3btj8+lwxxd3fI+82COD
# m0VMUbzeulg2RRy00QeOHqh7Poic4gys7MTeP8zX+frdcUvAGQM70rYZ1Tf7RIGV
# ooxTrIDSaWGZNsdiPlwNfYsOAvCuWpD4c7kU7RCoJM3K4MCyCsd4wQRch23mbNAC
# vylvLlZRYEbEMYIDDTCCAwkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAD2rM92KnN0mtoAAAAAAPYwDQYJYIZIAWUDBAIBBQCgggFKMBoG
# CSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQg93XKwGzv
# mCrc2XsMlrM7Y0R0ahpylCfrsyW2zZFBCzYwgfoGCyqGSIb3DQEJEAIvMYHqMIHn
# MIHkMIG9BCD3h0F3arTtFwnZ0yXjPeaAEVJWm2KVFg+pkE5xL5O06jCBmDCBgKR+
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAA9qzPdipzdJraAAAA
# AAD2MCIEIF7YZ+r6E2zjXng9Olx76rQY4LX69jOFif+2GVZ4lBZfMA0GCSqGSIb3
# DQEBCwUABIIBAEGhsguzYtbQOvsk2A0m12Yon1iUtCdx9WYmnY5EVM2R0PXsx96c
# YWVzZhz/3bOJhkNR1xqVzdiysyIjFS2/FSPVcynJUBzqlf122oHWRWUiFYCSeuyL
# +uqDSURTvd6pJgVafFbQcjswS0tpIqGXOavzTv0w/R5FTYOqprETUYNapXCjGF8e
# s7kLh2DN2wcI1VJGctiEmQQd0pL2epza5hYBUKC68vGR2TSXs+rF5yWtl30kzSaL
# B4T0zUQUSeOBzP5ts8Anay3ImtKx6QnKm+6PJGIKXAngqPSWcI6Tu/eAaG2syXvZ
# ebxYz+ZpESbn9g/i53SkJqsxZitexxkyLTs=
# SIG # End signature block
