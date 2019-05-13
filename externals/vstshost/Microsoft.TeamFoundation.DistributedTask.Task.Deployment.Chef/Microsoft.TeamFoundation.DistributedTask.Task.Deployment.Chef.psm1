function Invoke-Knife
{
    <#
        .SYNOPSIS
        Returns the output of knife command

        .PARAMETER argumets
        Arguments for knife command
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(mandatory=$true)]
        [string[]]$arguments
    )

    $ErrorActionPreference = 'Stop'
    pushd $global:chefRepo
    try
    {
        $command = "knife "
        $arguments | foreach{ $command += "$_ " }
        $command = $command.Trim()
        Write-verbose "Running knife command: $command" -verbose
        iex $command
    }
    finally
    {
        popd
    }
}

function Initialize-ChefRepo()
{
	[CmdletBinding()]
    Param
    (
		[Parameter(mandatory=$true)]
        $connectedServiceDetails
    )

    $ErrorActionPreference = 'Stop'
    Write-Verbose "Creating Chef Repo" -verbose

    $userName = $connectedServiceDetails.Authorization.Parameters.Username
    Write-Verbose "userName = $userName" -Verbose
    $passwordKey = $connectedServiceDetails.Authorization.Parameters.Password
    $organizationUrl = $connectedServiceDetails.Url
    Write-Verbose "organizationUrl = $organizationUrl" -Verbose
    
    #create temporary chef repo
    $randomGuid=[guid]::NewGuid()
    $tempDirectory = [System.Environment]::GetEnvironmentVariable("temp","Machine")
    $chefRepoPath = Get-TemporaryDirectoryForChef
    $global:chefRepo = "$chefRepoPath"
    New-Item $chefRepoPath -type Directory | Out-Null

    #create knife config directory
    $knifeConfigDirectoryPath = Join-Path -Path $chefRepoPath -ChildPath ".chef"
    New-Item $knifeConfigDirectoryPath -type Directory | Out-Null

    #create knife.rb
    $knifeConfigPath = Join-Path -Path $knifeConfigDirectoryPath -ChildPath "knife.rb"
    New-Item $knifeConfigPath -type File | Out-Null

    #create passwordKey File
    $privateKeyFileName = $userName + ".pem"
    $privateKeyFilePath = Join-Path -Path $knifeConfigDirectoryPath -ChildPath $privateKeyFileName
    New-Item $privateKeyFilePath -type File -value $passwordKey | Out-Null

    Invoke-Knife @("configure --repository '$chefRepoPath' --server-url '$organizationUrl' --user '$userName' --validation-client-name '$userName'  --validation-key '$privateKeyFileName' --config '$knifeConfigPath' --yes") | Out-Null

    Write-Verbose "Chef Repo Created" -verbose
}

function Get-TemporaryDirectoryForChef
{
    [CmdletBinding()]
    Param
    ()

    $ErrorActionPreference = 'Stop'
    $randomGuid=[guid]::NewGuid()
    $tempDirectory = [System.Environment]::GetEnvironmentVariable("temp","Machine")
    return (Join-Path -Path $tempDirectory -ChildPath $randomGuid)
}

function Invoke-GenericMethod
{
    [CmdletBinding()]
	param(
	$instance = $(throw “Please provide an instance on which to invoke the generic method”),
	[string] $methodName = $(throw “Please provide a method name to invoke”),
	[string[]] $typeParameters = $(throw “Please specify the type parameters”),
	[object[]] $methodParameters = $(throw “Please specify the method parameters”)
	)

    $ErrorActionPreference = 'Stop'
	## Determine if the types in $set1 match the types in $set2, replacing generic
	## parameters in $set1 with the types in $genericTypes
	function ParameterTypesMatch([type[]] $set1, [type[]] $set2, [type[]] $genericTypes)
	{
		$typeReplacementIndex = 0
		$currentTypeIndex = 0

		## Exit if the set lengths are different
		if($set1.Count -ne $set2.Count)
		{
			return $false
		}

	## Go through each of the types in the first set
		foreach($type in $set1)
		{
			## If it is a generic parameter, then replace it with a type from
			## the $genericTypes list
			if($type.IsGenericParameter)
			{
				$type = $genericTypes[$typeReplacementIndex]
				$typeReplacementIndex++
			}

			## Check that the current type (i.e.: the original type, or replacement
			## generic type) matches the type from $set2
			if($type -ne $set2[$currentTypeIndex])
			{
				return $false
			}
			$currentTypeIndex++
		}

		return $true
	}

	## Convert the type parameters into actual types
	[type[]] $typedParameters = $typeParameters

	## Determine the type that we will call the generic method on. Initially, assume
	## that it is actually a type itself.
	$type = $instance

	## If it is not, then it is a real object, and we can call its GetType() method
	if($instance -isnot "Type")
	{
		$type = $instance.GetType()
	}

	## Search for the method that:
	## – has the same name
	## – is public
	## – is a generic method
	## – has the same parameter types
	foreach($method in $type.GetMethods())
	{
		# Write-Host $method.Name
		if(($method.Name -eq $methodName) -and
		($method.IsPublic) -and
		($method.IsGenericMethod))
		{
			$parameterTypes = @($method.GetParameters() | % { $_.ParameterType })
			$methodParameterTypes = @($methodParameters | % { $_.GetType() })
			if(ParameterTypesMatch $parameterTypes $methodParameterTypes $typedParameters)
			{
				## Create a closed representation of it
				$newMethod = $method.MakeGenericMethod($typedParameters)

				## Invoke the method
				$newMethod.Invoke($instance, $methodParameters)

				return
			}
		}
	}

	## Return an error if we couldn’t find that method
	throw (Get-LocalizedString -Key "Could not find method: '{0}'" -ArgumentList $methodName)
}

function Wait-ForChefNodeRunsToComplete()
{
	[CmdletBinding()]
    Param
    (
        [Parameter(mandatory=$true)]
        [string]$environmentName,
		[Parameter(mandatory=$true)]
        [int]$runWaitTimeInMinutes,
		[Parameter(mandatory=$true)]
        [int]$pollingIntervalTimeInSeconds
    )

    $ErrorActionPreference = 'Stop'
	$driftInSeconds = 30;
	$attributeUpdateTime = (Get-Date).ToUniversalTime();
	$attributeUpdateTimeWithDrift = $attributeUpdateTime.AddSeconds($driftInSeconds)
	$allNodeRunsCompleted = $false;
	$failureNodesList = @();
	$successNodesList = @();
	$noRunsNodeList = @();
	$nodes = Invoke-Knife @("node list -E $environmentName")
	$nodesCompletionTable = @{};
	foreach($node in $nodes)
	{
		$nodesCompletionTable.Add($node, $false);
	}
	
	Write-Host (Get-LocalizedString -Key "Waiting for runs to complete on all the nodes of the environment: '{0}'" -ArgumentList $environmentName)

	while(Get-ShouldWaitForNodeRuns -attributeUpdateTime $attributeUpdateTime `
          -runWaitTimeInMinutes $runWaitTimeInMinutes -allNodeRunsCompleted $allNodeRunsCompleted)
	{
		$runListFetchAndParse = {
            $runListJson = Invoke-Knife @("runs list -E $environmentName -F json")
		    #TODO: might remove this, added to check E2E failure intermittent
		    Write-Verbose ($runListJson | Out-string) -verbose
            return [Newtonsoft.Json.Linq.JArray]::Parse($runListJson);
        }

        $runArray = Invoke-WithRetry -Command $runListFetchAndParse -RetryDelay 10 -MaxRetries 10 -OperationDetail "fetch/parse run list of chef nodes"

		foreach($run in $runArray.GetEnumerator())
		{
			$nodeName = $run["node_name"].ToString();
			if($nodesCompletionTable.Contains($nodeName) `
			-and (-not $nodesCompletionTable[$nodeName]) `
			-and ([System.DateTime]::Parse($run["start_time"].ToString()) -gt $attributeUpdateTimeWithDrift))
			{
				$runStatus = $run["status"].ToString();
				$runId = $run["run_id"].ToString();

				if($runStatus -eq "failure")
				{
					$runString = Get-DetailedRunHistory $runId
					$runLog = "`n" + ($runString | out-string)
					Write-Error (Get-LocalizedString -Key "Run on node '{0}' has failed. Check logs below: {1}" -ArgumentList $nodeName, $runLog) -EA "Continue"
					$failureNodesList += $nodeName
					$nodesCompletionTable[$nodeName] = $true
				}
				elseif($runStatus -eq "success")
				{
					Write-Host (Get-LocalizedString -Key "Run on node '{0}' has succeeded. run_id: '{1}'" -ArgumentList $nodeName, $runId)
					$successNodesList += $nodeName
					$nodesCompletionTable[$nodeName] = $true
				}
				else
				{
					#InProgress condition which is equivalent to no run on node, no-op
			}
		}
		}

		$allNodeRunsCompleted = $true;
		foreach($isCompleted in $nodesCompletionTable.Values)
		{
			if(-not $isCompleted)
			{
				$allNodeRunsCompleted = $false;
				break;        
			}
		}

		if(-not $allNodeRunsCompleted)
		{
			Start-Sleep -s $pollingIntervalTimeInSeconds
		}
	}

	if($allNodeRunsCompleted)
	{
		Write-Host (Get-LocalizedString -Key "Runs have completed on all the nodes in the environment: '{0}'" -ArgumentList $environmentName)
	}
	else
	{
		foreach($nodeCompletionData in $nodesCompletionTable.GetEnumerator())
		{
			if($nodeCompletionData.Value -eq $false)
			{
				$noRunsNodeList += $nodeCompletionData.Name
			}
		}

		Write-Host (Get-LocalizedString -Key "Runs have not completed on all the nodes in the environment: '{0}'" -ArgumentList $environmentName)
		$noRunsNodeListString = "`n" + ($noRunsNodeList -join "`n")
		Write-Host (Get-LocalizedString -Key "Runs have not completed on the following nodes: {0}" -ArgumentList $noRunsNodeListString)
	}

	if($successNodesList.Count -gt 0)
	{
		$successNodesListString = "`n" + ($successNodesList -join "`n")
		Write-Host (Get-LocalizedString -Key "Runs have completed successfully on the following nodes: {0}" -ArgumentList $successNodesListString)
	}

	if(($failureNodesList.Count -gt 0) -or (-not $allNodeRunsCompleted))
	{
		if($failureNodesList.Count -eq 0)
		{
			Write-Host (Get-LocalizedString -Key "Chef deployment has failed because chef runs have not completed on all the nodes in the environment. However, there were no chef run failures. Consider increasing wait time for chef runs to complete, and check nodes if they are reachable from chef server and able to pull the recipes from the chef server.")
		}
		else
		{
			$failureNodesListString = "`n" + ($failureNodesList -join "`n")
			Write-Host (Get-LocalizedString -Key "Runs have failed on the following nodes: {0}" -ArgumentList $failureNodesListString)
		}

		throw (Get-LocalizedString -Key "Chef deployment has failed on the environment: '{0}'" -ArgumentList $environmentName)
	}
	else
	{
		Write-Host (Get-LocalizedString -Key "Chef deployment has succeeded on the environment: '{0}'"  -ArgumentList $environmentName)
	}
}

function Get-ShouldWaitForNodeRuns
{
    [CmdletBinding()]
	Param
    (
		[Parameter(mandatory=$true)]
        [DateTime]$attributeUpdateTime,
        [Parameter(mandatory=$true)]
        [int]$runWaitTimeInMinutes,
        [Parameter(mandatory=$true)]
        [bool]$allNodeRunsCompleted
    )

    $ErrorActionPreference = 'Stop'
    return ((Get-Date).ToUniversalTime()  `
            -lt $attributeUpdateTime.AddMinutes($runWaitTimeInMinutes)) `
	        -and ($allNodeRunsCompleted -eq $false)
}

function Get-PathToNewtonsoftBinary
{
    [CmdletBinding()]
    Param
    ()

    return '$PSScriptRoot\..\Newtonsoft.Json.dll'
}

function Get-DetailedRunHistory()
{
	[CmdletBinding()]
	Param
    (
		[Parameter(mandatory=$true)]
        [string]$runIdString
    )

	return Invoke-knife @("runs show $runIdString")
}

function Invoke-WithRetry {
    [CmdletBinding()]
    param(    
    [Parameter(Mandatory)]
    $Command,
    [Parameter(Mandatory)]
    $RetryDelay = 5,
    [Parameter(Mandatory)]
    $MaxRetries = 5,
    [Parameter(Mandatory)]
    $OperationDetail
    )
    
    $ErrorActionPreference = 'Stop'
    $currentRetry = 0
    $success = $false

    do {
        try
        {
            $result = & $Command
            $success = $true
            return $result
        }
        catch [System.Exception]
        {            
            Write-Verbose ("Failed to execute operation `"$OperationDetail`" during retry: " + $_.Exception.Message) -verbose

            $currentRetry = $currentRetry + 1
            
            if ($currentRetry -gt $MaxRetries)
            {                
                throw $_
            } 
            else 
            {
                Write-Verbose ("Waiting $RetryDelay second(s) before retry attempt #$currentRetry of operation `"$OperationDetail`"") -Verbose
                Start-Sleep -s $RetryDelay
            }
        }
    } while (!$success);
}
# SIG # Begin signature block
# MIIjhgYJKoZIhvcNAQcCoIIjdzCCI3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBGzlHJuS8puzGK
# mhZ0RBK2vb9SAGUz2JiA9pipAB1f9aCCDYEwggX/MIID56ADAgECAhMzAAABA14l
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg/aVtoBN5
# +2WOrY6p99BY5OEXzxXPHiXW87qJbhMwCv8wQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQB5xmjp2B1y27Arr+KpGuWxkclbh7J6CyFi0NHw6mZc
# O8AyKTTajBZQaOPbARwGDG5fHS1FakRWGMxZoh2mHXK9DRB3ax8GwDp8t0D5zY7L
# MBqRsjlCSdI98hfwoxa1KhJN8pKq65+cMKlsbvP+6FecqDxC+T3N3larug2TOnyo
# fMjSA+fGPCCA9ZatW7JbxUr5lrrH3dPcn5DB1/eCLxKqz6xo55mLwK4w9FvKdzB1
# rx+/eLV+PWEnkoTVzVSvuZHRJHt2+NwhTwNs5JHQV5kRv8gYZcuTv7D1RCXJYpYv
# UsuLZJvNwjWQN+uRbdFsSKEZxh8YgJm7tJ+06QTtc9WqoYIS5TCCEuEGCisGAQQB
# gjcDAwExghLRMIISzQYJKoZIhvcNAQcCoIISvjCCEroCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIHLdSxnktPiEezsHn5pr8H2TRjL1M+9qVKwochZY
# 3pIvAgZctG7A6AoYEzIwMTkwNDMwMjI0NDI5LjQ4MlowBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjNCQkQtRTMzOC1FOUExMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIOPDCCBPEwggPZoAMCAQICEzMAAAD0wKpcc8v+rA8AAAAAAPQw
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MTgxMDI0MjExNDI1WhcNMjAwMTEwMjExNDI1WjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0JCRC1FMzM4LUU5
# QTExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQY7TeTsdQXJevkSG86VTj2fDLqFYy
# 7WloMrG9n+/ZwdP03lKNqsBIxcdvhp/aSI25XDvnp01pjiPV1ZOBNrEs+fJigxIl
# TpVrX3+awEFty190WA+yvHSJMYqWj7IKolH7RUEKVkSj4cWnYiW6HxRRVLVIax0H
# Xh6NX8NpzpSPjPQn3+anbZ3NYGYrzM6ZHsEryFLFsKD7/uSQFv9lA993J5wUTE8f
# W/uaAlFbw/Epjmel9LAQ/HgBr/7tYm9UPMPX171LfkRb6jE8MHOaQQekcBO4bgho
# EofBT6r54P9GacguULvU7033MGLQhhGNFIF6mb7jauRgKWOJjH7rEljtAgMBAAGj
# ggEbMIIBFzAdBgNVHQ4EFgQUnLgfJwcXkbsNIS7ZEufr3IJS9agwHwYDVR0jBBgw
# FoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENB
# XzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAx
# MC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDAN
# BgkqhkiG9w0BAQsFAAOCAQEAcIPtmx4u2tziOmue9xmTte/lqMzodrmb2F2RijP5
# kDxaDnuavWnofNttWRVil4jZzLCZEvQKuVIWvW2gVFSawe7zt3GzorjeS49nGdzD
# aVnYRI/baTY24fxF12cEqvNj08PrWNQwhxPuES5xOcDIbIOHAeG/ddcXXd7OuW5G
# Nxgus95inCcyF/NdCjrSYFTFYZZEM9sDeRomEpdnmWqwj+YL/Ymux0PEjgVbaE28
# CBCeoLJ2/chyvJJFp6YW8DIqZUQYRcQRnLYZwomNbx0rL8myEykDnjw6kiPSdf2P
# fHBzNzeooTxra+/y3X4KTwy+lcDIPT0X92wDfUsbwBiGYzCCBnEwggRZoAMCAQIC
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
# cGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozQkJELUUzMzgtRTlB
# MTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcG
# BSsOAwIaAxUAmyMx+a+6rCaE0EH3UFeoc6yTGDeggYMwgYCkfjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOBys38wIhgPMjAx
# OTA0MzAxOTQzNTlaGA8yMDE5MDUwMTE5NDM1OVowdzA9BgorBgEEAYRZCgQBMS8w
# LTAKAgUA4HKzfwIBADAKAgEAAgIqxAIB/zAHAgEAAgISSTAKAgUA4HQE/wIBADA2
# BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIB
# AAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAD64OYo3YcPeeQJuPytBWUv0rjOEGr3d
# 1Nzl8XmTq+vjFkQHTCY8/0Ob/pLIYIA8C56gQI0Jx+DcruVTjs47BMcd3vZLfkVT
# 3Ey7I697+eHMxGQjzYREeB+CshJ/OebvVc6sfad3MYxOQ/2gvbYZ5afDzVrCuKn7
# OtK/OaO0i01tMYIDDTCCAwkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAD0wKpcc8v+rA8AAAAAAPQwDQYJYIZIAWUDBAIBBQCgggFKMBoG
# CSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgbLeLMq1j
# 7zRK26M765WwFUY/7mcfB9g+YrzenUDj23swgfoGCyqGSIb3DQEJEAIvMYHqMIHn
# MIHkMIG9BCA6By8tCMiCbaETbRxKjjaJems5eLv16IdLu50ljOIy1zCBmDCBgKR+
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAA9MCqXHPL/qwPAAAA
# AAD0MCIEIFR7eSKrUQV0Ai1O7BjC1RA5XrIVzrXicEjlf6iSS+CiMA0GCSqGSIb3
# DQEBCwUABIIBACn21ikBJpzHRjsYdZntMMt4lZDJdhlY0xAWox7Vb/Yr4/69ncfB
# 9kpYCDlxd6nZzkWapSunsZdtuLWr4MzgrHw9TJbMVWNAkykAaXJYwbxzcTpinV+D
# Q1/x0TbU4Hb+NMIbqQhTlsKvXyR5c3opHphvRWJJA2mmUyWNcBX69lb6Ha0NE+Ot
# r8laa0znRvD+BQWBGGiVEclSFmR9EbKF8gE8z97Lv1yxIS4pbdnAWQqQ/WlxS6Nz
# jXbRXuxrosxvAGCUCweDg1zGfEy/oVpghWJShepalZbQLE8lS8BPIrTXU8dLD097
# wuM3l11RDI5dm3sAJ6r+yFx1s6kFqFCIPrg=
# SIG # End signature block
