<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.211
	 Created on:   	11/9/2022 8:49 AM
	 Created by:   	SYSTEM
	 Organization: 	
	 Filename:     	
	===========================================================================
	.DESCRIPTION
		Description of the PowerShell service.
#>


# Warning: Do not rename Start-MyService, Invoke-MyService and Stop-MyService functions


#Create the current timestamp
function Get-TimeStamp ($a)
{
	
	return "{0:MM-dd-yy} {0:HH:mm:ss}" -f ($a)
	
}

Function UpdateLogTime
{
	$GLobal:LogTimeStamp = Get-TimeStamp (Get-Date)
}

function Read-LastRun
{
	
	$query = "Select max(tstamp) from $global:SQLTable"
	$timestamps = Invoke-SQLcmd -ServerInstance $global:SQLInstance -query $query -U $SQLUser -P $Sqlpwd -Database $global:SQLDatabase
	$Global:LastRun = $timestamps.column1
}

<#
	.SYNOPSIS
		A brief description of the Get_ThreatByClassification function.
	
	.DESCRIPTION
		A detailed description of the Get_ThreatByClassification function.
	
	.EXAMPLE
		PS C:\> Get_ThreatByClassification
	
	.NOTES
		Additional information about the function.
#>
function Get_ThreatByClassification
{
	$URL = "https://$Global:Tenant.sentinelone.net/web/api/v2.0/private/threats/filters-count?apiToken=$Global:apiKey"
	$web1 = Invoke-RestMethod -uri $URL
	$temp = $web1.data
	$metrics = $temp | Where-Object title -Contains Classification
}

#Get Threats in sentinel one by Computer with the creation date
function Get_ActiveThreatByAgent
{
	$StartTime = Get-TimeStamp (Get-Date)
	#"Start --- $StartTime" | Out-file .\SentinelOneTimelog.txt -Append
	
	
	$Global:CurrentRunTimeStamp = Get-TimeStamp (Get-Date)
	Read-LastRun
	
	$lastrunlocal = $Global:LastRun
	$Exe_Date = $lastRunlocal.ToString("yyyy-MM-dd")
	$Exe_Hours = $lastRunlocal.ToString("HH")
	$Exe_Minute = $lastRunlocal.ToString("mm")
	$Exe_Seconde = $lastRunlocal.ToString("ss")
	$Exe_Mili = $lastRunlocal.ToString("ffffff")
	#$Skip = ""
	
	
	$URL = "https://$Global:Tenant.sentinelone.net/web/api/v2.0/threats?apiToken=$Global:apiKey&skipCount=True&countOnly=false&limit=100&createdAt__gt=$Exe_Date" + "T$EXE_Hours" + "%3A$EXE_Minute" + "%3A$EXE_Seconde." + $Exe_Mili + "Z"
	$test1 = $url
	
	Try
	{
		
		
		$web1 = Invoke-RestMethod -uri $URL
		$CountWebItem = $web1.data | Measure-Object threatName
		$PageCount = 0
		
		DO
		{
			$metrics = $web1.data
			
			foreach ($i in $metrics)
			{
				$SiteName = $i.SiteName
				$AssetName = $i.agentComputerName
				$ThreatName = $i.threatName
				$Classification = $i.classification
				$mitigationMode = $I.mitigationMode
				$createdDate = $i.createdAt
				$Resolved = $i.Resolved
				$Rank = $i.rank
				$AgentOS = $i.agentOsType
				$engines = $i.engines
				$username = $i.username
				$mitigationStatus = $I.mitigationStatus
				
				$InputMetric = @{
					ThreatName = "$ThreatName"
				}
				
				
				Try
				{
					
					$timestamp = (([datetime]"$createdDate").ToUniversalTime()).ToString("MM/dd/yyyy HH:mm:ss.ffffff")
					
					$insertquery = "INSERT INTO [dbo].[$global:SQLTable] ([Site],[mitigationStatus],[Engines],[endpoint],[MitigationMode],[tstamp],[Username],[AgentOS],[ThreatName],[ThreatNameTag],[Classification],[Resolved],[Rank]) VALUES ('$SiteName','$mitigationStatus','$engines','$AssetName','$mitigationMode','$timestamp','$username','$AgentOS','$ThreatName','$ThreatName','$Classification','$Resolved','$Rank') "
					
					
					Invoke-SQLcmd -ServerInstance $global:SQLInstance -query $insertquery -U $Global:SQLUser -P $global:Sqlpwd -Database $global:SQLDatabase
					
				}
				catch
				{
					$ErrorMessage = $_.Exception.Message
					UpdateLogTime
					$Tag_Log = @{
						Event = "Error"
					}
					$LogMetric = @{
						message = "$ErrorMessage" + " -- $createdDate -- $SiteName -- $AssetName -- $ThreatName -- $mitigationMode -- $Resolved -- $Classification -- $Rank -- $AgentOS -- $engines -- $username"
					}
					Write-Influx -Measure Get_ActiveThreatByAgent -tag $Tag_Log -Metrics $LogMetric -Database $Global:Influxdb_Log -Server $Global:InfluxServer -Credential $Global:InfluxCred -Verbose
					"$Global:LogTimeStamp" + " --- " + "$ErrorMessage" + " -- $createdDate -- $SiteName -- $AssetName -- $ThreatName -- $mitigationMode -- $Resolved -- $Classification -- $Rank -- $AgentOS -- $engines -- $username" | Out-file .\SentinelOneError.txt -Append
				}
			}
			
			$PageCount = $PageCount + $global:SkipValue
			$URLTemp = $URL + "&skip=$PageCount"
			
			$web1 = Invoke-RestMethod -uri $URLTemp
			$Global:CountWebItem = $web1.data | Measure-Object threatName
			$Global:CountWebItem.Count
			UpdateLogTime
			
			
			$Tag_Log = @{
				Event = "Log"
			}
			$LogMetric = @{
				message = $URLTemp + " - " + $CountWebItem.Count
			}
						
		}
		While ($Global:CountWebItem.Count -gt 0)
	}
	catch
	{
		$ErrorMessage = $_.Exception.Message
		$Tag_Log = @{
			Event = "Error"
		}
		$LogMetric = @{
			message = $ErrorMessage
		}
	
	}
	
		UpdateLogTime
	
}


function Start-MyService
{
	# Place one time startup code here.
	# Initialize global variables and open connections if needed
	$global:bRunService = $true
	$global:bServiceRunning = $false
	$global:bServicePaused = $false
	
	Import-Module sqlserver
	$T = 1
	
	$Global:ExecuteTime = Get-date
	$Global:apiKey = "INSERT YOUR TOKEN HERE"
	$global:SkipValue = 100
	$Global:Tenant = "INSERT NAME OF YOUR S1 TENANT"
	$GLobal:LogTimeStamp = ""
	$global:SQLUser = 'ENTER THE MSSQL USER TO USE'
	$global:Sqlpwd = 'ENTER THE MSSQL USER PASSWORD'
	$global:SQLInstance = 'NAME OF THE MSSQL SERVER INSTANCE'
	$Global:SQLTable = 'NAME OF THE TABLE TO USE'
	$global:SQLDatabase = 'NAME OF THE DATABSE TO USE'
}

function Invoke-MyService
{
	$global:bServiceRunning = $true
	while($global:bRunService) {
		try 
		{
			if($global:bServicePaused -eq $false) #Only act if service is not paused
			{
				#Place code for your service here
				#e.g. $ProcessList = Get-Process solitaire -ErrorAction SilentlyContinue
				
				# Use Write-Host or any other PowerShell output function to write to the System's application log
				Get_ActiveThreatByAgent
			}
		}
		catch
		{
			# Log exception in application log
			Write-Host $_.Exception.Message
		}
		# Adjust sleep timing to determine how often your service becomes active
		if($global:bServicePaused -eq $true)
		{
			Start-Sleep -Seconds 20 # if the service is paused we sleep longer between checks
		}
		else
		{
			Start-Sleep –Seconds 10 # a lower number will make your service active more often and use more CPU cycles
		}
	}
	$global:bServiceRunning	= $false
}

function Stop-MyService
{
	$global:bRunService = $false # Signal main loop to exit
	$CountDown = 30 # Maximum wait for loop to exit
	while($global:bServiceRunning -and $Countdown -gt 0)
	{
		Start-Sleep -Seconds 1 # wait for your main loop to exit
		$Countdown = $Countdown - 1
	}
	# Place code to be executed on service stop here
	# Close files and connections, terminate jobs and
	# use remove-module to unload blocking modules
}

function Pause-MyService
{
	# Service is being paused
	# Save state 
	$global:bServicePaused = $true
	# Note that the thread your PowerShell script is running on is not suspended on 'pause'.
	# It is your responsibility in the service loop to pause processing until a 'continue' command is issued.
	# It is recommended to sleep for longer periods between loop iterations when the service is paused.
	# in order to prevent excessive CPU usage by simply waiting and looping.
}

function Continue-MyService
{
	# Service is being continued from a paused state
	# Restore any saved states if needed
	$global:bServicePaused = $false
}
