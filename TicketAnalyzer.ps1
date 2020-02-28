$LIST = klist
$TimeMatches=@()
$Regex = '\d\/(\d{1}|\d{2})\/(\d){4} \d.*\d'
$TicketCount = 0
$DateTimeFormat = "M/d/yyyy H:mm:ss"
$TimeCounter = 0

#Attempts to match all times in klist and dumps them into a psobject for collection
foreach($Line in $LIST | Select-String  -Pattern '(Start Time)|(End Time)') {
  $Line -match $Regex
  $StartDateTime = [DateTime]::ParseExact($Matches[0],$DateTimeFormat,$null)
  $TimeMatches += $StartDateTime
  $TicketCount++
}
#Iterates through all times of all TGTs to detect tickets with expiration times greater than 10 hours
for($TicketCount -gt 0; $TimeCounter -lt $TicketCount; $TimeCounter+=2){
  $TimeDifference = New-TimeSpan $TimeMatches[$TimeCounter] $TimeMatches[$TimeCounter+1]
  if($TimeDifference.TotalHours -gt 10){
    Write-Host "Warning suspicious TGT detection on" $env:computername -ForegroundColor Red
    klist
  }
  $TimeDifference
}
