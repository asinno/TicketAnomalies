#Send UDP Datagram By PeteGoo https://gist.github.com/PeteGoo/21a5ab7636786670e47c
function Send-UdpDatagram
{
      Param ([string] $EndPoint, 
      [int] $Port, 
      [string] $Message)

      $IP = [System.Net.Dns]::GetHostAddresses($EndPoint) 
      $Address = [System.Net.IPAddress]::Parse($IP) 
      $EndPoints = New-Object System.Net.IPEndPoint($Address, $Port) 
      $Socket = New-Object System.Net.Sockets.UDPClient 
      $EncodedText = [Text.Encoding]::ASCII.GetBytes($Message) 
      $SendMessage = $Socket.Send($EncodedText, $EncodedText.Length, $EndPoints) 
      $Socket.Close() 
} 

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
    $Message = Write-Host "Warning suspicious TGT detection on" $env:computername -ForegroundColor Red
    Send-UdpDatagram -EndPoint 'Endpoint' -Port 'Port' -Message $Message
  }
  $TimeDifference
}
