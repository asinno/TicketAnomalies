#Trust all certs
Add-Type -TypeDefinition @'
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
'@
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName TrustAllCertsPolicy

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

#Declare Variables
$LIST = klist
$TimeMatches=@()
$Regex = '\d\/(\d{1}|\d{2})\/(\d){4} \d.*\d'
$TicketCount = 0
$DateTimeFormat = "M/d/yyyy H:mm:ss"
$TimeCounter = 0
$SuspiciousTicket = @()

#Attempts to match all times in klist and dumps them into a psobject for collection
foreach($Line in $LIST | Select-String  -Pattern '(Start Time)|(End Time)') {
  $Line -match $Regex
  $StartDateTime = [DateTime]::ParseExact($Matches[0],$DateTimeFormat,$null)
  $TimeMatches += $StartDateTime
  $TicketCount++
}
#Iterates through all times of all Tickets to detect tickets with expiration times greater than 10 hours
for($TicketCount -gt 0; $TimeCounter -lt $TicketCount; $TimeCounter+=2){
  $TimeDifference = New-TimeSpan $TimeMatches[$TimeCounter] $TimeMatches[$TimeCounter+1]
  if($TimeDifference.TotalHours -gt 10){
    #Creates object to store ticket and device properties to be sent over UDP or any other protocol the user would like.
    $SuspiciousTicket = ConvertTo-Json -InputObject @{ 
      host= "$env:COMPUTERNAME";
      source="PowerShell Suspicious Ticket Finder";
      sourcetype="PowerShell Scripts";
      event = @{
      Title="Suspicious ticket on $env:COMPUTERNAME";
      timestamp= "{0:MM/dd/yyyy hh:mm:sstt zzz}" -f (Get-Date);
      FQDN= "$env:computername.$env:userdnsdomain";
      klist= klist;
      Description = 'This alert has detected a suspicious ticket on an endpoint. It works by checking if the expiration time of a ticket is greater than 10-hours. This typically indicates the presence of a golden ticket or silver ticket.';
      }
    } -Compress
    #Send data over UDP, must specific endpoint and port
    #Send-UdpDatagram -EndPoint 'Endpoint' -Port 'Port' -Message $SuspiciousTicket | ConvertTo-Json
    #Send to Splunk
    $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $Headers.Add("Authorization", 'Splunk HEC TOKEN')
    #$Message = $SuspiciousTicket | ConvertTo-Json
    $SplunkServer = "https://SPLUNK:8088/services/collector/event"
    Invoke-RestMethod -Uri $splunkserver -Method Post -Headers $headers -Body $SuspiciousTicket
}
}
