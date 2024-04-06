try 
{
    # Declaring Bitlocker OS Drive Mount Point
    $SysVol = $env:SystemDrive

    # Get current Bitlocker OS volume status to check if it is in desired configuration, else trigger remediation 
    $BitlockerSysVolStatus = Get-BitLockerVolume -MountPoint $SysVol -ErrorAction Stop

    if ($BitlockerSysVolStatus -ne $null)
    {
       # When OS Volume is already Fully Encrypted with XtsAes256 bit encryption...
       if (($BitlockerSysVolStatus.EncryptionMethod -eq "XtsAes256") -and ($BitlockerSysVolStatus.VolumeStatus -like "FullyEncrypted") -and ($BitLockerSysVolStatus.ProtectionStatus -eq 'On') -and ($BitLockerSysVolStatus.KeyProtector.KeyProtectorType -contains 'Tpm') -and ($BitLockerSysVolStatus.KeyProtector.KeyProtectorType -contains 'RecoveryPassword'))
            {
                # No need to remediate on exit code 0
                Write-Host "Already in desired configuration."
                Exit 0        
            }
       else
            {
                # Remediate on exit code 1
                Write-Host "System not in desired configuration."
                Exit 1
            }
    }
}
catch 
{
    $errMsg = $_.Exception.Message
    Write-Host $errMsg
    Exit 1
}
