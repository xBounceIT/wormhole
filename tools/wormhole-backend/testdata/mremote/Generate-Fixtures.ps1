param([Parameter(Mandatory = $true)][string]$BouncyCastlePath)

$ErrorActionPreference = 'Stop'
$assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $BouncyCastlePath).Path)
if ($assembly.GetName().Version.ToString() -ne '1.8.1.0') {
    throw 'These compatibility vectors require BouncyCastle.Crypto 1.8.1.0.'
}

function Protect-Fixture([string]$Plaintext, [string]$Password, [int]$Offset) {
    # Deterministic salt and nonce are ONLY for public test vectors.
    [byte[]]$salt = $Offset..($Offset + 15)
    [byte[]]$nonce = ($Offset + 16)..($Offset + 31)
    $generator = [Org.BouncyCastle.Crypto.Generators.Pkcs5S2ParametersGenerator]::new()
    $passwordBytes = [Org.BouncyCastle.Crypto.PbeParametersGenerator]::Pkcs5PasswordToBytes($Password.ToCharArray())
    $generator.Init($passwordBytes, $salt, 1000)
    $key = $generator.GenerateDerivedMacParameters(256)
    $parameters = [Org.BouncyCastle.Crypto.Parameters.AeadParameters]::new($key, 128, $nonce, $salt)
    $cipher = [Org.BouncyCastle.Crypto.Modes.GcmBlockCipher]::new([Org.BouncyCastle.Crypto.Engines.AesEngine]::new())
    $cipher.Init($true, $parameters)
    $plain = [Text.Encoding]::UTF8.GetBytes($Plaintext)
    $encrypted = [byte[]]::new($cipher.GetOutputSize($plain.Length))
    $length = $cipher.ProcessBytes($plain, 0, $plain.Length, $encrypted, 0)
    $null = $cipher.DoFinal($encrypted, $length)
    return [Convert]::ToBase64String([byte[]]($salt + $nonce + $encrypted))
}

foreach ($case in @(
    @{ Name = 'custom-ascii'; Password = 'Password1'; Offset = 0 },
    @{ Name = 'custom-latin1'; Password = ('P' + [char]0xE4 + 'ssw' + [char]0xF6 + 'rd1'); Offset = 64 }
)) {
    $verifier = Protect-Fixture 'ThisIsProtected' $case.Password $case.Offset
    $secret = Protect-Fixture 'demo-secret' $case.Password ($case.Offset + 32)
    $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" ConfVersion="2.6" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="$verifier">
  <Node Name="Lab" Type="Container">
    <Node Name="ssh-demo" Type="Connection" Protocol="SSH2" Hostname="ssh.example.test" Port="22" Username="demo" Password="$secret" />
  </Node>
</mrng:Connections>
"@
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot ($case.Name + '.xml')), ($xml.Replace("`r`n", "`n") + "`n"), [Text.UTF8Encoding]::new($false))
}
