# Solar PuTTY Decryptor

Can be use for penetration testing or CTFs.

## Usage

```sh
usage: script.py session [-h] [-wl WORDLIST] [-p PASSWORD] 

Decrypt Solar-PuTTY session using a password or wordlist.

positional arguments:
  session               Path to the Solar-PuTTY session (.dat) file

optional arguments:
  -h, --help            show this help message and exit
  -wl WORDLIST, --wordlist WORDLIST
                        Path to the wordlist file (optional).
  -p PASSWORD, --password PASSWORD
                        Password to use for decryption (optional)
```


```sh
SolarPuttyDecryptor.py session_file --wordlist <some_wordlist>
```

or

```sh
SolarPuttyDecryptor.py session_file --password <password>
```


## Supplimental

Wrappers around calling SolarPuttyDecrypt.exe.

```powershell
$file = "C:\path\to\file.txt"
$exe = "C:\path\to\SolarPuttyDecrypt.exe"
$lines = Get-Content -Path $file


foreach ($line in $lines) {
    & $exe $line
}
```



## References
* https://www.jetbrains.com/decompiler/
* https://www.solarwinds.com/free-tools/solar-putty
* https://hackmd.io/@tahaafarooq/cracking-solar-putty
* https://voidsec.com/solarputtydecrypt/
* https://github.com/VoidSec/SolarPuttyDecrypt
