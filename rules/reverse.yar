rule Meterpreter_rev_tcp
{

        strings:
		$metadatos = "ab.exe" wide nocase
		$dll1 = "kernel32.dll" nocase
		$dll2 = "ws2_32.dll" nocase
		

        condition:
              #metadatos == 2 and all of ($dll*)
}
