rule html_malware_sample {
	meta:
		author = "Malcore Yara Generator"
		ref = "https://malcore.io"
		copyright = "Internet 2.0 Pty Ltd"
		file_sha256 = "0d535700921aa82df64c1151d819914462f27eaf4a5cf913ce37c2e502864b1d"
	strings:
		$magic = { 3c 21 }
		$mickey = "Mickey Club"
		$hex_string1 = { d9 81 d8 a7 d9 84 2c 20 d9 85 d8 ad d9 84 20 d9 }
		$hex_string2 = { 77 77 77 2e 68 65 64 65 79 61 2e 63 6f 6d 2f 6d }
	condition:
		$magic at 0 and all of them
}
