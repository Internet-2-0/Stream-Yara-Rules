rule html_rule {
	meta:
		author = "Malcore Yara Generator"
		ref = "https://malcore.io"
		copyright = "Internet 2.0 Pty Ltd"
		file_sha256 = "a42a3b313543eaf26932a19652400b067c4aac6dc9b791f75dd6529afc681494"
	strings:
		$magic = { 3c 21 }
		$name = "REKLAM VER"
		$encoded1 = "AOuZoY5TtRSTU2bREiwJWVvCtOTfQaqrlg"
		$encoded2 = "call%20of%20duty%202%20hileleri%20nereye%20yaz%C3%83%C2%83%C3%82%C2%84%C3%83%C2%82%C3%82%C2%B1l%C3%83%C2%83%C3%82%C2%84%C3%83%C2%82%C3%82%C2%B1"
		$encoded3 = "EF604E06FFBF68C452D1AECB01394C5B01155C62B924A54A750E6D8DD2AD0BC1854A7AD421A02FC8C1"
		$url_start1 = { 6c 28 68 74 74 70 3a 2f 2f 77 77 77 2e 62 6c 6f }
		$url_start2 = { 78 63 33 5c 78 38 33 5c 78 63 32 5c 78 38 34 5c }
		$url_start3 = { 20 77 77 77 2e 61 64 68 6f 6f 64 2e 63 6f 6d 20 }
		$match1 = "https://www.blogger.com/navbar.g?targetBlogID"
		$match2 = "http://zirve100.com/CounterV4.js"
	condition:
		$magic at 0 and $name and 3 of ($url_start*) and 2 of ($match*) and 3 of ($encoded*)
		
}
