rule unknown_rule_1 {
	meta:
		author = "thomas perkins"
	strings:
		$magic = { 4D 5A }
		$match = "VerQueryValueW"
		// ljmp   $0x7e46,$0x794186f7
		$asm_1 = { ea f7 86 41 79 46 7e }
		// lcall  $0x8c6a,$0x9e42867e
		$asm_2 = { 9a 7e 86 42 9e 6a 8c }
		// lock sub 0x3fd3f71e,%edx
		$asm_3 = { f0 2b 15 1e f7 d3 3f }
	condition:
		$magic at 0 and $match and 3 of ($asm_*)
}
