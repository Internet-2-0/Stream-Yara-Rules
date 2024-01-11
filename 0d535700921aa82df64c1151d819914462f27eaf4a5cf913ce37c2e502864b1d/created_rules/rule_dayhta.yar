rule MYG___MALWARE__9c49d0f96681f73c0fa3eda7a25d8b6583d6aabe4bb18929874ffbed6b4253cf_tmp {
	meta:
		author = "Dayhta"
		ref = "github.com/dayhta"
		copyright = "Internet 2.0 Pty Ltd"
		file_sha256 = "0d535700921aa82df64c1151d819914462f27eaf4a5cf913ce37c2e502864b1d"

	strings:
		// specific strings found in binary
		$specific1 = {3c 21 64 6f 63}
	condition:
		all of them
}
