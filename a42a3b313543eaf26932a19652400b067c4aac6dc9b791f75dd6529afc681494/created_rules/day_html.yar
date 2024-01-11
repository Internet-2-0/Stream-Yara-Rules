rule MY_ROBOX {
    meta:
        author = "Dayhta"
        ref = "https://malcore.io"
        copyright = "Internet 2.0 Pty Ltd"
        file_sha256 = "a42a3b313543eaf26932a19652400b067c4aac6dc9b791f75dd6529afc681494"

    strings:
        // specific strings found in binary
        $specific1 = "http://www.auto-ping.com/"
        $specific3 = "<a dir='ltr' href='http://komsuciftlikcharles.blogspot.com/search/label/Acunn.com%20Maxioyun%20St%C3%BCdyoda%20Canl%C4%B1%20Yay%C4%B1n%C4%B1%20izleme%20F%C4%B1rsat%C4%B1'>Acunn.com Maxioyun St"
        $specific4 = "<a dir='ltr' href='http://komsuciftlikcharles.blogspot.com/search/label/%C3%87%C3%B6plerdeki%20demir%20at%C4%B1klar%C4%B1n%C4%B1n%20ayr%C4%B1lmas%C4%B1nda%20hangi%20y%C3%B6ntem%20kullan%C4%B1l%C4%B1yor'>"

        // hex strings found in binary
        $hex_string1 = { 77 77 77 2e 61 64 68  6f 6f 64 2e 63 6f 6d }
        $hex_string2 = { 3c 21 44 4f 43 54 59 50  45 20 68 74 6d 6c 3e }
    

        // matchable strings in the binary
        $match_string1 = "url: 'https://www.blogger.com/navbar.g?targetBlogID\\x3d737965624744931304\\x26blogName\\x3dkom%C5%9Fu+%C3%A7iftlik+hileleri+%7C+kom%C5%9Fu+%C3%A7iftli...\\x26publishMode\\x3dPUBLISH_MODE_BLOGSPOT\\x26navbarType\\x3dLIGHT\\x26layoutType\\x3dLAYOUTS\\x26searchRoot\\x3dhttps://komsuciftlikcharles.blogspot.com/search\\x26blogLocale\\x3dtr\\x26v\\x3d2\\x26homepageUrl\\x3dhttp://komsuciftlikcharles.blogspot.com/\\x26vt\\x3d-1534083366370641433',"
        $match_string2 = "id: \"navbar-iframe\""

    condition:
        2 of ($specific*) and 2 of ($hex_string*) and 1 of ($match_string*)

// NOTE: this rule caused an issue during compilation (line 24: empty string "$match_string3") review manually
}
