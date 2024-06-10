import "pe"
import "console"
import "math"


rule Turla_Main_DLL_{

	meta:
		Author = "Diyar Saadi"
		Date = "06/10/2024"
		Threat_Actor = "APT"
	
	strings:

		$c = "libcurl"
		$c1 = "curl.exe"
		$c2 = "curl"

	condition:
		(uint16be(0) == 0x4d5a) // note : DLL have same EXE PE Header Known as MZ Header
		and 2 of ($c*) and (pe.number_of_signatures==0) and 
		for any section in pe.sections:(
			console.log("Entropy Value : ", math.entropy(section.raw_data_offset,section.raw_data_size)) and
			console.hex("Entropy Header : ", uint16be(section.raw_data_offset))
		) and
		for any resource in pe.resources:
		(
			console.log("Entropy Res Value : ", math.entropy(resource.offset,resource.length)) and
			console.hex("Entropy Res Header : ", uint16be(resource.offset))
		) and 
		for any export in pe.export_details:(
			export.name matches /^[a-z]{2}_/
		) and (pe.number_of_exports == 0 and pe.number_of_exports != 1 ) and
		(pe.number_of_imports <= 8 and pe.number_of_imports == 10 and pe.number_of_imports !=0
		and pe.number_of_signatures == 0 and pe.number_of_signatures != 1
		and pe.number_of_resources == 1 and pe.number_of_resources != 0 and 
		console.log("IS DLL : ", pe.is_dll())
		and (filesize < 505KB and filesize > 400KB))
		
}

rule Turla_DLL_STRINGS{

	meta:
		Author = "Diyar Saadi"
		Date = "06/10/2024"
		Threat_Actor = "APT"
	strings:
		$c = "Fatal libcurl error" nocase wide
		$c1 = "Netscape HTTP Coockie False" nocase
		$c2 = "CURL_SSL_VERSION" nocase
		$c3 = "CURL_SSL_BACKEND" nocase
		$c4 = "CURLOPT_RESOLVE" nocase
	condition:
		all of ($c*) and 
		uint16be(0) == 0x4d5a // note : DLL have same EXE PE Header Known as MZ Header
}

