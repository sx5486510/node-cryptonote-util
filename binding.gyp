{
    "targets": [
        {
            "target_name": "cryptonote",
			'defines': [
			    '_WIN32_WINNT=0x0600'
			],
            "sources": [
                "src/main.cc",
                "src/cryptonote_core/cryptonote_tx_utils.cpp",
                "src/cryptonote_core/cryptonote_format_utils.cpp",
                "src/cryptonote_core/miner.cpp",
                "src/crypto/tree-hash.c",
                "src/crypto/crypto.cpp",
                "src/crypto/crypto-ops.c",
                "src/crypto/crypto-ops-data.c",
                "src/crypto/hash.c",
                "src/crypto/keccak.c",
                "src/common/base58.cpp",
                "src/crypto/hash-extra-blake.c",
                "src/crypto/aesb.c",
                "src/crypto/slow-hash.c",
"src/crypto/hash-extra-groestl.c",
                "src/crypto/hash-extra-jh.c",
                "src/crypto/hash-extra-skein.c",
                "src/crypto/oaes_lib.c",
                "src/crypto/blake256.c",
                "src/crypto/groestl.c",
                "src/crypto/jh.c",
                "src/crypto/skein.c",               
 "src/crypto/random.c",
                "src/contrib/epee/src/hex.cpp",
				"external/easylogging++/easylogging++.cc",
            ],
			"msvs_settings": {
			    "VCCLCompilerTool": {
				"ExceptionHandling": 1
			    }
			},
	  
            "include_dirs": [
                "src",
                "src/contrib/epee/include",
				"external/easylogging++",
                "<!(node -e \"require('nan')\")",
            ],
            "link_settings": {
			    'library_dirs': [
				    'E:/SDK/boost_1_64_0/lib64-msvc-14.0/lib/'
                ],
            },
            "cflags_cc!": [ "-fno-exceptions", "-fno-rtti" ],
            "cflags_cc": [
                  "-std=c++0x",
                  "-fexceptions",
                  "-fno-rtti",
                  "-fGR",
            ],
        }
    ]
}
