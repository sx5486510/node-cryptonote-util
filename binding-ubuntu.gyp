{
    "targets": [
        {
            "target_name": "cryptonote",
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
                "src/crypto/aesb.c",
                "src/contrib/epee/src/hex.cpp",
				"external/easylogging++/easylogging++.cc",
            ],
            "include_dirs": [
                "src",
                "src/contrib/epee/include",
				"external/easylogging++",
                "<!(node -e \"require('nan')\")",
            ],
            "link_settings": {
                "libraries": [
                    "-lboost_system",
                    "-lboost_date_time",
                ]
            },
            "cflags_cc!": [ "-fno-exceptions", "-fno-rtti" ],
            "cflags_cc": [
                  "-std=c++0x",
                  "-fexceptions",
                  "-frtti",
            ],
        }
    ]
}
