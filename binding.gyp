{
    "targets": [
        {
            "target_name": "cryptonote",
            "sources": [
                "src/CryptoNoteCore/CryptoNoteFormatUtils.cpp",
                "src/CryptoNoteCore/CryptoNoteSerialization.cpp",
                "src/CryptoNoteCore/TransactionExtra.cpp",
                "src/CryptoNoteCore/CryptoNoteTools.cpp",
                "src/crypto/tree-hash.c",
                "src/crypto/crypto.cpp",
                "src/crypto/crypto-ops.c",
                "src/crypto/crypto-ops-data.c",
                "src/crypto/hash.c",
                "src/crypto/keccak.c",
                "src/crypto/blake256.c",
                "src/crypto/hash-extra-blake.c",
                "src/crypto/hash-extra-groestl.c",
                "src/crypto/hash-extra-skein.c",
                "src/crypto/hash-extra-jh.c",
                "src/Logging/ILogger.cpp",
                "src/Common/MemoryInputStream.cpp",
                "src/Common/StringView.cpp",
                "src/Common/Base58.cpp",
                "src/Common/StringTools.cpp",
                "src/Common/StreamTools.cpp",
                "src/Common/VectorOutputStream.cpp",
                "src/main.cc",
                "src/cn-hash.cpp",
            ],
            "include_dirs": [
                "src",
                "src/contrib/epee/include",
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
