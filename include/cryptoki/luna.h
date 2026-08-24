
#if !defined(_CRYPTOKI_LUNA_H_)
#define _CRYPTOKI_LUNA_H_

/* extracted from luna include/cryptoki_v2.h */

#define CKM_LUNA_CAST_KEY_GEN_OLD_XXX       0x00008000        // Entrust added capabilities
#define CKM_LUNA_CAST_ECB_OLD_XXX           0x00008001        // Entrust added capabilities
#define CKM_LUNA_CAST_CBC_OLD_XXX           0x00008002        // Entrust added capabilities
#define CKM_LUNA_CAST_MAC_OLD_XXX           0x00008003        // Entrust added capabilities
#define CKM_LUNA_CAST3_KEY_GEN_OLD_XXX      0x00008004        // Entrust added capabilities
#define CKM_LUNA_CAST3_ECB_OLD_XXX          0x00008005        // Entrust added capabilities
#define CKM_LUNA_CAST3_CBC_OLD_XXX          0x00008006        // Entrust added capabilities
#define CKM_LUNA_CAST3_MAC_OLD_XXX          0x00008007        // Entrust added capabilities
#define CKM_LUNA_PBE_MD2_DES_CBC_OLD_XXX    0x00008008        // Password based encryption
#define CKM_LUNA_PBE_MD5_DES_CBC_OLD_XXX    0x00008009        // Password based encryption
#define CKM_LUNA_PBE_MD5_CAST_CBC_OLD_XXX   0x0000800A        // Password based encryption
#define CKM_LUNA_PBE_MD5_CAST3_CBC_OLD_XXX  0x0000800B        // Password based encryption
#define CKM_LUNA_CONCATENATE_BASE_AND_KEY_OLD_XXX   0x0000800C       // SPKM & SLL added capabilities
#define CKM_LUNA_CONCATENATE_KEY_AND_BASE_OLD_XXX   0x0000800D       // SPKM & SLL added capabilities
#define CKM_LUNA_CONCATENATE_BASE_AND_DATA_OLD_XXX  0x0000800E       // SPKM & SLL added capabilities
#define CKM_LUNA_CONCATENATE_DATA_AND_BASE_OLD_XXX  0x0000800F       // SPKM & SLL added capabilities
#define CKM_LUNA_XOR_BASE_AND_DATA_OLD_XXX          0x00008010       // SPKM & SLL added capabilities
#define CKM_LUNA_EXTRACT_KEY_FROM_KEY_OLD_XXX       0x00008011       // SPKM & SLL added capabilities
#define CKM_LUNA_MD5_KEY_DERIVATION_OLD_XXX         0x00008012       // SPKM & SLL added capabilities
#define CKM_LUNA_MD2_KEY_DERIVATION_OLD_XXX         0x00008013       // SPKM & SLL added capabilities
#define CKM_LUNA_SHA1_KEY_DERIVATION_OLD_XXX        0x00008014       // SPKM & SLL added capabilities
#define CKM_LUNA_GENERIC_SECRET_KEY_GEN_OLD_XXX     0x00008015       // Generation of secret keys
#define CKM_LUNA_CAST5_KEY_GEN_OLD_XXX              0x00008016       // Entrust added capabilities
#define CKM_LUNA_CAST5_ECB_OLD_XXX                  0x00008017       // Entrust added capabilities
#define CKM_LUNA_CAST5_CBC_OLD_XXX                  0x00008018       // Entrust added capabilities
#define CKM_LUNA_CAST5_MAC_OLD_XXX                  0x00008019       // Entrust added capabilities
#define CKM_LUNA_PBE_SHA1_CAST5_CBC_OLD_XXX         0x0000801A       // Entrust added capabilities
#define CKM_LUNA_KEY_TRANSLATION                    0x0000801B       // Entrust added capabilities
#define CKM_LUNA_XOR_BASE_AND_KEY                   0x8000001B
#define CKM_LUNA_2DES_KEY_DERIVATION                0x0000801C       // Custom Gemplus Capabilities
#define CKM_LUNA_INDIRECT_LOGIN_REENCRYPT           0x0000801D       // Used for indirect login
#define CKM_LUNA_PBE_SHA1_DES3_EDE_CBC_OLD          0x0000801E
#define CKM_LUNA_PBE_SHA1_DES2_EDE_CBC_OLD          0x0000801F
#define CKM_LUNA_HAS160                             0x80000100
#define CKM_LUNA_KCDSA_KEY_PAIR_GEN                 0x80000101
#define CKM_LUNA_KCDSA_HAS160                       0x80000102
#define CKM_LUNA_SEED_KEY_GEN                       0x80000103
#define CKM_LUNA_SEED_ECB                           0x80000104
#define CKM_LUNA_SEED_CBC                           0x80000105
#define CKM_LUNA_SEED_CBC_PAD                       0x80000106
#define CKM_LUNA_SEED_MAC                           0x80000107
#define CKM_LUNA_SEED_MAC_GENERAL                   0x80000108
#define CKM_LUNA_KCDSA_SHA1                         0x80000109
#define CKM_LUNA_KCDSA_SHA224                       0x8000010A
#define CKM_LUNA_KCDSA_SHA256                       0x8000010B
#define CKM_LUNA_KCDSA_SHA384                       0x8000010C
#define CKM_LUNA_KCDSA_SHA512                       0x8000010D
#define CKM_LUNA_KCDSA_PARAMETER_GEN                0x8000010F
// Defined prior PKCS#11 and renamed to CKM_SHA224_xxx_OLD after PKCS#11 was updated
#define CKM_LUNA_SHA224_RSA_PKCS_OLD                 0x80000110
#define CKM_LUNA_SHA224_RSA_PKCS_PSS_OLD             0x80000111
#define CKM_LUNA_SHA224_OLD                          0x80000112
#define CKM_LUNA_SHA224_HMAC_OLD                     0x80000113
#define CKM_LUNA_SHA224_HMAC_GENERAL_OLD             0x80000114
#define CKM_LUNA_SHA224_KEY_DERIVATION_OLD           0x80000115
#define CKM_LUNA_DES3_CTR                            0x80000116
#define CKM_LUNA_AES_CFB8                            0x80000118
#define CKM_LUNA_AES_CFB128                          0x80000119
#define CKM_LUNA_AES_OFB                             0x8000011a
//#define CKM_AES_CTR                             0x80000000 + 0x11b
#define CKM_LUNA_AES_GCM_2_20a5d1                    0x8000011c
#define CKM_LUNA_ARIA_CFB8                           0x8000011d
#define CKM_LUNA_ARIA_CFB128                         0x8000011e
#define CKM_LUNA_ARIA_OFB                            0x8000011f
#define CKM_LUNA_ARIA_CTR                            0x80000120
#define CKM_LUNA_ARIA_GCM                            0x80000121
#define CKM_LUNA_ECDSA_SHA224                        0x80000122
#define CKM_LUNA_ECDSA_SHA256                        0x80000123
#define CKM_LUNA_ECDSA_SHA384                        0x80000124
#define CKM_LUNA_ECDSA_SHA512                        0x80000125
#define CKM_LUNA_AES_GMAC                            0x80000126
#define CKM_LUNA_ARIA_CMAC                           0x80000128
#define CKM_LUNA_ARIA_CMAC_GENERAL                   0x80000129
#define CKM_LUNA_SEED_CMAC                           0x8000012c
#define CKM_LUNA_SEED_CMAC_GENERAL                   0x8000012d
#define CKM_LUNA_DES3_CBC_PAD_IPSEC_OLD              0x00000137
#define CKM_LUNA_DES3_CBC_PAD_IPSEC                  0x8000012e
#define CKM_LUNA_AES_CBC_PAD_IPSEC_OLD               0x00001089
#define CKM_LUNA_AES_CBC_PAD_IPSEC                   0x8000012f
#define CKM_LUNA_ARIA_L_ECB                          0x80000130
#define CKM_LUNA_ARIA_L_CBC                          0x80000131
#define CKM_LUNA_ARIA_L_CBC_PAD                      0x80000132
#define CKM_LUNA_ARIA_L_MAC                          0x80000133
#define CKM_LUNA_ARIA_L_MAC_GENERAL                  0x80000134
#define CKM_LUNA_SHA224_RSA_X9_31                    0x80000135
#define CKM_LUNA_SHA256_RSA_X9_31                    0x80000136
#define CKM_LUNA_SHA384_RSA_X9_31                    0x80000137
#define CKM_LUNA_SHA512_RSA_X9_31                    0x80000138
#define CKM_LUNA_SHA1_RSA_X9_31_NON_FIPS             0x80000139
#define CKM_LUNA_SHA224_RSA_X9_31_NON_FIPS           0x8000013a
#define CKM_LUNA_SHA256_RSA_X9_31_NON_FIPS           0x8000013b
#define CKM_LUNA_SHA384_RSA_X9_31_NON_FIPS           0x8000013c
#define CKM_LUNA_SHA512_RSA_X9_31_NON_FIPS           0x8000013d
#define CKM_LUNA_RSA_X9_31_NON_FIPS                  0x8000013e
#define CKM_LUNA_DSA_SHA224                          0x80000140  //DH -moved here to keep ECDSA SHA 2 same as FW4
#define CKM_LUNA_DSA_SHA256                          0x80000141
#define CKM_LUNA_RSA_FIPS_186_3_AUX_PRIME_KEY_PAIR_GEN     0x80000142
#define CKM_LUNA_RSA_FIPS_186_3_PRIME_KEY_PAIR_GEN         0x80000143
#define CKM_LUNA_SEED_CTR                            0x80000144
#define CKM_LUNA_KCDSA_HAS160_NO_PAD                 0x80000145
#define CKM_LUNA_KCDSA_SHA1_NO_PAD                   0x80000146
#define CKM_LUNA_KCDSA_SHA224_NO_PAD                 0x80000147
#define CKM_LUNA_KCDSA_SHA256_NO_PAD                 0x80000148
#define CKM_LUNA_KCDSA_SHA384_NO_PAD                 0x80000149
#define CKM_LUNA_KCDSA_SHA512_NO_PAD                 0x80000151
#define CKM_LUNA_DES3_X919_MAC                       0x80000150
#define CKM_LUNA_ECDSA_KEY_PAIR_GEN_W_EXTRA_BITS     0x80000160
#define CKM_LUNA_ECDSA_GBCS_SHA256                   0x80000161
#define CKM_LUNA_AES_KW                              0x80000170
#define CKM_LUNA_AES_KWP                             0x80000171
#define CKM_LUNA_TDEA_KW                             0x80000172
#define CKM_LUNA_TDEA_KWP                            0x80000173
#define CKM_LUNA_AES_CBC_PAD_EXTRACT                0x80000200
#define CKM_LUNA_AES_CBC_PAD_INSERT                 0x80000201
#define CKM_LUNA_AES_CBC_PAD_EXTRACT_FLATTENED      0x80000202
#define CKM_LUNA_AES_CBC_PAD_INSERT_FLATTENED       0x80000203
#define CKM_LUNA_AES_CBC_PAD_EXTRACT_DOMAIN_CTRL    0x80000204
#define CKM_LUNA_AES_CBC_PAD_INSERT_DOMAIN_CTRL     0x80000205
//defined as CKM_DES3_DERIVE_ECB in Eracom PTKC
#define CKM_LUNA_PLACE_HOLDER_FOR_ERACOME_DEF_IN_SHIM 0x80000502
#define CKM_LUNA_DES2_DUKPT_PIN                     0x80000611
#define CKM_LUNA_DES2_DUKPT_MAC                     0x80000612
#define CKM_LUNA_DES2_DUKPT_MAC_RESP                0x80000613
#define CKM_LUNA_DES2_DUKPT_DATA                    0x80000614
#define CKM_LUNA_DES2_DUKPT_DATA_RESP               0x80000615
#define CKM_LUNA_ECIES                              0x80000A00
#define CKM_LUNA_XOR_BASE_AND_DATA_W_KDF            0x80000A01
#define CKM_LUNA_NIST_PRF_KDF                       0x80000A02
#define CKM_LUNA_PRF_KDF                            0x80000A03
#define CKM_LUNA_AES_XTS                            0x80000A04
#define CKM_LUNA_SM3                                0x80000B01
#define CKM_LUNA_SM3_HMAC                           0x80000B02
#define CKM_LUNA_SM3_HMAC_GENERAL                   0x80000B03
#define CKM_LUNA_SM3_KEY_DERIVATION                 0x80000B04
#define CKM_LUNA_EC_EDWARDS_KEY_PAIR_GEN            0x80000C01
#define CKM_LUNA_EDDSA_NACL                         0x80000C02 // ed25519 sign/verify - NaCl compatible
#define CKM_LUNA_EDDSA                              0x80000C03 // ed25519 sign/verify
#define CKM_LUNA_SHA1_EDDSA_NACL                    0x80000C04
#define CKM_LUNA_SHA224_EDDSA_NACL                  0x80000C05
#define CKM_LUNA_SHA256_EDDSA_NACL                  0x80000C06
#define CKM_LUNA_SHA384_EDDSA_NACL                  0x80000C07
#define CKM_LUNA_SHA512_EDDSA_NACL                  0x80000C08
#define CKM_LUNA_SHA1_EDDSA                         0x80000C09
#define CKM_LUNA_SHA224_EDDSA                       0x80000C0A
#define CKM_LUNA_SHA256_EDDSA                       0x80000C0B
#define CKM_LUNA_SHA384_EDDSA                       0x80000C0C
#define CKM_LUNA_SHA512_EDDSA                       0x80000C0D
#define CKM_LUNA_EC_MONTGOMERY_KEY_PAIR_GEN         0x80000D01
#define CKM_LUNA_SM3                                0x80000B01
#define CKM_LUNA_SM3_HMAC                           0x80000B02
#define CKM_LUNA_SM3_HMAC_GENERAL                   0x80000B03
#define CKM_LUNA_SM3_KEY_DERIVATION                 0x80000B04
#define CKM_LUNA_BIP32_MASTER_DERIVE                0x80000E00
#define CKM_LUNA_BIP32_CHILD_DERIVE                 0x80000E01

#endif  /* _CRYPTOKI_LUNA_H_ */
