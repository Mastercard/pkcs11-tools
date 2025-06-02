/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * Copyright (c) 2018 Mastercard
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __PKCS11LIB_H__
#define __PKCS11LIB_H__

#include "config.h"

#include <stddef.h>		/* needed for size_t */
#include <stdio.h>		/* needed for FILE */
#include <stdbool.h>		/* needed for bool type */
#include <openssl/bio.h>	/* needed for BIO */

/* add support for dmalloc */
#ifdef DEBUG_DMALLOC
#  include <dmalloc.h>
#endif


#include "cryptoki.h"

/* grammar version, for wrapped keys */
#define  SUPPORTED_GRAMMAR_VERSION "2.2"
#define  TOOLKIT_VERSION_SUPPORTING_GRAMMAR "2.5.0"

/* Program Error Codes */
#define RC_OK                    0x00
#define RC_DLOPEN_ERROR          0x01
#define RC_DLSYM_ERROR		 0x02
#define RC_DLFUNC_ERROR		 0x03
#define RC_ERROR_MEMORY		 0x04
#define RC_ERROR_LIBRARY	 0x05
#define RC_ERROR_GETOPT		 0x06
#define RC_ERROR_READ_INPUT	 0x07
#define RC_ERROR_USAGE		 0x08
#define RC_ERROR_INVALID_HANDLE	 0x09
#define RC_ERROR_OBJECT_EXISTS   0x0a
#define RC_ERROR_PKCS11_API      0x0b
#define RC_ERROR_KEYGEN_FAILED   0x0c
#define RC_ERROR_OBJECT_NOT_FOUND 0x0d

typedef enum e_func_rc {
    rc_ok,
    rc_dlopen_error,
    rc_dlsym_error,
    rc_dlfunc_error,
    rc_error_memory,
    rc_error_invalid_slot_or_token,
    rc_error_library,
//    rc_error_getopt,
//    rc_error_read_input,
    rc_error_usage,
    rc_error_prompt,
//    rc_error_invalid_handle,
    rc_error_object_exists,
    rc_error_pkcs11_api,
    rc_error_object_not_found,
//    rc_error_keygen_failed,
    rc_error_invalid_label,
    rc_error_envelope_wrapping_unsupported, /* issue for JWK which does not support envelope wrapping */
    rc_error_wrapping_key_too_short,
    rc_error_openssl_api,
//    rc_error_regex_compile,
//    rc_error_regex_nomatch,
    rc_error_unknown_wrapping_alg,
//    rc_error_not_yet_implemented,
    rc_error_invalid_parameter_for_method,
    rc_error_invalid_argument,
    rc_error_unsupported,
    rc_error_parsing,		/* issue when parsing a file  */
    rc_error_oops,		/* "assertion" like error. */
    rc_error_wrong_key_type,	/* if the key type wanted doesn't match */
    rc_error_wrong_object_class,
    rc_warning_not_entirely_completed, /* when a command has only partially succeeded */
    rc_error_other_error,
    rc_error_insecure,
    rc_error_dsa_missing_public_key,
    rc_error_ec_or_ed_missing_public_key,
    rc_error_lexer,
} func_rc;

#define AES_WRAP_MECH_SIZE_MAX 8 /* for both rfc3394 and rfc5496, remember the compatible */
				 /* mechanisms. We don't anticipate that list to be large */

typedef struct s_p11_ctx {
    char *library;
    char *nssinitparams;		/* NSS configDir */
    void *libhandle;			/* library handle pointer */
    CK_FUNCTION_LIST FunctionList;
    CK_SLOT_ID slot;
    int slotindex;
    CK_SESSION_HANDLE Session;
    CK_BBOOL initialized;
    CK_BBOOL logged_in;
#ifdef HAVE_DUPLICATES_ENABLED
    CK_BBOOL can_duplicate;
#endif

    /* in support to rfc3394: */
    /* the following table will contain a list of AES wrapping mechanisms */
    /* supported by the selected token. On PKCS#11 v2.40, the standard is */
    /* called CKM_AES_KEY_WRAP, but many vendors have their own vendor-   */
    /* specific implementation. These will be tried.                      */
    CK_MECHANISM_TYPE rfc3394_mech[AES_WRAP_MECH_SIZE_MAX];
    size_t rfc3394_mech_size;
    /* in support to rfc5649: */
    /* the following table will contain a list of AES wrapping mechanisms */
    /* supported by the selected token. On PKCS#11 v2.40, the standard is */
    /* called CKM_AES_KEY_WRAP_PAD, but many vendors have their own       */
    /* vendor-specific implementation.                                    */
    CK_MECHANISM_TYPE rfc5649_mech[AES_WRAP_MECH_SIZE_MAX];
    size_t rfc5649_mech_size;
} pkcs11Context;

typedef struct CK_NSS_C_INITIALIZE_ARGS {
	CK_CREATEMUTEX CreateMutex;
	CK_DESTROYMUTEX DestroyMutex;
	CK_LOCKMUTEX LockMutex;
	CK_UNLOCKMUTEX UnlockMutex;
	CK_FLAGS flags;
	CK_CHAR_PTR *LibraryParameters;
	CK_VOID_PTR pReserved;
} CK_NSS_C_INITIALIZE_ARGS;

/* pkcs11_idtemplate */
#define IDTMPL_RESOURCE_POS  0
#define IDTMPL_OBJECT_CLASS_POS 1
#define IDTMPL_TEMPLATE_SIZE 10


typedef struct s_p11_idtmpl {
    CK_ATTRIBUTE*    template;
    CK_ULONG         template_len;
    CK_OBJECT_CLASS  oclass;
    CK_BBOOL         has_resource; /* resource is one of CKA_ID, CKA_LABEL, CKA_SERIAL_NUMBER */
    CK_BBOOL         has_class;
} pkcs11IdTemplate;

/* pkcs11_search */
typedef struct s_p11_srch {
    pkcs11Context *p11Context;
    CK_C_FindObjectsInit FindObjectsInit;
    CK_C_FindObjects FindObjects;
    CK_C_FindObjectsFinal FindObjectsFinal;

    CK_OBJECT_HANDLE *handle_array;
    CK_ULONG allocated;
    CK_ULONG count;
    CK_ULONG index;

} pkcs11Search;

/* pkcs11_keycomp */

typedef void * KeyImportCtx;

typedef struct s_p11_attrlist {
    pkcs11Context *p11Context;
    CK_C_GetAttributeValue GetAttributeValue;
    // SetAttributeValue was never read, only set - removing
    // CK_C_SetAttributeValue SetAttributeValue;

    CK_ATTRIBUTE *attr_array;
    CK_ULONG allocated;
    bool cast;			/* this flag is to know how was the object created */
    bool has_template;		/* this flag to remember if we have template attributes */
} pkcs11AttrList;


/* supported key types */
typedef enum {
    unknown,
    aes,
    des,
    des2,			/* des3 double length */
    des3,			/* des3 triple length */
    rsa,
    ec,				/* Regular EC */
    ed,				/* Edwards EC */
    dsa,
    dh,
    generic,
#if defined(HAVE_NCIPHER)
    hmacsha1,
    hmacsha224,
    hmacsha256,
    hmacsha384,
    hmacsha512
#endif
} key_type_t;

/* supported wrapping methods */
enum wrappingmethod { w_unknown,     /* unidentified alg */
		      w_pkcs1_15,    /* PKCS#1 v1.5, uses an RSA key for un/wrapping */
		      w_pkcs1_oaep,  /* PKCS#1 OAEP, uses an RSA key for un/wrapping */
		      w_cbcpad,      /* wraps private key (PKCS#8), padding according to PKCS#7, then symmetric key in CBC mode */
		      w_rfc3394,     /* wraps keys according to RFC3394 */
		      w_rfc5649,     /* wraps keys according to RFC5649 */
		      w_envelope,    /* envelope wrapping ( Private Key -> Symmetric Key -> Any Key) */
};

/* supported hashing algorithms */
typedef enum {
    sha1,
    sha224,
    sha256,
    sha384,
    sha512
} hash_alg_t ;

/* supported signature algorithms for generating CSRs and certificates */
/* needed to allow RSA PKCS and RSA PSS as RSA signature algorithms    */
typedef enum {
    s_default,          /* default for the selected algorithm*/
    s_rsa_pkcs1,		/* PKCS#1  (CKM_RSA_PKCS) */
    s_rsa_pss,			/* RSA PSS (CKM_RSA_PKCS_PSS) */
} sig_alg_t ;

/* attribCtx contains a context that can hold parameters parsed from command line
   that contains attributes.
   It currently supports these grammars:
   - CKA_DERIVE=true CKA_LABEL="label" CKA_UNWRAP_TEMPLATE={ CKA_EXTRACTABLE=false ... }
   - the attributes can be shortened by removing the "CKA_" prefix
   - boolean attributes can be true/false, CK_TRUE/CK_FALSE, yes/no, on/off
   - boolean attributes without a value are set to CK_TRUE
   - boolean attributes prefixed with "no" are set to CK_FALSE
   - other attributes follow the same value syntax as for wrappedKeyCtx
 */

typedef struct s_p11_attribctx {
    size_t current_idx;		/* the current index */
    size_t mainlist_idx;	/* the index of the main list */
    // the following three were only ever written, but never read - removing for now.
//    size_t wraptemplate_idx;	/* the index of the wrap template list */
//    size_t unwraptemplate_idx;	/* the index of the unwrap template list */
//    size_t derivetemplate_idx;	/* the index of the derive template list */
    bool has_wrap_template;	/* whether or not we have a wrap template */
    bool has_unwrap_template;	/* whether or not we have an unwrap template */
    bool has_derive_template;	/* whether or not we have a derive template */
    int level;			/* used by parser to prevent mutli-level templates */
    size_t saved_idx;		/* used by lexer to temporary store the index used for the template */

    struct {
	CK_ATTRIBUTE *attrlist;
	size_t attrnum;
    } attrs[4];

    /* the following two members keep track of allowed mechanisms, when specified */
    CK_MECHANISM_TYPE_PTR allowedmechs;
    size_t allowedmechs_len;
} attribCtx;

/* pkcs11_unwrap / pkcs11_wrap / pkcs11_wctx */

typedef struct s_p11_wrappedkeyctx {
    pkcs11Context *p11Context;

    char *wrappingkeylabel;
    char *wrappedkeylabel;		     /* inner key only - outer key will have random name and ID */

    char *filename;			     /* filename used to write wrapping file */

    /* the following two members keep track of allowed mechanisms, when specified */
    CK_MECHANISM_TYPE_PTR allowedmechs;
    size_t allowedmechs_len;

    struct {				     /* inner or outer but never both (by design) */
	CK_MECHANISM_TYPE aes_wrapping_mech;     /* used when wrapping_meth is w_rfc3394 or w_rfc5649 */
	CK_BYTE_PTR iv;			     /* used for CKM_XXX_CBC_PAD and CKM_AES_KEY_WRAP_PAD */
	CK_ULONG iv_len;                         /* used for CBC_XXX_CBC_PAD and CKM_AES_KEY_WRAP_PAD */
    CK_ULONG keysize;           // to handle AES key wrapping with JWK, where identifiers require key size
    } aes_params;
    CK_RSA_PKCS_OAEP_PARAMS_PTR oaep_params; /* inner or outer but never both (by design) */

    CK_BBOOL is_envelope;	/* in case of envelope encryption, remember it here */
    /* outer key is stored in [0], inner key is stored in [1] */
    struct {
	CK_OBJECT_HANDLE wrappingkeyhandle;
	CK_OBJECT_HANDLE wrappedkeyhandle;
	CK_OBJECT_CLASS wrappedkeyobjclass;
	CK_BYTE_PTR wrapped_key_buffer;
	CK_ULONG wrapped_key_len;
	enum wrappingmethod wrapping_meth;
    } key[2];		/* [0] is outer, [1] is inner */

    /* in case there is a public key, the following attributes are used */
    CK_BYTE_PTR pubk_buffer;
    CK_ULONG pubk_len;
    CK_OBJECT_HANDLE pubkhandle;

    attribCtx *wrpkattribs;	     /* structure to hold wrappedkey attributes */
    attribCtx *pubkattribs;	     /* structure to hold public key attributes */

} wrappedKeyCtx;

/* key index, see pkcs11_wctx.c for a comment explaining how this works */
#define WRAPPEDKEYCTX_OUTER_KEY_INDEX 0 /* when w_envelope */
#define WRAPPEDKEYCTX_INNER_KEY_INDEX 1 /* when w_envelope */
#define WRAPPEDKEYCTX_LONE_KEY_INDEX  1 /* for all other wrapping methods */
#define WRAPPEDKEYCTX_INNER_OR_LONE_KEY_INDEX 1
#define WRAPPEDKEYCTX_NO_INDEX        -1 /* when no index is needed */

/* supported content types in .wrap files */
enum contenttype { ct_unknown,	/* unidentified app */
		   ct_appl_p11,	/* application/pkcs11-tools */
};


/* /\* Supplementary flags for NSS *\/ */
/* #define NSSCK_VENDOR_NSS 0x4E534350 /\* NSCP *\/ */
/* #define CKA_NSS (CKA_VENDOR_DEFINED|NSSCK_VENDOR_NSS) */
/* #define CKA_TRUST (CKA_NSS + 0x2000) */

/* /\* "Purpose" trust information *\/ */
/* #define CKA_TRUST_SERVER_AUTH           (CKA_TRUST +  8) */
/* #define CKA_TRUST_CLIENT_AUTH           (CKA_TRUST +  9) */
/* #define CKA_TRUST_CODE_SIGNING          (CKA_TRUST + 10) */
/* #define CKA_TRUST_EMAIL_PROTECTION      (CKA_TRUST + 11) */



#define PASSWORD_NOLOGIN ":::nologin"
#define PASSWORD_EXEC ":::exec:"


/* macros used by internal lib */

/* Endianness : counts for class-based search strings */

#ifdef WORDS_BIGENDIAN
 #define CLASS_CERT "CKA_CLASS/{00 00 00 00 00 00 00 01}"
 #define CLASS_PUBK "CKA_CLASS/{00 00 00 00 00 00 00 02}"
 #define CLASS_PRVK "CKA_CLASS/{00 00 00 00 00 00 00 03}"
 #define CLASS_SECK "CKA_CLASS/{00 00 00 00 00 00 00 04}"
 #define CLASS_DATA "CKA_CLASS/{00 00 00 00 00 00 00 00}"
#else
 #define CLASS_CERT "CKA_CLASS/{01 00 00 00 00 00 00 00}"
 #define CLASS_PUBK "CKA_CLASS/{02 00 00 00 00 00 00 00}"
 #define CLASS_PRVK "CKA_CLASS/{03 00 00 00 00 00 00 00}"
 #define CLASS_SECK "CKA_CLASS/{04 00 00 00 00 00 00 00}"
 #define CLASS_DATA "CKA_CLASS/{00 00 00 00 00 00 00 00}"
#endif

/* prototypes */

/* pkcs11_utils.c */

char * pkcs11_prompt( char *, CK_BBOOL );
void pkcs11_prompt_free_buffer(char *arg);
char * pkcs11_pipe_password( char * passwordexec );
func_rc prompt_for_hex(char *message, char *prompt, char *target, int len);

// char * print_keyClass( CK_ULONG );
// char * print_keyType( CK_ULONG );
// CK_ULONG get_object_class(char *);
CK_ATTRIBUTE_TYPE get_attribute_type(char *arg);

void release_attribute( CK_ATTRIBUTE_PTR arg );
void release_attributes(CK_ATTRIBUTE attrs[], size_t cnt);

char * hex2bin_new(char *label, size_t size, size_t *outsize);
void hex2bin_free(char *ptr);

CK_ATTRIBUTE_PTR get_attribute_for_type_and_value(CK_ATTRIBUTE_TYPE argattrtype, char *arg );
int get_attributes_from_argv( CK_ATTRIBUTE *attrs[] , int pos, int argc, char **argv);
char * label_or_id(CK_ATTRIBUTE_PTR label, CK_ATTRIBUTE_PTR id, char *buffer, int buffer_len);

/* pkcs11_error.c */
func_rc pkcs11_error( CK_RV, char * const );
func_rc pkcs11_warning( CK_RV, char * const );

/* pkcs11_ll_[PLATFORM].c */
/* platform-specific low-level routines */

void * pkcs11_ll_dynlib_open( const char *libname);
void pkcs11_ll_dynlib_close( void * handle );
void * pkcs11_ll_dynlib_getfunc(void *handle, const char *funcname);
void pkcs11_ll_clear_screen(void);
void pkcs11_ll_echo_on(void);
void pkcs11_ll_echo_off(void);
void pkcs11_ll_clear_screen(void);
// void pkcs11_ll_release_screen(void);
char *pkcs11_ll_basename(char *path);
void pkcs11_ll_set_binary(FILE *fp);
unsigned long pkcs11_ll_bigendian_ul(unsigned long argul);

/* pkcs11_context.c */
pkcs11Context * pkcs11_newContext( char *libraryname, char * nssconfigdir );
void pkcs11_freeContext( pkcs11Context *p11Context );
func_rc pkcs11_initialize( pkcs11Context * );
func_rc pkcs11_finalize( pkcs11Context * );

/* pkcs11_GetSession.c */
func_rc pkcs11_open_session( pkcs11Context * p11Context, int slot, char *tokenlabel, char * password, int so, int interactive );
func_rc pkcs11_close_session( pkcs11Context * p11Context );

// int setKeyLabel( pkcs11Context *, CK_OBJECT_HANDLE, char * );
// int showKey( pkcs11Context *, CK_OBJECT_HANDLE );

/* pkcs11_idtemplate.c */
pkcs11IdTemplate* pkcs11_create_id(char* url);
pkcs11IdTemplate * pkcs11_make_idtemplate(char *labelorid);
pkcs11IdTemplate * pkcs11_make_idtemplate_with_extra_attributes(char *labelorid);
void pkcs11_delete_idtemplate(pkcs11IdTemplate * idtmpl) ;
int pkcs11_sizeof_idtemplate(pkcs11IdTemplate *idtmpl);

/* pkcs11_random.c */
func_rc pkcs11_getrandombytes(pkcs11Context *p11Context, CK_BYTE_PTR buffer, CK_ULONG desired_length);

/* pkcs11_peekpoke.c */
CK_OBJECT_HANDLE pkcs11_getObjectHandle( pkcs11Context * p11Context, CK_OBJECT_CLASS oclass, CK_ATTRIBUTE_TYPE idorlabel, CK_BYTE_PTR byteArrayPtr, CK_ULONG byteArrayLen );
// CK_OBJECT_HANDLE pkcs11_findPrivateKeyByLabel( pkcs11Context * p11Context, char *label );
// CK_OBJECT_HANDLE pkcs11_findPublicKeyByLabel( pkcs11Context * p11Context, char *label );
// CK_BBOOL pkcs11_is_mech_supported(pkcs11Context *p11ctx, CK_MECHANISM_TYPE m);


CK_RV pkcs11_setObjectAttribute( pkcs11Context * p11Context, CK_OBJECT_HANDLE objectHandle, CK_ATTRIBUTE_PTR attr);
// CK_RV pkcs11_setObjectAttributes( pkcs11Context * p11Context, CK_OBJECT_HANDLE objectHandle, CK_ATTRIBUTE attrs[], size_t cnt );

// int pkcs11_getObjectAttributes( pkcs11Context * p11Context, CK_OBJECT_HANDLE objectHandle, CK_ATTRIBUTE attr[], int attrlen );
// void pkcs11_freeObjectAttributesValues( CK_ATTRIBUTE attr[], int attrlen);

func_rc pkcs11_adjust_keypair_id(pkcs11Context * p11Context, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey);
CK_ULONG pkcs11_get_object_size(pkcs11Context *p11ctx, CK_OBJECT_HANDLE obj);
void pkcs11_adjust_des_key_parity(CK_BYTE* pucKey, int nKeyLen);
// int pkcs11_get_rsa_modulus_bits(pkcs11Context *p11Context, CK_OBJECT_HANDLE obj);
// int pkcs11_get_dsa_pubkey_bits(pkcs11Context *p11Context, CK_OBJECT_HANDLE hndl);
CK_OBJECT_CLASS pkcs11_get_object_class(pkcs11Context *p11Context, CK_OBJECT_HANDLE hndl);
key_type_t pkcs11_get_key_type(pkcs11Context *p11Context, CK_OBJECT_HANDLE hndl);
char *pkcs11_alloclabelforhandle(pkcs11Context *p11Context, CK_OBJECT_HANDLE hndl);

/* pkcs11_x509.c */

CK_OBJECT_HANDLE pkcs11_importcert( pkcs11Context * p11Context,
				    char *filename,
				    void *x509,
				    char *label,
				    int trusted);

/* pkcs11_pubk.c */
CK_ULONG pkcs11_new_SKI_value_from_pubk(EVP_PKEY *pubkey, CK_BYTE_PTR *buf);

CK_OBJECT_HANDLE pkcs11_importpubk( pkcs11Context * p11Context,
				    char *filename,
				    char *label,
				    CK_ATTRIBUTE attrs[],
				    CK_ULONG numattrs );

CK_OBJECT_HANDLE pkcs11_importpubk_from_buffer( pkcs11Context * p11Context,
						unsigned char *buffer,
						size_t len,
						char *label,
						CK_ATTRIBUTE attrs[],
						CK_ULONG numattrs );


/* pkcs11_data.c */
CK_OBJECT_HANDLE pkcs11_importdata( pkcs11Context * p11Context,
				    char *filename,
				    char *label);

/* pkcs11_ec.c */

bool pkcs11_is_ed_param_named_25519(const uint8_t *ecparam, size_t ecparamlen);
bool pkcs11_is_ed_param_named_448(const uint8_t *ecparam, size_t ecparamlen);

bool pkcs11_ex_curvename2oid(char *name, CK_BYTE **where, CK_ULONG *len, key_type_t keytype);

bool pkcs11_ec_curvename2oid(char *name, CK_BYTE **where, CK_ULONG *len);
char * pkcs11_ec_oid2curvename(CK_BYTE *param, CK_ULONG param_len, char *where, size_t maxlen);
void pkcs11_ec_freeoid(CK_BYTE_PTR buf);

// bool pkcs11_ed_curvename2oid(char *name, CK_BYTE **where, CK_ULONG *len);
char * pkcs11_ed_oid2curvename(CK_BYTE *param, CK_ULONG param_len, char *where, size_t maxlen);
// void pkcs11_ed_freeoid(CK_BYTE_PTR buf);

/* pkcs11_keygen.c */
typedef enum {
    kg_token,			/* token key */
    kg_session_for_wrapping,	/* session key, that will be wrapped */
    kg_token_for_wrapping	/* create session key, wrap, then copy locally as token key */
} key_generation_t;

func_rc pkcs11_genAES( pkcs11Context * p11Context,
		       char *label,
		       CK_ULONG bits,
		       CK_ATTRIBUTE attrs[],
		       CK_ULONG numattrs,
		       CK_OBJECT_HANDLE_PTR hSecretKey,
		       key_generation_t gentype);

func_rc pkcs11_genDESX( pkcs11Context * p11Context,
			char *label,
			CK_ULONG bits,
			CK_ATTRIBUTE attrs[],
			CK_ULONG numattrs,
			CK_OBJECT_HANDLE_PTR hSecretKey,
			key_generation_t gentype);

/* HMAC keys */
func_rc pkcs11_genGeneric( pkcs11Context * p11Context,
			   char *label,
			   key_type_t kt,
			   CK_ULONG bits,
			   CK_ATTRIBUTE attrs[],
			   CK_ULONG numattrs,
			   CK_OBJECT_HANDLE_PTR hSecretKey,
			   key_generation_t gentype);

func_rc pkcs11_genRSA( pkcs11Context * p11Context,
		       char *label,
		       CK_ULONG bits,
		       uint32_t pubexp,
		       CK_ATTRIBUTE attrs[],
		       CK_ULONG numattrs,
		       CK_OBJECT_HANDLE_PTR hPublicKey,
		       CK_OBJECT_HANDLE_PTR hPrivateKey,
		       key_generation_t gentype);

func_rc pkcs11_genEC( pkcs11Context * p11Context,
		      char *label,
		      char *param,
		      CK_ATTRIBUTE attrs[],
		      CK_ULONG numattrs,
		      CK_OBJECT_HANDLE_PTR hPublicKey,
		      CK_OBJECT_HANDLE_PTR hPrivateKey,
		      key_generation_t gentype);

func_rc pkcs11_genED( pkcs11Context * p11Context,
		      char *label,
		      char *param,
		      CK_ATTRIBUTE attrs[],
		      CK_ULONG numattrs,
		      CK_OBJECT_HANDLE_PTR hPublicKey,
		      CK_OBJECT_HANDLE_PTR hPrivateKey,
		      key_generation_t gentype);

int pkcs11_testgenEC_support( pkcs11Context * p11Context, const char *param );

func_rc pkcs11_genDSA(pkcs11Context * p11Context,
		      char *label,
		      char *param,
		      CK_ATTRIBUTE attrs[],
		      CK_ULONG numattrs,
		      CK_OBJECT_HANDLE_PTR hPublicKey,
		      CK_OBJECT_HANDLE_PTR hPrivateKey,
		      key_generation_t gentype);

func_rc pkcs11_genDH(pkcs11Context * p11Context,
		     char *label,
		     char *param,
		     CK_ATTRIBUTE attrs[],
		     CK_ULONG numattrs,
		     CK_OBJECT_HANDLE_PTR hPublicKey,
		     CK_OBJECT_HANDLE_PTR hPrivateKey,
		     key_generation_t gentype);

/* pkcs11_cert_common.c */
X509_NAME *pkcs11_DN_new_from_string(char *subject, long chtype, bool multirdn, bool reverse);
bool pkcs11_X509_check_DN(char *subject);
const EVP_MD *pkcs11_get_EVP_MD(key_type_t key_type, hash_alg_t hash_alg);
EVP_PKEY *pkcs11_SPKI_from_RSA(pkcs11AttrList *attrlist );
EVP_PKEY *pkcs11_SPKI_from_DSA(pkcs11AttrList *attrlist );
EVP_PKEY *pkcs11_SPKI_from_EC(pkcs11AttrList *attrlist );
EVP_PKEY *pkcs11_SPKI_from_ED(pkcs11AttrList *attrlist );


/* pkcs11_req.c */
CK_VOID_PTR pkcs11_create_X509_REQ(pkcs11Context *p11Context,
				   char *dn,
				   bool reverse,
				   bool fake,
				   char *san[],
				   int sancnt,
				   bool ext_ski,
				   key_type_t key_type,
                   sig_alg_t sig_alg,
				   hash_alg_t hash_alg,
				   CK_OBJECT_HANDLE hprivkey,
				   pkcs11AttrList *attrlist) ;

void write_X509_REQ(CK_VOID_PTR req, char *filename, bool verbose);
void pkcs11_free_X509_REQ(CK_VOID_PTR req);

/* pkcs11_cert.c */
CK_VOID_PTR pkcs11_create_X509_CERT(pkcs11Context *p11Context,
				    char *dn,
				    bool reverse,
				    int days,
				    char *san[],
				    int sancnt,
				    bool ext_ski,
				    key_type_t key_type,
                    sig_alg_t sig_alg,
				    hash_alg_t hash_alg,
				    CK_OBJECT_HANDLE hprivkey,
				    pkcs11AttrList *attrlist);

void write_X509_CERT(CK_VOID_PTR crt, char *filename, bool verbose);
void pkcs11_free_X509_CERT(CK_VOID_PTR crt);


// CK_ULONG pkcs11_allocate_and_hash_sha1(CK_BYTE_PTR data, CK_ULONG datalen, CK_VOID_PTR_PTR buf);

/* pkcs11_masq.c */

typedef struct x509_req_handle_struct_t x509_req_handle_t;

x509_req_handle_t *pkcs11_get_X509_REQ_from_file(char *csrfilename);
void x509_req_handle_t_free(x509_req_handle_t *hndl);
bool pkcs11_masq_X509_REQ(x509_req_handle_t *req,
			  char *dn,
			  bool reverse,
			  char *san[],
			  int sancnt,
			  bool ext_ski);


/* pkcs11_search.c */
pkcs11Search *pkcs11_new_search(pkcs11Context *p11Context, CK_ATTRIBUTE_PTR template, CK_ULONG length);
pkcs11Search *pkcs11_new_search_from_idtemplate( pkcs11Context *p11Context, pkcs11IdTemplate *idtmpl);

CK_OBJECT_HANDLE pkcs11_fetch_next(pkcs11Search *p11s);
void pkcs11_delete_search(pkcs11Search *p11s);
int pkcs11_label_exists(pkcs11Context *p11Context, char *label);
int pkcs11_privatekey_exists(pkcs11Context *p11Context, char *label);
int pkcs11_publickey_exists(pkcs11Context *p11Context, char *label);
int pkcs11_secretkey_exists(pkcs11Context *p11Context, char *label);
int pkcs11_certificate_exists(pkcs11Context *p11Context, char *label);
int pkcs11_data_exists(pkcs11Context *p11Context, char *label);
int pkcs11_findkeypair(pkcs11Context *p11Context, char *label, CK_OBJECT_HANDLE_PTR hPublicKey, CK_OBJECT_HANDLE_PTR hPrivateKey);
int pkcs11_findpublickey(pkcs11Context *p11Context, char *label, CK_OBJECT_HANDLE_PTR hPublicKey);
int pkcs11_findprivatekey(pkcs11Context *p11Context, char *label, CK_OBJECT_HANDLE_PTR hPublicKey);
int pkcs11_findsecretkey(pkcs11Context *p11Context, char *label, CK_OBJECT_HANDLE_PTR hSecretKey);
int pkcs11_findprivateorsecretkey(pkcs11Context *p11Context, char *label, CK_OBJECT_HANDLE_PTR hKey, CK_OBJECT_CLASS *oclass);


/* pkcs11_attr.c */

#define _ATTR(attr) (CK_ATTRIBUTE_TYPE)(attr)
#define  _ATTR_END  _ATTR(0xFFFFFFFFL)

pkcs11AttrList *pkcs11_new_attrlist(pkcs11Context *p11Context, ...);
pkcs11AttrList *pkcs11_new_attrlist_from_array(pkcs11Context *p11Context, CK_ATTRIBUTE_PTR attrs, CK_ULONG attrlen);
pkcs11AttrList *pkcs11_cast_to_attrlist(pkcs11Context *p11Context, CK_ATTRIBUTE_PTR attrs, CK_ULONG numattrs);

// void pkcs11_attrlist_assign_context(pkcs11AttrList *attrlist, pkcs11Context *p11Context);

bool pkcs11_set_attr_in_attrlist ( pkcs11AttrList *attrlist,
				   CK_ATTRIBUTE_TYPE attrib,
				   CK_VOID_PTR pvalue,
				   CK_ULONG len );

bool pkcs11_attrlist_has_attribute(const pkcs11AttrList *attrlist, CK_ATTRIBUTE_TYPE attr);
CK_ATTRIBUTE_PTR pkcs11_get_attr_in_attrlist ( pkcs11AttrList *attrlist,
					       CK_ATTRIBUTE_TYPE attrib );

CK_ATTRIBUTE_PTR pkcs11_get_attr_in_array ( CK_ATTRIBUTE_PTR array,
					    size_t arraysize, /* in bytes */
					    CK_ATTRIBUTE_TYPE attrib );

bool pkcs11_read_attr_from_handle ( pkcs11AttrList *attrlist, CK_OBJECT_HANDLE handle);
bool pkcs11_read_attr_from_handle_ext ( pkcs11AttrList *attrlist, CK_OBJECT_HANDLE handle, ... );
bool pkcs11_attr_is_template(CK_ATTRIBUTE_TYPE attrtype);
bool pkcs11_attr_is_allowed_mechanisms(CK_ATTRIBUTE_TYPE attrtype);

pkcs11AttrList *pkcs11_attrlist_extend(pkcs11AttrList *attrlist, CK_ATTRIBUTE_PTR attrs, CK_ULONG numattrs);

void pkcs11_delete_attrlist(pkcs11AttrList *attrlist);

CK_ATTRIBUTE * const pkcs11_attrlist_get_attributes_array(pkcs11AttrList *attrlist);
CK_ULONG const pkcs11_attrlist_get_attributes_len(pkcs11AttrList *attrlist);

/* pkcs11_openssl.c */
const char * pkcs11_openssl_version(void);
void pkcs11_openssl_error(char * file, int line);
#define P_ERR() pkcs11_openssl_error(__FILE__,__LINE__)

CK_ULONG pkcs11_openssl_alloc_and_sha1(CK_BYTE_PTR data, CK_ULONG datalen, CK_VOID_PTR_PTR buf);
void pkcs11_openssl_free(CK_VOID_PTR_PTR buf);

/* pkcs11_ossl_rsa_meth.c */
void pkcs11_rsa_method_setup();
void pkcs11_rsa_method_pkcs11_context(pkcs11Context * p11Context, CK_OBJECT_HANDLE hPrivateKey, bool fake);

/* pkcs11_ossl_dsa_meth.c */
void pkcs11_dsa_method_setup();
void pkcs11_dsa_method_pkcs11_context(pkcs11Context * p11Context, CK_OBJECT_HANDLE hPrivateKey, bool fake);

/* pkcs11_ossl_ecdsa_meth.c */
void pkcs11_ecdsa_method_setup();
void pkcs11_ecdsa_method_pkcs11_context(pkcs11Context * p11Context, CK_OBJECT_HANDLE hPrivateKey, bool fake);

/* pkcs11_ossl_eddsa_meth.c */
void pkcs11_eddsa_method_setup();
void pkcs11_eddsa_method_pkcs11_context(pkcs11Context * p11Context, CK_OBJECT_HANDLE hPrivateKey, bool fake);


/* list functions */
// int pkcs11_ls_certs(pkcs11Context *p11Context);
// int pkcs11_ls_pubk(pkcs11Context *p11Context);
// int pkcs11_ls_privk(pkcs11Context *p11Context);
// int pkcs11_ls_secrk(pkcs11Context *p11Context);
// int pkcs11_ls_data(pkcs11Context *p11Context);
func_rc pkcs11_ls( pkcs11Context *p11Context, char *pattern);


/* rm functions */
int pkcs11_rm_objects_with_label(pkcs11Context *p11Context, char *label, int interactive, int verbose);

/* mv functions */
int pkcs11_mv_objects(pkcs11Context *p11Context, char *source, char *dest, int interactive, int verbose);

/* cp functions */
int pkcs11_cp_objects(pkcs11Context *p11Context, char *source, char *dest, int interactive, int verbose);

/* cat functions */
func_rc pkcs11_cat_object_with_label(pkcs11Context *p11Context, char *label, int openssl_native, BIO *sink);
func_rc pkcs11_cat_object_with_handle(pkcs11Context *p11Context, CK_OBJECT_HANDLE hndl, int openssl_native, BIO *sink);

/* more functions */
func_rc pkcs11_more_object_with_label(pkcs11Context *p11Context, char *label);

/* od functions */
func_rc pkcs11_dump_object_with_label(pkcs11Context *p11Context, char *label);

/* keycomp functions */
KeyImportCtx * pkcs11_import_component_init(pkcs11Context *p11Context, char *unwrappinglabel, char *targetlabel);
func_rc pkcs11_import_component(KeyImportCtx *kctx, unsigned char * comp, size_t len);
CK_OBJECT_HANDLE pkcs11_import_component_final(KeyImportCtx *kctx);


/* info functions */
CK_MECHANISM_TYPE pkcs11_get_mechanism_type_from_name(char *name); /* pkcs11_mechanism.c */
const char *pkcs11_get_mechanism_name_from_type(CK_MECHANISM_TYPE mech); /* pkcs11_mechanism.c */
CK_ATTRIBUTE_TYPE pkcs11_get_attribute_type_from_name(char *name); /* pkcs11_attrdesc.c */
// const char *pkcs11_get_attribute_name_from_type(CK_ATTRIBUTE_TYPE attrtyp); /* pkcs11_attrdesc.c */

func_rc pkcs11_info_library(pkcs11Context *p11Context);
func_rc pkcs11_info_slot(pkcs11Context *p11Context);
func_rc pkcs11_info_ecsupport(pkcs11Context *p11Context);

/* chattr function */
func_rc pkcs11_change_object_attributes(pkcs11Context *p11Context, char *label, CK_ATTRIBUTE *attr, size_t cnt, int interactive );

/* kcv functions */

/* supported MAC algorithms, for p11kcv */
typedef enum {
    legacy,			/* legacy is used to behave like before: it picks the old algorithm, based upon the key type */
    kcv,            /* tries to use CKA_CHECK_VALUE attribute if found */
    hash_sha1,
    hash_sha256,
    hash_sha384,
    hash_sha512,
    ecb,			/* CKM_XXX_ECB method - can be used with an encryption key instead */
    mac,			/* CKM_XXX_MAC */
    cmac,			/* CKM_XXX_CMAC */
    aes_xcbc_mac,		/* CKM_AES_XCBC_MAC */
    aes_xcbc_mac_96,		/* CKM_AES_XCBC_MAC_96 */
} mac_alg_t;

#define MAX_KCV_CLEARTEXT_SIZE 256
void pkcs11_display_kcv( pkcs11Context *p11Context, char *label, unsigned hmacdatasize, mac_alg_t algo, size_t kcvsize);

/* wrap/unwrap functions */
func_rc pkcs11_prepare_wrappingctx(wrappedKeyCtx *wctx, char *wrappingjob);
func_rc pkcs11_wrap_from_label(wrappedKeyCtx *wctx, char *wrappedkeylabel);
func_rc pkcs11_wrap_from_handle(wrappedKeyCtx *wctx, CK_OBJECT_HANDLE wrappedkeyhandle, CK_OBJECT_HANDLE pubkhandle);
func_rc pkcs11_output_wrapped_key( wrappedKeyCtx *wctx, bool jwkoutput, char* wrapping_key_id);

wrappedKeyCtx *pkcs11_new_wrapped_key_from_file(pkcs11Context *p11Context, char *filename);
func_rc pkcs11_unwrap(pkcs11Context *p11Context, wrappedKeyCtx *ctx, char *wrappingkeylabel, char *wrappedkeylabel, CK_ATTRIBUTE attrs[], CK_ULONG numattrs, key_generation_t keygentype );
const CK_OBJECT_HANDLE pkcs11_get_wrappedkeyhandle(wrappedKeyCtx *ctx);
const CK_OBJECT_HANDLE pkcs11_get_publickeyhandle(wrappedKeyCtx *ctx);

wrappedKeyCtx *pkcs11_new_wrappedkeycontext(pkcs11Context *p11Context);
void pkcs11_free_wrappedkeycontext(wrappedKeyCtx *wctx);
CK_MECHANISM_TYPE_PTR pkcs11_wctx_get_allowed_mechanisms(wrappedKeyCtx *ctx);
size_t pkcs11_wctx_get_allowed_mechanisms_len(wrappedKeyCtx *ctx);
void pkcs11_wctx_free_mechanisms(wrappedKeyCtx *wctx); /* to free allowed mechanisms */
void pkcs11_wctx_forget_mechanisms(wrappedKeyCtx *wctx); /* for transfer of ownership */

/* pkcs11_attribctx */
attribCtx *pkcs11_new_attribcontext();
void pkcs11_free_attribcontext(attribCtx *ctx);
func_rc pkcs11_parse_attribs_from_argv(attribCtx *ctx , int pos, int argc, char **argv, const char *additional);
CK_ATTRIBUTE_PTR pkcs11_get_attrlist_from_attribctx(attribCtx *ctx);
size_t pkcs11_get_attrnum_from_attribctx(attribCtx *ctx);
void pkcs11_adjust_attrnum_on_attribctx(attribCtx *ctx, size_t value);

func_rc pkcs11_attribctx_add_mechanism(attribCtx *ctx, CK_MECHANISM_TYPE attrtype);
func_rc pkcs11_attribctx_free_mechanisms(attribCtx *ctx);
void pkcs11_attribctx_forget_mechanisms(attribCtx *ctx);
CK_MECHANISM_TYPE_PTR pkcs11_attribctx_get_allowed_mechanisms(attribCtx *ctx);
size_t pkcs11_attribctx_get_allowed_mechanisms_len(attribCtx *ctx);


/* End - Function Prototypes */

/* Callback Prompt Strings */
#define SLOT_PROMPT_STRING			"Enter slot index: "
#define PASS_PROMPT_STRING			"Enter passphrase for token: "
// #define TOKEN_PASS_PROMPT_STRING		"Enter passphrase for token '%s': "

#define MAXBUFSIZE              1024
// #define MAXKEYS			2000
// #define MAX_KEY_LABEL_SIZE	32
// #define MAX_BYTE_ARRAY_SIZE	20

#define PARSING_MAX_ATTRS       32   /* max number of attributes inside a wrap file */
#define CMDLINE_MAX_ATTRS       32   /* max number of attributes for cmdline parsing */

#endif

/*
 *--------------------------------------------------------------------------------
 * $Log$
 *--------------------------------------------------------------------------------
*/
