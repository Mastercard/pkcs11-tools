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
#include <openssl/bio.h>	/* needed for BIO */

/* add support for dmalloc */
#ifdef DEBUG_DMALLOC
#  include <dmalloc.h>
#endif


#include "cryptoki.h"

/* grammar version, for wrapped keys */
#define  SUPPORTED_GRAMMAR_VERSION "2.0"
#define  TOOLKIT_VERSION_SUPPORTING_GRAMMAR "2.0.0"

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
    rc_error_getopt,
    rc_error_read_input,
    rc_error_usage,
    rc_error_prompt,
    rc_error_invalid_handle,
    rc_error_object_exists,
    rc_error_pkcs11_api,
    rc_error_object_not_found,
    rc_error_keygen_failed,
    rc_error_invalid_label,
    rc_error_wrapping_key_too_short,
    rc_error_openssl_api,
    rc_error_regex_compile,
    rc_error_regex_nomatch,
    rc_error_unknown_wrapping_alg,
    rc_error_not_yet_implemented,
    rc_error_invalid_parameter_for_method,
    rc_error_invalid_argument,
    rc_error_unsupported,
    rc_error_parsing,		/* issue when parsing a file  */
    rc_error_oops,		/* "assertion" like error. */
    rc_error_wrong_key_type,	/* if the key type wanted doesn't match */
    rc_error_wrong_object_class,
    rc_warning_not_entirely_completed, /* when a command has only partially succeeded */
    rc_error_other_error,
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
    CK_BBOOL logged_in;

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


typedef struct s_p11_idtmpl {
    CK_ATTRIBUTE     template[2];
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
    CK_C_SetAttributeValue SetAttributeValue;

    CK_ATTRIBUTE *attr_array;
    CK_ULONG allocated;
    int cast;			/* this flag is to know how was the object created */
} pkcs11AttrList;


/* supported key types */
enum keytype { unknown, aes, des, rsa, ec, dsa, dh, generic,
	       hmacsha1,
	       hmacsha224,
	       hmacsha256,
	       hmacsha384,
	       hmacsha512};

/* supported wrapping methods */
enum wrappingmethod { w_unknown,     /* unidentified alg */
		      w_pkcs1_15,    /* PKCS#1 v1.5, uses an RSA key for un/wrapping */
		      w_pkcs1_oaep,  /* PKCS#1 OAEP, uses an RSA key for un/wrapping */
		      w_cbcpad,      /* wraps private key (PKCS#8), padding according to PKCS#7, then symmetric key in CBC mode */
		      w_rfc3394,     /* wraps keys according to RFC3394 */
		      w_rfc5649,     /* wraps keys according to RFC5649 */
		      w_envelope,    /* envelope wrapping ( Private Key -> Symmetric Key -> Any Key) */
};

/* pkcs11_unwrap / pkcs11_wrap / pkcs11_wctx */

typedef struct s_p11_wrappedkeyctx {
    pkcs11Context *p11Context;
    CK_ATTRIBUTE *attrlist;	             /* inner key only */
    CK_ULONG attrlen;			     /* inner key only */
    char *wrappingkeylabel;
    char *wrappedkeylabel;	             /* inner key only - outer key will have random name and ID */
    char *filename;			     /* filename used to write wrapping file */
    struct {				     /* inner or outer but never both (by design) */
	CK_MECHANISM_TYPE aes_wrapping_mech;     /* used when wrapping_meth is w_rfc3394 or w_rfc5649 */
	CK_BYTE_PTR iv;			     /* used for CKM_XXX_CBC_PAD and CKM_AES_KEY_WRAP_PAD */
	CK_ULONG iv_len;                         /* used for CBC_XXX_CBC_PAD and CKM_AES_KEY_WRAP_PAD */
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
    CK_ATTRIBUTE *pubkattrlist;
    CK_ULONG pubkattrlen;
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

char * print_keyClass( CK_ULONG );
char * print_keyType( CK_ULONG );
CK_ULONG get_object_class(char *);
CK_ATTRIBUTE_TYPE get_attribute_type(char *arg);

void release_attribute( CK_ATTRIBUTE_PTR arg );
void release_attributes(CK_ATTRIBUTE attrs[], size_t cnt);

char * hex2bin_new(char *label, size_t size, size_t *outsize);
void hex2bin_free(char *ptr);

CK_ATTRIBUTE_PTR get_attribute_for_type_and_value(CK_ATTRIBUTE_TYPE argattrtype, char *arg );
int get_attributes_from_argv( CK_ATTRIBUTE *attrs[] , int pos, int argc, char **argv);
char * label_or_id(CK_ATTRIBUTE_PTR label, CK_ATTRIBUTE_PTR id, char *buffer, int buffer_len);
void pkcs11_error( CK_RV, char * );

/* pkcs11_ll_[PLATFORM].c */
/* platform-specific low-level routines */

void * pkcs11_ll_dynlib_open( const char *libname);
void pkcs11_ll_dynlib_close( void * handle );
void * pkcs11_ll_dynlib_getfunc(void *handle, const char *funcname);
void pkcs11_ll_clear_screen(void);
void pkcs11_ll_echo_on(void);
void pkcs11_ll_echo_off(void);
void pkcs11_ll_clear_screen(void);
void pkcs11_ll_release_screen(void);
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

int setKeyLabel( pkcs11Context *, CK_OBJECT_HANDLE, char * );
int showKey( pkcs11Context *, CK_OBJECT_HANDLE );

/* pkcs11_idtemplate.c */
pkcs11IdTemplate * pkcs11_make_idtemplate(char *labelorid);
void pkcs11_delete_idtemplate(pkcs11IdTemplate * idtmpl) ;
int pkcs11_sizeof_idtemplate(pkcs11IdTemplate *idtmpl);

/* pkcs11_random.c */
func_rc pkcs11_getrandombytes(pkcs11Context *p11Context, CK_BYTE_PTR buffer, CK_ULONG desired_length);

/* pkcs11_peekpoke.c */
CK_OBJECT_HANDLE pkcs11_getObjectHandle( pkcs11Context * p11Context, CK_OBJECT_CLASS oclass, CK_ATTRIBUTE_TYPE idorlabel, CK_BYTE_PTR byteArrayPtr, CK_ULONG byteArrayLen );
CK_OBJECT_HANDLE pkcs11_findPrivateKeyByLabel( pkcs11Context * p11Context, char *label );
CK_OBJECT_HANDLE pkcs11_findPublicKeyByLabel( pkcs11Context * p11Context, char *label );
CK_BBOOL pkcs11_is_mech_supported(pkcs11Context *p11ctx, CK_MECHANISM_TYPE m);


CK_RV pkcs11_setObjectAttribute( pkcs11Context * p11Context, CK_OBJECT_HANDLE objectHandle, CK_ATTRIBUTE_PTR attr);
CK_RV pkcs11_setObjectAttributes( pkcs11Context * p11Context, CK_OBJECT_HANDLE objectHandle, CK_ATTRIBUTE attrs[], size_t cnt );

int pkcs11_getObjectAttributes( pkcs11Context * p11Context, CK_OBJECT_HANDLE objectHandle, CK_ATTRIBUTE attr[], int attrlen );
void pkcs11_freeObjectAttributesValues( CK_ATTRIBUTE attr[], int attrlen);

int pkcs11_adjust_keypair_id(pkcs11Context * p11Context, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey);
CK_ULONG pkcs11_get_object_size(pkcs11Context *p11ctx, CK_OBJECT_HANDLE obj);
void pkcs11_adjust_des_key_parity(CK_BYTE* pucKey, int nKeyLen);
int pkcs11_get_rsa_modulus_bits(pkcs11Context *p11Context, CK_OBJECT_HANDLE obj);
int pkcs11_get_dsa_pubkey_bits(pkcs11Context *p11Context, CK_OBJECT_HANDLE hndl);
CK_OBJECT_CLASS pkcs11_get_object_class(pkcs11Context *p11Context, CK_OBJECT_HANDLE hndl);
CK_KEY_TYPE pkcs11_get_key_type(pkcs11Context *p11Context, CK_OBJECT_HANDLE hndl);
char *pkcs11_alloclabelforhandle(pkcs11Context *p11Context, CK_OBJECT_HANDLE hndl);

/* pkcs11_x509.c */

CK_OBJECT_HANDLE pkcs11_importcert( pkcs11Context * p11Context,
				    char *filename,
				    char *label,
				    int trusted);

/* pkcs11_pubk.c */
CK_OBJECT_HANDLE pkcs11_importpubk( pkcs11Context * p11Context,
				    char *filename,
				    char *label,
				    int trusted,
				    CK_ATTRIBUTE attrs[],
				    CK_ULONG numattrs );

CK_OBJECT_HANDLE pkcs11_importpubk_from_buffer( pkcs11Context * p11Context,
						unsigned char *buffer,
						size_t len,
						char *label,
						int trusted,
						CK_ATTRIBUTE attrs[],
						CK_ULONG numattrs );


/* pkcs11_data.c */
CK_OBJECT_HANDLE pkcs11_importdata( pkcs11Context * p11Context,
				    char *filename,
				    char *label);

/* pkcs11_ec.c */

CK_BBOOL pkcs11_ec_curvename2oid(char *name, CK_BYTE **where, CK_ULONG *len);
char * pkcs11_ec_oid2curvename(CK_BYTE *param, CK_ULONG param_len, char *where, size_t maxlen);
void pkcs11_ec_freeoid(CK_BYTE_PTR buf);

/* pkcs11_keygen.c */
typedef enum {
    kg_token,
    kg_session_for_wrapping
} key_generation_t;

int pkcs11_genAES( pkcs11Context * p11Context,
		   char *label,
		   CK_ULONG bits,
		   CK_ATTRIBUTE attrs[],
		   CK_ULONG numattrs,
		   CK_OBJECT_HANDLE_PTR hSecretKey,
                   key_generation_t gentype);

int pkcs11_genDESX( pkcs11Context * p11Context,
		    char *label,
		    CK_ULONG bits,
		    CK_ATTRIBUTE attrs[],
		    CK_ULONG numattrs,
		    CK_OBJECT_HANDLE_PTR hSecretKey,
		    key_generation_t gentype);

/* HMAC keys */
int pkcs11_genGeneric( pkcs11Context * p11Context,
		       char *label,
		       enum keytype kt,
		       CK_ULONG bits,
		       CK_ATTRIBUTE attrs[],
		       CK_ULONG numattrs,
		       CK_OBJECT_HANDLE_PTR hSecretKey,
		       key_generation_t gentype);

int pkcs11_genRSA( pkcs11Context * p11Context,
		   char *label,
		   CK_ULONG bits,
		   CK_ATTRIBUTE attrs[],
		   CK_ULONG numattrs,
		   CK_OBJECT_HANDLE_PTR hPublicKey,
		   CK_OBJECT_HANDLE_PTR hPrivateKey,
		   key_generation_t gentype);


int pkcs11_genECDSA( pkcs11Context * p11Context,
		     char *label,
		     char *param,
		     CK_ATTRIBUTE attrs[],
		     CK_ULONG numattrs,
		     CK_OBJECT_HANDLE_PTR hPublicKey,
		     CK_OBJECT_HANDLE_PTR hPrivateKey,
		     key_generation_t gentype);

int pkcs11_testgenECDSA_support( pkcs11Context * p11Context, const char *param );

int pkcs11_genDSA(pkcs11Context * p11Context,
		  char *label,
		  char *param,
		  CK_ATTRIBUTE attrs[],
		  CK_ULONG numattrs,
		  CK_OBJECT_HANDLE_PTR hPublicKey,
		  CK_OBJECT_HANDLE_PTR hPrivateKey,
		  key_generation_t gentype);

int pkcs11_genDH(pkcs11Context * p11Context,
		 char *label,
		 char *param,
		 CK_ATTRIBUTE attrs[],
		 CK_ULONG numattrs,
		 CK_OBJECT_HANDLE_PTR hPublicKey,
		 CK_OBJECT_HANDLE_PTR hPrivateKey,
		 key_generation_t gentype);


/* pkcs11_req.c */

int pkcs11_X509_REQ_check_DN(char *subject);
CK_VOID_PTR pkcs11_create_unsigned_X509_REQ(char *dn, int reverse, char *san[], int sancnt, CK_ATTRIBUTE_PTR ski, CK_ATTRIBUTE_PTR modulus, CK_ATTRIBUTE_PTR exponent);

CK_VOID_PTR pkcs11_create_unsigned_X509_REQ_DSA(char *dn, int reverse, char *san[], int sancnt, CK_ATTRIBUTE_PTR ski, CK_ATTRIBUTE_PTR prime, CK_ATTRIBUTE_PTR subprime, CK_ATTRIBUTE_PTR base, CK_ATTRIBUTE_PTR pubkey );

CK_VOID_PTR pkcs11_create_unsigned_X509_REQ_EC(char *dn, int reverse, char *san[], int sancnt, CK_ATTRIBUTE_PTR ski, char *curvename, CK_ATTRIBUTE_PTR p_ec_point, int *degree);

int pkcs11_sign_X509_REQ(pkcs11Context * p11Context, CK_VOID_PTR req, int outputbytes, CK_OBJECT_HANDLE hPrivateKey, CK_MECHANISM_TYPE mechtype, int fake);
void write_X509_REQ(CK_VOID_PTR req, char *filename, int verbose);
CK_ULONG pkcs11_allocate_and_hash_sha1(CK_BYTE_PTR data, CK_ULONG datalen, CK_VOID_PTR_PTR buf);


CK_BBOOL pkcs11_extract_pubk_from_X509_REQ(char *csrfilename, CK_ATTRIBUTE_PTR modulus, CK_ATTRIBUTE_PTR exponent);
void pkcs11_free_X509_REQ_attributes(CK_ATTRIBUTE_PTR modulus, CK_ATTRIBUTE_PTR exponent);
int pkcs11_fakesign_X509_REQ(CK_VOID_PTR req, int pubkeybits, CK_MECHANISM_TYPE mechtype); /* perform fake signature */


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

void pkcs11_attrlist_assign_context(pkcs11AttrList *attrlist, pkcs11Context *p11Context);

CK_BBOOL pkcs11_set_attr_in_attrlist ( pkcs11AttrList *attrlist,
				       CK_ATTRIBUTE_TYPE attrib,
				       CK_VOID_PTR pvalue,
				       CK_ULONG len );
CK_ATTRIBUTE_PTR pkcs11_get_attr_in_attrlist ( pkcs11AttrList *attrlist,
					       CK_ATTRIBUTE_TYPE attrib );

CK_BBOOL pkcs11_read_attr_from_handle ( pkcs11AttrList *attrlist, CK_OBJECT_HANDLE handle);
CK_BBOOL pkcs11_read_attr_from_handle_ext ( pkcs11AttrList *attrlist, CK_OBJECT_HANDLE handle, ... );

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

/* list functions */
int pkcs11_ls_certs(pkcs11Context *p11Context);
int pkcs11_ls_pubk(pkcs11Context *p11Context);
int pkcs11_ls_privk(pkcs11Context *p11Context);
int pkcs11_ls_secrk(pkcs11Context *p11Context);
int pkcs11_ls_data(pkcs11Context *p11Context);
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
const char *get_mechanism_name(CK_MECHANISM_TYPE mech); /* pkcs11_mechanism.c */
CK_ATTRIBUTE_TYPE get_attribute_type_from_name(char *name); /* pkcs11_attrdesc.c */

func_rc pkcs11_info_slot(pkcs11Context *p11Context);
func_rc pkcs11_info_ecsupport(pkcs11Context *p11Context);

/* chattr function */
func_rc pkcs11_change_object_attributes(pkcs11Context *p11Context, char *label, CK_ATTRIBUTE *attr, size_t cnt, int interactive );

/* kcv functions */
void pkcs11_display_kcv( pkcs11Context *p11Context, char *label );

/* wrap/unwrap functions */
func_rc pkcs11_prepare_wrappingctx(wrappedKeyCtx *wctx, char *wrappingjob);
func_rc pkcs11_wrap_from_label(wrappedKeyCtx *wctx, char *wrappedkeylabel);
func_rc pkcs11_wrap_from_handle(wrappedKeyCtx *wctx, CK_OBJECT_HANDLE wrappedkeyhandle, CK_OBJECT_HANDLE pubkhandle);
func_rc pkcs11_output_wrapped_key( wrappedKeyCtx *wctx);

wrappedKeyCtx *pkcs11_new_wrapped_key_from_file(pkcs11Context *p11Context, char *filename);
func_rc pkcs11_unwrap(pkcs11Context *p11Context, wrappedKeyCtx *ctx, char *wrappingkeylabel, char *wrappedkeylabel, CK_ATTRIBUTE attrs[], CK_ULONG numattrs, key_generation_t keygentype );
const CK_OBJECT_HANDLE pkcs11_get_wrappedkeyhandle(wrappedKeyCtx *ctx);
const CK_OBJECT_HANDLE pkcs11_get_publickeyhandle(wrappedKeyCtx *ctx);

wrappedKeyCtx *pkcs11_new_wrappedkeycontext(pkcs11Context *p11Context);
void pkcs11_free_wrappedkeycontext(wrappedKeyCtx *wctx);


/* End - Function Prototypes */

/* Callback Prompt Strings */
#define SLOT_PROMPT_STRING			"Enter slot index: "
#define PASS_PROMPT_STRING			"Enter passphrase for token: "
#define TOKEN_PASS_PROMPT_STRING		"Enter passphrase for token '%s': "

#define MAXBUFSIZE              1024
#define MAXKEYS			2000
#define MAX_KEY_LABEL_SIZE	32
#define MAX_BYTE_ARRAY_SIZE	20

#define PARSING_MAX_ATTRS       32   /* max number of attributes for unwrap templates */

#endif

/*
 *--------------------------------------------------------------------------------
 * $Log$
 *--------------------------------------------------------------------------------
*/
