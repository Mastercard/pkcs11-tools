/* attributes lexical analyser */
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

/* %option debug */
%option case-insensitive
%option noyywrap yylineno
%option header-file="attribctx_lexer.h"
%option never-interactive
%option prefix="cl"
%option outfile="lex.yy.c"

%top{
#include <config.h>
}

%{
#include <stdarg.h>
#include "pkcs11lib.h"
#include "attribctx_parser.h"

%}

%x STR
%%

^"#".*             { /* skipping comment */ }

<INITIAL>[\"]   { cllval.val_str.len=0; BEGIN(STR); }
<STR>[^\"]+     { cllval.val_str.val = strdup(cltext); cllval.val_str.len = strlen(cltext); }
<STR><<EOF>>    { clerror(NULL, "Unterminated quoted string"); yyterminate(); }
<STR>[\"]   {   /* special case: if we have an empty string, regular rule is never executed */
		/* in which case, we perform the empty string assignment from here */
    if (cllval.val_str.len==0) { cllval.val_str.val=strdup(""); } BEGIN(INITIAL); return STRING;
	    }

NOT|NO|!                            { return NO; }
CKA_ID|ID                           { cllval.ckattr = CKA_ID; return CKATTR_STR; }
CKA_LABEL|LABEL                     { cllval.ckattr = CKA_LABEL; return CKATTR_STR; }
CKA_CLASS|CLASS                     { cllval.ckattr = CKA_CLASS; return CKATTR_CLASS; }
CKA_TOKEN|TOKEN                     { cllval.ckattr = CKA_TOKEN; return CKATTR_BOOL; }
CKA_KEY_TYPE|KEY_TYPE               { cllval.ckattr = CKA_KEY_TYPE; return CKATTR_KEY; }
CKA_SUBJECT|SUBJECT                 { cllval.ckattr = CKA_SUBJECT; return CKATTR_STR; }
CKA_ENCRYPT|ENCRYPT                 { cllval.ckattr = CKA_ENCRYPT; return CKATTR_BOOL; }
CKA_DECRYPT|DECRYPT                 { cllval.ckattr = CKA_DECRYPT; return CKATTR_BOOL; }
CKA_WRAP|WRAP                       { cllval.ckattr = CKA_WRAP; return CKATTR_BOOL; }
CKA_UNWRAP|UNWRAP                   { cllval.ckattr = CKA_UNWRAP; return CKATTR_BOOL; }
CKA_SIGN|SIGN                       { cllval.ckattr = CKA_SIGN; return CKATTR_BOOL; }
CKA_SIGN_RECOVER|SIGN_RECOVER       { cllval.ckattr = CKA_SIGN_RECOVER; return CKATTR_BOOL; }
CKA_VERIFY|VERIFY                   { cllval.ckattr = CKA_VERIFY; return CKATTR_BOOL; }
CKA_VERIFY_RECOVER|VERIFY_RECOVER   { cllval.ckattr = CKA_VERIFY_RECOVER; return CKATTR_BOOL; }
CKA_DERIVE|DERIVE                   { cllval.ckattr = CKA_DERIVE; return CKATTR_BOOL; }
CKA_PRIVATE|PRIVATE                 { cllval.ckattr = CKA_PRIVATE; return CKATTR_BOOL; }
CKA_SENSITIVE|SENSITIVE             { cllval.ckattr = CKA_SENSITIVE; return CKATTR_BOOL; }
CKA_EXTRACTABLE|EXTRACTABLE         { cllval.ckattr = CKA_EXTRACTABLE; return CKATTR_BOOL; }
CKA_MODIFIABLE|MODIFIABLE           { cllval.ckattr = CKA_MODIFIABLE; return CKATTR_BOOL; }
CKA_COPYABLE|COPYABLE               { cllval.ckattr = CKA_COPYABLE; return CKATTR_BOOL; }
CKA_START_DATE|START_DATE           { cllval.ckattr = CKA_START_DATE; return CKATTR_DATE; }
CKA_END_DATE|END_DATE               { cllval.ckattr = CKA_END_DATE; return CKATTR_DATE; }
CKA_EC_PARAMS|EC_PARAMS             { cllval.ckattr = CKA_EC_PARAMS; return CKATTR_STR; }
CKA_WRAP_TEMPLATE|WRAP_TEMPLATE     { cllval.ckattr = CKA_WRAP_TEMPLATE; return CKATTR_TEMPLATE; }
CKA_UNWRAP_TEMPLATE|UNWRAP_TEMPLATE { cllval.ckattr = CKA_UNWRAP_TEMPLATE; return CKATTR_TEMPLATE; }
CKA_DERIVE_TEMPLATE|DERIVE_TEMPLATE { cllval.ckattr = CKA_DERIVE_TEMPLATE; return CKATTR_TEMPLATE; }
CKA_WRAP_WITH_TRUSTED|WRAP_WITH_TRUSTED { cllval.ckattr = CKA_WRAP_WITH_TRUSTED; return CKATTR_BOOL; }
CKA_TRUSTED|TRUSTED                 { cllval.ckattr = CKA_TRUSTED; return CKATTR_BOOL; }
CKA_ALLOWED_MECHANISMS|ALLOWED_MECHANISMS { cllval.ckattr = CKA_ALLOWED_MECHANISMS; return CKATTR_ALLOWEDMECH; }


CKK_GENERIC_SECRET|GENERIC_SECRET|GENERIC { cllval.val_key = CKK_GENERIC_SECRET; return KEYTYPE; }
CKK_DES|DES                               { cllval.val_key = CKK_DES           ; return KEYTYPE; }
CKK_DES2|DES2                             { cllval.val_key = CKK_DES2          ; return KEYTYPE; }
CKK_DES3|DES3                             { cllval.val_key = CKK_DES3          ; return KEYTYPE; }
CKK_AES|AES                               { cllval.val_key = CKK_AES           ; return KEYTYPE; }
CKK_MD5_HMAC|MD5_HMAC                     { cllval.val_key = CKK_MD5_HMAC      ; return KEYTYPE; }
CKK_SHA_1_HMAC|SHA_1_HMAC|SHA1_HMAC       { cllval.val_key = CKK_SHA_1_HMAC    ; return KEYTYPE; }
CKK_RIPEMD128_HMAC|RIPEMD128_HMAC         { cllval.val_key = CKK_RIPEMD128_HMAC; return KEYTYPE; }
CKK_RIPEMD160_HMAC|RIPEMD128_HMAC         { cllval.val_key = CKK_RIPEMD160_HMAC; return KEYTYPE; }
CKK_SHA256_HMAC|SHA256_HMAC               { cllval.val_key = CKK_SHA256_HMAC   ; return KEYTYPE; }
CKK_SHA384_HMAC|SHA384_HMAC               { cllval.val_key = CKK_SHA384_HMAC   ; return KEYTYPE; }
CKK_SHA512_HMAC|SHA512_HMAC               { cllval.val_key = CKK_SHA512_HMAC   ; return KEYTYPE; }
CKK_SHA224_HMAC|SHA224_HMAC               { cllval.val_key = CKK_SHA224_HMAC   ; return KEYTYPE; }
CKK_RSA|RSA                               { cllval.val_key = CKK_RSA           ; return KEYTYPE; }
CKK_DH|DH                                 { cllval.val_key = CKK_DH            ; return KEYTYPE; }
CKK_DSA|DSA                               { cllval.val_key = CKK_DSA           ; return KEYTYPE; }
CKK_EC|EC                                 { cllval.val_key = CKK_EC            ; return KEYTYPE; }
CKK_EC_EDWARDS|EC_EDWARDS|EDWARDS|ED      { cllval.val_key = CKK_EC_EDWARDS    ; return KEYTYPE; }

CKO_DATA|DATA                             { cllval.val_cls = CKO_DATA ; return OCLASS; }
CKO_CERTIFICATE|CERTIFICATE|CERT          { cllval.val_cls = CKO_CERTIFICATE ; return OCLASS; }
CKO_PUBLIC_KEY|PUBLIC_KEY|PUBK            { cllval.val_cls = CKO_PUBLIC_KEY ; return OCLASS; }
CKO_PRIVATE_KEY|PRIVATE_KEY|PRVK          { cllval.val_cls = CKO_PRIVATE_KEY ; return OCLASS; }
CKO_SECRET_KEY|SECRET_KEY|SECK            { cllval.val_cls = CKO_SECRET_KEY ; return OCLASS; }
CKO_HW_FEATURE|HW_FEATURE                 { cllval.val_cls = CKO_HW_FEATURE ; return OCLASS; }
CKO_DOMAIN_PARAMETERS|DOMAIN_PARAMETERS   { cllval.val_cls = CKO_DOMAIN_PARAMETERS ; return OCLASS; }
CKO_MECHANISM|MECHANISM                   { cllval.val_cls = CKO_MECHANISM ; return OCLASS; }
CKO_OTP_KEY|OTP_KEY                       { cllval.val_cls = CKO_OTP_KEY ; return OCLASS; }

CKM_[a-z0-9_]+     { cllval.val_mech = pkcs11_get_mechanism_type_from_name(cltext);
                     if (cllval.val_mech==0xFFFFFFFF) {
			clerror(NULL, "Unknown mechanism identifier <%s>", cltext);
                        yyterminate();
                     }
                     return CKMECH;
                   }

0x[[:xdigit:]]+ {   if(strlen(cltext)%2==1) {
			clerror(NULL, "Invalid hexadecimal string <%s>: odd length", cltext);
			yyterminate();
		    } else {
			cllval.val_str.len = (strlen(cltext)>>1) - 1; /* we skip the '0x' prefix */
			/* convert to hex */
			size_t i;
			char *target = malloc(cllval.val_str.len);
			if(target==NULL) {
			    cllval.val_str.len = 0 ;
			    clerror(NULL,"Memory allocation error during lexical analysis of <%s>", cltext);
			    yyterminate();
			}

			/* we start at cltext[2] */
			for(i=0;i<cllval.val_str.len; i++) {
			    /* the following trick is needed to have CLANG shut up */
			    /* strictly speaking, %x expects indeed a pointer to an integer */

			    volatile int tmp;
			    sscanf( &cltext[ (i<<1) + 2 ], "%2x", &tmp);
			    target[i] = (unsigned char) tmp;
			}
			cllval.val_str.val = target; /* then reassign */
			return STRING;
		    }
		}

[[:digit:]]{8} { memcpy(cllval.val_date.as_buffer, cltext, 8); return TOK_DATE; }

true|CK_TRUE|yes|on|1    { cllval.val_bool = 1; return TOK_BOOLEAN; }
false|CK_FALSE|no|off|0  { cllval.val_bool = 0; return TOK_BOOLEAN; }

[\n\r\t ,]+         { /* ignore whitespace and comma */ }
"="                { return ASSIGN; }
"{"                { return CURLY_OPEN; }
"}"                { return CURLY_CLOSE; }
.                  { return cltext[0]; } /* catch-all http://stackoverflow.com/questions/18837828/how-should-i-handle-lexical-errors-in-my-flex-lexer */
					 /* gives it back to bison, so error comes from parser */

%%


void clerror(attribCtx *ctx, const char *s, ...)
{
    va_list ap;
    va_start(ap, s);

    fprintf(stderr, "Error during parsing at line %d: ", cllineno);
    vfprintf(stderr, s, ap);
    fprintf(stderr, "\n");

    va_end(ap);
}
