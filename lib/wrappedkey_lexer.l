/* wrappedkey lexical analyser */
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
%option header-file="wrappedkey_lexer.h"
%option never-interactive

%top{
#include <config.h>
}

%{
#include <stdarg.h>
#include "wrappedkey_parser.h"

#define PUBLIC_KEY_PROLOG "-----BEGIN PUBLIC KEY-----"
#define PUBLIC_KEY_EPILOG "-----END PUBLIC KEY-----"

%}

%x OUTERKEYPEM INNERKEYPEM PUBKPEM STR
%%

^"#".*             { /* skipping comment */ }

<INITIAL>^"-----BEGIN OUTER WRAPPED KEY-----" { BEGIN(OUTERKEYPEM); }
<INITIAL>^"-----BEGIN "("INNER ")?"WRAPPED KEY-----" { BEGIN(INNERKEYPEM); }
<INITIAL>^"-----BEGIN PUBLIC KEY-----" { BEGIN(PUBKPEM); }

<OUTERKEYPEM>^"-----END OUTER WRAPPED KEY-----" { BEGIN(INITIAL); return OUTER; }
<INNERKEYPEM>^"-----END "("INNER ")?"WRAPPED KEY-----" { BEGIN(INITIAL); return INNER; }
<PUBKPEM>^"-----END PUBLIC KEY-----" { BEGIN(INITIAL); return PUBK; }

<OUTERKEYPEM,INNERKEYPEM,PUBKPEM><<EOF>> { yyerror(NULL, "Incomplete PEM block"); yyterminate(); }
<OUTERKEYPEM,INNERKEYPEM,PUBKPEM>[^\n\r][A-Za-z0-9+/=\n\r]+ { yylval.val_pem = (unsigned char *)strdup(yytext); }
<OUTERKEYPEM,INNERKEYPEM,PUBKPEM>[\n\r] { /* ignore initial line feed */ }

<INITIAL>[\"]   { yylval.val_str.len=0; BEGIN(STR); }
<STR>[^\"]+     { yylval.val_str.val = strdup(yytext); yylval.val_str.len = strlen(yytext); }
<STR><<EOF>>    { yyerror(NULL, "Unterminated quoted string"); yyterminate(); }
<STR>[\"]   {   /* special case: if we have an empty string, regular rule is never executed */
		/* in which case, we perform the empty string assignment from here */
                if (yylval.val_str.len==0) { yylval.val_str.val=strdup(""); } BEGIN(INITIAL); return STRING;
	    }

Content-Type       { return CTYPE; }
"application/pkcs11-tools" { yylval.val_contenttype = ct_appl_p11; return CTYPE_VAL; }

Wrapping-Algorithm { return WRAPPING_ALG; }
pkcs1              { yylval.val_wrappingmethod = w_pkcs1_15; return PKCS1ALGO; }
oaep               { yylval.val_wrappingmethod = w_pkcs1_oaep; return OAEPALGO;  }
cbcpad             { yylval.val_wrappingmethod = w_cbcpad; return CBCPADALGO;  }
rfc3394            { yylval.val_wrappingmethod = w_rfc3394; return RFC3394ALGO;  }
rfc5649            { yylval.val_wrappingmethod = w_rfc5649; return RFC5649ALGO;  }
envelope           { yylval.val_wrappingmethod = w_envelope; return ENVELOPEALGO; }

Wrapping-Key       { return WRAPPING_KEY; }
Grammar-Version    { return GRAMMAR_VERSION; }

CKA_ID             { yylval.ckattr = CKA_ID; return CKATTR_STR; }
CKA_LABEL          { yylval.ckattr = CKA_LABEL; return CKATTR_STR; }
CKA_CLASS          { yylval.ckattr = CKA_CLASS; return CKATTR_CLASS; }
CKA_TOKEN          { yylval.ckattr = CKA_TOKEN; return CKATTR_BOOL; }
CKA_KEY_TYPE       { yylval.ckattr = CKA_KEY_TYPE; return CKATTR_KEY; }
CKA_SUBJECT        { yylval.ckattr = CKA_SUBJECT; return CKATTR_STR; }
CKA_ENCRYPT        { yylval.ckattr = CKA_ENCRYPT; return CKATTR_BOOL; }
CKA_DECRYPT        { yylval.ckattr = CKA_DECRYPT; return CKATTR_BOOL; }
CKA_WRAP           { yylval.ckattr = CKA_WRAP; return CKATTR_BOOL; }
CKA_UNWRAP         { yylval.ckattr = CKA_UNWRAP; return CKATTR_BOOL; }
CKA_SIGN           { yylval.ckattr = CKA_SIGN; return CKATTR_BOOL; }
CKA_SIGN_RECOVER   { yylval.ckattr = CKA_SIGN_RECOVER; return CKATTR_BOOL; }
CKA_VERIFY         { yylval.ckattr = CKA_VERIFY; return CKATTR_BOOL; }
CKA_VERIFY_RECOVER { yylval.ckattr = CKA_VERIFY_RECOVER; return CKATTR_BOOL; }
CKA_DERIVE         { yylval.ckattr = CKA_DERIVE; return CKATTR_BOOL; }
CKA_PRIVATE        { yylval.ckattr = CKA_PRIVATE; return CKATTR_BOOL; }
CKA_SENSITIVE      { yylval.ckattr = CKA_SENSITIVE; return CKATTR_BOOL; }
CKA_EXTRACTABLE    { yylval.ckattr = CKA_EXTRACTABLE; return CKATTR_BOOL; }
CKA_MODIFIABLE     { yylval.ckattr = CKA_MODIFIABLE; return CKATTR_BOOL; }
CKA_START_DATE     { yylval.ckattr = CKA_START_DATE; return CKATTR_DATE; }
CKA_END_DATE       { yylval.ckattr = CKA_END_DATE; return CKATTR_DATE; }
CKA_CHECK_VALUE    { yylval.ckattr = CKA_CHECK_VALUE; return CKATTR_STR; }
CKA_EC_PARAMS      { yylval.ckattr = CKA_EC_PARAMS; return CKATTR_STR; }
CKA_TRUSTED        { yylval.ckattr = CKA_TRUSTED; return CKATTR_BOOL; }
CKA_WRAP_WITH_TRUSTED { yylval.ckattr = CKA_WRAP_WITH_TRUSTED; return CKATTR_BOOL; }
CKA_WRAP_TEMPLATE  { yylval.ckattr = CKA_WRAP_TEMPLATE; return CKATTR_TEMPLATE; }
CKA_UNWRAP_TEMPLATE { yylval.ckattr = CKA_UNWRAP_TEMPLATE; return CKATTR_TEMPLATE; }
CKA_DERIVE_TEMPLATE { yylval.ckattr = CKA_DERIVE_TEMPLATE; return CKATTR_TEMPLATE; }
CKA_ALLOWED_MECHANISMS { yylval.ckattr = CKA_ALLOWED_MECHANISMS; return CKATTR_ALLOWEDMECH; }

CKK_GENERIC_SECRET { yylval.val_key = CKK_GENERIC_SECRET; return KEYTYPE; }
CKK_DES            { yylval.val_key = CKK_DES           ; return KEYTYPE; }
CKK_DES2           { yylval.val_key = CKK_DES2          ; return KEYTYPE; }
CKK_DES3           { yylval.val_key = CKK_DES3          ; return KEYTYPE; }
CKK_AES            { yylval.val_key = CKK_AES           ; return KEYTYPE; }
CKK_MD5_HMAC       { yylval.val_key = CKK_MD5_HMAC      ; return KEYTYPE; }
CKK_SHA_1_HMAC     { yylval.val_key = CKK_SHA_1_HMAC    ; return KEYTYPE; }
CKK_RIPEMD128_HMAC { yylval.val_key = CKK_RIPEMD128_HMAC; return KEYTYPE; }
CKK_RIPEMD160_HMAC { yylval.val_key = CKK_RIPEMD160_HMAC; return KEYTYPE; }
CKK_SHA256_HMAC    { yylval.val_key = CKK_SHA256_HMAC   ; return KEYTYPE; }
CKK_SHA384_HMAC    { yylval.val_key = CKK_SHA384_HMAC   ; return KEYTYPE; }
CKK_SHA512_HMAC    { yylval.val_key = CKK_SHA512_HMAC   ; return KEYTYPE; }
CKK_SHA224_HMAC    { yylval.val_key = CKK_SHA224_HMAC   ; return KEYTYPE; }
CKK_RSA            { yylval.val_key = CKK_RSA           ; return KEYTYPE; }
CKK_DH             { yylval.val_key = CKK_DH            ; return KEYTYPE; }
CKK_DSA            { yylval.val_key = CKK_DSA           ; return KEYTYPE; }
CKK_EC             { yylval.val_key = CKK_EC            ; return KEYTYPE; }
CKK_EC_EDWARDS     { yylval.val_key = CKK_EC_EDWARDS    ; return KEYTYPE; }

CKO_DATA           { yylval.val_cls = CKO_DATA ; return OCLASS; }
CKO_CERTIFICATE    { yylval.val_cls = CKO_CERTIFICATE ; return OCLASS; }
CKO_PUBLIC_KEY     { yylval.val_cls = CKO_PUBLIC_KEY ; return OCLASS; }
CKO_PRIVATE_KEY    { yylval.val_cls = CKO_PRIVATE_KEY ; return OCLASS; }
CKO_SECRET_KEY     { yylval.val_cls = CKO_SECRET_KEY ; return OCLASS; }
CKO_HW_FEATURE     { yylval.val_cls = CKO_HW_FEATURE ; return OCLASS; }
CKO_DOMAIN_PARAMETERS { yylval.val_cls = CKO_DOMAIN_PARAMETERS ; return OCLASS; }
CKO_MECHANISM      { yylval.val_cls = CKO_MECHANISM ; return OCLASS; }
CKO_OTP_KEY        { yylval.val_cls = CKO_OTP_KEY ; return OCLASS; }

mgf                { return PARAMMGF; }
CKG_MGF1_SHA1      { yylval.val_mgf = CKG_MGF1_SHA1; return MGFTYPE; }
CKG_MGF1_SHA224    { yylval.val_mgf = CKG_MGF1_SHA224; return MGFTYPE; }
CKG_MGF1_SHA256    { yylval.val_mgf = CKG_MGF1_SHA256; return MGFTYPE; }
CKG_MGF1_SHA384    { yylval.val_mgf = CKG_MGF1_SHA384; return MGFTYPE; }
CKG_MGF1_SHA512    { yylval.val_mgf = CKG_MGF1_SHA512; return MGFTYPE; }

hash                 { return PARAMHASH; }

CKM_[a-z0-9_]+     { yylval.val_mech = pkcs11_get_mechanism_type_from_name(yytext);
                     if (yylval.val_mech==0xFFFFFFFF) {
			yyerror(NULL, "Unknown mechanism identifier <%s>", yytext);
                        yyterminate();
                     }
                     return CKMECH;
                   }

label              { return PARAMLABEL; }
iv                 { return PARAMIV; }
flavo[u]?r         { return PARAMFLAVOUR; }
nss                { yylval.val_mech = CKM_NSS_AES_KEY_WRAP_PAD; return CKMECH; }
outer              { return PARAMOUTER; }
inner              { return PARAMINNER; }

@                  { return WRAPPINGJOBHEADER; }
wrappingkey        { return P_WRAPPINGKEY; }
file(name)?        { return P_FILENAME; }
algo(rithm)?       { return P_ALGORITHM; }

true|CK_TRUE|yes|1  { yylval.val_bool = 1; return TOK_BOOLEAN; }
false|CK_FALSE|no|0 { yylval.val_bool = 0; return TOK_BOOLEAN; }


0x[[:xdigit:]]+ {   if(strlen(yytext)%2==1) {
			yyerror(NULL, "Invalid hexadecimal string <%s>: odd length", yytext);
			yyterminate();
		    } else {
			yylval.val_str.len = (strlen(yytext)>>1) - 1; /* we skip the '0x' prefix */
			/* convert to hex */
			size_t i;
			char *target = malloc(yylval.val_str.len);
			if(target==NULL) {
			    yylval.val_str.len = 0 ;
			    yyerror(NULL,"Memory allocation error during lexical analysis of <%s>", yytext);
			    yyterminate();
			}

			/* we start at yytext[2] */
			for(i=0;i<yylval.val_str.len; i++) {
			    /* the following trick is needed to have CLANG shut up */
			    /* strictly speaking, %x expects indeed a pointer to an integer */

			    volatile int tmp;
			    sscanf( &yytext[ (i<<1) + 2 ], "%2x", &tmp);
			    target[i] = (unsigned char) tmp;
			}
			yylval.val_str.val = target; /* then reassign */
			return STRING;
		    }
		}

[[:digit:]]{8} { memcpy(yylval.val_date.as_buffer, yytext, 8); return TOK_DATE; }

[[:digit:]]+\.[[:digit:]]+ { yylval.val_dottednumber = strdup(yytext); return DOTTEDNUMBER; }

[\n\r\t ]+         { /* ignore whitespace */ }

.                  { return yytext[0]; } /* catch-all http://stackoverflow.com/questions/18837828/how-should-i-handle-lexical-errors-in-my-flex-lexer */
					 /* gives it back to bison, so error comes from parser */

%%


void yyerror(wrappedKeyCtx *ctx, const char *s, ...)
{
    va_list ap;
    va_start(ap, s);

    fprintf(stderr, "Error during parsing at line %d: ", yylineno);
    vfprintf(stderr, s, ap);
    fprintf(stderr, "\n");

    va_end(ap);
}
