#ifndef WRAPPEDKEY_HELPER_H
#define WRAPPEDKEY_HELPER_H

#include "pkcs11lib.h"


/* internal functions used by parser */
func_rc _wrappedkey_parser_append_attr(wrappedKeyCtx *ctx, CK_ATTRIBUTE_TYPE attrtyp, void *buffer, size_t len );
func_rc _wrappedkey_parser_append_pkcs(wrappedKeyCtx *ctx, unsigned char *b64buffer);
func_rc _wrappedkey_parser_set_wrapping_key(wrappedKeyCtx *ctx, void *buffer, size_t len);
func_rc _wrappedkey_parser_set_wrapping_alg(wrappedKeyCtx *ctx, enum wrappingmethod meth );
func_rc _wrappedkey_parser_set_wrapping_param_hash(wrappedKeyCtx *ctx, CK_MECHANISM_TYPE hash);
func_rc _wrappedkey_parser_set_wrapping_param_mgf(wrappedKeyCtx *ctx, CK_MECHANISM_TYPE mgf);
func_rc _wrappedkey_parser_set_wrapping_param_label(wrappedKeyCtx *ctx, void *buffer, size_t len);
func_rc _wrappedkey_parser_set_wrapping_param_iv(wrappedKeyCtx *ctx, void *buffer, size_t len);
func_rc _wrappedkey_parser_set_wrapping_param_flavour(wrappedKeyCtx *wctx, CK_MECHANISM_TYPE wrapalg);


#endif
