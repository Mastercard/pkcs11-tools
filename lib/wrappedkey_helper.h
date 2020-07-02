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

/* wrappedkey_helper.h: header files for wrappedkey_helper.c */

#ifndef WRAPPEDKEY_HELPER_H
#define WRAPPEDKEY_HELPER_H

#include "pkcs11lib.h"

/* internal functions used by parser */
func_rc _wrappedkey_parser_wkey_append_attr(wrappedKeyCtx *ctx, CK_ATTRIBUTE_TYPE attrtyp, void *buffer, size_t len );
func_rc _wrappedkey_parser_wkey_append_cryptogram(wrappedKeyCtx *ctx, unsigned char *b64buffer, int keyindex);
func_rc _wrappedkey_parser_wkey_set_wrapping_key(wrappedKeyCtx *ctx, void *buffer, size_t len);
func_rc _wrappedkey_parser_wkey_set_wrapping_alg(wrappedKeyCtx *ctx, enum wrappingmethod meth, int keyindex );
func_rc _wrappedkey_parser_wkey_set_wrapping_param_hash(wrappedKeyCtx *ctx, CK_MECHANISM_TYPE hash);
func_rc _wrappedkey_parser_wkey_set_wrapping_param_mgf(wrappedKeyCtx *ctx, CK_MECHANISM_TYPE mgf);
func_rc _wrappedkey_parser_wkey_set_wrapping_param_label(wrappedKeyCtx *ctx, void *buffer, size_t len);
func_rc _wrappedkey_parser_wkey_set_wrapping_param_iv(wrappedKeyCtx *ctx, void *buffer, size_t len);
func_rc _wrappedkey_parser_wkey_set_wrapping_param_flavour(wrappedKeyCtx *wctx, CK_MECHANISM_TYPE wrapalg);

func_rc _wrappedkey_parser_pubk_append_attr(wrappedKeyCtx *ctx, CK_ATTRIBUTE_TYPE attrtyp, void *buffer, size_t len );
func_rc _wrappedkey_parser_pubk_append_pem(wrappedKeyCtx *wctx, unsigned char *pem);

#endif
