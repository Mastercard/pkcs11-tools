/* -*- mode: c; c-file-style:"stroustrup"; -*- */

/*
 * Copyright (c) 2021 Mastercard
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

/* attribctx_helper.h: header files for wrappedkey_helper.c */

#ifndef ATTRIBCTX_HELPER_H
#define ATTRIBCTX_HELPER_H

#include "pkcs11lib.h"

/* internal functions used by parser */
func_rc _attribctx_parser_append_attr(attribCtx *ctx, CK_ATTRIBUTE_TYPE attrtyp, void *buffer, size_t len );
func_rc _attribctx_parser_assign_list_to_template(attribCtx *clctx, CK_ATTRIBUTE_TYPE attrtyp );

#endif /* ATTRIBCTX_HELPER_H */
