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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11lib.h"


typedef struct {
    CK_BYTE_PTR d;
    CK_ULONG l;
} DATA;

static DATA * new_data_from_file(char *filename)
{

    DATA * rv = NULL;
    
    FILE *fp = NULL;

    fp = fopen(filename,"rb"); /* open in binary mode */
    
    if(fp==NULL) {
	perror("***file Error");
	goto cleanup;
    }

    if(fseek(fp, 0L, SEEK_END)<0) {
	perror("***file Error");
	goto cleanup;
    }	

    /* allocate structure */
    rv = calloc(1, sizeof (DATA));
    
    if(rv==NULL) {
	fprintf(stderr, "***malloc error");
	goto cleanup;
    }

    rv->l = ftell(fp);		/* find data len */
    rv->d = malloc(rv->l);	/* and allocate */
    if(rv->d==NULL) {
	fprintf(stderr, "***malloc error");
	goto cleanup;
    }
	
    if(rv->d) {
	rewind(fp);		    /* rewind */
	fread(rv->d, 1, rv->l, fp); /* load into buffer*/
	if(ferror(fp)) {
	    perror("***file error");
	    rv->l = 0;		/* mark we want to cleanup */
	}
    }	

cleanup:

    /* if rv not null but rv->l==0, operation did not complete */
    if(rv && rv->l==0) {
	/* special case: failure at fread() step */
	if(rv->d!=NULL) { free(rv->d);	}
	free(rv);
	rv=NULL;
    }

    /* close file */
    if (fp!=NULL) { fclose(fp); fp=NULL; }

    return rv;
}



static void free_DATA_buf(DATA *data)
{
    if(data) {
	if(data->l>0 && data->d) {
	    free(data->d);
	    data->d=NULL;
	    data->l=0;
	}
    }
}


CK_OBJECT_HANDLE pkcs11_importdata( pkcs11Context * p11Context, char *filename, char *label)
{

    CK_OBJECT_HANDLE hDATA = NULL_PTR;

    CK_RV retCode;
    CK_OBJECT_CLASS objClass = CKO_DATA;

    CK_BBOOL ck_false = CK_FALSE;
    CK_BBOOL ck_true = CK_TRUE;
    
    CK_ATTRIBUTE dataTemplate[] = {
	{CKA_CLASS, &objClass, sizeof objClass},             /* 0  */
	{CKA_LABEL, label, strlen(label) },		     /* 1  */
	{CKA_TOKEN, &ck_true, sizeof ck_true },		     /* 2  */
	{CKA_PRIVATE, &ck_true, sizeof ck_true },	     /* 3  */
	{CKA_MODIFIABLE, &ck_true, sizeof ck_true },	     /* 4  */
	{CKA_VALUE, NULL, 0 },				     /* 5  */
    };

    DATA * data = NULL;

    data = new_data_from_file(filename);
    
    if(data) {

	/* point to buffer */
	dataTemplate[5].pValue = data->d;
	dataTemplate[5].ulValueLen = data->l;
	
	retCode = p11Context->FunctionList.C_CreateObject(p11Context->Session, 
							  dataTemplate, 
							  sizeof(dataTemplate) / sizeof(CK_ATTRIBUTE), 
							  &hDATA);

	if(retCode != CKR_OK) {
	    pkcs11_error( retCode, "CreateObject" );
	}
	
	free(data);
    }
    return hDATA;
}
