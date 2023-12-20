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
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <regex.h>

#include "pkcs11lib.h"


/* 
   in the following structure, CKA_ID or CKA_LABEL are set at position 0 
   and CKA_CLASS at position 1 
*/


static pkcs11IdTemplate * new_idtemplate()
{
    pkcs11IdTemplate *idtmpl;

    idtmpl = calloc(1, sizeof (pkcs11IdTemplate));

    if(idtmpl) {

	idtmpl->template[IDTMPL_OBJECT_CLASS_POS].pValue = &(idtmpl->oclass);
	idtmpl->template[IDTMPL_OBJECT_CLASS_POS].ulValueLen = sizeof idtmpl->oclass;
	idtmpl->template[IDTMPL_OBJECT_CLASS_POS].type = CKA_CLASS;

	idtmpl->has_resource = CK_FALSE;
	idtmpl->has_class = CK_FALSE;
    }

    return idtmpl;
}


static inline void delete_idtemplate(pkcs11IdTemplate * idtmpl)
{
    if(idtmpl) {
	if(idtmpl->has_resource == CK_TRUE && idtmpl->template[IDTMPL_RESOURCE_POS].pValue != NULL) {
	    free(idtmpl->template[IDTMPL_RESOURCE_POS].pValue);
	    idtmpl->template[IDTMPL_RESOURCE_POS].pValue = NULL;
	    idtmpl->template[IDTMPL_RESOURCE_POS].ulValueLen = 0L;
	    idtmpl->has_resource = CK_FALSE;
	}
	free(idtmpl);
    }
}


static inline void adjust_template_len(pkcs11IdTemplate *idtmpl)
{
    if(idtmpl) {
	idtmpl->template_len = 0;

	if(idtmpl->has_resource == CK_TRUE) {
	    idtmpl->template_len = 1;
	} 

	if(idtmpl->has_class == CK_TRUE) {
	    idtmpl->template_len++;
	} 
    }    
}

static void idtemplate_setresource(pkcs11IdTemplate *idtmpl, char *id, int size, CK_ATTRIBUTE_TYPE what)
{
    if(idtmpl && id) {
	/* free if already occupied */
	if(idtmpl->has_resource == CK_TRUE && idtmpl->template[IDTMPL_RESOURCE_POS].pValue != NULL) {
	    free(idtmpl->template[IDTMPL_RESOURCE_POS].pValue);
	    idtmpl->template[IDTMPL_RESOURCE_POS].pValue = NULL;
	    idtmpl->template[IDTMPL_RESOURCE_POS].ulValueLen = 0L;
	    idtmpl->has_resource = CK_FALSE;
	}

	/* now assign */
	idtmpl->template[IDTMPL_RESOURCE_POS].pValue = malloc(size);
	if( idtmpl->template[IDTMPL_RESOURCE_POS].pValue ) {
	    memcpy( idtmpl->template[IDTMPL_RESOURCE_POS].pValue, id, size);
	    idtmpl->template[IDTMPL_RESOURCE_POS].ulValueLen = (CK_ULONG)size;
	    idtmpl->template[IDTMPL_RESOURCE_POS].type = what;
	    
	    idtmpl->has_resource = CK_TRUE;
	}

	adjust_template_len(idtmpl);
    }
}

static bool idtemplate_addresource(CK_ATTRIBUTE* additional_attributes, CK_ULONG* additional_attributes_len, char* attr_value, int attr_value_len, CK_ATTRIBUTE_TYPE what)
{
    if(!additional_attributes || !attr_value || !additional_attributes_len) {
		fprintf(stderr, "idtemplate_addresource: no template or id detected. - [%s]\n", attr_value);
		return false;
	}

	//skip locations with values
	int iter = 0;
	const size_t max_extra_template_len = 8 - *additional_attributes_len;
	while(additional_attributes[iter].pValue != NULL && iter <= max_extra_template_len){
		iter++;
	}

	if(iter > max_extra_template_len) {
		fprintf(stderr, "idtemplate_addresource: additional_attributes is full. - [%s]\n", attr_value); //arbitrary limit
		return false;
	}

	/* now assign */
	additional_attributes[iter].pValue = malloc(attr_value_len);
	if( additional_attributes[iter].pValue ) {
	    memcpy( additional_attributes[iter].pValue, attr_value, attr_value_len);
	    additional_attributes[iter].ulValueLen = (CK_ULONG)attr_value_len;
	    additional_attributes[iter].type = what;
	}
	return true;
}

static void idtemplate_setclass(pkcs11IdTemplate *idtmpl, CK_OBJECT_CLASS cl)
{
    if(idtmpl) {
	idtmpl->oclass = cl;	/* copy the object */
	idtmpl->has_class = CK_TRUE;
    }
    
    adjust_template_len(idtmpl);
}


/*------------------------------------------------------------------------*/

CK_OBJECT_CLASS parse_object_class(char* object_type) {

	if(!object_type) {
		fprintf(stderr, "parse_object_class: invalid input provided.\n");
		return 0xFFFFFFFF;
	}

	size_t object_type_len = strlen(object_type);
	if(!object_type_len) {
		fprintf(stderr, "parse_object_class: empty input provided.\n");
		return 0xFFFFFFFF;
	}

	if(strncasecmp("prvk", object_type, object_type_len) ==0 ) { /* private key case */
		return CKO_PRIVATE_KEY;
	} 
	else if (strncasecmp("pubk", object_type, object_type_len) ==0 ) { /* public key case */
		return CKO_PUBLIC_KEY;
	} 
	else if (strncasecmp("seck", object_type, object_type_len) ==0 ) { /* secret key case */
		return CKO_SECRET_KEY;
	} 
	else if (strncasecmp("cert", object_type, object_type_len) ==0 ) { /* cert case */
		return CKO_CERTIFICATE;
	} 
	else if (strncasecmp("data", object_type, object_type_len) ==0 ) { /* cert case */
		return CKO_DATA;
	}

	fprintf(stderr, "parse_object_class: invalid object type provided.\n");
	return 0xFFFFFFFF;
}

CK_ATTRIBUTE_TYPE parse_attribute_type(char* attr_type) {
	
	if(!attr_type) {
		fprintf(stderr, "parse_attribute_type: invalid input provided.\n");
		return CKA_LABEL;
	}
	
	size_t attr_type_len = strlen(attr_type);
	if(!attr_type_len) {
		fprintf(stderr, "parse_attribute_type: empty input provided.\n");
		return CKA_LABEL;
	}

	if(strncasecmp("id", attr_type, attr_type_len) ==0 ) { 
		return CKA_ID;
	} 
	else if(strncasecmp("sn", attr_type, attr_type_len) ==0 ) {
		return CKA_SERIAL_NUMBER;
	}
	else {
		CK_ATTRIBUTE_TYPE cka_resourceid = pkcs11_get_attribute_type_from_name(attr_type);
			
		if(cka_resourceid != 0xFFFFFFFF) {
			return cka_resourceid;
		}
		
		fprintf(stderr, "parse_attribute_type: cannot parse attribute in regular expression - attribute not managed or unknown. - [%s]\n", attr_type);
	}

	fprintf(stderr, "parse_attribute_type: failed to determine attribute type; defaulting to CKA_LABEL. - [%s]\n", attr_type);
	return CKA_LABEL;
}

char* parse_attribute_value(char* attr_value, const regex_t* regx, size_t *outsize) {
	
	if(!attr_value) {
		fprintf(stderr, "parse_attribute_value: invalid input provided.\n");
		return NULL;
	}

	size_t attr_value_len = strlen(attr_value);
	if(!attr_value_len) {
		fprintf(stderr, "parse_attribute_value: empty input provided.\n");
		return NULL;
	}

	if (regexec(regx, attr_value, 0, NULL, 0) != 0) {
		fprintf(stderr, "parse_attribute_value: invalid format detected. - [%s]\n", attr_value);
		return NULL;
	}

	if(attr_value[0] == '{') {/* we have a HEX string */
		return hex2bin_new(attr_value, attr_value_len, outsize);
	} 

	*outsize = attr_value_len;	
	return attr_value;
}

bool parse_attributes(char* attributes, pkcs11IdTemplate* template_buffer, CK_ATTRIBUTE* additional_attributes, CK_ULONG* additional_attributes_len) {

	if(!attributes || !template_buffer || !additional_attributes || !additional_attributes_len ){
		fprintf(stderr, "parse_attributes: invalid input detected.");
		return false;
	}

	const char forward_slash_delim = '/';//todo static globals? Eric - thoughts?
	const char plus_delim = '+';

	char* attr_value_regex_str = "^(\\{([[:xdigit:].:[:space:]]+)\\}|([^/{}]+))$";
	regex_t attr_value_regex;
	
	int error_code = regcomp(&attr_value_regex, attr_value_regex_str, REG_EXTENDED | REG_ICASE | REG_NOSUB);
	if(error_code != 0) {
		fprintf(stderr, "parse_attributes: failed to compile regular expression.");
		return false;
	}
	
	char* label_ptr = NULL;
	char* attr_type, *attr_value;
	size_t label_len = 0;
	CK_ATTRIBUTE_TYPE cka_resourceid;

	char* attr = strsep(&attributes, &plus_delim);
	while(attr != NULL) {

		attr_type = strsep(&attr, &forward_slash_delim);
		cka_resourceid = parse_attribute_type(attr_type);

		attr_value = strsep(&attr, &forward_slash_delim);
		label_ptr = parse_attribute_value(attr_value, &attr_value_regex, &label_len);

		if(attr_value != NULL && label_ptr != NULL) {
			if(template_buffer->has_resource) {
				idtemplate_addresource(additional_attributes, additional_attributes_len, label_ptr, label_len, cka_resourceid);
			}
			else {
				idtemplate_setresource(template_buffer, label_ptr, label_len, cka_resourceid);
				memcpy(template_buffer->template, additional_attributes, template_buffer->template_len);
				*additional_attributes_len = template_buffer->template_len;
			}

			if(attr_value[0] == '{') { //fulfills our regex so it must be a hex value
				hex2bin_free(label_ptr);
				label_len = 0;
			}
		}
		else {
			fprintf(stderr, "parse_attributes: failed to parse attribute value. - [%s]\n", attr);
		}
		attr = strsep(&attributes, &plus_delim);
	}
	
	if(error_code == 0){
		regfree(&attr_value_regex); 
	}

	return true;
}

pkcs11IdTemplate * pkcs11_make_idtemplate_with_extra_attributes(char *resourceid, CK_ATTRIBUTE* additional_attributes, CK_ULONG* additional_attributes_len)
{
    /* given a label or id, fill in template for performing search */

    /* 

       [CLASS/][BY_LABEL_OR_ID/]WHAT
       
       with:
       - CLASS (facultative) be one of pubk/, prvk/, seck/, cert/, data/. 
         If missing, CKA_OBJECT is assumed. -> if missing there is no determination? todo confirm

       - BY_LABEL_OR_ID (facultative) be one of id/, label/ or sn/.
         if missing, CKA_LABEL is assumed. -> all attr types supported

       - WHAT (mandatory) be either an hexadecimal string between brackets,
         eventually with decoration characters that can be whitespace, ':' or '.',
         or a label ( with no bracket character or '/' allowed ).
	   - Ex: cert/sn/12335344+CKA_ENCRYPT/{01}
     */

	char *error_msg = NULL;

	pkcs11IdTemplate * template_buffer = new_idtemplate();
    pkcs11IdTemplate * return_value = NULL;

    if(template_buffer == NULL) {
		error_msg = "failed to create new idtemplate.";
		goto err;
    }

	const char forward_slash_delim = '/';
	char* temp_resource_id = strdup(resourceid);

	CK_OBJECT_CLASS objectclass;
	char* object_type = strsep(&temp_resource_id, &forward_slash_delim);//todo confirm Solaris10 support for strsep
	if(object_type == NULL){
		error_msg = "no class found.";
	    goto err;
	}

	objectclass = parse_object_class(object_type);
	if(objectclass != 0xFFFFFFFF) {
		idtemplate_setclass(template_buffer, objectclass);
	}

	if(temp_resource_id == NULL) {
		if(!template_buffer->has_class) {
			error_msg = "no class or attribute found.";
			goto err;
		}
		//todo consider scenario when there is a class but no type/value; should we set a default i.e. type = CK_LABEL, value = ""?
		// else {
		// 	char dummy = '';
		// 	idtemplate_setresource(template_buffer, &dummy, 0, CKA_LABEL);
		// }
	}
	else {
		if(!parse_attributes(temp_resource_id, template_buffer, additional_attributes, additional_attributes_len)) {
			error_msg = "failed to parse attributes.";
			goto err;
		}
	}
	/* housekeeping */
    return_value = template_buffer;		/* transfer idtmpl to rv */
    template_buffer = NULL;
err:
    if (template_buffer) {
		delete_idtemplate(template_buffer);
		template_buffer=NULL; 
	}
	
	if(error_msg) {
		fprintf(stderr, "pkcs11_make_idtemplate: failed to parse message:[%s].\n *Error* [%s]\n", resourceid, error_msg);
		free(temp_resource_id);
		free(error_msg);
	}
    return return_value;
}


pkcs11IdTemplate * pkcs11_make_idtemplate(char *resourceid)
{
    pkcs11IdTemplate * idtmpl = NULL;
    pkcs11IdTemplate * rv = NULL;

    CK_OBJECT_CLASS objectclass;
    int has_class = 0;
    CK_ATTRIBUTE_TYPE cka_resourceid;

    char *idlblptr = NULL;
    size_t idlbllen = 0;

    /* given a label or id, fill in template for performing search */

    /* 

       [CLASS/][BY_LABEL_OR_ID/]WHAT
       
       with:
       - CLASS (facultative) be one of pubk/, prvk/, seck/, cert/, data/. 
         If missing, CKA_OBJECT is assumed.

       - BY_LABEL_OR_ID (facultative) be one of id/, label/ or sn/.
         if missing, CKA_LABEL is assumed.

       - WHAT (mandatory) be either an hexadecimal string between brackets,
         eventually with decoration characters that can be whitespace, ':' or '.',
         or a label ( with no bracket character or '/' allowed ).


     */

    char *regexstr = "^(pubk/|prvk/|seck/|cert/|data/)?(id/|label/|sn/|CKA_[[:alpha:]_]+/)?(\\{([[:xdigit:].:[:space:]]+)\\}|([^/{}]+))$";
    size_t groupcnt = 6;

    /* groups of this regex: 
       
       group[0] = the entire string
       group[1] = pubk/ or prvk/ or seck/ or cert/ or data/
       group[2] = id/, label/, sn/ or CKA_*something*
       group[3] = one of group[4] or group[5]
       group[4] = hex string
       group[5] = ascii string
     */

    regex_t regex;

    regmatch_t regex_group[groupcnt];

    int regi=-1;


    /* allocate structure */
    idtmpl = new_idtemplate();

    if(idtmpl==NULL) {
	fprintf(stderr, "***ERROR: cannot allocate attribute list\n");
	goto err;
    }

    
    /* specific case: if resourceid is NULL, we just return the structure as is */
    /* meaning that length of template is 0 */
    
    if(resourceid!=NULL) {

	regi=regcomp(&regex, regexstr, REG_EXTENDED | REG_ICASE);

	if (regi!=0)
	{
	    fprintf(stderr, "***ERROR: cannot compile regex\n");
	    goto err;
	};

	if (regexec(&regex, resourceid, groupcnt, regex_group, 0) != 0)
	{
	    fprintf(stderr, "***ERROR: invalid path to object: [%s]\n", resourceid);
	    goto err;
	}
    

	/* analyse regex results */

	/* first, determine if there is an object class specified */

	if(regex_group[1].rm_so == (size_t)-1) {
	    has_class = 0;
	    /* no object class specified  */
	} else {
	    size_t group_len = regex_group[1].rm_eo - regex_group[1].rm_so;
	    has_class = 1;
	    if(strncasecmp("prvk/", &resourceid[regex_group[1].rm_so], group_len) ==0 ) { /* private key case */
		objectclass = CKO_PRIVATE_KEY;
	    } else if (strncasecmp("pubk/", &resourceid[regex_group[1].rm_so], group_len) ==0 ) { /* public key case */
		objectclass = CKO_PUBLIC_KEY;
	    } else if (strncasecmp("seck/", &resourceid[regex_group[1].rm_so], group_len) ==0 ) { /* secret key case */
		objectclass = CKO_SECRET_KEY;
	    } else if (strncasecmp("cert/", &resourceid[regex_group[1].rm_so], group_len) ==0 ) { /* cert case */
		objectclass = CKO_CERTIFICATE;
	    } else if (strncasecmp("data/", &resourceid[regex_group[1].rm_so], group_len) ==0 ) { /* cert case */
		objectclass = CKO_DATA;
	    }
	}

	/* second, check if we have 'id/' or 'sn/'. In all other cases, we consider it being CKA_LABEL */

	if(regex_group[2].rm_so>=0) {
	    if(strncasecmp("id/", 
			   &resourceid[regex_group[2].rm_so],
			   regex_group[2].rm_eo - regex_group[2].rm_so) ==0 ) { 
		cka_resourceid = CKA_ID;
	    } else if(strncasecmp("sn/", 
				  &resourceid[regex_group[2].rm_so],
				  regex_group[2].rm_eo - regex_group[2].rm_so) ==0 ) {
	    cka_resourceid = CKA_SERIAL_NUMBER;
	    } else if(strncasecmp("CKA_", &resourceid[regex_group[2].rm_so], 4) ==0 ) {
		/* we need to retrienve the character */
		char compare_buf[128];
		
		if(regex_group[2].rm_eo - regex_group[2].rm_so > (sizeof compare_buf)-1 ) {
		    fprintf(stderr, "***ERROR: cannot parse attribute in regular expression - attribute name too long\n");
		    goto err;
		}

		/* we copy in compare_buf all chars excepting the trailing '/'  */
		memcpy(compare_buf, &resourceid[regex_group[2].rm_so], regex_group[2].rm_eo - regex_group[2].rm_so - 1);
		compare_buf[ regex_group[2].rm_eo - regex_group[2].rm_so -1  ] = 0; /* null-terminate string */

		cka_resourceid = pkcs11_get_attribute_type_from_name(compare_buf);

		if(cka_resourceid == 0xFFFFFFFF) {
		    fprintf(stderr, "***ERROR: cannot parse attribute in regular expression - attribute not managed or unknown\n");
		    goto err;
		}
		
	    } else {
		/* last possibility is label */
		cka_resourceid = CKA_LABEL;
	    }
	} else {
	    /* no prefix specified, default case is label */
	    cka_resourceid = CKA_LABEL;
	}
	

	/* third, extract identifier value, ASCII or hex */
    
	if(regex_group[4].rm_so>=0) 	{ /* we have HEX string */

	    idlblptr = hex2bin_new( &resourceid[ regex_group[4].rm_so ], regex_group[4].rm_eo - regex_group[4].rm_so, &idlbllen);
	
	    if(idlblptr==NULL) {
		fprintf(stderr, "***ERROR: memory error\n");
		goto err;
	    }
	} else { 			/* ASCII */
	    idlblptr = &resourceid[ regex_group[5].rm_so ];
	    idlbllen = strlen(idlblptr);	
	}

	/* set values */
    
	idtemplate_setresource(idtmpl, idlblptr, idlbllen, cka_resourceid);

	if(has_class) {
	    idtemplate_setclass(idtmpl, objectclass);
	}

	/* housekeeping */

	if(regex_group[4].rm_so>0) 	{ /* we have HEX string */
	    hex2bin_free(idlblptr);
	    idlbllen = 0;
	}
    }
    
    rv = idtmpl;		/* transfer idtmpl to rv */
    idtmpl = NULL;

err:
    if(regi==0) { regfree(&regex); } /* if regi==0, regcomp() was successful */
    if (idtmpl) { delete_idtemplate(idtmpl); idtmpl=NULL; }

    return rv;
}


void pkcs11_delete_idtemplate(pkcs11IdTemplate * idtmpl) 
{
    delete_idtemplate(idtmpl);
}


int pkcs11_sizeof_idtemplate(pkcs11IdTemplate *idtmpl)
{
    return idtmpl->template_len;
}

