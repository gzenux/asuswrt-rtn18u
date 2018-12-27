/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   XML (Extensible Markup Language) parser.

   The XML parser reads Unicode characters (possible from
   different input encodings) from an input stream of type SshStream.
   The parser parses the input and notifies the application about the
   parsed elements of the XML document.  The API follows the look and
   feel of the Simple API for XML (SAX).

   References:

     http://www.w3.org/TR/2000/REC-xml-20001006
                Extensible Markup Language (XML) 1.0 (Second Edition)

     http://www.w3.org/TR/1999/REC-xml-names-19990114
                Namespaces in XML
*/

#ifndef SSHXML_H
#define SSHXML_H

#include "sshstream.h"
#include "sshadt.h"
#include "sshoperation.h"

/* ************************ Types and definitions ***************************/

/** Parser features. */
#define SSH_XML_PARSER_NAMESPACES "http://xml.org/sax/features/namespaces"

/** Result codes from XML library operations. */
typedef enum
{
  /** XML library operation completed successfully. */
  SSH_XML_OK,
  /** XML library could not allocate dynamic memory to complete operation. */
  SSH_XML_ERROR_MEMORY,
  /** Input data was not according to DTD or it was truncated,
     containted too many levels, bad parameter references, invalid
     general references, invalid characters, invalid comments ('--'
     within comment), mismatching markers or similar errors.  */
  SSH_XML_ERROR_NOT_WELL_FORMED,
  /** Element being validated contains multiple ID tags, or is declared
      more than once. */
  SSH_XML_ERROR_NOT_VALID,
  /*  TODO: Some obvious error codes are missing. */
  /** Any other error. */
  SSH_XML_ERROR
} SshXmlResult;

/** An XML parser object handle. */
typedef struct SshXmlParserRec *SshXmlParser;

/** An XML verifier object handle. */
typedef struct SshXmlVerifierRec *SshXmlVerifier;

/** A result callback for asynchronous XML interfaces. */
typedef void (*SshXmlResultCB)(SshXmlResult result, void *context);

/** A destructor callback for the context data 'context'. */
typedef void (*SshXmlDestructorCB)(void *context);

/** A stream callback for an asynchronous resource query operation.

   The provider of the resources (the module that calls this stream
   callbacks) must not modify or touch the returned stream after this
   call.  It belongs to the XML library.

   @param stream
   The resulting stream that implements the resource being queried.

   @param stream_name
   Gives an optional name for the input stream.

   @param destructor_cb
   Specifies a callback function that is called when the stream
   'stream' is destroyed.

   */
typedef void (*SshXmlStreamCB)(SshStream stream, const char *stream_name,
                               SshXmlDestructorCB destructor_cb,
                               void *destructor_cb_context,
                               void *context);


/* ******************************* Handlers *********************************/

/** Document content handler. This structure describes the methods the
    library uses when communicating towards the application.
    Applications need to implement the corresponding callback
    functions.  Any of the application-provided callback functions may
    be a NULL_FNPTR in case the application is not interested in
    receiving such information.

    The applications must eventually call the 'result_cb' function with
    a proper return status and 'result_cb_context'. In case the
    application does not call the provided 'result_cb' from within the
    invocation of the callback function, it needs to return an
    operation handle that the library may use to cancel the
    application callback (e.g. notify the application that it is no
    longer prepared for receiving 'result_cb' from the application.

    @param context
    The 'context' pointer is that given as 'handler_context' argument
    for ssh_xml_parser_create().

    */
struct SshXmlContentHandlerRec
{
  /** The start of the document.  This is called before any other
      callback functions will be called for the current document. */
  SshOperationHandle (*start_document)(SshXmlParser parser,
                                       SshXmlResultCB result_cb,
                                       void *result_cb_context,
                                       void *context);

  /** The end of the document.  This is the last callback that is called
      for a document.  The parser will call this after it has reached
      the end of the input stream or if it has encountered an error
      from the document. */
  SshOperationHandle (*end_document)(SshXmlParser parser,
                                     SshXmlResultCB result_cb,
                                     void *result_cb_context,
                                     void *context);

  /** The start of an element.  The arguments 'name' and 'name_len'
      specify the qualified name of the element. */
  SshOperationHandle (*start_element)(SshXmlParser parser,
                                      const unsigned char *name,
                                      size_t name_len,
                                      SshADTContainer attributes,
                                      SshXmlResultCB result_cb,
                                      void *result_cb_context,
                                      void *context);

  /** The end of an element.  This callback is called for each element for
      which the parser called the 'start_element' callback.  This is
      called also from empty elements. */
  SshOperationHandle (*end_element)(SshXmlParser parser,
                                    const unsigned char *name,
                                    size_t name_len,
                                    SshXmlResultCB result_cb,
                                    void *result_cb_context,
                                    void *context);

  /** Character data.  The parser can return all character data with a
      single call or it may call the callback multiple times to return
      the character data in chunks.

      @param all_whitespace
      TRUE if the characters are all whitespace characters. */
  SshOperationHandle (*characters)(SshXmlParser parser,
                                   const unsigned char *data,
                                   size_t data_len,
                                   Boolean all_whitespace,
                                   SshXmlResultCB result_cb,
                                   void *result_cb_context,
                                   void *context);

  /** Ignorable whitespace in an element content. The data will contain
      the whitespace ignored.

      @param in_dtd
      Will be true if this occurred during the parsing of a DTD. */
  SshOperationHandle (*ignorable_wspace)(SshXmlParser parser,
                                         const unsigned char *data,
                                         size_t data_len,
                                         Boolean in_dtd,
                                         SshXmlResultCB result_cb,
                                         void *result_cb_context,
                                         void *context);

  /** The parser has just read a processing instruction '<?..?>' sequence,
      that is.

      @param target
      The name of the processing instruction.

      @param data
      The content of the instruction.

      */
  SshOperationHandle (*pi)(SshXmlParser parser,
                           const unsigned char *target,
                           size_t target_len,
                           const unsigned char *data,
                           size_t data_len,
                           SshXmlResultCB result_cb,
                           void *result_cb_context,
                           void *context);
};

typedef struct SshXmlContentHandlerRec SshXmlContentHandlerStruct;
typedef struct SshXmlContentHandlerRec *SshXmlContentHandler;


/** Error handler. These optional, application-defined functions are
    called when the parser/validator encounters an error situation. */
struct SshXmlErrorHandlerRec
{
  /** A warning - warnings are less serious than errors and fatal
      errors and they can normally be ignored. */
  void (*warning)(SshXmlParser parser,
                  const char *input_name, SshUInt32 line, SshUInt32 column,
                  const char *warning, void *context);

  /** A non-fatal error - according to the XML 1.0 specification, these
      are version number mismatches and violations of element and
      attribute constraints. */
  void (*error)(SshXmlParser parser,
                const char *input_name, SshUInt32 line, SshUInt32 column,
                const char *error, void *context);

  /** A fatal error - fatal errors are violations of XML documents's
      well-formedness constraints, unsupported character encodings,
      malformed character encodings, and errors in entity and character
      references. */
  void (*fatal_error)(SshXmlParser parser,
                      const char *input_name, SshUInt32 line, SshUInt32 column,
                      const char *error, void *context);
};

typedef struct SshXmlErrorHandlerRec SshXmlErrorHandlerStruct;
typedef struct SshXmlErrorHandlerRec *SshXmlErrorHandler;



/* DTD handler. */

/** The type of an element content specification. */
typedef enum
{
  SSH_XML_ELEMENT_CONTENT_EMPTY, /** EMPTY. */
  SSH_XML_ELEMENT_CONTENT_ANY,   /** ANY. */
  SSH_XML_ELEMENT_CONTENT_EXPR   /** Mixed or children. */
} SshXmlElementContentSpec;

/** DTD handler. These application defined functions are called to
    inform the application about the DTD. */
struct SshXmlDtdHandlerRec
{
  /** Entity declaration handler - just read in an entity with the given
      'name'; general is true, if the entity declaration contained '&'
      as its type; entity values starting with ' or " signs are
      internals.; the value is the internal value; the 'pubid', 'sysid'
      and 'ndata' are the external id references for non-internal
      entities (or NULL for internal entities). */
  SshOperationHandle (*entity_decl)(SshXmlParser parser,
                                    const unsigned char *name,
                                    size_t name_len,
                                    Boolean general,
                                    Boolean internal,
                                    const unsigned char *value,
                                    size_t value_len,
                                    const unsigned char *pubid,
                                    size_t pubid_len,
                                    const unsigned char *sysid,
                                    size_t sysid_len,
                                    const unsigned char *ndata,
                                    size_t ndata_len,
                                    SshXmlResultCB result_cb,
                                    void *result_cb_context,
                                    void *context);

  /** Notation declaration handler - just read in notation with the given
      'name'; the notation refers to external ID identified by 'pubid'
      and 'sysid'. */
  SshOperationHandle (*notation_decl)(SshXmlParser parser,
                                      const unsigned char *name,
                                      size_t name_len,
                                      const unsigned char *pubid,
                                      size_t pubid_len,
                                      const unsigned char *sysid,
                                      size_t sysid_len,
                                      SshXmlResultCB result_cb,
                                      void *result_cb_context,
                                      void *context);
  /** Element declaration handler - just read in element with given
      'name'; its content specification is one of EMPTY, ANY, or
      EXPR; in case of EXPR the 'content_spec_expr' string specifies
      the allowed children. */
  SshOperationHandle (*element_decl)(SshXmlParser parser,
                                     const unsigned char *name,
                                     size_t name_len,
                                     SshXmlElementContentSpec content_spec,
                                     const unsigned char *content_spec_expr,
                                     size_t content_spec_expr_len,
                                     SshXmlResultCB result_cb,
                                     void *result_cb_context,
                                     void *context);

  /** Attribute list declaration handler - read in ATTLIST referencing
      element 'element_name'; attributes specified for the referenced
      entity are the ADT BAG container; each element at the container
      is of type SshXmlAttributeDefinition. */
  SshOperationHandle (*attlist_decl)(SshXmlParser parser,
                                     const unsigned char *element_name,
                                     size_t element_name_len,
                                     SshADTContainer attribute_defs,
                                     SshXmlResultCB result_cb,
                                     void *result_cb_context,
                                     void *context);

  /** Document type declaration handler - read in DOCTYPE with given
      'name'; 'pubid' gives the identity if 'PUBLIC' was given on
      declaration and 'sysid' if 'SYSTEM' was given; if the DOCTYPE
      contains embedded DTD, it is parsed prior to calling this
      callback function. */
  SshOperationHandle (*doctype)(SshXmlParser parser,
                                const unsigned char *name,
                                size_t name_len,
                                const unsigned char *pubid,
                                size_t pubid_len,
                                const unsigned char *sysid,
                                size_t sysid_len,
                                SshXmlResultCB result_cb,
                                void *result_cb_context,
                                void *context);
};

typedef struct SshXmlDtdHandlerRec SshXmlDtdHandlerStruct;
typedef struct SshXmlDtdHandlerRec *SshXmlDtdHandler;

/* Entity resolver. */

/** A callback function of this type is called to resolve unknown
    entities.

    The arguments 'pubid', 'pubid_len', 'sysid', 'sysid_len' specify
    the IDs of an external entity.

    The callback function must call the result callback 'result_cb' to
    complete the operation.

    @param where_defined
    Contains the name of the input stream that defined the entity.
    Note that the value of the argument 'where_defined' can be NULL.

    @param general
    Specifies whether the entity is a general or a parameter entity.

    @param name
    Specifies the name of the entity for unknown internal entities.
    Note that 'name' can have a value of NULL.

    @param name_len
    Specifies the length of the name of the entity for unknown internal
    entities.

    */
typedef SshOperationHandle (*SshXmlEntityCB)(SshXmlParser parser,
                                             const char *where_defined,
                                             Boolean general,
                                             const unsigned char *name,
                                             size_t name_len,
                                             const unsigned char *pubid,
                                             size_t pubid_len,
                                             const unsigned char *sysid,
                                             size_t sysid_len,
                                             SshXmlStreamCB result_cb,
                                             void *result_cb_context,
                                             void *context);

/* Parse done notification. */

/** A callback function of this type is called when the XML parser
    'parser' has finished the parse operation.  This callback can be
    used to clear any dynamic state in chained parsers. */
typedef void (*SshXmlParseDoneCB)(SshXmlParser parser, void *context);


/* ********************* Handling XML parser objects ************************/

/** Parameters for an XML parser.  If any of the fields has the value
    NULL or 0, the default value will be used for that field. */
struct SshXmlParamsRec
{
  /** Be strict XML 1.0 (Second Edition) parser.  As a default, allow
      some quite commonly used sloppiness. */
  Boolean strict_1_0_ed_2;

  /** Do not support 'Namespaces in XML'. */
  Boolean no_namespaces;
};

typedef struct SshXmlParamsRec SshXmlParamsStruct;
typedef struct SshXmlParamsRec *SshXmlParams;

/** Creates an XML parser object.

    Each of 'content_handler', 'error_handler' and 'dtd_handler'
    parameters must be non-null pointers. However the function
    pointers they contain may be null.

    The pointers given to this function need to stay alive until a
    ssh_xml_parser_destroy call has returned.

    See ssh_xml_parser_parse_dtd_file and
    ssh_xml_parser_parse_xml_file for ways to pass documents to
    the parser.

    @param params
    Specifies optional parameters for the parser.  If the argument
    'params' has the value NULL or any of its fields has the value
    NULL or 0, the default values will be used for those fields.

    @param entity_resolver
    The 'entity_resolver' function is called for resolving external
    entities.

    @param parse_done_cb
    The 'parse_done_cb' function is called to indicate the document
    has been parsed, and that this instance of parser will no longer
    call any callbacks.

    @param handler_context
    The 'handler_context' pointer is given as a 'context' argument to
    all callbacks specified at 'content_handler', 'error_handler', and
    'dtd_handler' structures and for 'entity_resolver' and
    'parse_done_cb' functions.

    */
SshXmlParser ssh_xml_parser_create(
                        SshXmlParams params,
                        const SshXmlContentHandlerStruct *content_handler,
                        const SshXmlErrorHandlerStruct *error_handler,
                        const SshXmlDtdHandlerStruct *dtd_handler,
                        SshXmlEntityCB entity_resolver,
                        SshXmlParseDoneCB parse_done_cb,
                        void *handler_context);

/** Destroy the XML parser 'parser'. */
void ssh_xml_parser_destroy(SshXmlParser parser);

/** Enable or disable the 'feature' feature for the 'parser' parser. */
void ssh_xml_parser_feature(SshXmlParser parser, const char *feature,
                            Boolean enable);


/* ******************** Handling XML verifier objects ***********************/

/** A callback function of this type is called to fetch the DTD
    indicated by 'pubid' and 'sysid' of an XML document that is
    currently being verified.

    This application-defined function needs to return the DTD as a
    stream using the library provided callback function 'result_cb'.

    The stream may be NULL if the DTD could not be retrieved. */

typedef SshOperationHandle (*SshXmlVerifierDtdCB)(SshXmlParser parser,
                                                  const unsigned char *pubid,
                                                  size_t pubid_len,
                                                  const unsigned char *sysid,
                                                  size_t sysid_len,
                                                  SshXmlStreamCB result_cb,
                                                  void *result_cb_context,
                                                  void *context);

/** Parameters for an XML verifier.  If any of the fields has the value
    NULL or 0, the default value will be used for that field. */
struct SshXmlVerifierParamsRec
{
  /** Don't allow attribute declaration override - this option can be
      used to prevent an internal DTD subset from overriding the external
      DTD. */
  Boolean no_attr_decl_override;

  /** Do not allow references to ID attributes which are defined later
      in the document. */
  Boolean no_forward_id_refs;
};

typedef struct SshXmlVerifierParamsRec SshXmlVerifierParamsStruct;
typedef struct SshXmlVerifierParamsRec *SshXmlVerifierParams;

/** Create a new XML verifier object. */
SshXmlVerifier ssh_xml_verifier_create(SshXmlVerifierParams params,
                                       SshXmlVerifierDtdCB dtd_callback,
                                       void *dtd_callback_context);

/** Destroy the XML verifier object 'verifier'. */
void ssh_xml_verifier_destroy(SshXmlVerifier verifier);

/** Sets the verifier 'verifier' for the XML parser 'parser'.
    The verifier will intercept some handler methods and provide
    verifier XML content for the user of the parser 'parser'.

    Note that you must configure your handler methods for the parser
    before you set the verifier object for it.

    @return
    The function returns TRUE if the verifier was set, and FALSE
    otherwise. */

Boolean ssh_xml_parser_set_verifier(SshXmlParser parser,
                                    SshXmlVerifier verifier);

/** Unhook the verifier 'verifier' from the parser for which it was set
    with the ssh_xml_parser_set_verifier function. */
void ssh_xml_verifier_unhook(SshXmlVerifier verifier);


/* ********************* High-level parsing functions ***********************/

/** Parse 'data_len' bytes of XML data 'data' with the parser 'parser'.
    The function calls the result callback 'result_cb' to notify about
    the success of the operation. */
SshOperationHandle ssh_xml_parser_parse_xml_data(SshXmlParser parser,
                                                 const unsigned char *data,
                                                 size_t data_len,
                                                 SshXmlResultCB result_cb,
                                                 void *context);

/** Parse 'data_len' bytes of DTD data 'data' with the parser 'parser'.
    The function calls the result callback 'result_cb' to notify about
    the success of the operation. */
SshOperationHandle ssh_xml_parser_parse_dtd_data(SshXmlParser parser,
                                                 const unsigned char *data,
                                                 size_t data_len,
                                                 SshXmlResultCB result_cb,
                                                 void *context);

/** Parse XML file 'file_name' with the parser 'parser'.  The function
    calls the result callback 'result_cb' to notify about the success
    of the operation. */
SshOperationHandle ssh_xml_parser_parse_xml_file(SshXmlParser parser,
                                                 const char *file_name,
                                                 SshXmlResultCB result_cb,
                                                 void *context);

/** Parse DTD file 'file_name' with the parser 'parser'.  The function
    calls the result callback 'result_cb' to notify about the success
    of the operation. */
SshOperationHandle ssh_xml_parser_parse_dtd_file(SshXmlParser parser,
                                                 const char *file_name,
                                                 SshXmlResultCB result_cb,
                                                 void *context);


/* ******** Accessing names, attributes, and attribute definitions **********/

/** Case sensitive match name 'name' of length 'name_len' to the string
    'string'.  If the arguments 'name_len' or 'string_len' have the
    value 0, the function will assume that the corresponding 'name' or
    'string' argument is null-terminated.

    @return
    The function returns TRUE if the 'name' and 'string' match,
    and FALSE otherwise. */
Boolean ssh_xml_match(const unsigned char *name, size_t name_len,
                      const unsigned char *string, size_t string_len);


/* These functions can be used in handler method functions. They are not useful
   outside of handler functions. */

/** Get the local part of the qualified name 'name'.  The returned
    value is valid as long as the parser 'parser' is valid. */
const unsigned char *ssh_xml_get_local_name(SshXmlParser parser,
                                            const unsigned char *name,
                                            size_t name_len,
                                            size_t *local_name_len_return);

/** Get the namespace name from the qualified name 'name'.  The
    returned value is valid as long as the parser 'parser' is valid. */
const unsigned char *ssh_xml_get_namespace(SshXmlParser parser,
                                           const unsigned char *name,
                                           size_t name_len,
                                           size_t *namespace_name_len_return);

/** Get the namespace name from the qualified attribute name 'name'.
    This is like ssh_xml_get_namespace() but attributes do not have
    a default namespace.  The returned value is valid as long as the
    parser 'parser' is valid. */
const unsigned char *ssh_xml_get_attr_namespace(
                                        SshXmlParser parser,
                                        const unsigned char *name,
                                        size_t name_len,
                                        size_t *namespace_name_len_return);

/** Returns an ADT handle for the attribute 'name' from the attribute
    bag 'attributes'.

    @return
    The function returns a valid ADT handle, or
    SSH_ADT_INVALID if there was no such attribute. */
SshADTHandle ssh_xml_get_attr_handle_by_name(SshADTContainer attributes,
                                             const unsigned char *name,
                                             size_t name_len);

/** Get the qualified name of the attribute 'handle'. */
const unsigned char *ssh_xml_attr_handle_get_name(SshADTContainer attributes,
                                                  SshADTHandle handle,
                                                  size_t *name_len_return);

/** Get the value of the attribute 'handle'. */
const unsigned char *ssh_xml_attr_handle_get_value(SshADTContainer attributes,
                                                   SshADTHandle handle,
                                                   size_t *value_len_return);

/** Get the value of the attribute 'name'.

    @return
    The function returns NULL if the attribute is unspecified, and its
    value otherwise. If the argument 'value_len_return' is non-null,
    it is set to contain the length of the attribute value. */
const unsigned char *ssh_xml_get_attr_value(SshADTContainer attributes,
                                            const unsigned char *name,
                                            size_t name_len,
                                            size_t *value_len_return);


/* Enumerating over items of an attribute value. */

/** The type of the attribute value to enumerate. */
typedef enum
{
  SSH_XML_ATTR_ENUM_IDREFS,
  SSH_XML_ATTR_ENUM_ENTITIES,
  SSH_XML_ATTR_ENUM_NMTOKENS
} SshXmlAttrEnumType;

/** Context data for an attribute value enumeration. */
typedef struct SshXmlAttrEnumCtxRec *SshXmlAttrEnumCtx;
/** Context data for an attribute value enumeration. */
typedef struct SshXmlAttrEnumCtxRec SshXmlAttrEnumCtxStruct;

/** Start enumerating the value of the attribute 'attr_name',
    'attr_name_len'.  The type of the attribute value is specified with
    the 'enum_type' argument.  The function initializes the enumeration
    into the enumeration context 'enum_ctx'.  It must remain valid as
    long as the enumeration is active. */
void ssh_xml_attr_value_enum_init(SshADTContainer attributes,
                                  const unsigned char *attr_name,
                                  size_t attr_name_len,
                                  SshXmlAttrEnumType enum_type,
                                  SshXmlAttrEnumCtx enum_ctx);

/** Start enumerating UTF-8 encoded value 'value' with the enumeration
    type 'enum_type'.  The function intializes the enumeration context
    'enum_ctx' which must be allocated by the caller. */
void ssh_xml_value_enum_init(const unsigned char *value, size_t value_len,
                             SshXmlAttrEnumType enum_type,
                             SshXmlAttrEnumCtx enum_ctx);

/** Get the next value of the attribute value enumeration 'enum_ctx'.
    The function returns the value or NULL if all values have been
    enumerated. */
const unsigned char *ssh_xml_attr_value_enum_next(SshXmlAttrEnumCtx enum_ctx,
                                                  size_t *value_len_return);


/* ******************** Locations in the input stream ***********************/

/** The current location in the input stream of the parser 'parser'.

    @return
    The name of the input file, the current line number, and
    the current column are returned in 'input_stream_name_return',
    'linenum_return', and 'column_return' respectively. */
void ssh_xml_location(SshXmlParser parser,
                      const char **input_stream_name_return,
                      SshUInt32 *linenum_return,
                      SshUInt32 *column_return);


/* ********************* Low-level parsing functions ************************/

/** Parse input stream 'stream' with the XML parser 'parser'.

    The arguments 'destructor_cb' and 'destructor_cb_context'
    specify an optional destructor callback that is called after
    the stream 'stream' has been destroyed.

    The function will call the result callback 'result_cb' when
    the parsing is complete.  The function will destroy the stream
    when the parsing is done either successfully on
    unsuccessfully.

    @param dtd
    Specifies whether the input stream contains DTD or XML data.

    @param stream_name
    Gives a human readable name for the input stream 'stream'.  It
    is shown in possible error messages generated from the stream.

    */

SshOperationHandle ssh_xml_parser_parse_stream(
                                        SshXmlParser parser,
                                        Boolean dtd,
                                        SshStream stream,
                                        const char *stream_name,
                                        SshXmlDestructorCB destructor_cb,
                                        void *destructor_cb_context,
                                        SshXmlResultCB result_cb,
                                        void *context);

/* Include internal structure definitions which are shown only to
   allow inlining them into structures and for allocating them from
   the stack. */
#include "sshxml_structs.h"

#endif /* not SSHXML_H */
