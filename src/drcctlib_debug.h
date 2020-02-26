#ifndef _DRCCTLIB_DEBUG_H_
#define _DRCCTLIB_DEBUG_H_

// #define DRCCTLIB_DEBUG
#ifdef DRCCTLIB_DEBUG
const char * drsym_error_t_strlist[] = {
    "DRSYM_SUCCESS",                     /**< Operation succeeded. */
    "DRSYM_ERROR",                       /**< Operation failed. */
    "DRSYM_ERROR_INVALID_PARAMETER",     /**< Operation failed: invalid parameter */
    "DRSYM_ERROR_INVALID_SIZE",          /**< Operation failed: invalid size */
    "DRSYM_ERROR_LOAD_FAILED",           /**< Operation failed: unable to load symbols */
    "DRSYM_ERROR_SYMBOL_NOT_FOUND",      /**< Operation failed: symbol not found */
    "DRSYM_ERROR_LINE_NOT_AVAILABLE",    /**< Operation failed: line info not available */
    "DRSYM_ERROR_NOT_IMPLEMENTED",       /**< Operation failed: not yet implemented */
    "DRSYM_ERROR_FEATURE_NOT_AVAILABLE", /**< Operation failed: not available */
    "DRSYM_ERROR_NOMEM",                 /**< Operation failed: not enough memory */
    "DRSYM_ERROR_RECURSIVE" /**< Operation failed: unavailable when recursive */
};

#    define GET_DRSYM_ERROR_TYPE_MESSAGE(x) drsym_error_t_strlist[x]

#endif

#endif // _DRCCTLIB_DEBUG_H_