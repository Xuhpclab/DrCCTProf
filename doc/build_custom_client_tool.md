# How to build your own custom tools?

coming soon

## Data Structures

## Functional APIs
- context_handle_t **drcctlib_get_context_handle**(void *drcontext, int32_t opaqueHandle);
  - Description:
    - Get the calling context handle (context_handle_t)
  - Arguments:
    -drcontext: Dynamorio’s thread private context of the asking thread.
    - opaqueHandle: handle passed by DrCCTProf to the client tool in its userCallback.
- data_handle_t **drcctlib_get_data_hndl**(void *drcontext, void *address);
  - Description:
      - Call when need the handle to a data object (data_handle_t)
  - Arguments:
    - drcontext: Dynamorio’s thread private context of the asking thread.
    - address: effective address for which the data object is needed.
