# Alias drrun

```
alias drrun="$PWD/build/bin64/drrun"
alias testpath="$PWD/test_apps/build/test_app_cct"

drrun -t drcctlib_memory_only -- testpath/test_app_cct
drrun -t drcctlib_instr_statistics -- $PWD/test_apps/build/test_app_cct -debug
```
