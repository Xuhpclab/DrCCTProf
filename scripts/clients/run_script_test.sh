#! /bin/bash
CUR_DIR=$(cd "$(dirname "$0")";pwd)
# set -euo pipefail
# APP_FUN_PATH=$CUR_DIR/../../test_apps/build/test_app_cct
APP_FUN_PATH=$CUR_DIR/../../test_apps/build/test_app_multithread
$CUR_DIR/run_cct_null.sh $APP_FUN_PATH
$CUR_DIR/run_cct_ins_counting.sh $APP_FUN_PATH
$CUR_DIR/run_cct_all_ins.sh $APP_FUN_PATH
$CUR_DIR/run_cct_mem.sh $APP_FUN_PATH
$CUR_DIR/run_cct_mem_with_datatcentric.sh $APP_FUN_PATH
$CUR_DIR/run_cct_memory_with_data_centric_with_search.sh $APP_FUN_PATH