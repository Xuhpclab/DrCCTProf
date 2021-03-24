/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#ifndef _DRCCTLIB_VSCODEEX_FORMAT_H_
#define _DRCCTLIB_VSCODEEX_FORMAT_H_

#include <cstdint>
#include <vector>
#include <string>
#include <map>

#include "dr_api.h"
#include "drcctlib_defines.h"
#include "drcctlib_utils.h"

#include "profile.pb-c.h"

namespace DrCCTProf { namespace Profile {

    typedef struct _function_map_key_t{
        int64_t file_path_;
        int64_t name_;

        bool operator==(const struct _function_map_key_t &f) const {
            return file_path_ == f.file_path_ && name_ == f.name_;
        }

        bool operator<(const struct _function_map_key_t &f)  const {
            return file_path_ < f.file_path_ || (file_path_ == f.file_path_ && name_ < f.name_);
        }
    } function_map_key_t;

    class string_table_t {
    public:
        DR_EXPORT
        string_table_t();

        DR_EXPORT
        ~string_table_t();

        DR_EXPORT
        int64_t
        add_string(std::string str);

        DR_EXPORT
        int64_t
        add_string(char *c_str);

        DR_EXPORT
        std::string
        get_string(int64_t index);
        
        DR_EXPORT
        size_t
        get_table_size();

        DR_EXPORT
        char**
        encode();

    private:
        std::map<std::string, int64_t> *table_;
        int64_t max_index_;

        char** buffer_;
        char* table_buffer_;
    };

    class fmt_metric_type_t {
    public:
        DR_EXPORT
        fmt_metric_type_t(int64_t value_type, int64_t unit, int64_t des);
        DR_EXPORT
        ~fmt_metric_type_t();

        DR_EXPORT
        Drcctprof__Profile__MetricType * encode();
    private:
        int64_t value_type_;
        int64_t unit_;
        int64_t des_;
        
        Drcctprof__Profile__MetricType buffer_;
    };

    class fmt_metric_t {
    public:
        DR_EXPORT
        fmt_metric_t(int64_t int_value, uint64_t uint_value, int64_t str_value);
        DR_EXPORT
        ~fmt_metric_t();

        DR_EXPORT
        Drcctprof__Profile__Metric *
        encode();

    private:
        int64_t int_value_;
        uint64_t uint_value_;
        int64_t str_value_;

        Drcctprof__Profile__Metric buffer_;
    };

    class source_file_t {
    public:
        DR_EXPORT
        source_file_t(uint64_t id, int64_t file_name, int64_t location_path,
                      int64_t type);
        DR_EXPORT
        ~source_file_t();

        DR_EXPORT
        uint64_t
        get_id();

        DR_EXPORT
        Drcctprof__Profile__SourceFile *
        encode();

    private:
        uint64_t id_;
        int64_t file_name_;
        int64_t location_path_;
        int64_t type_;

        Drcctprof__Profile__SourceFile buffer_;
    };

    class function_t {
    public:
        DR_EXPORT
        function_t(uint64_t id, int64_t name, int64_t system_name, int64_t start_line,
                   source_file_t *source_file);
        DR_EXPORT
        ~function_t();

        DR_EXPORT
        uint64_t
        get_id();

        DR_EXPORT
        void
        set_start_line(int64_t line_no);

        DR_EXPORT
        Drcctprof__Profile__Function *
        encode();

    private:
        uint64_t id_;
        int64_t name_;
        int64_t system_name_;
        int64_t start_line_;
        source_file_t *source_file_;

        Drcctprof__Profile__Function buffer_;
    };

    class line_t {
    public:
        DR_EXPORT
        line_t(function_t *func, int64_t line);
        DR_EXPORT
        ~line_t();

        DR_EXPORT
        Drcctprof__Profile__Line *
        encode();

    private:
        function_t *func_;
        int64_t line_;

        Drcctprof__Profile__Line buffer_;
    };

    class location_t {
    public:
        DR_EXPORT
        location_t(uint64_t id);
        DR_EXPORT
        ~location_t();
        DR_EXPORT
        void
        append_line(line_t *line);

        DR_EXPORT
        uint64_t
        get_id();

        DR_EXPORT
        Drcctprof__Profile__Location *
        encode();

    private:
        uint64_t id_;
        std::vector<line_t *> *line_;

        Drcctprof__Profile__Location buffer_;
    };

    class fmt_context_t {
    public:
        DR_EXPORT
        fmt_context_t(uint64_t id, location_t *location, fmt_context_t *parent);
        DR_EXPORT ~fmt_context_t();
        DR_EXPORT
        void
        add_child(fmt_context_t *child);

        DR_EXPORT
        uint64_t
        get_id();

        DR_EXPORT
        Drcctprof__Profile__Context *
        encode();

    private:
        uint64_t id_;
        location_t *location_;
        fmt_context_t *parent_;
        std::vector<fmt_context_t *> *children_;

        Drcctprof__Profile__Context buffer_;
    };

    class sample_t {
    public:
        DR_EXPORT
        sample_t(fmt_context_t *context);
        DR_EXPORT
        ~sample_t();
        DR_EXPORT
        void
        append_metirc(fmt_metric_t *metric);

        DR_EXPORT
        Drcctprof__Profile__Sample *
        encode();

    private:
        fmt_context_t *context_;
        std::vector<fmt_metric_t *> *metric_;

        Drcctprof__Profile__Sample buffer_;
    };

    class profile_t {
    public:
        DR_EXPORT
        profile_t();
        DR_EXPORT
        ~profile_t();

        DR_EXPORT
        Drcctprof__Profile__Profile *
        encode();

        DR_EXPORT
        void
        serialize_to_file(const char *file_name);

        DR_EXPORT
        void
        add_metric_type(int64_t value_type, std::string unit, std::string des);

        DR_EXPORT
        sample_t *
        add_sample(context_t *ctxt);

        DR_EXPORT
        fmt_context_t *
        add_context(context_t *ctxt);

        DR_EXPORT
        location_t *
        add_location(context_t *ctxt);

        DR_EXPORT
        function_t *
        add_function(context_t *ctxt);

        DR_EXPORT
        source_file_t *
        add_source_file(context_t *ctxt);

    private:
        std::vector<fmt_metric_type_t *> *metric_type_list_;
        std::vector<sample_t *> *sample_list_;

        std::map<uint64_t, fmt_context_t *> *context_map_;
        std::map<uint64_t, location_t *> *location_map_;

        uint64_t func_max_id_;
        std::map<function_map_key_t, function_t *> *func_map_;

        std::map<int64_t, source_file_t *> *source_file_map_;

        string_table_t *string_table_;

        Drcctprof__Profile__Profile buffer_;
    };
}
}

#endif // _DRCCTLIB_VSCODEEX_FORMAT_H_