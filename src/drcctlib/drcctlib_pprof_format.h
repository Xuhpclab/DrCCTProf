/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#ifndef _DRCCTLIB_PPROF_FORMAT_H_
#define _DRCCTLIB_PPROF_FORMAT_H_

#include <cstdint>
#include <vector>
#include <string>
#include <map>

#include "dr_api.h"
#include "drcctlib_defines.h"
#include "drcctlib_utils.h"

#include "pprof_profile.pb-c.h"

namespace DrCCTProf { namespace PprofProfile {

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

    class value_type_t {
    public:
        DR_EXPORT
        value_type_t(int64_t type, int64_t unit);
        DR_EXPORT
        ~value_type_t();

        DR_EXPORT
        Perftools__Profiles__ValueType * encode();
    private:
        int64_t type_;
        int64_t unit_;
        
        Perftools__Profiles__ValueType buffer_;
    };

    class label_t {
    public:
        DR_EXPORT
        label_t(int64_t key, int64_t str, int64_t num, int64_t num_unit);
        DR_EXPORT
        ~label_t();

        DR_EXPORT
        Perftools__Profiles__Label *
        encode();

    private:
        int64_t key_;
        int64_t str_;
        int64_t num_;
        int64_t num_unit_;

        Perftools__Profiles__Label buffer_;
    };

    class mapping_t {
    public:
        DR_EXPORT
        mapping_t(uint64_t id, uint64_t memory_start, uint64_t memory_end,
                  uint64_t file_offset, int64_t filename, int64_t build_id,
                  bool has_functions, bool has_filenames, bool has_line_numbers,
                  bool has_inline_frames);
        DR_EXPORT
        ~mapping_t();

        DR_EXPORT
        uint64_t
        get_id();

        DR_EXPORT
        Perftools__Profiles__Mapping *
        encode();

    private:
        uint64_t id_;
        uint64_t memory_start_;
        uint64_t memory_limit_;
        uint64_t file_offset_;

        int64_t filename_;
        int64_t build_id_;
        bool has_functions_;
        bool has_filenames_;
        bool has_line_numbers_;
        bool has_inline_frames_;

        Perftools__Profiles__Mapping buffer_;
    };

    class function_t {
    public:
        DR_EXPORT
        function_t(uint64_t id, int64_t name, int64_t system_name, int64_t start_line,
                   int64_t filename);
        DR_EXPORT
        ~function_t();

        DR_EXPORT
        uint64_t
        get_id();

        DR_EXPORT
        void
        set_start_line(int64_t line_no);

        DR_EXPORT
        Perftools__Profiles__Function *
        encode();

    private:
        uint64_t id_;
        int64_t name_;
        int64_t system_name_;
        int64_t start_line_;
        int64_t filename_;

        Perftools__Profiles__Function buffer_;
    };

    class line_t {
    public:
        DR_EXPORT
        line_t(function_t *func, int64_t line);
        DR_EXPORT
        ~line_t();

        DR_EXPORT
        Perftools__Profiles__Line *
        encode();

    private:
        function_t *func_;
        int64_t line_;

        Perftools__Profiles__Line buffer_;
    };

    class location_t {
    public:
        DR_EXPORT
        location_t(uint64_t id, mapping_t* mapping, uint64_t address, bool is_folded);
        DR_EXPORT
        ~location_t();
        DR_EXPORT
        void
        append_line(line_t *line);

        DR_EXPORT
        uint64_t
        get_id();

        DR_EXPORT
        Perftools__Profiles__Location *
        encode();

    private:
        uint64_t id_;
        mapping_t* mapping_;
        uint64_t address_;
        std::vector<line_t *> *line_;
        bool is_folded_;

        Perftools__Profiles__Location buffer_;
    };

    class sample_t {
    public:
        DR_EXPORT
        sample_t();
        DR_EXPORT
        ~sample_t();
        DR_EXPORT
        void
        append_location(location_t *location);
        DR_EXPORT
        void
        append_value(int64_t value);
        DR_EXPORT
        void
        append_label(label_t *);

        DR_EXPORT
        Perftools__Profiles__Sample *
        encode();

    private:
        std::vector<location_t *> *location_;
        std::vector<int64_t> *value_;
        std::vector<label_t *> *label_;

        Perftools__Profiles__Sample buffer_;
    };

    class profile_t {
    public:
        DR_EXPORT
        profile_t();
        DR_EXPORT
        ~profile_t();

        DR_EXPORT
        Perftools__Profiles__Profile *
        encode();

        DR_EXPORT
        void
        serialize_to_file(const char *filename);

        DR_EXPORT
        void
        add_sample_type(std::string type, std::string unit);

        DR_EXPORT
        sample_t *
        add_sample(context_t *ctxt);

        DR_EXPORT
        mapping_t *
        add_mapping(context_t *ctxt);

        DR_EXPORT
        location_t *
        add_location(context_t *ctxt);

        DR_EXPORT
        function_t *
        add_function(context_t *ctxt);

    private:
        std::vector<value_type_t *> *sample_type_list_;
        std::vector<sample_t *> *sample_list_;

        std::map<uint64_t, mapping_t *> *mapping_map_;
        uint64_t location_max_id_;
        std::map<uint64_t, uint64_t> *location_ip_map_;
        std::map<uint64_t, location_t *> *location_map_;

        uint64_t func_max_id_;
        std::map<function_map_key_t, function_t *> *func_map_;

        string_table_t *string_table_;

        Perftools__Profiles__Profile buffer_;
    };
}
}

#endif // _DRCCTLIB_PPROF_FORMAT_H_