/*
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */
#include <stdio.h>
#include <algorithm>

#include "drcctlib_pprof_format.h"

#define DRCCTLIB_PRINTF(_FORMAT, _ARGS...) \
    DRCCTLIB_PRINTF_TEMPLATE("pprof_format", _FORMAT, ##_ARGS)
#define DRCCTLIB_EXIT_PROCESS(_FORMAT, _ARGS...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("pprof_format", _FORMAT, ##_ARGS)

/*
 * DrCCTProf::PprofProfile::string_table_t
 */

DrCCTProf::PprofProfile::string_table_t::string_table_t()
    : max_index_(0)
    , buffer_(NULL)
    , table_buffer_(NULL)
{
    this->table_ = new std::map<std::string, int64_t>();
    (*this->table_).insert(std::pair<std::string, int64_t>("", this->max_index_));
}

DrCCTProf::PprofProfile::string_table_t::~string_table_t()
{
    delete this->table_;
    free(this->buffer_);
    free(this->table_buffer_);
}

int64_t
DrCCTProf::PprofProfile::string_table_t::add_string(std::string str)
{
    std::map<std::string, int64_t>::iterator it = (*this->table_).find(str);
    if (it != (*this->table_).end()) {
        return it->second;
    }
    (*this->table_).insert(std::pair<std::string, int64_t>(str, ++this->max_index_));
    return this->max_index_;
}

int64_t
DrCCTProf::PprofProfile::string_table_t::add_string(char *c_str)
{
    if (c_str == NULL) {
        DRCCTLIB_EXIT_PROCESS(
            "Error: [DrCCTProf::PprofProfile::string_table_t::add_string(char* c_str)] c_str "
            "== NULL .");
    }
    std::string str = c_str;
    return this->add_string(str);
}

std::string
DrCCTProf::PprofProfile::string_table_t::get_string(int64_t index)
{
    if (index > this->max_index_) {
        return std::string("");
    }
    auto it = std::find_if(
        (*this->table_).begin(), (*this->table_).end(),
        [&index](const std::pair<std::string, int64_t> &p) { return p.second == index; });

    if (it == (*this->table_).end()) {
        return std::string("");
    } else {
        return it->first;
    }
}

size_t
DrCCTProf::PprofProfile::string_table_t::get_table_size()
{
    return (size_t)(max_index_ + 1);
}

char **
DrCCTProf::PprofProfile::string_table_t::encode()
{
    if (this->buffer_) {
        free(this->buffer_);
    }
    size_t buffer_size = (size_t)(max_index_ + 1);
    this->buffer_ = (char **)malloc(sizeof(char *) * buffer_size);

    size_t global_len = 0;
    std::map<int64_t, size_t> *offset_map = new std::map<int64_t, size_t>();
    for (auto &str : (*this->table_)) {
        size_t str_len = str.first.length() + 1;
        (*offset_map).insert(std::pair<int64_t, size_t>(str.second, str_len));
        global_len += str_len;
    }
    if (this->table_buffer_) {
        free(this->table_buffer_);
    }
    this->table_buffer_ = (char *)malloc(sizeof(char) * global_len);

    size_t cur_offset = 0;
    for (size_t i = 0; i < buffer_size; i++) {
        this->buffer_[i] = this->table_buffer_ + cur_offset;
        size_t temp_offset = cur_offset;
        cur_offset += (*offset_map)[i];
        (*offset_map)[i] = temp_offset;
    }

    for (auto &str : (*this->table_)) {
        memcpy(this->buffer_[str.second], str.first.c_str(), str.first.length() + 1);
    }

    delete offset_map;

    return this->buffer_;
}

/*
 * DrCCTProf::PprofProfile::value_type_t
 */

DrCCTProf::PprofProfile::value_type_t::value_type_t(int64_t type, int64_t unit)
    : type_(type)
    , unit_(unit)
{
    this->buffer_ = PERFTOOLS__PROFILES__VALUE_TYPE__INIT;
}

DrCCTProf::PprofProfile::value_type_t::~value_type_t()
{
}

Perftools__Profiles__ValueType *
DrCCTProf::PprofProfile::value_type_t::encode()
{
    this->buffer_.type = this->type_;
    this->buffer_.unit = this->unit_;
    return &(this->buffer_);
}

/*
 * DrCCTProf::PprofProfile::label_t
 */

DrCCTProf::PprofProfile::label_t::label_t(int64_t key, int64_t str, int64_t num, int64_t num_unit)
    : key_(key)
    , str_(str)
    , num_(num)
    , num_unit_(num_unit)
{
    this->buffer_ = PERFTOOLS__PROFILES__LABEL__INIT;
}

DrCCTProf::PprofProfile::label_t::~label_t()
{
}

Perftools__Profiles__Label *
DrCCTProf::PprofProfile::label_t::encode()
{
    this->buffer_.key = this->key_;
    this->buffer_.str = this->str_;
    this->buffer_.num = this->num_;
    this->buffer_.num_unit = this->num_unit_;
    return &(this->buffer_);
}

/*
 * DrCCTProf::PprofProfile::mapping_t
 */

DrCCTProf::PprofProfile::mapping_t::mapping_t(uint64_t id, uint64_t memory_start, uint64_t memory_limit,
                  uint64_t file_offset, int64_t filename, int64_t build_id,
                  bool has_functions, bool has_filenames, bool has_line_numbers,
                  bool has_inline_frames)
    :id_(id)
    ,memory_start_(memory_start)
    ,memory_limit_(memory_limit)
    ,file_offset_(file_offset)
    ,filename_(filename)
    ,build_id_(build_id)
    ,has_functions_(has_functions)
    ,has_filenames_(has_filenames)
    ,has_line_numbers_(has_line_numbers)
    ,has_inline_frames_(has_inline_frames)
{
    this->buffer_ = PERFTOOLS__PROFILES__MAPPING__INIT;
}

DrCCTProf::PprofProfile::mapping_t::~mapping_t()
{
}

uint64_t
DrCCTProf::PprofProfile::mapping_t::get_id()
{
    return this->id_;
}

Perftools__Profiles__Mapping *
DrCCTProf::PprofProfile::mapping_t::encode()
{
    this->buffer_.id = this->id_;
    this->buffer_.memory_start = this->memory_start_;
    this->buffer_.memory_limit = this->memory_limit_;
    this->buffer_.file_offset = this->file_offset_;

    this->buffer_.filename = this->filename_;
    this->buffer_.build_id = this->build_id_;

    this->buffer_.has_functions = this->has_functions_ ? 1 : 0;
    this->buffer_.has_filenames = this->has_filenames_ ? 1 : 0;
    this->buffer_.has_line_numbers = this->has_line_numbers_ ? 1 : 0;
    this->buffer_.has_inline_frames = this->has_inline_frames_ ? 1 : 0;

    return &(this->buffer_);
}


/*
 * DrCCTProf::PprofProfile::function_t
 */

DrCCTProf::PprofProfile::function_t::function_t(uint64_t id, int64_t name, int64_t system_name, int64_t start_line,
                   int64_t filename)
    : id_(id)
    , name_(name)
    , system_name_(system_name)
    , start_line_(start_line)
    , filename_(filename)
{
    buffer_ = PERFTOOLS__PROFILES__FUNCTION__INIT;
}

DrCCTProf::PprofProfile::function_t::~function_t()
{
}

uint64_t
DrCCTProf::PprofProfile::function_t::get_id()
{
    return this->id_;
}

void
DrCCTProf::PprofProfile::function_t::set_start_line(int64_t line_no)
{
    this->start_line_ = (this->start_line_ == 0 || this->start_line_ > line_no)
        ? line_no
        : this->start_line_;
}

Perftools__Profiles__Function *
DrCCTProf::PprofProfile::function_t::encode()
{
    this->buffer_.id = this->id_;
    this->buffer_.name = this->name_;
    this->buffer_.system_name = this->system_name_;
    this->buffer_.start_line = this->start_line_;
    this->buffer_.filename = this->filename_;
    return &(this->buffer_);
}

/*
 * DrCCTProf::PprofProfile::line_t
 */

DrCCTProf::PprofProfile::line_t::line_t(DrCCTProf::PprofProfile::function_t *func, int64_t line)
    : func_(func)
    , line_(line)
{
    this->buffer_ = PERFTOOLS__PROFILES__LINE__INIT;
}

DrCCTProf::PprofProfile::line_t::~line_t()
{
}

Perftools__Profiles__Line *
DrCCTProf::PprofProfile::line_t::encode()
{
    this->buffer_.function_id = this->func_->get_id();
    this->buffer_.line = this->line_;
    return &(this->buffer_);
}

/*
 * DrCCTProf::PprofProfile::location_t
 */

DrCCTProf::PprofProfile::location_t::location_t(uint64_t id, mapping_t* mapping, uint64_t address, bool is_folded)
    : id_(id)
    , mapping_(mapping)
    , address_(address)
    , is_folded_(is_folded)
{
    this->line_ = new std::vector<DrCCTProf::PprofProfile::line_t *>();
    this->buffer_ = PERFTOOLS__PROFILES__LOCATION__INIT;
}

DrCCTProf::PprofProfile::location_t::~location_t()
{
    std::for_each(std::begin(*this->line_), std::end(*this->line_),
                  [](DrCCTProf::PprofProfile::line_t *l) { delete l; });
    delete this->line_;
    free(this->buffer_.line);
}

void
DrCCTProf::PprofProfile::location_t::append_line(DrCCTProf::PprofProfile::line_t *line)
{
    (*this->line_).push_back(line);
}

uint64_t
DrCCTProf::PprofProfile::location_t::get_id()
{
    return this->id_;
}

Perftools__Profiles__Location *
DrCCTProf::PprofProfile::location_t::encode()
{
    this->buffer_.id = this->id_;
    this->buffer_.address = this->address_;
    if (this->mapping_) {
        this->buffer_.mapping_id = this->mapping_->get_id();
    }
    this->buffer_.is_folded = this->is_folded_;
    this->buffer_.n_line = (*this->line_).size();
    if (this->buffer_.line) {
        free(this->buffer_.line);
    }
    this->buffer_.line = (Perftools__Profiles__Line **)malloc(
        this->buffer_.n_line * sizeof(Perftools__Profiles__Line *));
    for (size_t i = 0; i < this->buffer_.n_line; i++) {
        this->buffer_.line[i] = (*this->line_)[i]->encode();
    }
    return &(this->buffer_);
}

/*
 * DrCCTProf::PprofProfile::sample_t
 */

DrCCTProf::PprofProfile::sample_t::sample_t()
{
    this->location_ = new std::vector<DrCCTProf::PprofProfile::location_t *>();
    this->label_ = new std::vector<DrCCTProf::PprofProfile::label_t *>();
    this->value_ = new std::vector<int64_t>();
    this->buffer_ = PERFTOOLS__PROFILES__SAMPLE__INIT;
}

DrCCTProf::PprofProfile::sample_t::~sample_t()
{
    delete this->location_;
    std::for_each(std::begin(*this->label_), std::end(*this->label_),
                  [](DrCCTProf::PprofProfile::label_t *l) { delete l; });
    delete this->label_;
    delete this->value_;

    free(this->buffer_.location_id);
    free(this->buffer_.value);
    free(this->buffer_.label);
}

void
DrCCTProf::PprofProfile::sample_t::append_location(DrCCTProf::PprofProfile::location_t *location)
{
    (*this->location_).push_back(location);
}

void
DrCCTProf::PprofProfile::sample_t::append_value(int64_t value)
{
    (*this->value_).push_back(value);
}

void
DrCCTProf::PprofProfile::sample_t::append_label(DrCCTProf::PprofProfile::label_t *label)
{
    (*this->label_).push_back(label);
}

Perftools__Profiles__Sample *
DrCCTProf::PprofProfile::sample_t::encode()
{
    this->buffer_.n_location_id = this->location_->size();
    if (this->buffer_.location_id) {
        free(this->buffer_.location_id);
    }
    if (this->buffer_.n_location_id > 0) {
        this->buffer_.location_id = (uint64_t *)malloc(
            this->buffer_.n_location_id * sizeof(uint64_t));
        for (size_t i = 0; i < this->buffer_.n_location_id; i++) {
            this->buffer_.location_id[i] = (*this->location_)[i]->get_id();
        }
    }

    this->buffer_.n_label = this->label_->size();
    if (this->buffer_.label) {
        free(this->buffer_.label);
    }
    if (this->buffer_.n_label > 0) {
        this->buffer_.label = (Perftools__Profiles__Label **)malloc(
            this->buffer_.n_label * sizeof(Perftools__Profiles__Label *));
        for (size_t i = 0; i < this->buffer_.n_label; i++) {
            this->buffer_.label[i] = (*this->label_)[i]->encode();
        }
    }

    this->buffer_.n_value = this->value_->size();
    if (this->buffer_.value) {
        free(this->buffer_.value);
    }
    if (this->buffer_.n_value > 0) {
        this->buffer_.value = (int64_t *)malloc(
            this->buffer_.n_value * sizeof(int64_t));
        for (size_t i = 0; i < this->buffer_.n_value; i++) {
            this->buffer_.value[i] = (*this->value_)[i];
        }
    }
    return &(this->buffer_);
}

/*
 * DrCCTProf::PprofProfile::profile_t
 */

DrCCTProf::PprofProfile::profile_t::profile_t()
    :location_max_id_(1) 
    ,func_max_id_(1)
{
    this->sample_type_list_ = new std::vector<DrCCTProf::PprofProfile::value_type_t *>();
    this->sample_list_ = new std::vector<DrCCTProf::PprofProfile::sample_t *>();

    this->mapping_map_ = new std::map<uint64_t, DrCCTProf::PprofProfile::mapping_t *>();
    this->location_ip_map_ = new std::map<uint64_t, uint64_t>();
    this->location_map_ = new std::map<uint64_t, DrCCTProf::PprofProfile::location_t *>();

    this->func_map_ = new std::map<DrCCTProf::PprofProfile::function_map_key_t, DrCCTProf::PprofProfile::function_t *>();
    this->string_table_ = new DrCCTProf::PprofProfile::string_table_t();

    this->buffer_ = PERFTOOLS__PROFILES__PROFILE__INIT;
}

DrCCTProf::PprofProfile::profile_t::~profile_t()
{
    std::for_each(std::begin(*this->sample_type_list_),
                  std::end(*this->sample_type_list_),
                  [](DrCCTProf::PprofProfile::value_type_t *st) { delete st; });
    delete this->sample_type_list_;
    free(this->buffer_.sample_type);

    std::for_each(std::begin(*this->sample_list_), std::end(*this->sample_list_),
                  [](DrCCTProf::PprofProfile::sample_t *sm) { delete sm; });
    delete this->sample_list_;
    free(this->buffer_.sample);

    for (auto &c : (*this->mapping_map_)) {
        delete c.second;
    }
    delete this->mapping_map_;
    free(this->buffer_.mapping);

    delete this->location_ip_map_;
    for (auto &l : (*this->location_map_)) {
        delete l.second;
    }
    delete this->location_map_;
    free(this->buffer_.location);

    for (auto &f : (*this->func_map_)) {
        delete f.second;
    }
    delete this->func_map_;
    free(this->buffer_.function);

    delete this->string_table_;
}

Perftools__Profiles__Profile *
DrCCTProf::PprofProfile::profile_t::encode()
{
    this->buffer_.n_sample_type = (*this->sample_type_list_).size();
    this->buffer_.sample_type = (Perftools__Profiles__ValueType **)malloc(
        sizeof(Perftools__Profiles__ValueType *) * this->buffer_.n_sample_type);
    for (size_t i = 0; i < this->buffer_.n_sample_type; i++) {
        this->buffer_.sample_type[i] = (*this->sample_type_list_)[i]->encode();
    }

    this->buffer_.n_sample = (*this->sample_list_).size();
    this->buffer_.sample = (Perftools__Profiles__Sample **)malloc(
        sizeof(Perftools__Profiles__Sample *) * this->buffer_.n_sample);
    for (size_t i = 0; i < this->buffer_.n_sample; i++) {
        this->buffer_.sample[i] = (*this->sample_list_)[i]->encode();
    }

    this->buffer_.n_mapping = (*this->mapping_map_).size();
    this->buffer_.mapping = (Perftools__Profiles__Mapping **)malloc(
        sizeof(Perftools__Profiles__Mapping *) * this->buffer_.n_mapping);
    uint64_t idx = 0;
    for (auto &c : (*this->mapping_map_)) {
        this->buffer_.mapping[idx] = c.second->encode();
        idx++;
    }

    this->buffer_.n_location = (*this->location_map_).size();
    this->buffer_.location = (Perftools__Profiles__Location **)malloc(
        sizeof(Perftools__Profiles__Location *) * this->buffer_.n_location);
    idx = 0;
    for (auto &l : (*this->location_map_)) {
        this->buffer_.location[idx] = l.second->encode();
        idx++;
    }

    this->buffer_.n_function = (*this->func_map_).size();
    this->buffer_.function = (Perftools__Profiles__Function **)malloc(
        sizeof(Perftools__Profiles__Function *) * this->buffer_.n_function);
    idx = 0;
    for (auto &f : (*this->func_map_)) {
        this->buffer_.function[idx] = f.second->encode();
        idx++;
    }

    this->buffer_.n_string_table = this->string_table_->get_table_size();
    this->buffer_.string_table = this->string_table_->encode();
    return &(this->buffer_);
}

void
DrCCTProf::PprofProfile::profile_t::serialize_to_file(const char *filename)
{
    this->encode();
    size_t len = perftools__profiles__profile__get_packed_size(&(this->buffer_));
    uint8_t *buf = (uint8_t *)malloc(len);
    perftools__profiles__profile__pack(&(this->buffer_), buf);
    FILE *p_file;
    p_file = fopen(filename, "wb");
    fwrite (buf, len, 1, p_file);
    fclose(p_file);
    free(buf);
}

void
DrCCTProf::PprofProfile::profile_t::add_sample_type(std::string type, std::string unit)
{
    DrCCTProf::PprofProfile::value_type_t *sample_type =
        new DrCCTProf::PprofProfile::value_type_t(this->string_table_->add_string(type), this->string_table_->add_string(unit));
    (*this->sample_type_list_).push_back(sample_type);
}

DrCCTProf::PprofProfile::sample_t *
DrCCTProf::PprofProfile::profile_t::add_sample(context_t *ctxt)
{
    if (ctxt == NULL) {
        DRCCTLIB_EXIT_PROCESS(
            "Error: [DrCCTProf::PprofProfile::profile_t::add_sample(char* c_str)] ctxt "
            "== NULL .");
    }
    DrCCTProf::PprofProfile::sample_t *sample = new DrCCTProf::PprofProfile::sample_t();
    (*this->sample_list_).push_back(sample);
    context_t *cur_ctxt = ctxt;
    while (cur_ctxt && (ptr_int_t)cur_ctxt->ip != 0) {
        location_t* location = this->add_location(cur_ctxt);
        sample->append_location(location);
        cur_ctxt = cur_ctxt->pre_ctxt;
    }
    return sample;
}

DR_EXPORT
DrCCTProf::PprofProfile::mapping_t *
DrCCTProf::PprofProfile::profile_t::add_mapping(context_t *ctxt)
{
    //Todo
    return NULL;
}

DrCCTProf::PprofProfile::location_t *
DrCCTProf::PprofProfile::profile_t::add_location(context_t *ctxt)
{
    std::map<uint64_t, uint64_t>::iterator it = (*this->location_ip_map_).find((ptr_int_t)ctxt->ip);
    if (it != (*this->location_ip_map_).end()) {
        return (*this->location_map_)[it->second];
    }
    DrCCTProf::PprofProfile::location_t *location = new DrCCTProf::PprofProfile::location_t(location_max_id_++, this->add_mapping(ctxt), (ptr_int_t)ctxt->ip, false);
    location->append_line(new DrCCTProf::PprofProfile::line_t(this->add_function(ctxt), ctxt->line_no));
    (*this->location_map_).insert(std::pair<uint64_t, DrCCTProf::PprofProfile::location_t *>(location->get_id(), location));
    return location;
}

DrCCTProf::PprofProfile::function_t *
DrCCTProf::PprofProfile::profile_t::add_function(context_t *ctxt)
{
    DrCCTProf::PprofProfile::function_map_key_t key = { this->string_table_->add_string(ctxt->file_path),
                               this->string_table_->add_string(ctxt->func_name) };
    std::map<DrCCTProf::PprofProfile::function_map_key_t, DrCCTProf::PprofProfile::function_t *>::iterator it = (*this->func_map_).find(key);
    if (it != (*this->func_map_).end()) {
        it->second->set_start_line(ctxt->line_no);
        return it->second;
    }
    DrCCTProf::PprofProfile::function_t *func = new DrCCTProf::PprofProfile::function_t(this->func_max_id_++, key.name_, key.name_,
                                      ctxt->line_no, key.file_path_);
    (*this->func_map_).insert(std::pair<DrCCTProf::PprofProfile::function_map_key_t, DrCCTProf::PprofProfile::function_t *>(key, func));
    return func;
}