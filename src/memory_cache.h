#ifndef _MEMORY_CACHE_H_
#define _MEMORY_CACHE_H_

#include <unistd.h>
#include <iostream>
#include <vector>

#include <sys/resource.h>
#include <sys/mman.h>
#include "dr_api.h"

using namespace std;

#define MEMORY_CACHE_PRINTF(format, args...)                                      \
    do {                                                                          \
        char name[MAXIMUM_PATH] = "";                                             \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));            \
        pid_t pid = getpid();                                                     \
        dr_printf("[memory_cache(%s%d) msg]====" format "\n", name, pid, ##args); \
    } while (0)

#define MEMORY_CACHE_EXIT_PROCESS(format, args...)                                \
    do {                                                                          \
        char name[MAXIMUM_PATH] = "";                                             \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));            \
        pid_t pid = getpid();                                                     \
        dr_printf("[memory_cache(%s%d) msg]====" format "\n", name, pid, ##args); \
    } while (0);                                                                  \
    dr_exit_process(-1)

template <class T> class memory_cache_t {
public:
    memory_cache_t();
    ~memory_cache_t();
    bool
    init(int32_t sub_add_num, int32_t debris_size_min_size, int32_t max_add_times);
    void
    add_debris(T *debris_start, int32_t debris_size);
    void
    init_sub_cache_frame(T **sub_cache_frame_vector, int32_t *sub_cache_frame_size_vector,
                         int32_t sub_cache_min_num, int32_t sub_cache_frame_max_num);

private:
    void
    sub_add();
    void
    free_all();

public:
    int32_t debris_size_min_size_;
    int32_t sub_add_num_;
private:
    bool debris_mode_;
    int32_t max_add_times_;

    int32_t cur_use_pool_id_;
    int32_t cur_use_pool_start_;
    T **cache_pool_vector_;

    vector<T *> debris_vector_;
    vector<int32_t> debris_size_vector_;
};

template <class T> class tls_memory_cache_t {
public:
    tls_memory_cache_t(memory_cache_t<T> *memory_cache, void *memory_cache_lock,
                       int32_t cache_min_num);
    ~tls_memory_cache_t();
    T *
    get_next_object();
    void
    free_unuse_object();
private:
    void
    reinit_sub_cache();

private:
    memory_cache_t<T> *memory_cache_;
    void *memory_cache_lock_;

    int32_t cache_min_num_;
    int32_t cache_frame_min_size_;
    int32_t cache_frame_num_;

    T **cache_frame_vector_;
    int32_t *cache_frame_size_vector_;

    int32_t last_use_frame_id_;
    int32_t last_use_num_;
};


template <class T>
memory_cache_t<T>::memory_cache_t()
    : debris_size_min_size_(0)
    , sub_add_num_(0)
    , debris_mode_(false)
    , max_add_times_(0)
    , cur_use_pool_id_(-1)
    , cur_use_pool_start_(0)
    , cache_pool_vector_(NULL)
{
}
template <class T>
memory_cache_t<T>::~memory_cache_t()
{
    free_all();
}

template <class T>
bool
memory_cache_t<T>::init(int32_t sub_add_num, int32_t debris_size_min_size,
                     int32_t max_add_times)
{
    debris_size_min_size_ = debris_size_min_size;
    debris_mode_ = false;
    sub_add_num_ = sub_add_num;
    max_add_times_ = max_add_times;
    
    cache_pool_vector_ = (T **)dr_global_alloc(max_add_times_ * sizeof(T *));
    cur_use_pool_id_ = -1;
    sub_add();
    return true;
}

template <class T>
void
memory_cache_t<T>::sub_add()
{
    cur_use_pool_id_++;
    if (cur_use_pool_id_ >= max_add_times_) {
        MEMORY_CACHE_EXIT_PROCESS("ERROR:memory_cache_t full_error \n");
    }
    T *sub_cache = (T *)dr_raw_mem_alloc(
        sub_add_num_ * sizeof(T),
        DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
    if (sub_cache == NULL) {
        MEMORY_CACHE_EXIT_PROCESS("ERROR:memory_cache_t sub_cache add error %d\n", cur_use_pool_id_);
    }
    cache_pool_vector_[cur_use_pool_id_] = sub_cache;
    cur_use_pool_start_ = 0;
}

template <class T>
void
memory_cache_t<T>::free_all()
{
    for (int32_t i = 0; i <= cur_use_pool_id_; i++) {
        dr_raw_mem_free(cache_pool_vector_[i], sub_add_num_ * sizeof(T));
    }
    dr_global_free(cache_pool_vector_, max_add_times_ * sizeof(T *));
}

template <class T>
void
memory_cache_t<T>::add_debris(T *debris_start, int32_t debris_size)
{
    if (debris_size < debris_size_min_size_) {
        return;
    }
    debris_vector_.push_back(debris_start);
    debris_size_vector_.push_back(debris_size);
    // MEMORY_CACHE_PRINTF("DEBUG:memory_cache_t add_debris debris_size %d\n", debris_size);
}

template <class T>
void
memory_cache_t<T>::init_sub_cache_frame(T **sub_cache_frame_vector,
                                     int32_t *sub_cache_frame_size_vector,
                                     int32_t sub_cache_min_num,
                                     int32_t sub_cache_frame_max_num)
{
    if (!debris_mode_) {
        int32_t cur_use_pool_last = sub_add_num_ - cur_use_pool_start_;
        if (cur_use_pool_last >= sub_cache_min_num) {
            sub_cache_frame_vector[0] =
                cache_pool_vector_[cur_use_pool_id_] + cur_use_pool_start_;
            sub_cache_frame_size_vector[0] = sub_cache_min_num;
            cur_use_pool_start_ += sub_cache_min_num;
        } else {
            if (cur_use_pool_last >= debris_size_min_size_) {
                add_debris(cache_pool_vector_[cur_use_pool_id_] + cur_use_pool_start_,
                           cur_use_pool_last);
            }
            debris_mode_ = true;
        }
    }
    if (debris_mode_) {
        int32_t size = debris_vector_.size();
        bool use_debris = false;
        if (sub_cache_frame_max_num <= size) {
            use_debris = true;
        } else {
            int32_t debris_max_number = 0;
            for (int32_t i = 0; i < size ; i++) {
                debris_max_number += debris_size_vector_[i];
            }
            if (debris_max_number >= sub_cache_min_num) {
                use_debris = true;
            }
        }
        if (use_debris) {
            int sub_cache_add_number = 0;
            for (int32_t i = 0; i < size; i++) {
                sub_cache_frame_vector[i] = debris_vector_.back();
                sub_cache_frame_size_vector[i] = debris_size_vector_.back();
                sub_cache_add_number += debris_size_vector_.back();
                debris_vector_.pop_back();
                debris_size_vector_.pop_back();
                if (sub_cache_add_number >= sub_cache_min_num) {
                    break;
                }
            }
        } else {
            sub_add();
            debris_mode_ = false;
            init_sub_cache_frame(sub_cache_frame_vector, sub_cache_frame_size_vector,
                                 sub_cache_min_num, sub_cache_frame_max_num);
        }
    }
}

template <class T>
tls_memory_cache_t<T>::tls_memory_cache_t(memory_cache_t<T> *memory_cache,
                                       void *memory_cache_lock, int32_t cache_min_num)
{
    memory_cache_ = memory_cache;
    memory_cache_lock_ = memory_cache_lock;
    cache_min_num_ = cache_min_num;
    if (cache_min_num_ > memory_cache->sub_add_num_) {
        MEMORY_CACHE_EXIT_PROCESS("ERROR:tls_memory_cache_t cache_min_num_(%d) > "
                  "memory_cache->sub_add_num_(%d)\n",
                  cache_min_num_, memory_cache->sub_add_num_);
    }
    cache_frame_min_size_ = memory_cache->debris_size_min_size_;
    cache_frame_num_ = cache_min_num_ % cache_frame_min_size_ > 0
        ? cache_min_num_ / cache_frame_min_size_ + 1
        : cache_min_num_ / cache_frame_min_size_;

    cache_frame_vector_ = (T **)dr_global_alloc(cache_frame_num_ * sizeof(T *));
    cache_frame_size_vector_ =
        (int32_t *)dr_global_alloc(cache_frame_num_ * sizeof(int32_t));
    for (int32_t i = 0; i < cache_frame_num_; i++) {
        cache_frame_vector_[i] = NULL;
        cache_frame_size_vector_[i] = 0;
    }
    reinit_sub_cache();
    last_use_frame_id_ = 0;
    last_use_num_ = -1;
}

template <class T> 
tls_memory_cache_t<T>::~tls_memory_cache_t()
{
    dr_global_free(cache_frame_vector_, cache_frame_num_ * sizeof(T *));
    dr_global_free(cache_frame_size_vector_, cache_frame_num_ * sizeof(int32_t));
}

template <class T> 
T *
tls_memory_cache_t<T>::get_next_object()
{
    last_use_num_++;
    if (last_use_num_ >= cache_frame_size_vector_[last_use_frame_id_]) {
        last_use_frame_id_++;
        last_use_num_ = 0;
        if (last_use_frame_id_ >= cache_frame_num_ ||
            cache_frame_size_vector_[last_use_frame_id_] == 0) {
            reinit_sub_cache();
            last_use_frame_id_ = 0;
            last_use_num_ = 0;
        }
    }
    // MEMORY_CACHE_PRINTF("DEBUG:last_use_frame_id_ %d, last_use_num_ %d\n", last_use_frame_id_,
    //                 last_use_num_);
    return cache_frame_vector_[last_use_frame_id_] + last_use_num_;
}

template <class T>
void
tls_memory_cache_t<T>::free_unuse_object()
{
    dr_mutex_lock(memory_cache_lock_);
    int32_t unuse_num = cache_frame_size_vector_[last_use_frame_id_] - last_use_num_ - 1;
    if (unuse_num >= cache_frame_min_size_) {
        memory_cache_->add_debris(
            cache_frame_vector_[last_use_frame_id_] + last_use_num_ + 1, unuse_num);
    }
    for (int32_t i = last_use_frame_id_ + 1; i < cache_frame_num_; i++) {
        unuse_num = cache_frame_size_vector_[i];
        if (unuse_num >= cache_frame_min_size_) {
            memory_cache_->add_debris(cache_frame_vector_[i], unuse_num);
        }
    }
    dr_mutex_unlock(memory_cache_lock_);
    for (int32_t i = 0; i < cache_frame_num_; i++) {
        cache_frame_vector_[i] = NULL;
        cache_frame_size_vector_[i] = 0;
    }
}

template <class T> 
void
tls_memory_cache_t<T>::reinit_sub_cache()
{
    for (int32_t i = 0; i < cache_frame_num_; i++) {
        cache_frame_vector_[i] = NULL;
        cache_frame_size_vector_[i] = 0;
    }
    dr_mutex_lock(memory_cache_lock_);
    memory_cache_->init_sub_cache_frame(cache_frame_vector_, cache_frame_size_vector_,
                                        cache_min_num_, cache_frame_num_);
    dr_mutex_unlock(memory_cache_lock_);
}

#endif //_MEMORY_CACHE_H_