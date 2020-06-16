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
    memory_cache_t(int32_t page1_bit, int32_t page2_bit, int32_t debris_min_size, void (*init_object_index)(T*, int32_t index));
    ~memory_cache_t();
    void
    add_debris(T *debris_start, int32_t debris_size);
    void
    init_sub_cache_frame(T **sub_cache_frame_vector, int32_t *sub_cache_frame_size_vector,
                         int32_t sub_cache_min_num, int32_t sub_cache_frame_max_num);
    T*
    get_object_by_index(int32_t index);
    int32_t
    get_debris_min_size();
    int32_t
    get_page2_size();
private:
    void
    init_new_page2();
    void
    free_all();
private:
    int32_t page1_bit_;
    int32_t page1_size_;
    int32_t page1_mask_;

    int32_t page2_bit_;
    int32_t page2_size_;
    int32_t page2_mask_;

    int32_t debris_min_size_;
    bool debris_mode_;

    int32_t cur_page1_index_;
    int32_t cur_page2_index_;
    
    T **page1_cache_;
    void (*init_object_index_)(T*, int32_t index);

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
memory_cache_t<T>::memory_cache_t(int32_t page1_bit, int32_t page2_bit, int32_t debris_min_size, void (*init_object_index)(T*, int32_t index))
{
    page1_bit_ = page1_bit;
    page1_size_ = 1 << page1_bit_;
    page1_mask_ = page1_size_ - 1;

    page2_bit_ = page2_bit;
    page2_size_ = 1 << page2_bit_;
    page2_mask_ = page2_size_ - 1;
    
    debris_min_size_ = debris_min_size;
    debris_mode_ = false;
    
    page1_cache_ = (T **)dr_global_alloc(page1_size_ * sizeof(T *));
    init_object_index_ = init_object_index;

    cur_page1_index_ = -1;
    cur_page2_index_ = -1;
    init_new_page2();
}
template <class T>
memory_cache_t<T>::~memory_cache_t()
{
    free_all();
}

template <class T>
void
memory_cache_t<T>::init_new_page2()
{
    cur_page1_index_++;
    if (cur_page1_index_ >= page1_size_) {
        MEMORY_CACHE_EXIT_PROCESS("ERROR:memory_cache_t full_error \n");
    }
    T *page2_cache = (T *)dr_raw_mem_alloc(
        page2_size_ * sizeof(T),
        DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
    if (page2_cache == NULL) {
        MEMORY_CACHE_EXIT_PROCESS("ERROR:memory_cache_t page2_cache add error %d\n", cur_page1_index_);
    }
    for (int32_t i = 0; i < page2_size_; i++) {
        if(init_object_index_ != NULL) {
            init_object_index_(&page2_cache[i], (cur_page1_index_ << page2_bit_) + i);
        }
    }
    page1_cache_[cur_page1_index_] = page2_cache;
    cur_page2_index_ = 0;
}

template <class T>
void
memory_cache_t<T>::free_all()
{
    for (int32_t i = 0; i <= cur_page1_index_; i++) {
        dr_raw_mem_free(page1_cache_[i], page2_size_ * sizeof(T));
    }
    dr_global_free(page1_cache_, page1_size_ * sizeof(T *));
}

template <class T>
void
memory_cache_t<T>::add_debris(T *debris_start, int32_t debris_size)
{
    if (debris_size < debris_min_size_) {
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
        int32_t cur_use_pool_last = page2_size_ - cur_page2_index_;
        if (cur_use_pool_last >= sub_cache_min_num) {
            sub_cache_frame_vector[0] =
                page1_cache_[cur_page1_index_] + cur_page2_index_;
            sub_cache_frame_size_vector[0] = sub_cache_min_num;
            cur_page2_index_ += sub_cache_min_num;
        } else {
            if (cur_use_pool_last >= debris_min_size_) {
                add_debris(page1_cache_[cur_page1_index_] + cur_page2_index_,
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
            init_new_page2();
            debris_mode_ = false;
            init_sub_cache_frame(sub_cache_frame_vector, sub_cache_frame_size_vector,
                                 sub_cache_min_num, sub_cache_frame_max_num);
        }
    }
}

template <class T>
T*
memory_cache_t<T>::get_object_by_index(int32_t index){
    int32_t page1_index = (index >> page2_bit_) & page1_mask_;
    int32_t page2_index = index & page2_mask_;
    return page1_cache_[page1_index] + page2_index;
}

template <class T>
int32_t
memory_cache_t<T>::get_debris_min_size() {
    return debris_min_size_;
}

template <class T>
int32_t
memory_cache_t<T>::get_page2_size() {
    return page2_size_;
}




template <class T>
tls_memory_cache_t<T>::tls_memory_cache_t(memory_cache_t<T> *memory_cache,
                                       void *memory_cache_lock, int32_t cache_min_num)
{
    memory_cache_ = memory_cache;
    memory_cache_lock_ = memory_cache_lock;
    cache_min_num_ = cache_min_num;
    if (cache_min_num_ > memory_cache->get_page2_size()) {
        MEMORY_CACHE_EXIT_PROCESS("ERROR:tls_memory_cache_t cache_min_num_(%d) > "
                  "memory_cache->page2_size_(%d)\n",
                  cache_min_num_, memory_cache->get_page2_size());
    }
    cache_frame_min_size_ = memory_cache->get_debris_min_size();
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