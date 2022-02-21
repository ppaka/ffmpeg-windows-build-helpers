#include <stdlib.h>
#include <string.h>
#include "libavutil/avstring.h"
#include "libavutil/time.h"
#include "unitybuf.h"

static UnitybufStates **g_all_contexts;
static size_t g_all_contexts_count = 0;

static atomic_int g_is_lock = ATOMIC_VAR_INIT(0);
static void lock() {
    while (g_is_lock != 0) {
        av_usleep(1);
    }
    g_is_lock = 1;
}
static void unlock() {
    g_is_lock = 0;
    av_usleep(0);
}

static void local_lock(UnitybufStates *states) {
    while (states->is_lock != 0) {
        av_usleep(1);
    }
    states->is_lock = 1;
}
static void local_unlock(UnitybufStates *states) {
    states->is_lock = 0;
    av_usleep(0);
}

DLL_EXPORT int unitybuf_open(URLContext *h, const char *uri, int flags) {
    lock();

    ((UnitybufContext *)h->priv_data)->states = (UnitybufStates *)av_mallocz(sizeof(UnitybufStates));
    UnitybufStates *priv_data = ((UnitybufContext *)h->priv_data)->states;

    char *newUri = (char *)av_mallocz(sizeof(char) * (strlen(uri) + 1));
    strcpy(newUri, uri);
    priv_data->uri = newUri;
    char *uri2 = (char *)av_mallocz(sizeof(char) * (strlen(uri) + 1));
    strcpy(uri2, uri + 9);
    char *str_num_ptr = strtok(uri2, "/");
    priv_data->data_size = (size_t)atoi(str_num_ptr);
    str_num_ptr = strtok(NULL, "/");
    priv_data->max_count = (size_t)atoi(str_num_ptr);
    if (priv_data->max_count <= 0) {
        priv_data->max_count = INT_MAX - 1;
    }
    av_freep(&uri2);

    priv_data->count = (size_t)0;
    priv_data->read_position = (size_t)0;

    priv_data->datas = NULL;
    priv_data->data_lengths = NULL;

    priv_data->clear_count = 0;

    priv_data->flags = flags;

    priv_data->is_lock = 0;

    if (g_all_contexts_count <= 0) {
        g_all_contexts = (UnitybufStates **)av_mallocz(sizeof(UnitybufStates *));
        if (g_all_contexts == NULL) {
            unlock();
            return AVERROR(ENOMEM);
        }
        g_all_contexts[0] = priv_data;
        g_all_contexts_count = 1;
    }
    else {
        UnitybufStates **newContexts = (UnitybufStates **)av_mallocz(sizeof(UnitybufStates *) * (g_all_contexts_count + 1));
        if (newContexts == NULL) {
            unlock();
            return AVERROR(ENOMEM);
        }
        for (size_t loop = 0; loop < g_all_contexts_count; loop++) {
            newContexts[loop] = g_all_contexts[loop];
        }
        newContexts[g_all_contexts_count] = priv_data;
        av_freep(&g_all_contexts);
        g_all_contexts = newContexts;
        g_all_contexts_count++;
    }

    unlock();

    return 0;
}

DLL_EXPORT UnitybufStates *unitybuf_get_handle_dll(const char *uri) {
    UnitybufStates *priv_data = NULL;

    if (g_is_lock != 0) {
        return NULL;
    }

    lock();
    for (size_t loop = 0; loop < g_all_contexts_count; loop++) {
        if (strcmp(g_all_contexts[loop]->uri, uri) == 0) {
            priv_data = g_all_contexts[loop];
            break;
        }
    }
    unlock();

    return priv_data;
}

static int unitybuf_clear_inner(UnitybufStates *priv_data) {
    UnitybufStates **new_all_contexts = av_mallocz(sizeof(UnitybufStates *) * (g_all_contexts_count - 1));
    size_t pos = 0;
    for (size_t loop = 0; loop < g_all_contexts_count; loop++) {
        if (g_all_contexts[loop] != priv_data) {
            new_all_contexts[pos] = g_all_contexts[loop];
            pos++;
        }
    }
    g_all_contexts = new_all_contexts;
    g_all_contexts_count--;

    if (priv_data->datas != NULL) {
        for (size_t loop = 0; loop < priv_data->count; loop++) {
            av_freep(&priv_data->datas[loop]);
        }
        av_freep(&priv_data->datas);
    }

    if (priv_data->data_lengths != NULL) {
        av_freep(&priv_data->data_lengths);
    }
    
    if (priv_data->uri != NULL) {
        av_freep(&priv_data->uri);
    }

    av_freep(&priv_data);

    return 0;
}

DLL_EXPORT int unitybuf_close(URLContext *h) {
    UnitybufStates *priv_data = ((UnitybufContext *)h->priv_data)->states;
    
    int ret = 0;
    priv_data->clear_count++;
    if (priv_data->clear_count >= 2) {
        lock();
        ret = unitybuf_clear_inner(priv_data);
        unlock();
    }
    return ret;
}

DLL_EXPORT int unitybuf_clear_dll(UnitybufStates *priv_data) {
    if (priv_data == NULL) {
        return -1;
    }

    priv_data->clear_count++;
    if (priv_data->clear_count >= 2) {
        lock();
        unitybuf_clear_inner(priv_data);
        unlock();
    }

    return 0;
}

static int remove_datas(UnitybufStates *priv_data, int del_count) {
    if (priv_data->count - del_count <= 0) {
        if (priv_data->datas != NULL) {
            for (size_t loop = 0; loop < priv_data->count; loop++) {
                av_freep(&priv_data->datas[loop]);
            }
            av_freep(&priv_data->datas);
        }
        if (priv_data->data_lengths != NULL) {
            av_freep(&priv_data->data_lengths);
        }
        priv_data->datas = NULL;
        priv_data->data_lengths = NULL;
        priv_data->count = 0;

        return 0;
    }

    uint8_t **new_datas = av_mallocz(sizeof(uint8_t *) * (priv_data->count - del_count));
    if (new_datas == NULL) {
        return AVERROR(ENOMEM);
    }
    size_t *new_data_lengths = av_mallocz(sizeof(size_t) * (priv_data->count - del_count));
    if (new_data_lengths == NULL) {
        return AVERROR(ENOMEM);
    }
    for (size_t loop = 0; loop < priv_data->count - del_count; loop++) {
        new_datas[loop] = priv_data->datas[loop + del_count];
        new_data_lengths[loop] = priv_data->data_lengths[loop + del_count];
    }
    if (priv_data->datas != NULL) {
        for (size_t loop = 0; loop < del_count; loop++) {
            av_freep(&priv_data->datas[loop]);
        }
        av_freep(&priv_data->datas);
    }
    if (priv_data->data_lengths != NULL) {
        av_freep(&priv_data->data_lengths);
    }
    priv_data->datas = new_datas;
    priv_data->data_lengths = new_data_lengths;
    priv_data->count -= del_count;

    return 0;
}

static int unitybuf_write_inner(UnitybufStates *priv_data, const unsigned char *buf, int size) {
    if (priv_data->clear_count > 0) {
        return 0;
    } 

    int del_count = priv_data->count - priv_data->max_count;
    if (del_count > 0) {
        int remove_result = remove_datas(priv_data, del_count);
        if (remove_result < 0) {
            return remove_result;
        }
    }

    uint8_t *new_data;
    new_data = av_mallocz(sizeof(uint8_t) * size);
    if (new_data == NULL) {
        return AVERROR(ENOMEM);
    }
    int write_size = size;

    memcpy(new_data, buf, write_size);

    uint8_t **new_datas = av_mallocz(sizeof(uint8_t *) * (priv_data->count + 1));
    if (new_datas == NULL) {
        return AVERROR(ENOMEM);
    }
    size_t *new_data_lengths = av_mallocz(sizeof(size_t) * (priv_data->count + 1));
    if (new_data_lengths == NULL) {
        return AVERROR(ENOMEM);
    }
    for (size_t loop = 0; loop < priv_data->count; loop++) {
        new_datas[loop] = priv_data->datas[loop];
        new_data_lengths[loop] = priv_data->data_lengths[loop];
    }
    new_datas[priv_data->count] = new_data;
    new_data_lengths[priv_data->count] = write_size;
    if (priv_data->datas != NULL) {
        av_freep(&priv_data->datas);
    }
    if (priv_data->data_lengths != NULL) {
        av_freep(&priv_data->data_lengths);
    }
    priv_data->datas = new_datas;
    priv_data->data_lengths = new_data_lengths;
    priv_data->count++;

    return write_size;
}

DLL_EXPORT int unitybuf_write(URLContext *h, const unsigned char *buf, int size) {
    UnitybufStates *priv_data = ((UnitybufContext *)h->priv_data)->states;
    local_lock(priv_data);
    int ret = unitybuf_write_inner(priv_data, buf, size);
    local_unlock(priv_data);
    return ret;
}

DLL_EXPORT int unitybuf_write_dll(UnitybufStates *priv_data, const unsigned char *buf, int size) {
    int ret = AVERROR(EINVAL);

    if (priv_data != NULL) {
        local_lock(priv_data);
        ret = unitybuf_write_inner(priv_data, buf, size);
        local_unlock(priv_data);
    }

    return ret;
}

static int unitybuf_count(UnitybufStates *handle) {
    if (handle->data_size <= 0) {
        int ret = handle->count;
        return ret;
    }
    else {
        if (handle->count <= 0) {
            return 0;
        }
        int all_size = handle->data_lengths[0] - handle->read_position;
        for (int loop = 1; loop < handle->count; loop++) {
            all_size += handle->data_lengths[loop];
        }
        return all_size / handle->data_size;
    }
    return 0;
}

static int unitybuf_read_inner(UnitybufStates *priv_data, unsigned char *buf, int size) {
    if (priv_data->clear_count > 1 || (priv_data->clear_count > 0 && unitybuf_count(priv_data) <= 0)) {
        return AVERROR_EOF;
    } 

    if (priv_data->data_size <= 0) {
        if (size <= 0 || priv_data->count <= 0) {
            return AVERROR(EAGAIN);
        }

        int memcpy_size = priv_data->data_lengths[0] - priv_data->read_position;
        if (memcpy_size > size) {
            memcpy_size = size;
        }
        memcpy(buf, priv_data->datas[0] + priv_data->read_position, memcpy_size);

        priv_data->read_position += memcpy_size;
        if (priv_data->read_position >= priv_data->data_lengths[0]) {
            priv_data->read_position -= priv_data->data_lengths[0];

            int remove_result = remove_datas(priv_data, 1);
            if (remove_result < 0) {
                return remove_result;
            }
        }
        
        return memcpy_size;
    }
    else {
        int all_size = 0;
        int count = 0;
        for (int loop = 0; loop < priv_data->count; loop++) {
            all_size += priv_data->data_lengths[loop];
            if (all_size >= priv_data->data_size) {
                count = loop + 1;
                break;
            }
        }

        if (count == 0) {
            return AVERROR(EAGAIN);
        }

        int pos = 0;
        for (int loop = 0; loop < count; loop++) {
            memcpy(buf + pos, priv_data->datas[loop], priv_data->data_lengths[loop]);
            pos += priv_data->data_lengths[loop];
        }

        int remove_result = remove_datas(priv_data, count);
        if (remove_result < 0) {
            return remove_result;
        }

        return pos;
    }
}

DLL_EXPORT int unitybuf_read(URLContext *h, unsigned char *buf, int size) {
    UnitybufStates *priv_data = ((UnitybufContext *)h->priv_data)->states;
    local_lock(priv_data);
    int ret = unitybuf_read_inner(priv_data, buf, size);
    local_unlock(priv_data);
    if (ret == AVERROR(EAGAIN)) {
        av_usleep(1);
    }
    return ret;
}

DLL_EXPORT int unitybuf_read_dll(UnitybufStates *priv_data, unsigned char *buf, int size) {
    int ret = 0;

    if (priv_data != NULL) {
        local_lock(priv_data);
        ret = unitybuf_read_inner(priv_data, buf, size);
        local_unlock(priv_data);
    }

    return ret;
}

DLL_EXPORT int unitybuf_count_dll(UnitybufStates *handle) {
    local_lock(handle);
    int ret = unitybuf_count(handle);
    local_unlock(handle);
    return ret;
}