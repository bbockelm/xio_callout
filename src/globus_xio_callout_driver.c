/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_common.h"
#include "globus_xio_callout_driver.h"

GlobusDebugDefine(GLOBUS_XIO_CALLOUT);
GlobusXIODeclareDriver(callout);

#define GlobusXIOCalloutDebugPrintf(level, message)                  \
    GlobusDebugPrintf(GLOBUS_XIO_CALLOUT, level, message)

#define GlobusXIOCalloutDebugEnter()                                 \
    GlobusXIOCalloutDebugPrintf(                                     \
        GLOBUS_XIO_CALLOUT_DEBUG_TRACE,                              \
        ("[%s] Entering\n", _xio_name))

#define GlobusXIOCalloutDebugExit()                                  \
    GlobusXIOCalloutDebugPrintf(                                     \
        GLOBUS_XIO_CALLOUT_DEBUG_TRACE,                              \
        ("[%s] Exiting\n", _xio_name))

#define GRIDFTP_HDFS_LIBRARY "/usr/lib/libglobus_gridftp_server_hdfs.so"
#define USERNAME_SYMBOL "gridftp_user_name"
#define FILENAME_SYMBOL "gridftp_file_name"
#define EVENT_TYPE_SYMBOL "gridftp_transfer_type"

typedef enum
{
    GLOBUS_XIO_CALLOUT_DEBUG_ERROR = 1,
    GLOBUS_XIO_CALLOUT_DEBUG_WARNING = 2,
    GLOBUS_XIO_CALLOUT_DEBUG_TRACE = 4,
    GLOBUS_XIO_CALLOUT_DEBUG_INFO = 8,
} globus_xio_callout_debug_levels_t;

typedef union globus_xio_callout_pid_u 
{
    int pid;
    void *ptr;
} globus_xio_callout_pid_t;

typedef struct globus_xio_callout_handle_s
{
    globus_mutex_t lock;
    char *         script;
    char *         contact_string;
    char *         file_name;
    char *         user_name;
    char *         transfer_type;
    globus_size_t  interval;
    int            startup_pid;
    int            update_pid;
    int            shutdown_pid;
    int            want_destroy;
    globus_callback_handle_t update_cb;
} globus_l_xio_callout_handle_t;

static int
globus_l_xio_callout_activate();

static int
globus_l_xio_callout_deactivate();

#include "version.h"

GlobusXIODefineModule(callout) =
{
    "globus_xio_callout",
    globus_l_xio_callout_activate,
    globus_l_xio_callout_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

static globus_mutex_t                   globus_l_xio_callout_pid_mutex;
static globus_hashtable_t               globus_l_xio_callout_pid_table;

static
globus_result_t globus_l_xio_callout_fork_startup(
    globus_l_xio_callout_handle_t *     handle,
    const char *                        event_name,
    int *                               pid);

static
void
globus_l_xio_callout_sigchld(
    void *                              user_arg);

static
void
globus_l_xio_callout_update_cb(
    void *                              arg)
{
    globus_l_xio_callout_handle_t * handle = (globus_l_xio_callout_handle_t *)arg;

    int pid;
    globus_l_xio_callout_fork_startup(handle, "UPDATE", &pid);

    globus_l_xio_callout_sigchld(arg);
}

static
globus_result_t globus_l_xio_callout_handle_destroy_internal(void * arg);

static
void
globus_l_xio_callout_unregister_cb(
    void *                              arg)
{
    GlobusXIOName(globus_l_xio_callout_unregister_cb);
    GlobusXIOCalloutDebugEnter();

    globus_l_xio_callout_handle_t * handle = (globus_l_xio_callout_handle_t *)arg;
    int want_destroy = 0;
    globus_mutex_lock(&handle->lock);
    handle->update_cb = 0;
    want_destroy = handle->want_destroy;
    globus_mutex_unlock(&handle->lock);

    if (want_destroy)
    {
        globus_l_xio_callout_handle_destroy_internal(arg);
    }

    GlobusXIOCalloutDebugExit();
}

static
globus_result_t
globus_l_xio_callout_handle_destroy(
    void *                              arg)
{
    globus_result_t                     result = GLOBUS_SUCCESS;

    GlobusXIOName(globus_l_xio_callout_handle_destroy);
    GlobusXIOCalloutDebugEnter();

    globus_l_xio_callout_handle_t * handle = (globus_l_xio_callout_handle_t *)arg;

    if (!handle) goto done;

    globus_mutex_lock(&handle->lock);
    int no_cb = handle->update_cb == GLOBUS_NULL;
    handle->want_destroy = 1;
    globus_mutex_unlock(&handle->lock);
    if (no_cb)
    {
        result = globus_l_xio_callout_handle_destroy_internal(arg);
    }
    else
    {
        result = globus_callback_unregister(
            handle->update_cb,
            globus_l_xio_callout_unregister_cb,
            handle,
            NULL);
    }

done:
    GlobusXIOCalloutDebugExit();
    return result;
}

static
globus_result_t
globus_l_xio_callout_handle_destroy_internal(
    void *                              arg)
{
    globus_xio_callout_pid_t pid_storage; pid_storage.ptr = NULL;

    GlobusXIOName(globus_l_xio_callout_handle_destroy_internal);
    GlobusXIOCalloutDebugEnter();

    globus_l_xio_callout_handle_t * handle = (globus_l_xio_callout_handle_t *)arg;

    if (!handle) goto done;

    globus_mutex_lock(&globus_l_xio_callout_pid_mutex);
    globus_mutex_lock(&handle->lock);

    if (handle->script) globus_free(handle->script);
    if (handle->contact_string) globus_free(handle->contact_string);

    if (handle->startup_pid)
    {
        pid_storage.pid = handle->startup_pid;
        globus_hashtable_remove(&globus_l_xio_callout_pid_table, pid_storage.ptr);
    }
    if (handle->update_pid)
    {
        pid_storage.pid = handle->update_pid;
        globus_hashtable_remove(&globus_l_xio_callout_pid_table, pid_storage.ptr);
    }
    if (handle->shutdown_pid)
    {
        pid_storage.pid = handle->shutdown_pid;
        globus_hashtable_remove(&globus_l_xio_callout_pid_table, pid_storage.ptr);
    }
    globus_mutex_unlock(&handle->lock);
    globus_mutex_unlock(&globus_l_xio_callout_pid_mutex);

    globus_mutex_destroy(&handle->lock);

    globus_free(handle);

done:
    GlobusXIOCalloutDebugExit();
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_callout_handle_init(
    void **                              out_attr)
{
    globus_result_t result = GLOBUS_SUCCESS;

    GlobusXIOName(globus_l_xio_callout_handle_init);
    GlobusXIOCalloutDebugEnter();

    globus_l_xio_callout_handle_t * attr = 
        (globus_l_xio_callout_handle_t *)globus_calloc(1, sizeof(globus_l_xio_callout_handle_t));
    if (!attr)
    {
        result = GlobusXIOErrorMemory("Callout Handle");
    }
    attr->interval = 60;
    globus_mutex_init(&attr->lock, GLOBUS_NULL);

    *out_attr = attr;

    GlobusXIOCalloutDebugExit();
    return result;
}

static
globus_result_t
globus_l_xio_callout_handle_copy(
    void **                             dst,
    void *                              src)
{
    globus_result_t                                result = GLOBUS_SUCCESS;
    globus_l_xio_callout_handle_t *                dst_handle;
    globus_l_xio_callout_handle_t *                src_handle;

    GlobusXIOName(globus_l_xio_callout_handle_copy);
    GlobusXIOCalloutDebugEnter();

    src_handle = (globus_l_xio_callout_handle_t *) src;

    if ((result = globus_l_xio_callout_handle_init((void **)&dst_handle)) != GLOBUS_SUCCESS)
    {
        goto done;
    }

    if (src_handle)
    {
        globus_mutex_lock(&src_handle->lock);
        if (src_handle->script)
        {
            //GlobusXIOCalloutDebugPrintf(GLOBUS_XIO_CALLOUT_DEBUG_INFO, ("Copying source handle with script %s\n", src_handle->script));
            dst_handle->script = strdup(src_handle->script);
        }
        if (src_handle->contact_string)
        {
            dst_handle->contact_string = strdup(src_handle->script);
        }
        dst_handle->update_cb = src_handle->update_cb;
        dst_handle->interval = src_handle->interval;
        dst_handle->startup_pid = src_handle->startup_pid;
        dst_handle->update_pid = src_handle->update_pid;
        dst_handle->shutdown_pid = src_handle->shutdown_pid;
        globus_mutex_unlock(&src_handle->lock);
    }

    *dst = dst_handle;
done:
    GlobusXIOCalloutDebugExit();
    return result;
}


static globus_xio_string_cntl_table_t  tb_l_string_opts_table[] =
{
    {"script", GLOBUS_XIO_CALLOUT_SCRIPT, globus_xio_string_cntl_string},
    {"interval", GLOBUS_XIO_CALLOUT_UPDATE_INTERVAL, globus_xio_string_cntl_formated_off},
    {NULL, 0, NULL}
};


static
globus_result_t
globus_l_xio_callout_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    globus_l_xio_callout_handle_t * handle;
    globus_result_t                 result = GLOBUS_SUCCESS;
    char *                          script_name;

    GlobusXIOName(globus_l_xio_callout_handle_cntl);
    GlobusXIOCalloutDebugEnter();

    GlobusXIOCalloutDebugPrintf(GLOBUS_XIO_CALLOUT_DEBUG_INFO, ("Got driver cmd %d\n", cmd));

    handle = (globus_l_xio_callout_handle_t *) driver_attr;

    switch (cmd)
    {
        case GLOBUS_XIO_CALLOUT_SCRIPT:
            script_name = va_arg(ap, char *);
            if (!script_name)
            {
                result = GlobusXIOErrorParameter("script");
                break;
            }
            GlobusXIOCalloutDebugPrintf(GLOBUS_XIO_CALLOUT_DEBUG_INFO, ("Got callout script %s\n", script_name));
            handle->script = strdup(script_name);
            break;

        case GLOBUS_XIO_CALLOUT_UPDATE_INTERVAL:
            handle->interval = va_arg(ap, globus_size_t);
            GlobusXIOCalloutDebugPrintf(GLOBUS_XIO_CALLOUT_DEBUG_INFO, ("Got callout interval %u\n", handle->interval));
            break;

        default:
            result = GlobusXIOErrorParameter("unknown");
            break;
    }

    GlobusXIOCalloutDebugExit();
    return result;
}

void
globus_l_xio_callout_sigchld(
    void *                              user_arg)
{
    int                                 child_pid;
    int                                 child_rc;
    int                                 child_status;
    globus_l_xio_callout_handle_t *     handle;

    GlobusXIOName(globus_l_xio_callout_sigchld);
    GlobusXIOCalloutDebugEnter();

    while( (child_pid = waitpid(-1, &child_status, WNOHANG)) > 0)
    {
        if(WIFEXITED(child_status))
        {
            child_rc = WEXITSTATUS(child_status);
            if (child_rc)
            {
                GlobusXIOCalloutDebugPrintf(GLOBUS_XIO_CALLOUT_DEBUG_WARNING, ("Child %d failed with status code %d\n", child_pid, child_rc));
            }
            else
            {
                GlobusXIOCalloutDebugPrintf(GLOBUS_XIO_CALLOUT_DEBUG_INFO, ("Child %d succeeded\n", child_pid));
            }
        }
        else if(WIFSIGNALED(child_status))
        {
            GlobusXIOCalloutDebugPrintf(GLOBUS_XIO_CALLOUT_DEBUG_WARNING, ("Child %d exited with signal %d\n", child_pid, WTERMSIG(child_status)));
        }

        globus_mutex_lock(&globus_l_xio_callout_pid_mutex);
        globus_xio_callout_pid_t pid_storage; pid_storage.ptr = 0; pid_storage.pid = child_pid;
        handle = (globus_l_xio_callout_handle_t*) globus_hashtable_lookup(&globus_l_xio_callout_pid_table, pid_storage.ptr);
        if (handle)
        {
            globus_mutex_lock(&handle->lock);
            if (handle->startup_pid == child_pid)
            {
                handle->startup_pid = 0;
            }
            else if (handle->update_pid == child_pid)
            {
                handle->update_pid = 0;
            }
            else if (handle->shutdown_pid == child_pid)
            {
                handle->shutdown_pid = 0;
            }
            globus_mutex_unlock(&handle->lock);
            globus_hashtable_remove(&globus_l_xio_callout_pid_table, pid_storage.ptr);
        }
        globus_mutex_unlock(&globus_l_xio_callout_pid_mutex);
    }

    GlobusXIOCalloutDebugExit();
}


globus_result_t
globus_l_xio_callout_fork_startup(
    globus_l_xio_callout_handle_t *     handle,
    const char *                        event_name,
    int *                               pid)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    int                                 p2c[2];
    int                                 fd_flags;
    int                                 rc;
    int                                 exit_code;
    int                                 len;
    char                                result_buffer[10];
    char *                              args[6];
    FILE *                              fh;

    GlobusXIOName(globus_l_xio_callout_fork_startup);
    GlobusXIOCalloutDebugEnter();

    if (!handle)
    {
        GlobusXIOCalloutDebugPrintf(GLOBUS_XIO_CALLOUT_DEBUG_WARNING, ("Cannot fork script with null handle.\n"));
        goto done;
    }
    if (!handle->script)
    {
        GlobusXIOCalloutDebugPrintf(GLOBUS_XIO_CALLOUT_DEBUG_WARNING, ("Callout module loaded, but no script defined.\n"));
        goto done;
    }
    if (!handle->contact_string)
    {
        GlobusXIOCalloutDebugPrintf(GLOBUS_XIO_CALLOUT_DEBUG_WARNING, ("Callout module loaded, but no contact string available.\n"));
        goto done;
    }

    void* gridftp_hdfs_lib_handle;
    gridftp_hdfs_lib_handle = dlopen(GRIDFTP_HDFS_LIBRARY, RTLD_LAZY|RTLD_GLOBAL|RTLD_NOLOAD);
    if(! gridftp_hdfs_lib_handle){
        //GlobusXIOCalloutDebugPrintf(GLOBUS_XIO_CALLOUT_DEBUG_WARNING, ("Globus GridFTP HDFS library failed to load, %s\n", dlerror()));
        fprintf(stdout, "Globus GridFTP HDFS library failed to load, %s\n", dlerror());
        result = GLOBUS_FAILURE;
        goto done;
    }

    /* Clear any existing error */
    dlerror();
    char *error;
    char *username = (char*) dlsym(gridftp_hdfs_lib_handle, USERNAME_SYMBOL);
    if((error = dlerror()) != NULL){
        fprintf(stdout, "%s\n", error);
        username = NULL;
    }
    char *filename = (char*) dlsym(gridftp_hdfs_lib_handle, FILENAME_SYMBOL);
    if((error = dlerror()) != NULL){
        fprintf(stdout, "%s\n", error);
        filename = NULL;
    }
    char *transfer_type = (char*) dlsym(gridftp_hdfs_lib_handle, EVENT_TYPE_SYMBOL);
    if((error = dlerror()) != NULL){
        fprintf(stdout, "%s\n", error);
        transfer_type = NULL;
    }
    if(username){
        //GlobusXIOCalloutDebugPrintf(GLOBUS_XIO_CALLOUT_DEBUG_WARNING, ("Username for this file transfer is %s\n", username));
        fprintf(stdout, "Username for this file transfer is %s\n", username);
    }
    else{
        //GlobusXIOCalloutDebugPrintf(GLOBUS_XIO_CALLOUT_DEBUG_WARNING, ("Username is not found in dlsym symbol look up.\n"));
        fprintf(stdout, "Username is not found in dlsym symbol look up.\n");
    }
    if(filename){
        //GlobusXIOCalloutDebugPrintf(GLOBUS_XIO_CALLOUT_DEBUG_WARNING, ("Filename for this file transfer is %s\n", filename));
        fprintf(stdout, "Filename for this file transfer is %s\n", filename);
    }
    else{
        //GlobusXIOCalloutDebugPrintf(GLOBUS_XIO_CALLOUT_DEBUG_WARNING, ("Filename is not found in dlsym symbol look up.\n"));
        fprintf(stdout, "Filename is not found in dlsym symbol look up.\n");

    }
    if(transfer_type){
        fprintf(stdout, "Event type for this file transfer is %s\n", transfer_type);
    }
    else{
        fprintf(stdout, "Event type is not found in dlsym symbol look up.\n");
    }
    
    handle->user_name = username; 
    handle->file_name = filename;
    handle->transfer_type = transfer_type;

    args[0] = "xio-callout";
    args[1] = (char*)event_name;
    args[2] = handle->contact_string;
    args[3] = handle->user_name;
    args[4] = handle->file_name;
    args[5] = handle->transfer_type;
    args[6] = NULL;

    if (pipe(p2c) < 0) {
        result = GlobusXIOErrorSystemError(pipe, errno);
        goto done;
    }
    if ((fd_flags = fcntl(p2c[1], F_GETFD, NULL)) == -1) {
        result = GlobusXIOErrorSystemError(fcntl, errno);
        goto done;
    }
    if (fcntl(p2c[1], F_SETFD, fd_flags | FD_CLOEXEC) == -1) {
        result = GlobusXIOErrorSystemError(fcntl, errno);
        goto done;
    }

    if ( (*pid = fork()) == -1)
    {
        result = GlobusXIOErrorSystemError(fork, errno);
        goto done;
    }
    else if (*pid)
    {   // Parent process
        close(p2c[1]);
        if ((fh = fdopen(p2c[0], "r")) == NULL)
        {
            close(p2c[0]);
        }
        rc = fscanf(fh, "%d", &exit_code);
        close(p2c[0]);
        if (rc == 1)
        { // Exec failed
            GlobusXIOErrorSystemError(execv, exit_code);
            goto done;
        }
    }
    else
    {
        close(1);
        close(2);
        close(0);
        if ((rc = execv(handle->script, args)) == -1) {
            len = snprintf(result_buffer, 10, "%d", errno);
            rc = write(p2c[1], result_buffer, len);
            while (rc == -1 && errno == EINTR) (rc = write(p2c[1], result_buffer, len));
            if (rc == -1) GlobusXIOErrorSystemError(write, errno);
        }
        _exit(errno);
    }

    // register the child pid
    globus_xio_callout_pid_t pid_storage; pid_storage.ptr = 0; pid_storage.pid = *pid;
    globus_mutex_lock(&globus_l_xio_callout_pid_mutex);
    {
        globus_hashtable_insert(
            &globus_l_xio_callout_pid_table,
            pid_storage.ptr,
            handle);
    }
    globus_mutex_unlock(&globus_l_xio_callout_pid_mutex);

done:
    GlobusXIOCalloutDebugExit();
    return result;
}

static
void
globus_l_xio_callout_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    char * contact_string = NULL;
    globus_l_xio_callout_handle_t * handle;

    GlobusXIOName(globus_l_xio_callout_open_cb);
    GlobusXIOCalloutDebugEnter();

    handle = (globus_l_xio_callout_handle_t *)user_arg;

    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    globus_xio_driver_handle_t d_handle = globus_xio_operation_get_driver_handle(op);
    result = globus_xio_driver_handle_cntl(
              d_handle,
              GLOBUS_XIO_QUERY,
              GLOBUS_XIO_GET_REMOTE_NUMERIC_CONTACT,
              &contact_string);
    if( result != GLOBUS_SUCCESS)
    {
        result = GlobusXIOErrorWrapFailed(
            "globus_xio_driver_handle_cntl query remote contact",
            result);
        goto error;
    }
    // Handle takes ownership of contact string
    handle->contact_string = contact_string;

    // Fork our callout process
    int pid;
    result = globus_l_xio_callout_fork_startup(handle, "STARTUP", &pid);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    // Setup a timer
    globus_reltime_t delay;
    GlobusTimeReltimeSet(delay, handle->interval, 0);
    globus_mutex_lock(&handle->lock);
    result = globus_callback_register_periodic(
                &handle->update_cb,
                &delay,
                &delay,
                globus_l_xio_callout_update_cb,
                handle);
    globus_mutex_unlock(&handle->lock);


error:

    globus_xio_driver_finished_open(handle, op, result);

    GlobusXIOCalloutDebugExit();
}

static
globus_result_t
globus_l_xio_callout_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_l_xio_callout_handle_t * passed_handle;
    globus_l_xio_callout_handle_t * handle;

    GlobusXIOName(globus_l_xio_callout_open);
    GlobusXIOCalloutDebugEnter();

    globus_result_t res = GLOBUS_SUCCESS;

    passed_handle = (globus_l_xio_callout_handle_t*)(driver_link ? driver_link : driver_attr);
    if (!passed_handle)
    {
        res = GlobusXIOErrorWrapFailed("No attributes passed to XIO callout driver", GLOBUS_FAILURE);
        goto error;
    }

    res = globus_l_xio_callout_handle_copy((void **)&handle, (void *)passed_handle);
    if (res != GLOBUS_SUCCESS)
    {
        res = GlobusXIOErrorWrapFailed("Failed to create new XIO callout handle", res);
        goto error;
    }

    res = globus_xio_driver_pass_open(
        op, contact_info, globus_l_xio_callout_open_cb, handle);
error:
    GlobusXIOCalloutDebugExit();
    return res;
}

static
void
globus_l_xio_callout_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    char *                              contact_string = NULL;
    int                                 pid;
    globus_l_xio_callout_handle_t *     handle;

    GlobusXIOName(globus_l_xio_callout_close_cb);
    GlobusXIOCalloutDebugEnter();

    handle = (globus_l_xio_callout_handle_t *)user_arg;

    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    // Fork our callout process
    result = globus_l_xio_callout_fork_startup(handle, "SHUTDOWN", &pid);
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    globus_mutex_lock(&handle->lock);
    int has_cb = handle->update_cb != GLOBUS_NULL;
    if (has_cb)
    {
        result = globus_callback_unregister(
            handle->update_cb,
            globus_l_xio_callout_unregister_cb,
            handle,
            NULL);
    }
    globus_mutex_unlock(&handle->lock);

error:
    if (contact_string) globus_free(contact_string);

    globus_xio_driver_finished_close(op, result);

    GlobusXIOCalloutDebugExit();
}

static
globus_result_t
globus_l_xio_callout_close(
    void *                              user_arg,
    void *                              attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    res = globus_xio_driver_pass_close(
        op, globus_l_xio_callout_close_cb, user_arg);
    return res;
}

static
void
globus_l_xio_callout_read_cb(
    struct globus_i_xio_op_s *          op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_driver_finished_read(op, result, nbytes);
}

static
globus_result_t
globus_l_xio_callout_read(
    void *                              user_arg,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_size_t                       wait_for;
    globus_result_t                     res;

    wait_for = globus_xio_operation_get_wait_for(op);
    res = globus_xio_driver_pass_read(
        op, (globus_xio_iovec_t *)iovec, iovec_count, wait_for,
        globus_l_xio_callout_read_cb, user_arg);
    return res;
}

static
void
globus_l_xio_callout_write_cb(
    struct globus_i_xio_op_s *          op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_xio_driver_finished_write(op, result, nbytes);
}

static
globus_result_t
globus_l_xio_callout_write(
    void *                              user_arg,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_size_t                       wait_for;

    wait_for = globus_xio_operation_get_wait_for(op);
    res = globus_xio_driver_pass_write(
        op, (globus_xio_iovec_t *)iovec, iovec_count, wait_for,
        globus_l_xio_callout_write_cb, user_arg);

    return res;
}


static
void
globus_l_xio_callout_accept_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_l_xio_callout_handle_t *     handle;

    GlobusXIOName(globus_l_xio_callout_accept_cb);
    GlobusXIOCalloutDebugEnter();

    handle = (globus_l_xio_callout_handle_t *) user_arg;

    globus_xio_driver_finished_accept(op, handle, result);
    GlobusXIOCalloutDebugExit();
    return;
}


static
globus_result_t
globus_l_xio_callout_accept(
    void *                              driver_server,
    globus_xio_operation_t              op)
{
    globus_l_xio_callout_handle_t *     cpy_handle;
    globus_l_xio_callout_handle_t *     handle;
    globus_result_t                     res;

    GlobusXIOName(globus_l_xio_callout_accept);
    GlobusXIOCalloutDebugEnter();

    cpy_handle = (globus_l_xio_callout_handle_t *)driver_server;
    globus_l_xio_callout_handle_copy((void **)&handle, (void *)cpy_handle);

    res = globus_xio_driver_pass_accept(
           op, globus_l_xio_callout_accept_cb, handle);
    if (res != GLOBUS_SUCCESS)
    {
        goto error_pass;
    }

    GlobusXIOCalloutDebugExit();
    return GLOBUS_SUCCESS;

 error_pass:
    GlobusXIOCalloutDebugExit();
    return res;
}


static
globus_result_t
globus_l_xio_callout_server_init(
    void *                              driver_attr,
    const globus_xio_contact_t *        contact_info,
    globus_xio_operation_t              op)
{
    globus_l_xio_callout_handle_t *     handle = NULL;
    globus_l_xio_callout_handle_t *     cpy_handle;
    globus_result_t                     res;

    GlobusXIOName(globus_l_xio_callout_server_init);
    GlobusXIOCalloutDebugEnter();

    /* first copy attr if we have it */
    if(driver_attr != NULL)
    {
        cpy_handle = (globus_l_xio_callout_handle_t *) driver_attr;
        globus_l_xio_callout_handle_copy((void **)&handle, (void *)cpy_handle);
    }

    res = globus_xio_driver_pass_server_init(op, contact_info, handle);
    if (res != GLOBUS_SUCCESS)
    {
        goto error_pass;
    }
    GlobusXIOCalloutDebugExit();

    return GLOBUS_SUCCESS;

 error_pass:
    GlobusXIOCalloutDebugExit();
    return res;
}

static
globus_result_t
globus_l_xio_callout_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     result = GLOBUS_SUCCESS;

    GlobusXIOName(globus_l_xio_callout_init);
    GlobusXIOCalloutDebugEnter();

    result = globus_xio_driver_init(&driver, "callout", NULL);
    if (result != GLOBUS_SUCCESS)
    {
        goto done;
    }

    globus_mutex_init(&globus_l_xio_callout_pid_mutex, GLOBUS_NULL);
    globus_hashtable_init(
        &globus_l_xio_callout_pid_table,
        256,
        globus_hashtable_voidp_hash,
        globus_hashtable_voidp_keyeq);


    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_callout_open,
        globus_l_xio_callout_close,
        globus_l_xio_callout_read,
        globus_l_xio_callout_write,
        globus_l_xio_callout_cntl,
        NULL);

    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_callout_handle_init,
        globus_l_xio_callout_handle_copy,
        globus_l_xio_callout_cntl,
        globus_l_xio_callout_handle_destroy);

    globus_xio_driver_set_server(
        driver,
        globus_l_xio_callout_server_init,
        globus_l_xio_callout_accept,
        globus_l_xio_callout_handle_destroy,
        globus_l_xio_callout_cntl,
        globus_l_xio_callout_cntl,
        globus_l_xio_callout_handle_destroy);

    globus_xio_driver_string_cntl_set_table(driver, tb_l_string_opts_table);

    // NOTE: we can't handle the sigchld - the GridFTP server already does this :(
/*
    result = globus_callback_register_signal_handler(
        SIGCHLD,
        GLOBUS_TRUE,
        globus_l_xio_callout_sigchld,
        NULL);
    if(result != GLOBUS_SUCCESS)
    {
        GlobusXIOCalloutDebugPrintf(GLOBUS_XIO_CALLOUT_DEBUG_ERROR, ("Failed to register SIGCHILD handler.\n"));
        goto done;
    }
*/
    *out_driver = driver;

done:
    GlobusXIOCalloutDebugExit();
    return GLOBUS_SUCCESS;
}

static
void
globus_l_xio_callout_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);

    globus_mutex_destroy(&globus_l_xio_callout_pid_mutex);
    globus_hashtable_destroy(&globus_l_xio_callout_pid_table);
}

GlobusXIODefineDriver(
    callout,
    globus_l_xio_callout_init,
    globus_l_xio_callout_destroy);

static
int
globus_l_xio_callout_activate(void)
{
    int                                 rc;

    GlobusDebugInit(GLOBUS_XIO_CALLOUT, TRACE);

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc == GLOBUS_SUCCESS)
    {
        GlobusXIORegisterDriver(callout);
    }
    
    return rc;
}

static
int
globus_l_xio_callout_deactivate(void)
{
    GlobusXIOUnRegisterDriver(callout);
    return globus_module_deactivate(GLOBUS_XIO_MODULE);
}
