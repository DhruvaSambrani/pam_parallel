#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#define MAX_CHILDREN 10
#define MSG_AUTH_RESULT 1
#define MSG_CONV_REQ    2

typedef struct {
    int type;
    int payload_int;
    char text[512];
} ipc_msg_t;

struct fg_child_data {
    int fd_in;
    int fd_out;
};

// --- FOREGROUND CHILD CONVERSATION ---
int fg_child_conv(int num_msg, const struct pam_message **msg,
                  struct pam_response **resp, void *appdata_ptr) {
    struct fg_child_data *cdata = (struct fg_child_data *)appdata_ptr;
    
    *resp = calloc(num_msg, sizeof(struct pam_response));
    if (!*resp) return PAM_BUF_ERR;

    for (int i = 0; i < num_msg; i++) {
        ipc_msg_t req;
        memset(&req, 0, sizeof(req));
        req.type = MSG_CONV_REQ;
        req.payload_int = msg[i]->msg_style;
        if (msg[i]->msg) {
            strncpy(req.text, msg[i]->msg, sizeof(req.text)-1);
        }
        
        write(cdata->fd_out, &req, sizeof(req)); 
        
        ipc_msg_t reply;
        if (read(cdata->fd_in, &reply, sizeof(reply)) <= 0) return PAM_CONV_ERR;
        
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF || msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
            (*resp)[i].resp = strdup(reply.text);
            (*resp)[i].resp_retcode = 0;
        } else {
            (*resp)[i].resp = NULL;
            (*resp)[i].resp_retcode = 0;
        }
    }
    return PAM_SUCCESS;
}

// --- BACKGROUND CHILD CONVERSATION ---
int bg_child_conv(int num_msg, const struct pam_message **msg,
                  struct pam_response **resp, void *appdata_ptr) {
    *resp = calloc(num_msg, sizeof(struct pam_response));
    if (!*resp) return PAM_BUF_ERR;

    for (int i = 0; i < num_msg; i++) {
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF || msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
            return PAM_CONV_ERR; 
        }
        
        if ((msg[i]->msg_style == PAM_TEXT_INFO || msg[i]->msg_style == PAM_ERROR_MSG) && msg[i]->msg) {
            int fd = open("/dev/tty", O_WRONLY);
            if (fd >= 0) {
                write(fd, "\r\n", 2);
                write(fd, msg[i]->msg, strlen(msg[i]->msg));
                write(fd, "\r\n", 2);
                close(fd);
            }
        }
        
        (*resp)[i].resp = NULL;
        (*resp)[i].resp_retcode = 0;
    }
    return PAM_SUCCESS;
}

// Gracefully unblocks the parent's frozen prompt (Works on CLI, gracefully ignored by GUI/Swaylock)
void break_parent_conv() {
    int fd = open("/dev/tty", O_WRONLY);
    if (fd >= 0) {
        char c = '\n';
        ioctl(fd, TIOCSTI, &c); 
        close(fd);
    }
}

// Sandbox execution wrapper
void run_child(const char *service, const char *user, const void *tty, const void *rhost, 
               const void *ruser, int pipe_read, int pipe_write, int is_fg) {
    
    struct fg_child_data cdata = {pipe_read, pipe_write};
    struct pam_conv conv;
    
    if (is_fg) {
        conv.conv = fg_child_conv;
        conv.appdata_ptr = &cdata;
    } else {
        conv.conv = bg_child_conv;
        conv.appdata_ptr = NULL;
    }
    
    pam_handle_t *pamh = NULL;
    int ret = pam_start(service, user, &conv, &pamh);
    if (ret == PAM_SUCCESS) {
        if (tty) pam_set_item(pamh, PAM_TTY, tty);
        if (rhost) pam_set_item(pamh, PAM_RHOST, rhost);
        if (ruser) pam_set_item(pamh, PAM_RUSER, ruser);
        
        ret = pam_authenticate(pamh, 0);
        pam_end(pamh, ret);
    }
    
    ipc_msg_t res;
    memset(&res, 0, sizeof(res));
    res.type = MSG_AUTH_RESULT;
    res.payload_int = ret;
    write(pipe_write, &res, sizeof(res));
    
    if (!is_fg && ret == PAM_SUCCESS) {
        break_parent_conv();
    }
    
    exit(0);
}

// --- PARENT PROCESS LOGIC ---
int do_real_conv(pam_handle_t *pamh, struct pam_conv *real_conv, ipc_msg_t *req, ipc_msg_t *reply) {
    memset(reply, 0, sizeof(ipc_msg_t));
    if (!real_conv || !real_conv->conv) return PAM_CONV_ERR;
    
    struct pam_message msg;
    const struct pam_message *msgp = &msg;
    struct pam_response *resp = NULL;
    
    msg.msg_style = req->payload_int;
    msg.msg = req->text;
    
    int ret = real_conv->conv(1, &msgp, &resp, real_conv->appdata_ptr);
    
    if (ret == PAM_SUCCESS && resp) {
        if (req->payload_int == PAM_PROMPT_ECHO_OFF || req->payload_int == PAM_PROMPT_ECHO_ON) {
            if (resp[0].resp) {
                strncpy(reply->text, resp[0].resp, sizeof(reply->text)-1);
                
                // CRITICAL FIX: Propagate the password into the parent PAM handle!
                // This ensures secondary modules like pam_kwallet or pam_systemd
                // don't fail when attempting to access the credentials.
                pam_set_item(pamh, PAM_AUTHTOK, resp[0].resp);
                
                free(resp[0].resp);
            }
        }
        free(resp);
    }
    return ret;
}

typedef struct {
    pid_t pid;
    int pipe_in;
    int pipe_out;
    int is_fg;
    int is_done;
} child_state_t;

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    char *fg_service = NULL;
    char *bg_services[MAX_CHILDREN];
    int num_bg = 0;
    
    for (int i=0; i<argc; i++) {
        if (strncmp(argv[i], "fg=", 3) == 0) {
            fg_service = strdup(argv[i] + 3);
        } else if (strncmp(argv[i], "bg=", 3) == 0) {
            char *list = strdup(argv[i] + 3);
            char *tok = strtok(list, ",");
            while(tok && num_bg < MAX_CHILDREN) {
                bg_services[num_bg++] = strdup(tok);
                tok = strtok(NULL, ",");
            }
            free(list);
        }
    }
    
    int total_children = (fg_service ? 1 : 0) + num_bg;
    if (total_children == 0) return PAM_AUTH_ERR;
    
    const char *user = NULL;
    pam_get_user(pamh, &user, NULL);
    const void *tty = NULL, *rhost = NULL, *ruser = NULL;
    pam_get_item(pamh, PAM_TTY, &tty);
    pam_get_item(pamh, PAM_RHOST, &rhost);
    pam_get_item(pamh, PAM_RUSER, &ruser);
    
    struct pam_conv *real_conv;
    if (pam_get_item(pamh, PAM_CONV, (const void **)&real_conv) != PAM_SUCCESS || !real_conv)
        return PAM_AUTH_ERR;

    child_state_t children[MAX_CHILDREN + 1];
    int child_idx = 0;
    
    // O_CLOEXEC prevents file descriptor leaking between concurrent background tasks
    #define FORK_CHILD(svc, is_foreground) do { \
        int p_to_c[2], c_to_p[2]; \
        if (pipe2(p_to_c, O_CLOEXEC) != 0 || pipe2(c_to_p, O_CLOEXEC) != 0) return PAM_AUTH_ERR; \
        pid_t pid = fork(); \
        if (pid == 0) { \
            close(p_to_c[1]); close(c_to_p[0]); \
            run_child(svc, user, tty, rhost, ruser, p_to_c[0], c_to_p[1], is_foreground); \
        } else if (pid > 0) { \
            close(p_to_c[0]); close(c_to_p[1]); \
            children[child_idx].pid = pid; \
            children[child_idx].pipe_in = p_to_c[1]; \
            children[child_idx].pipe_out = c_to_p[0]; \
            children[child_idx].is_fg = is_foreground; \
            children[child_idx].is_done = 0; \
            child_idx++; \
        } \
    } while(0)
    
    if (fg_service) FORK_CHILD(fg_service, 1);
    for (int i=0; i<num_bg; i++) FORK_CHILD(bg_services[i], 0);
    
    int active_children = total_children;
    int final_result = PAM_AUTH_ERR;
    
    while (active_children > 0) {
        fd_set readfds;
        FD_ZERO(&readfds);
        int max_fd = 0;
        
        for (int i=0; i<total_children; i++) {
            if (!children[i].is_done) {
                FD_SET(children[i].pipe_out, &readfds);
                if (children[i].pipe_out > max_fd) max_fd = children[i].pipe_out;
            }
        }
        
        int sel = select(max_fd + 1, &readfds, NULL, NULL, NULL);
        if (sel > 0) {
            for (int i=0; i<total_children; i++) {
                if (!children[i].is_done && FD_ISSET(children[i].pipe_out, &readfds)) {
                    ipc_msg_t msg;
                    if (read(children[i].pipe_out, &msg, sizeof(msg)) <= 0) {
                        children[i].is_done = 1;
                        active_children--;
                        continue;
                    }
                    
                    if (msg.type == MSG_AUTH_RESULT) {
                        if (msg.payload_int == PAM_SUCCESS) {
                            final_result = PAM_SUCCESS;
                            children[i].is_done = 1; // Mark winner as done to protect from SIGKILL
                            goto cleanup;
                        } else {
                            children[i].is_done = 1;
                            active_children--;
                            
                            // If user exhausted password retries, abort so they can retry fully
                            if (children[i].is_fg) {
                                goto cleanup;
                            }
                        }
                    } else if (msg.type == MSG_CONV_REQ && children[i].is_fg) {
                        ipc_msg_t reply;
                        // Pass 'pamh' downwards to intercept the password
                        do_real_conv(pamh, real_conv, &msg, &reply);
                        write(children[i].pipe_in, &reply, sizeof(reply));
                    }
                }
            }
        }
    }
    
cleanup:
    for (int i=0; i<total_children; i++) {
        if (!children[i].is_done) kill(children[i].pid, SIGKILL);
        waitpid(children[i].pid, NULL, 0); 
        close(children[i].pipe_in);
        close(children[i].pipe_out);
    }
    if (fg_service) free(fg_service);
    for (int i=0; i<num_bg; i++) free(bg_services[i]);
    
    return final_result;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}