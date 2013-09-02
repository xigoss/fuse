/*
gcc -Wall lunafuse.c `pkg-config fuse --cflags --libs` -o lunafuse -lsqlite3 -L /usr/lib -I /usr/included
*/
#define FUSE_USE_VERSION 26

#define _XOPEN_SOURCE 500

#include <stdio.h>
#include <string.h>
#include <fuse.h>
#include <errno.h>
#include <fcntl.h>
#include <sqlite3.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#define SHA1_LEN 40
#define SHA1_MAX 1048576

static const char *usage =
"usage: lunafuse [options]\n"
"\n"
"options:\n"
"    --help|-h             print this help message\n"
"    -m                    the path of db\n"
"    -k                    the path of data\n"
"    to use the function,'-k' and '-m' are necessary."
"\n";

#pragma pack(push, 1)

typedef struct fs_head_t {
    int32_t struct_size;       /* total size of this variable struct   */
    char     type;              /* file type: (LUNA_DIR, LUNA_FILE)     */
    char     op;                /* operation, see LUNA OPERATION NEW    */
    int16_t  mode;              /* linux mode: default file:644,dir 755 */
    int64_t  id;                /* file id: genrated by server          */
	int64_t  localid;           /* file id specified to client          */
    int64_t  pid;               /* file id of parent directory          */
    int64_t  histid;            /* last update id in hist table         */
    int64_t  size;              /* file size                            */
    int64_t  ctime;             /* file create time                     */
    int64_t  mtime;             /* file modify time                     */
    int32_t  offset_sha1;       /* sha1 offset base on data             */
    int32_t  offset_vclock;     /* vclock offset based on data          */
    char     status;            /* file status:see OBJECT STATUS        */
    char     data[0];           /* variable part of the struct          */
} fs_head_t;

#define fs_head_name(ph) ((ph)->data)
#define fs_head_name_size(ph) ((ph)->offset_sha1 - 1)   // -1 for the '/0'
#define fs_head_sha1(ph) ((ph)->data + (ph)->offset_sha1)
#define fs_head_sha1_size(ph) ((ph)->offset_vclock - (ph)->offset_sha1)
#define fs_head_vclock(ph) ((ph)->data + (ph)->offset_vclock) 
#define fs_head_vclock_size(ph) ((ph)->struct_size - sizeof(fs_head_t) - (ph)->offset_vclock)

#pragma pack(pop)

static char name[100][512];
static char sha1[401];
static char data_path[512];
static char time_f[100][20];
static int num = 0;  
static fs_head_t head[100][200];
sqlite3 *db;

static void getname_head(const char *path){
    int rc, j = 0;
    char *sql;
    char *p;
    const char *tail;
    sqlite3_stmt *stmt;

    char s[512];
    char t[512];
    strcpy(s, path);
    strcpy(t, path);
    if(strcmp(path, "/") == 0){
        strcat(s, "%");
        strcat(t, "%/%");
    }
    else{
        strcat(s, "/%");
        strcat(t, "/%/%");
    }
    
    sql = sqlite3_mprintf("SELECT name FROM head WHERE name LIKE %Q AND\
            name NOT LIKE %Q AND status = 'o' AND name != %Q", s, t, path);
    rc = sqlite3_prepare(db, sql, (int)strlen(sql), &stmt, &tail);
    if(rc != SQLITE_OK){
        fprintf(stderr, "SQL error:%s\n", sqlite3_errmsg(db));
    }
    
    rc = sqlite3_step(stmt);
    while(rc == SQLITE_ROW){
        strcpy(s, (const char*)sqlite3_column_text(stmt, 0));
        p = strrchr(s, '/');
        strcpy(name[j], p + 1);
        j++;
        rc = sqlite3_step(stmt);
    }   
    num = j;

    sqlite3_finalize(stmt);
}


static int getmode_head(const char *path){
    int rc;
    char *sql;
    const char *tail;
    sqlite3_stmt *stmt;
    int mode;
    
    sql = sqlite3_mprintf(
        "SELECT mode FROM head WHERE name=%Q AND status ='o'", path);
    rc = sqlite3_prepare(db, sql, (int)strlen(sql), &stmt, &tail);
    if(rc != SQLITE_OK){
        fprintf(stderr, "SQL error:%s\n", sqlite3_errmsg(db));
    }
    
    rc = sqlite3_step(stmt);
    if(rc == SQLITE_ROW){
        mode = sqlite3_column_int(stmt, 0);
    }   
    sqlite3_finalize(stmt);
    return mode;
}

static char gettype_head(const char *path){
    int rc;
    char *sql;
    const char *tail;
    sqlite3_stmt *stmt;
    char type;

    sql = sqlite3_mprintf(
        "SELECT type FROM head WHERE name=%Q AND status ='o'", path);
    rc = sqlite3_prepare(db, sql, (int)strlen(sql), &stmt, &tail);
    if(rc != SQLITE_OK){
        fprintf(stderr, "SQL error:%s\n", sqlite3_errmsg(db));
    }
    
    rc = sqlite3_step(stmt);
    if(rc == SQLITE_ROW){
        type = *sqlite3_column_text(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return type;
}

static int getsize_head(const char *path){
    int rc;
    char *sql;
    const char *tail;
    sqlite3_stmt *stmt;
    int size;
    
    sql = sqlite3_mprintf(
        "SELECT size FROM head WHERE name=%Q AND status='o'", path);
    rc = sqlite3_prepare(db, sql, (int)strlen(sql), &stmt, &tail);
    if(rc != SQLITE_OK){
        fprintf(stderr, "SQL error:%s\n", sqlite3_errmsg(db));
    }
    
    rc = sqlite3_step(stmt);
    if(rc == SQLITE_ROW){
        size = sqlite3_column_int(stmt, 0);
    }   
    sqlite3_finalize(stmt);
    return size;
}

static int getmtime_head(const char *path){
    int rc;
    char *sql;
    const char *tail;
    sqlite3_stmt *stmt;
    int mtime;
    
    sql = sqlite3_mprintf(
        "SELECT mtime FROM head WHERE name=%Q AND status='o'", path);
    rc = sqlite3_prepare(db, sql, (int)strlen(sql), &stmt, &tail);
    if(rc != SQLITE_OK){
        fprintf(stderr, "SQL error:%s\n", sqlite3_errmsg(db));
    }
    
    rc = sqlite3_step(stmt);
    if(rc == SQLITE_ROW){
        mtime = sqlite3_column_int64(stmt, 0);
    }   

    sqlite3_finalize(stmt);
    return mtime;
}

static int getctime_head(const char *path){
    int rc;
    char *sql;
    const char *tail;
    sqlite3_stmt *stmt;
    int ctime;
    
    sql = sqlite3_mprintf(
        "SELECT ctime FROM head WHERE name=%Q AND status='o'", path);
    rc = sqlite3_prepare(db, sql, (int)strlen(sql), &stmt, &tail);
    if(rc != SQLITE_OK){
        fprintf(stderr, "SQL error:%s\n", sqlite3_errmsg(db));
    }
    
    rc = sqlite3_step(stmt);
    if(rc == SQLITE_ROW){
        ctime = sqlite3_column_int64(stmt, 0);
    }   

    sqlite3_finalize(stmt);
    return ctime;
}

static void getsha1_head(const char *path){
    int rc;
    char *sql;
    const char *tail;
    sqlite3_stmt *stmt;
    
    sql = sqlite3_mprintf(
        "SELECT sha1 FROM head WHERE name=%Q AND status='o'", path);
    rc = sqlite3_prepare(db, sql, (int)strlen(sql), &stmt, &tail);
    if(rc != SQLITE_OK){
        fprintf(stderr, "SQL error:%s\n", sqlite3_errmsg(db));
    }
    
    rc = sqlite3_step(stmt);
    if(rc == SQLITE_ROW){
        strcpy(sha1, (char*)sqlite3_column_text(stmt, 0));
    }

    sqlite3_finalize(stmt);
}

//get the deleted file name
static void getname_del(const char *path){
    int rc, i, j = 0;
    char *sql;
    char *q;
    char s[512];
    char tmp_name[512];
    const char *tail;
    sqlite3_stmt *stmt;
    int len = strlen(path);

    strcpy(s, path);
    strcat(s, "%");
    
    sql = sqlite3_mprintf("SELECT name FROM hist WHERE name LIKE %Q AND\
            type='f' AND op='d' ", s);
    rc = sqlite3_prepare(db, sql, (int)strlen(sql), &stmt, &tail);
    if(rc != SQLITE_OK){
        fprintf(stderr, "SQL error:%s\n", sqlite3_errmsg(db));
    }
    
    rc = sqlite3_step(stmt);
    while(rc == SQLITE_ROW){
        strcpy(tmp_name, (char*)sqlite3_column_text(stmt, 0));
        q = strrchr(tmp_name, '/');
        for(i = 0; i < j; i++){
            if(strcmp(q + 1, name[i]) == 0){
                break;
            }
        }
        if(i == j){
            strcpy(name[j], q + 1);
            j++;
        }
        rc = sqlite3_step(stmt);
    }   
    num = j;

    sqlite3_finalize(stmt);
}

//get the name existed in hist table
static void getname_hist(char *path){
    int n;
    char s[512];
    char *p = strstr(path, "/.history/");
    char *q = strstr(path, "/.deleted");

    if(p != NULL){
        if(*(p + 29) == '/'){
            n = p - path + 1; 
            strncpy(s, path, n);
            s[n] = '\0';
            strcat(s, p + 30);
            strcpy(path, s);
        }else{
            if(strncmp(path, "/.history", 9) == 0){
                strcpy(path, "/");
            }
            else{
                n = p - path; 
                strncpy(s, path, n);
                s[n] = '\0';
                strcpy(path, s);
            }
        }
    }
    
    else if (q != NULL){
        if(*(q + 9) == '/'){
            n = q - path + 1; 
            strncpy(s, path, n);
            s[n] = '\0';
            strcat(s, q + 10);
            strcpy(path, s);
        }else{
            if(strncmp(path, "/.deleted", 9) == 0){
                strcpy(path, "/");
            }
            else{
                n = q - path; 
                strncpy(s, path, n);
                s[n] = '\0';
                strcpy(path, s);
            }
        }
    }
}

static int getmode_del(const char *path){
    int rc, len;
    char *sql;
    char *p;
    const char *tail;
    sqlite3_stmt *stmt;
    int mode;
    char s[512];
    char t[512];

    strcpy(s, path);
    p = strrchr(s, '/');
    len = p - s;
    strncpy(t, s, len);
    t[len] = '\0';
    strcat(t, "/%");
    strcat(t, p);

    sql = sqlite3_mprintf(
        "SELECT mode FROM hist WHERE name LIKE %Q OR name=%Q AND op ='d'", t, path);
    rc = sqlite3_prepare(db, sql, (int)strlen(sql), &stmt, &tail);
    if(rc != SQLITE_OK){
        fprintf(stderr, "SQL error:%s\n", sqlite3_errmsg(db));
    }
    
    rc = sqlite3_step(stmt);
    while(rc == SQLITE_ROW){
        mode = sqlite3_column_int(stmt, 0);
        rc = sqlite3_step(stmt);
    }   

    sqlite3_finalize(stmt);
    return mode;
}

static int getsize_del(const char *path){
    int rc, len;
    char *sql;
    char *p;
    const char *tail;
    sqlite3_stmt *stmt;
    int size;
    char s[512];
    char t[512];

    strcpy(s, path);
    p = strrchr(s, '/');
    len = p - s;
    strncpy(t, s, len);
    t[len] = '\0';
    strcat(t, "/%");
    strcat(t, p);
    
    sql = sqlite3_mprintf(
        "SELECT size FROM hist WHERE name LIKE %Q OR name=%Q AND op='d'", t, path);
    rc = sqlite3_prepare(db, sql, (int)strlen(sql), &stmt, &tail);
    if(rc != SQLITE_OK){
        fprintf(stderr, "SQL error:%s\n", sqlite3_errmsg(db));
    }
    
    rc = sqlite3_step(stmt);
    while(rc == SQLITE_ROW){
        size = sqlite3_column_int(stmt, 0);
        rc = sqlite3_step(stmt);
    }   

    sqlite3_finalize(stmt);
    return size;
}

static int getid_del(const char *path){
    int rc, id, len;
    char *sql;
    char *p;
    const char *tail;
    sqlite3_stmt *stmt;
    char s[512];
    char t[512];

    strcpy(s, path);
    p = strrchr(s, '/');
    len = p - s;
    strncpy(t, s, len);
    t[len] = '\0';
    strcat(t, "/%");
    strcat(t, p);

    sql = sqlite3_mprintf(
        "SELECT id FROM hist WHERE op='d' AND name LIKE %Q OR name=%Q", t, path);
    rc = sqlite3_prepare(db, sql, (int)strlen(sql), &stmt, &tail);
    rc = sqlite3_step(stmt);
    if(rc == SQLITE_ROW){
        id = sqlite3_column_int(stmt, 0);
    }   

    sqlite3_finalize(stmt);
    return id;
}

static void getsha1_del(const char *path){
    int rc, id, len;
    char *sql;
    char *p;
    const char *tail;
    sqlite3_stmt *stmt;
    char s[512];
    char t[512];
    id = getid_del(path);

    strcpy(s, path);
    p = strrchr(s, '/');
    len = p - s;
    strncpy(t, s, len);
    t[len] = '\0';
    strcat(t, "/%");
    strcat(t, p);

    sql = sqlite3_mprintf(
        "SELECT sha1 FROM hist WHERE op!='d' AND id<%d AND name LIKE %Q OR name=%Q ", id, t, path);
    rc = sqlite3_prepare(db, sql, (int)strlen(sql), &stmt, &tail);
    rc = sqlite3_step(stmt);
    while(rc == SQLITE_ROW){
        strcpy(sha1, (const char*)sqlite3_column_text(stmt, 0));
        rc = sqlite3_step(stmt);
    }

    sqlite3_finalize(stmt);
}

static void getsha1_dir(const char *path){
    int rc, n;
    char *sql, *p;
    const char *tail;
    sqlite3_stmt *stmt;
    char tmp_path[512];
    char time_s[20];

    if((p = strstr(path, "/.history/")) == NULL){
        return;
    }
    strncpy(time_s, p + 10, 19);
    time_s[19] = '\0';
    strcpy(tmp_path, path);
    getname_hist(tmp_path);
 
    sql = sqlite3_mprintf(
        "SELECT sha1 FROM hist WHERE name=%Q AND op='s' AND\
        datetime(timestamp,'unixepoch')=%Q", tmp_path, time_s);
    rc = sqlite3_prepare(db, sql, (int)strlen(sql), &stmt, &tail);
    if(rc != SQLITE_OK){
        fprintf(stderr, "SQL error:%s\n", sqlite3_errmsg(db));
    }
    
    rc = sqlite3_step(stmt);
    if(rc == SQLITE_ROW){
        strcpy(sha1, (char*)sqlite3_column_text(stmt, 0));
    }else {
        sha1[0] = '\0';
    }   

    sqlite3_finalize(stmt);
}

static void get_fs_head(char *sha1_path){
    char *buf;
    char *size;
    int32_t size_m,size_h, count = 0;
    int fd, res,i = 0;
    size = (char*)malloc(sizeof(char)*5);

	fd = open(sha1_path, O_RDONLY);
	if(fd == -1)
	    return;

    res = pread(fd, size, 4, 4);
    if(res != 4)
        return;
    size_m = *(int32_t*)size;
    
    buf = (char*)malloc((size_m + 1)*sizeof(char));
    res = pread(fd, buf, size_m, 12);
    if(res != size_m)
        return;

    while(count < size_m){
        res = pread(fd, size, 4, count+12);
        if(res != 4){
            return;
        }
        size_h = *(int32_t*)size;
        memcpy(head[i], buf + count, size_h); 
        count = count + size_h;
        i++;
    }        
    num = i;
    
    free(size);
    free(buf);
    close(fd);
}

static void gettime_hist(const char *path){
    int rc;
    int i = 0;
    char *sql;
    const char *tail;
    sqlite3_stmt *stmt;
    char path_tmp[512];

    int len = strlen(path);
    strcpy(path_tmp, path); 
    if(len == 9){
        path_tmp[1] = '\0';
    }
    else path_tmp[len-9] = '\0';
    
    sql = sqlite3_mprintf(
        "SELECT datetime(timestamp, 'unixepoch') FROM hist WHERE name=%Q AND op='s'", path_tmp);
    rc = sqlite3_prepare(db, sql, (int)strlen(sql), &stmt, &tail);
    if(rc != SQLITE_OK){
        fprintf(stderr, "SQL error:%s\n", sqlite3_errmsg(db));
    }
    
    rc = sqlite3_step(stmt);
    while(rc == SQLITE_ROW){
        strcpy(time_f[i], (char*)sqlite3_column_text(stmt, 0));
        i++;
        rc = sqlite3_step(stmt);
    }   
    num = i;

    sqlite3_finalize(stmt);
}

static int lunafuse_getattr(const char *path, struct stat *stbuf)
{
	int res = 0, i = 0, j;
    int len = strlen(path);
    char *p, *q;
    char tmp_path[512];
    char tmp_name[512];
    char sha1_path[512];
	memset(stbuf, 0, sizeof(struct stat));


	if (strcmp(path, "/") == 0 ||
        (len > 8 && strcmp(path + len -8, ".history") == 0)||
        ((p = strstr(path, "/.history")) != NULL && *(p + 29) != '/')
        || ((q = strstr(path, "/.deleted")) != NULL && *(q + 9) != '/')){ 
		stbuf->st_mode = S_IFDIR | 493;
		stbuf->st_nlink = 2;
	} 

    else if(strstr(path, "/.history/") != NULL){
        strcpy(tmp_name, path);
        getname_hist(tmp_name);
        p = strrchr(path, '/');
        j = p - path;
        strncpy(tmp_path, path, j);
        tmp_path[j] = '\0';
        getsha1_dir(tmp_path);
        strcpy(sha1_path, data_path);
        strcat(sha1_path, sha1);
        get_fs_head(sha1_path);

        while(i < num){
            if(strcmp(tmp_name, fs_head_name(head[i])) == 0){
                if(head[i]->type == 'd'){
                    stbuf->st_mode = S_IFDIR | head[i]->mode;
		            stbuf->st_nlink = 2;
                }else{
                    stbuf->st_mode = S_IFREG | head[i]->mode;
		            stbuf->st_nlink = 1;
                }
                stbuf->st_size = head[i]->size; 
                break;
            }
            i++;
        }
    }
    
    else if(strstr(path, "/.deleted/") != NULL){
        strcpy(tmp_path, path);
        getname_hist(tmp_path);
        stbuf->st_mode = S_IFREG | getmode_del(tmp_path);
	    stbuf->st_nlink = 1;
		stbuf->st_size = getsize_del(tmp_path);
    }

	else {
        if(gettype_head(path) == 'd'){
		            stbuf->st_mode = S_IFDIR | getmode_head(path);
		            stbuf->st_nlink = 2;
        }
        else if(gettype_head(path) == 'f'){
                    stbuf->st_mode = S_IFREG | getmode_head(path);
		            stbuf->st_nlink = 1;
            }
            else res = -ENOENT;
		stbuf->st_size = getsize_head(path);
		//stbuf->st_mtime = getmtime_head(path);
		//stbuf->st_ctime = getctime_head(path);
    }

	return res;
}

static int lunafuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
	(void) offset;
	(void) fi;
    int i = 0, n, j, len;
    char *p;
    char *q;
    char timename[20];
    char tmp_path[512];
    char sha1_path[512];

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

//under the history dir to filler the time dir
    if(strcmp(p = strrchr(path, '/'), "/.history") == 0){
        gettime_hist(path);
        while(i < num){
		    filler(buf, time_f[i], NULL, 0);
            i++;
        }
    }

//under the time dir to filler the file
    else if((q = strstr(path, "/.history/")) != NULL ){
        getsha1_dir(path);
        strcpy(sha1_path, data_path);
        strcat(sha1_path, sha1);
        get_fs_head(sha1_path);
        if(strlen(sha1) == 0){
            num = 0;
        }
        while(i < num){
            p = strrchr(fs_head_name(head[i]), '/');
            j = p - fs_head_name(head[i]) + 1;
            filler(buf, fs_head_name(head[i]) + j, NULL, 0);
            i++;
        }
    }

//filler deleted file
    else if((p = strstr(path, "/.deleted")) != NULL){
            strcpy(tmp_path, path);
            getname_hist(tmp_path);
            getname_del(tmp_path); 
            while(i < num){
                filler(buf, name[i], NULL, 0);
                i++;
            }
        }    

//normally
    else{
        filler(buf, ".history", NULL, 0);
        filler(buf, ".deleted", NULL, 0);
        getname_head(path);
        while(i < num){
	        filler(buf, name[i], NULL, 0);
            i++;
        }
    }

    return 0;
}

static int lunafuse_open(const char *path, struct fuse_file_info *fi)
{
	if ((fi->flags & 3) != O_RDONLY)
		return -EACCES;

	return 0;
}

static int lunafuse_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
    int fd, n, i = 0, j;
    int in_res, res = 0;
    off_t in_offset; 
    int sha1_len;
    char sha1_path[512];
    size_t in_size = size;
    char *p;
    char tmp_path[512];
    char tmp_name[512];
    
    (void) fi;
    
    if(strstr(path, "/.history/") != NULL){
        strcpy(tmp_name, path);
        getname_hist(tmp_name);
        p = strrchr(path, '/');
        j = p - path;
        strncpy(tmp_path, path, j);
        tmp_path[j] = '\0';
        getsha1_dir(tmp_path);
        strcpy(sha1_path, data_path);
        strcat(sha1_path, sha1);
        get_fs_head(sha1_path);

        while(i < num){
            if(strcmp(tmp_name, fs_head_name(head[i])) == 0){
            strncpy(sha1, fs_head_sha1(head[i]), fs_head_sha1_size(head[i])); 
            sha1[fs_head_sha1_size(head[i])] = '\0';
            break;
            }
        i++;
        }
    }

    else if(strstr(path, "/.deleted/") != NULL){
        strcpy(tmp_path, path);
        getname_hist(tmp_path);
        getsha1_del(tmp_path);
    }

    else {
        getsha1_head(path);
    }

    sha1_len = strlen(sha1); 
    strcpy(sha1_path, data_path);
    n = sha1_len/SHA1_LEN;
    i = offset/SHA1_MAX;

    while(n > i+1 && res != size){
        in_offset = offset%SHA1_MAX + 12;
        strncat(sha1_path, sha1+i*SHA1_LEN, SHA1_LEN);
	    fd = open(sha1_path, O_RDONLY);
	    if (fd == -1)
	        return -errno;
        in_res = pread(fd, buf + res, in_size, in_offset);
	    if (res == -1)
	        return -errno;
        res = res + in_res; 
        offset = offset + in_res;
        in_size = in_size - in_res;
        i = offset/SHA1_MAX;
        close (fd);
    }
    
    if(n == i+1 && res != size){
        in_offset = offset%SHA1_MAX + 12;
        strncat(sha1_path, sha1+i*SHA1_LEN, SHA1_LEN);
	    fd = open(sha1_path, O_RDONLY);
	    if (fd == -1)
	        return -errno;
        in_res = pread(fd, buf + res, in_size, in_offset);
	    if (res == -1)
	        return -errno;
        res = res + in_res; 
        close(fd);
    }
        
    return res;
}


static struct fuse_operations lunafuse_oper = {
	.getattr	= lunafuse_getattr,
	.readdir	= lunafuse_readdir,
	.open		= lunafuse_open,
	.read		= lunafuse_read,
};

int main(int argc, char *argv[])
{
    char db_path[512];
    int i = 1;
    int count = 0;
    getcwd(data_path, sizeof(data_path));

    while(i < argc){
        if(strcmp(argv[i], "-h") == 0||strcmp(argv[i], "--help") == 0){
            if(argc != 2){
                printf("command not found!\n");
                return -1;
            }
            fprintf(stderr, "%s", usage);
            return 0;    
        }

        else if(strcmp(argv[i], "-m") == 0){
            count++;
            strcpy(db_path, argv[i+1]);
        }

            else if(strcmp(argv[i], "-k") == 0){
                count++;
                strcat(data_path, "/");
                strcat(data_path, argv[i+1]);
                strcat(data_path, "/");
            }
        i++;
    } 

    int rc;
    rc = sqlite3_open(db_path, &db);
    if(rc){
        fprintf(stderr, "cannot open database:%s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    if((count*2 + 2) == argc){
        strcpy(argv[1], argv[argc-1]);
        argc = 2;
    }else{
        printf("command not found!\n");
        return -1;
    }
  
    fuse_main(argc, argv, &lunafuse_oper, NULL);
    
    sqlite3_close(db);
    return 0;
}

