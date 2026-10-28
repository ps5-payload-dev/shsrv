#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>




char *lv = "│   ";

void gen_branch(int last, char *path, char **branch){
    
    int level = 0;
    for(int i = 0; i < strlen(path); i++){
        if(path[i] == '/') {
            level++;
        }
    }
    
    char *cur_branch = "├─ ";
    
    if(last){
        cur_branch = "└─ "; 
    }
    for(int i = 0; i < level-1; i++) {
        char *new_branch = NULL;
        asprintf(&new_branch, "%s%s", lv, cur_branch);
        
        cur_branch = new_branch;
        free(new_branch);
    }
    *branch = cur_branch;
}



int tree( char *path, int *dir_cnt, int *file_cnt) {
    
    DIR *dir = opendir(path);
    if(!dir) {
        perror("opendir");
        printf("error path: %s\n", path);
        return -1;
        }
    struct dirent *entry = NULL;
    
    while((entry = readdir(dir)) != NULL) {
        
        int last = 0;
        
        long int curdir_idx = telldir(dir);
        seekdir(dir, curdir_idx +1);
        if (readdir(dir) == NULL) {
            last = 1;
        }
        seekdir(dir, curdir_idx);
        
        if(strcmp(entry->d_name, "..") && strcmp(entry->d_name, ".")) {
            if(entry->d_type == DT_DIR){
                (*dir_cnt)++;
                char newpath[PATH_MAX];
                snprintf(newpath, sizeof(newpath), "%s/%s", path, entry->d_name);
                
                char *b = NULL;
                gen_branch(last,path, &b);
                
                printf("%s%s\n", b, entry->d_name);
                
                tree(newpath, dir_cnt, file_cnt);
            }
            else {
                (*file_cnt)++;
                char *b = NULL;
                gen_branch(last,path, &b);
                
                printf("%s%s\n", b, entry->d_name);
            }
        }
    }
    
     
    
    closedir(dir);
    return 0;
}
int main(int argc, char** argv) {
    int dc = 0;
    int fc = 0;
    char *path = NULL;
    
    if(argc < 2) {
        path = getenv("PWD");
    }
    else {
        path = argv[1];
    }
    
    if(tree(path, &dc, &fc) == 0) {
        printf("\n%d directories %d files\n", (int)dc, (int)fc);
    }
    return 0;
    
}
