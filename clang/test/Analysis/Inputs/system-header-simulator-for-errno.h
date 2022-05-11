#pragma clang system_header

typedef __typeof(sizeof(int)) off_t;

int access(const char *path, int amode);
off_t lseek(int fildes, off_t offset, int whence);
