/// @brief device

#include "device.h"

#include "debug.h"		// xPRINTF
#include "kernel_symbols.h"

#include <linux/errno.h>	// error codes: ENOMEM
#include <linux/fcntl.h>	// O_NONBLOCK
#include <linux/fs.h>		// struct file
#include <linux/miscdevice.h>
#include <linux/uaccess.h>	// copy_from_user(), copy_to_user()

#define toULL(x) (unsigned long long)(x)

static int device_open(struct inode* inode, struct file* file)
{
	int ret;
	IPRINTF("");
	DPRINTF("inode->i_rdev: major=%u minor=%u", imajor(inode), iminor(inode));
	DPRINTF("filp->f_flags=%X", filp->f_flags);

	if (file->f_flags & O_NONBLOCK) {
		EPRINTF("'%s' mode is not supported", "non-blocking");
		ret = -EINVAL;
		goto out;
	}
	if (file->f_flags & O_RDWR) {
		EPRINTF("'%s' mode is not supported", "WRITE");
		ret = -EINVAL;
		goto out;
	}
	ret = 0;
out:
	DPRINTF("ret=%i", ret);
	return ret;
}

typedef struct {
	loff_t current_offset;
	loff_t* file_offset;

	char __user* user;
	size_t capacity;

	size_t size;
} device_read_context_t;

static int device_read_enumerate_kernel_symbols_cb(
	void* cb_context, const char* data, size_t size)
{
	device_read_context_t* context = cb_context;
	int ret;

	context->size += size;

	if (context->current_offset < *context->file_offset) {
		size_t skip = *context->file_offset - context->current_offset;
		if (skip > size) {
			skip = size;
		}
		context->current_offset += skip;
		data += skip;
		size -= skip;
	}

	if (size > context->capacity) {
		size = context->capacity;
	}
	if (size) {
		// 'copy_to_user' MAY sleep (for example in page fault handler)
		if (copy_to_user(context->user, data, size)) {
			WPRINTF("'copy_to_user()' failure");
			ret = -EFAULT;
			goto out;
		}
		context->current_offset += size;
		*context->file_offset += size;
		context->user += size;
		context->capacity -= size;
	}
	ret = 0;
out:
	return ret;
}

/*
    Whatever the amount of data the methods transfer, they should in
    general update the file position at *offset to represent the current
    file position after successful completion of the system call. Most of
    the time the 'offset' argument is just a pointer to filp->f_pos, but
    a different pointer is used in order to support the pread and pwrite
    system calls, which perform the equivalent of lseek and read or write
    in a single, atomic operation.
*/
static ssize_t device_read(
	struct file* file, char __user* user, size_t size, loff_t* offset)
{
	device_read_context_t context = {
		.current_offset = 0,
		.file_offset = offset,

		.user = user,
		.capacity = size,

		.size = 0,
	};
	int enumerate_kernel_symbols_result;
	enumerate_kernel_symbols_result =
	enumerate_kernel_symbols(&context, device_read_enumerate_kernel_symbols_cb);
	if (enumerate_kernel_symbols_result < 0) {
		WPRINTF("enumerate_kernel_symbols_result=%i", enumerate_kernel_symbols_result);
		return enumerate_kernel_symbols_result;
	}
	return size - context.capacity;
}

static int device_release(struct inode* inode, struct file* file)
{
	IPRINTF("");
	return 0;
}

static const struct file_operations operations = {
	.owner		= THIS_MODULE,
	.open		= device_open,
	.read		= device_read,
	.release	= device_release,
};

static struct miscdevice miscdevice = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "kernel_symbols",
	.fops = &operations,
};

int __init device_init(void)
{
	int ret;
	IPRINTF("");

	ret = misc_register(&miscdevice);
	if (ret) {
		EPRINTF("'%s()' failure %i", "misc_register", ret);
		goto out;
	}
	DPRINTF("miscdevice.minor=%i", miscdevice.minor);
	// Note: 'ret' is already 0 here
out:
	return ret;
}

void device_down(void)
{
	IPRINTF("");
	misc_deregister(&miscdevice);
	IPRINTF("");
}
