#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/fcntl.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>

//For prname
#include <linux/pid.h>
#include <linux/pid_namespace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Patryk Duda");
MODULE_DESCRIPTION("Advanced Module");

const struct file_operations advanced_fops[];
struct miscdevice device[];

static int __init advanced_init(void)
{
	
	int result, i;
	for (i = 0; i < 3; i++)
		if ((result = misc_register(&device[i])) < 0) {
			printk(KERN_WARNING "Cannot register the /dev/%s miscdevice", device[i].name);
			goto err;
		}
		
		
	
	
	err:
		for (i = 0; i < 3; i++)
			misc_deregister(&device[i]);
		return result;
}

static void __init advanced_exit(void)
{
	int i;
	for (i = 0; i < 3; i++)
			misc_deregister(&device[i]);
			
	printk(KERN_INFO "The ADVANCED module has been removed\n");
	return;
}

pid_t current_process = -1;
char process_name[TASK_COMM_LEN];


ssize_t prname_read(struct file *filp, char __user *user_buf,
	size_t count, loff_t *f_pos)
{
	size_t str_length = strlen(process_name) - *f_pos;
	size_t to_cpy = (count > str_length) ? str_length : count;
	
	if (current_process == -1)
		return -ENODATA;
		
	if( _copy_to_user(user_buf, process_name + *f_pos, to_cpy) != 0) {
		return -EFAULT;
	}
	
	*f_pos += to_cpy;
	return to_cpy;
	
}

ssize_t prname_write(struct file *filp, const char __user *user_buf,
	size_t count, loff_t *f_pos)
{
	int i;
	char prname_buffer[6];
	struct task_struct* process;
		
	for (i = 0; i< 6; i++)
		prname_buffer[i] = '\0';
		
	if(count >= 6) return -ENOSPC;
	if( _copy_from_user(prname_buffer, user_buf, count) != 0)
		return -EFAULT;
		
	sscanf(prname_buffer, "%u", &current_process);
	
	if ((process = get_pid_task(find_get_pid(current_process), PIDTYPE_PID)) == NULL) {
		return -ESRCH;
	}
	else {
		get_task_comm(process_name, process);
	}
	
	return count;
		
}

ssize_t jiffies_read(struct file *filp, char __user *user_buf,
	size_t count, loff_t *f_pos)
{
}
	
ssize_t mountderef_read(struct file *filp, char __user *user_buf,
	size_t count, loff_t *f_pos)
{
}
	
ssize_t mountderef_write(struct file *filp, const char __user *user_buf,
	size_t count, loff_t *f_pos)
{
}

module_init(advanced_init);
module_exit(advanced_exit);

const struct file_operations advanced_fops[] = { 
	{
	.read = prname_read,
	.write = prname_write,
	},
	{
	.read = jiffies_read,
	},
	{
	.read = mountderef_read,
	.write = mountderef_write,
	}
};

struct miscdevice device[] = {
	{
	.minor = MISC_DYNAMIC_MINOR,
	.name = "prname",
	.fops = &advanced_fops[0],
	.mode = 0600,
	},
	{
	.minor = MISC_DYNAMIC_MINOR,
	.name = "jiffies",
	.fops = &advanced_fops[1],
	.mode = 0600,
	},
	{
	.minor = MISC_DYNAMIC_MINOR,
	.name = "mountderef",
	.fops = &advanced_fops[2],
	.mode = 0600,
	}
};

