#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/fcntl.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Patryk Duda");

#define MYBUF_SIZE 40
#define CIRCULAR_MAJOR 199

char *mybuf;
char *position; //To keep position between write calls
static size_t tab_size;
static size_t tab_fill;

struct proc_dir_entry *proc_entry;
static char proc_buff[10];

const struct file_operations circular_fops;
const struct file_operations proc_fops;

struct miscdevice device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "circular",
	.fops = &circular_fops,
	.mode = 0600,
}; 



static int __init circular_init(void)
{
	int result = 0;

	/* Register an entry in /proc */
	proc_entry = proc_create("circular", 0000, NULL, &proc_fops);
	if (!proc_entry) {
		printk(KERN_WARNING "Cannot create /proc/circular\n");
		goto err;
	}

	/* Register a device with the given major number */
	result = misc_register(&device);
	if (result < 0) {
		printk(KERN_WARNING "Cannot register the /dev/circular miscdevice");
		goto err;
	}

	mybuf = kmalloc(MYBUF_SIZE, GFP_KERNEL);
	position = mybuf;
	tab_size = MYBUF_SIZE;
	tab_fill = 0;
	if (!mybuf) {
		result = -ENOMEM;
		goto err;
	} else {
	/*	int i;
		for (i = 0; i < MYBUF_SIZE; i++) {
			mybuf[i] = '\0';
		}*/
		mybuf[0] = '\0';
		result = 0;
		printk(KERN_INFO "The CIRCULAR module has been inserted.\n");
	}
	return result;

err:
	if (proc_entry) {
		proc_remove(proc_entry);
	}
	misc_deregister(&device);
	kfree(mybuf);
	return result;
}

static void __exit circular_exit(void)
{
	/* Unregister the device and /proc entry */
	misc_deregister(&device);
	if (proc_entry) {
		proc_remove(proc_entry);
	}

	/* Free the buffer. No need to check for NULL - read kfree docs */
	kfree(mybuf);

	printk(KERN_INFO "The CIRCULAR module has been removed\n");
}

ssize_t circular_read(struct file *filp, char __user *user_buf,
	size_t count, loff_t *f_pos)
{
	size_t tab_left = tab_fill - *f_pos;
	size_t to_cpy = (count > tab_left) ? tab_left : count;

	printk(KERN_WARNING "CIRCULAR: read f_pos is %lld\n", *f_pos);
	
	if( _copy_to_user(user_buf, mybuf, to_cpy) != 0) {
		printk(KERN_WARNING "CIRCULAR: could not copy data to user\n");
		return -EFAULT;
	}
		
	*f_pos += to_cpy;
	return to_cpy;
}

ssize_t circular_write(struct file *filp, const char __user *user_buf,
	size_t count, loff_t *f_pos)
{
	size_t tab_left = (tab_size) - (position - mybuf);
	if(tab_left <= 0) {
		position = mybuf;
		tab_left = tab_size;
	}
	size_t to_cpy = (count > tab_left) ? tab_left : count;
	printk(KERN_WARNING "CIRCULAR: write position is %d\n", position - mybuf);

	if( _copy_from_user(position, user_buf, to_cpy) != 0) {
		printk(KERN_WARNING "CIRCULAR: could not copy data from user\n");
		return -EFAULT;
	}
		
	*f_pos += to_cpy;
	position += to_cpy;
	
	if (position - mybuf > tab_fill)
		tab_fill = position - mybuf;
	printk(KERN_WARNING "CIRCULAR: tab_fill is %d\n", tab_fill);
	
	return to_cpy;
}

static ssize_t circular_write_proc(struct file *file, const char __user 
	*buffer, size_t length, loff_t *offset)
{
	size_t new_tab_size;
	char *tmp_tab;
	size_t pos = position - mybuf;
	
	int i;
	for (i = 0; i< 10; i++)
		proc_buff[i] = '\0';
		
	if(length >= 10) return -ENOSPC;
	if( _copy_from_user(proc_buff, buffer, length) != 0) return -EFAULT;
		
	sscanf(proc_buff, "%u", &new_tab_size);
	
	printk(KERN_INFO "CIRCULAR: new_tab_size %d bytes\n", new_tab_size);
	
	if((tmp_tab = krealloc(mybuf, new_tab_size, GFP_KERNEL)) == NULL) {
		printk(KERN_ALERT "CIRCULAR: can't get ram\n");
		return -ENOMEM;
	}
	
	tab_size = new_tab_size;
	mybuf = tmp_tab;
	position = pos < tab_size ? mybuf + pos : mybuf;
	tab_fill = tab_fill < tab_size ? tab_fill : tab_size;
		
	mybuf[tab_fill] = '\0';

	printk(KERN_INFO "CIRCULAR: allocated %d bytes of memory\n", tab_size);

	return length;
}

const struct file_operations circular_fops = {
	.read = circular_read,
	.write = circular_write,
};

const struct file_operations proc_fops = {
	.write = circular_write_proc,
};

module_init(circular_init);
module_exit(circular_exit);

