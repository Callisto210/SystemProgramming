#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/fcntl.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Patryk Duda");

#define MYBUF_SIZE 20
#define CIRCULAR_MAJOR 199

char *mybuf;
char *position; //To keep position between read calls
static size_t tab_size;

struct proc_dir_entry *proc_entry;
static char proc_buff[10];

const struct file_operations circular_fops;
const struct file_operations proc_fops;


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
	result = register_chrdev(CIRCULAR_MAJOR, "circular", &circular_fops);
	if (result < 0) {
		printk(KERN_WARNING
			"Cannot register the /dev/circular device with major number: %d\n",
			CIRCULAR_MAJOR);
		goto err;
	}

	mybuf = kmalloc(MYBUF_SIZE, GFP_KERNEL);
	if (!mybuf) {
		result = -ENOMEM;
		goto err;
	} else {
		int i;
		for (i = 0; i < MYBUF_SIZE; i++) {
			mybuf[i] = '\0';
		}
		result = 0;
		printk(KERN_INFO "The CIRCULAR module has been inserted.\n");
	}
	return result;

err:
	if (proc_entry) {
		proc_remove(proc_entry);
	}
	unregister_chrdev(CIRCULAR_MAJOR, "circular");
	kfree(mybuf);
	return result;
}

static void __exit circular_exit(void)
{
	/* Unregister the device and /proc entry */
	unregister_chrdev(CIRCULAR_MAJOR, "circular");
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
	size_t tab_left = tab_size - *f_pos;
	size_t to_cpy = (count > tab_left) ? tab_left : count;

	printk(KERN_WARNING "CIRCULAR: read f_pos is %lld\n", *f_pos);
	
	if( _copy_to_user(user_buf, position, to_cpy) != 0) {
		printk(KERN_WARNING "CIRCULAR: could not copy data to user\n");
		return -EPERM;
	}
		
	*f_pos += to_cpy;
	position += to_cpy;
	return to_cpy;
}

ssize_t circular_write(struct file *filp, const char __user *user_buf,
	size_t count, loff_t *f_pos)
{
	size_t tab_left = tab_size - (position - mybuf);
	size_t to_cpy = (count > tab_left) ? tab_left : count;
	printk(KERN_WARNING "CIRCULAR: write f_pos is %lld\n", *f_pos);
	
	if(tab_left <= 0) {
		position = mybuf
		return -EAGAIN;
	}

	if( _copy_from_user(position, user_buf, to_cpy) != 0) {
		printk(KERN_WARNING "CIRCULAR: could not copy data from user\n");
		return -EFAULT;
	}
		
	*f_pos += to_cpy;
	position += to_cpy;
	return to_cpy;
}

static ssize_t circular_write_proc(struct file *file, const char __user 
	*buffer, size_t length, loff_t *offset)
{
	size_t new_tab_size;
	char *tmp_tab;
	
	if(length >= 10) return -ENOSPC;
	if( _copy_from_user(proc_buff, buffer, length) != 0) return -EFAULT;
		
	sscanf(proc_buff, "%u", &new_tab_size);
	
	printk(KERN_INFO "CIRCULAR: new_tab_size %d bytes\n", new_tab_size);
	
	if((tmp_tab = krealloc(mybuf, new_tab_size, GFP_KERNEL)) == NULL) {
		printk(KERN_ALERT "CIRCULAR: can't get ram\n");
		return -ENOMEM;
	}
	
	tab_size = ksize(tmp_tab); //Niekoniecznie moglismy dostac tyle ile chcielismy
	mybuf = tmp_tab;

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

