#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/fcntl.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

#define MYBUF_SIZE 100
#define SIMPLE_MAJOR 199

const char * const text = "SIMPLE. Read calls: %zu, Write calls: %zu\n";

size_t read_count;
size_t write_count;
char *mybuf;
bool copied;
struct proc_dir_entry *proc_entry;

/* Operations for /dev/simple */
const struct file_operations simple_fops;

/* Operations for /proc/simple */
const struct file_operations proc_fops;


static int __init simple_init(void)
{
	int result = 0;

	/* Register an entry in /proc */
	proc_entry = proc_create("simple", 0000, NULL, &proc_fops);
	if (!proc_entry) {
		printk(KERN_WARNING "Cannot create /proc/simple\n");
		goto err;
	}

	/* Register a device with the given major number */
	result = register_chrdev(SIMPLE_MAJOR, "simple", &simple_fops);
	if (result < 0) {
		printk(KERN_WARNING
			"Cannot register the /dev/simple device with major number: %d\n",
			SIMPLE_MAJOR);
		goto err;
	}

	mybuf = kmalloc(MYBUF_SIZE, GFP_KERNEL);
	if (!mybuf) {
		result = -ENOMEM;
		goto err;
	} else {
		mybuf[0] = '\0';
		result = 0;
		printk(KERN_INFO "The SIMPLE module has been inserted.\n");
	}
	return result;

err:
	if (proc_entry) {
		proc_remove(proc_entry);
	}
	unregister_chrdev(SIMPLE_MAJOR, "simple");
	kfree(mybuf);
	return result;
}

static void __exit simple_exit(void)
{
	/* Unregister the device and /proc entry */
	unregister_chrdev(SIMPLE_MAJOR, "simple");
	if (proc_entry) {
		proc_remove(proc_entry);
	}

	/* Free the buffer. No need to check for NULL - read kfree docs */
	kfree(mybuf);

	printk(KERN_INFO "The SIMPLE module has been removed\n");
}

ssize_t simple_read(struct file *filp, char __user *user_buf,
	size_t count, loff_t *f_pos)
{
	size_t to_copy = strlen(mybuf);

	printk(KERN_WARNING "SIMPLE: read f_pos is %lld\n", *f_pos);

	if (*f_pos >= to_copy) {
		return 0;
	}

	if (copy_to_user(user_buf, mybuf, to_copy)) {
		printk(KERN_WARNING "SIMPLE: could not copy data to user\n");
		return -EFAULT;
	}
	read_count++;

	*f_pos += to_copy;
	return to_copy;
}

ssize_t simple_write(struct file *filp, const char __user *user_buf,
	size_t count, loff_t *f_pos)
{
	printk(KERN_WARNING "SIMPLE: write f_pos is %lld\n", *f_pos);

	// Cannot write more than buffer size (+ '\0')
	if (*f_pos >= MYBUF_SIZE - 1) {
		return -ENOSPC;
	}
	if (*f_pos + count > MYBUF_SIZE - 1) {
		count = MYBUF_SIZE - 1 - *f_pos;
	}
	if (copy_from_user(mybuf + *f_pos, user_buf, count)) {
		printk(KERN_WARNING "SIMPLE: could not copy data from user\n");
		return -EFAULT;
	}
	mybuf[count] = '\0';
	write_count++;
	*f_pos += count;
	return count;
}

ssize_t simple_read_proc(struct file *filp, char *user_buf,
	size_t count, loff_t *f_pos)
{
	char *buf;
	size_t length;
	ssize_t retval = 0;

	buf = kmalloc(100, GFP_KERNEL);
	if (!buf) {
		retval = -ENOMEM;
		goto out;
	}

	if (!copied) {
		length = snprintf(buf, 100, text, read_count, write_count);
		if (count < length) {
			retval = -EFBIG;
			goto out;
		}

		if (copy_to_user(user_buf, buf, length)) {
			printk(KERN_WARNING "SIMPLE: could not copy data to user\n");
			retval = -EFAULT;
			goto out;
		}
		retval = count;
		copied = true;
	} else {
		retval = 0;
		copied = false;
	}

out:
	kfree(buf);
	return retval;
}

const struct file_operations simple_fops = {
	.read = simple_read,
	.write = simple_write,
};

const struct file_operations proc_fops = {
	.read = simple_read_proc,
};

module_init(simple_init);
module_exit(simple_exit);

