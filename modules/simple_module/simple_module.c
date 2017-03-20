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

const char * const text = "SIMPLE. Read calls: %zu, Write calls: %zu\n";

size_t read_count;
size_t write_count;
char *mybuf;
bool copied;
struct proc_dir_entry *proc_entry;

/* Operations for /dev/circular */
const struct file_operations circular_fops;

/* Operations for /proc/circular */
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
	size_t to_copy = strlen(mybuf);

	printk(KERN_WARNING "CIRCULAR: read f_pos is %lld\n", *f_pos);

	if (*f_pos >= to_copy) {
		return 0;
	}

	if (copy_to_user(user_buf, mybuf, to_copy)) {
		printk(KERN_WARNING "CIRCULAR: could not copy data to user\n");
		return -EFAULT;
	}
	read_count++;

	*f_pos += to_copy;
	return to_copy;
}

ssize_t circular_write(struct file *filp, const char __user *user_buf,
	size_t count, loff_t *f_pos)
{
	int written = 0;
	int to_write = count;
	printk(KERN_WARNING "CIRCULAR: write f_pos is %lld\n", *f_pos);
	
	while (to_write > 0) {
		if (*f_pos + count > MYBUF_SIZE - 1) {
			count = MYBUF_SIZE - 1 - *f_pos;
		}
		if (copy_from_user(mybuf + *f_pos, user_buf, count)) {
			printk(KERN_WARNING "CIRCULAR: could not copy data from user\n");
			return -EFAULT;
		}
		to_write -= count;
		written += count;
		*f_pos = (*f_pos + count) % MYBUF_SIZE - 1;
	}
	write_count++;
	
	return written;
}

ssize_t circular_read_proc(struct file *filp, char *user_buf,
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
			printk(KERN_WARNING "CIRCULAR: could not copy data to user\n");
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

const struct file_operations circular_fops = {
	.read = circular_read,
	.write = circular_write,
};

const struct file_operations proc_fops = {
	.read = circular_read_proc,
};

module_init(circular_init);
module_exit(circular_exit);

