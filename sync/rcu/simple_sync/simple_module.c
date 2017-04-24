#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/uaccess.h>
#include <linux/delay.h>

MODULE_LICENSE("GPL");

const struct file_operations simple_fops;

const int simple_major = 198;

const char msg_str[] = "-0123456789-ABCDEFGHIJ-";
const int msg_len = sizeof(msg_str);
int msg_pos;

static int __init simple_init(void)
{
	int result;

	result = register_chrdev(simple_major, "simple", &simple_fops);
	if (result < 0) {
		printk(KERN_ERR "SIMPLE: cannot register the /dev/simple\n");
		return result;
	}

	printk(KERN_INFO "SIMPLE: module has been inserted.\n");
	return 0;
}

static void __exit simple_exit(void)
{
	unregister_chrdev(simple_major, "simple");

	printk(KERN_INFO "SIMPLE: module has been removed\n");
}

ssize_t simple_read(struct file *filp, char __user *user_buf,
	size_t count, loff_t *f_pos) {
	char *local_buf;
	int length_to_copy;
	int i;
	int err;

	// 1. Prepare the text to send

	// Calculate the length
	length_to_copy = msg_len - (msg_pos % msg_len);
	if (length_to_copy > count)
		length_to_copy = count;

	local_buf = kmalloc(length_to_copy, GFP_KERNEL);
	if (!local_buf) {
		err = -ENOMEM;
		goto cleanup;
	}

	for (i = 0; i < length_to_copy; i++) {
		local_buf[i] = msg_str[(msg_pos++) % msg_len];
		msleep(100);
	}

	// 2. Send the text
	err = copy_to_user(user_buf, local_buf, length_to_copy);
	if (err < 0)
		goto cleanup;

	err = length_to_copy;

cleanup:
	kfree(local_buf);
	return err;
}

const struct file_operations simple_fops = {
	.read = simple_read,
};

module_init(simple_init);
module_exit(simple_exit);

