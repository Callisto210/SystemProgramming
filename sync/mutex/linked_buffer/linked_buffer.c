#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/fcntl.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/seq_file.h>
#include <linux/delay.h>

MODULE_LICENSE("GPL");

#define LINKED_MAJOR 199
#define INTERNAL_SIZE 4

DEFINE_MUTEX(my_mutex);

const char * const proc_info = "reads: %zu\nwrites: %zu\ntotal length: %zu\n";

size_t read_count;
size_t write_count;
struct proc_dir_entry *proc_entry;

/* Operations for /dev/linked */
const struct file_operations linked_fops;

/* Operations for /proc/linked */
const struct file_operations proc_fops;

struct data {
	size_t length;
	char contents[INTERNAL_SIZE];
	struct list_head list;
};

LIST_HEAD(buffer);
size_t total_length;

static int __init linked_init(void)
{
	int result = 0;

	proc_entry = proc_create("linked", 0444, NULL, &proc_fops);
	if (!proc_entry) {
		printk(KERN_WARNING "Cannot create /proc/linked\n");
		goto err;
	}

	result = register_chrdev(LINKED_MAJOR, "linked", &linked_fops);
	if (result < 0) {
		printk(KERN_WARNING "Cannot register the /dev/linked\n");
		goto err;
	}

	printk(KERN_INFO "The linked module has been inserted.\n");
	return result;

err:
	if (proc_entry)
		proc_remove(proc_entry);

	unregister_chrdev(LINKED_MAJOR, "linked");
	return result;
}

static void clean_list(void)
{
	struct list_head *cur;
	struct list_head *tmp;
	struct data *data;

	list_for_each_safe(cur, tmp, &buffer) {
		data = list_entry(cur, struct data, list);
		printk(KERN_DEBUG "linked: clearing <%*pE>\n",
			INTERNAL_SIZE, data->contents);

		list_del(&(data->list));
		kfree(data);
	}
	total_length = 0;
}

static void __exit linked_exit(void)
{
	unregister_chrdev(LINKED_MAJOR, "linked");
	if (proc_entry)
		proc_remove(proc_entry);

	clean_list();

	printk(KERN_INFO "The linked module has been removed\n");
}

ssize_t linked_read(struct file *filp, char __user *user_buf,
	size_t count, loff_t *f_pos)
{
	struct data *data;
	size_t pos = 0;
	size_t copied = 0;
	size_t real_length = 0;

	printk(KERN_WARNING "linked: read, count=%zu f_pos=%lld\n",
		count, *f_pos);

	if (*f_pos > total_length)
		return 0;

	if (list_empty(&buffer))
		printk(KERN_DEBUG "linked: empty list\n");

	list_for_each_entry(data, &buffer, list) {
		size_t to_copy = min(data->length, count - copied);

		printk(KERN_DEBUG "linked: elem=[%zd]<%*pE>\n",
			data->length, INTERNAL_SIZE, data->contents);

		if (pos < *f_pos) {
			// Skip until we do match the entry
			pos += data->length;
			continue;
		}

		// We are in the correct entry

		if (copy_to_user(user_buf + copied, data->contents, to_copy)) {
			printk(KERN_WARNING "linked: could not copy data to user\n");
			return -EFAULT;
		}
		copied += to_copy;
		pos += to_copy;
		real_length += data->length;
		// We are over the buffer
		if (copied >= count)
			break;
	}
	printk(KERN_WARNING "linked: copied=%zd real_length=%zd\n",
		copied, real_length);
	*f_pos += real_length;
	read_count++;
	return copied;
}

ssize_t linked_write(struct file *filp, const char __user *user_buf,
	size_t count, loff_t *f_pos)
{
	struct data *data;
	ssize_t result = 0;
	size_t i = 0;

	mutex_lock(&my_mutex);

	printk(KERN_WARNING "linked: write, count=%zu f_pos=%lld\n",
		count, *f_pos);

	for (i = 0; i < count; i += INTERNAL_SIZE) {
		size_t to_copy = min((size_t) INTERNAL_SIZE, count - i);

		data = kzalloc(sizeof(struct data), GFP_KERNEL);
		if (!data) {
			result = -ENOMEM;
			goto err_data;
		}
		data->length = to_copy;

		if (copy_from_user(data->contents, user_buf + i, to_copy)) {
			result = -EFAULT;
			goto err_contents;
		}
		if (strncmp(data->contents, "xxx&", 4) == 0) {
			clean_list();
			result = count;
			goto err_contents;
		}
		list_add_tail(&(data->list), &buffer);
		total_length += to_copy;
		*f_pos += to_copy;
		mdelay(10);
	}

	write_count++;
	mutex_unlock(&my_mutex);
	return count;

err_contents:
	kfree(data);
err_data:
	mutex_unlock(&my_mutex);
	return result;
}

int linked_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, proc_info,
		read_count, write_count, total_length);
	return 0;
}

int linked_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, linked_proc_show, NULL);
}

const struct file_operations linked_fops = {
	.read = linked_read,
	.write = linked_write,
};

const struct file_operations proc_fops = {
	.open		= linked_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

module_init(linked_init);
module_exit(linked_exit);

