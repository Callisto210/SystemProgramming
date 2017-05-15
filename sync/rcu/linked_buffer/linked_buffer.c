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
#include <linux/rcupdate.h>
#include <linux/rculist.h>

MODULE_LICENSE("GPL");

spinlock_t some_lock;

#define LINKED_MAJOR 199
#define INTERNAL_SIZE 4

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
	struct data *data;

	list_for_each_entry_rcu(data, &buffer, list) {
		printk(KERN_DEBUG "linked: clearing <%*pE>\n",
			INTERNAL_SIZE, data->contents);

		list_del_rcu(&(data->list));
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
	size_t j = 0;
	
	char *tmp_buf = kmalloc(count, GFP_KERNEL);
	if (!tmp_buf) {
			return -ENOMEM;
	}

	printk(KERN_WARNING "linked: read, count=%zu f_pos=%lld\n",
		count, *f_pos);

	if (*f_pos > total_length) {
		kfree(tmp_buf);
		return 0;
	}

	if (list_empty(&buffer))
		printk(KERN_DEBUG "linked: empty list\n");

	rcu_read_lock();
	
	list_for_each_entry_rcu(data, &buffer, list) {
		size_t to_copy = min(data->length, count - copied);

		printk(KERN_DEBUG "linked: elem=[%zd]<%*pE>\n",
			data->length, INTERNAL_SIZE, data->contents);

		if (pos < *f_pos) {
			// Skip until we do match the entry
			pos += data->length;
			continue;
		}

		// We are in the correct entry
		for (j = 0; j < to_copy; j++) {
			tmp_buf[copied+j] = data->contents[j];
		}

		copied += to_copy;
		pos += to_copy;
		real_length += data->length;
		// We are over the buffer
		if (copied >= count)
			break;
	}
	rcu_read_unlock();
	
	if (copy_to_user(user_buf, tmp_buf, copied)) {
			printk(KERN_WARNING "linked: could not copy data to user\n");
			kfree(tmp_buf);
			return -EFAULT;
	}
	
	printk(KERN_WARNING "linked: copied=%zd real_length=%zd\n",
		copied, real_length);
	*f_pos += real_length;
	read_count++;
	kfree(tmp_buf);
	return copied;
}

ssize_t linked_write(struct file *filp, const char __user *user_buf,
	size_t count, loff_t *f_pos)
{
	struct data *data;
	ssize_t result = 0;
	size_t i = 0;
	size_t j = 0;
	char *tmp_buf = kmalloc(count, GFP_KERNEL);
	if (!tmp_buf) {
			result = -ENOMEM;
			goto err_data;
	}
	
	if (copy_from_user(tmp_buf, user_buf, count)) {
			result = -EFAULT;
			goto err_tmp;
		}

	printk(KERN_WARNING "linked: write, count=%zu f_pos=%lld\n",
		count, *f_pos);

	spin_lock(&some_lock);
	
	for (i = 0; i < count; i += INTERNAL_SIZE) {
		size_t to_copy = min((size_t) INTERNAL_SIZE, count - i);

		data = kzalloc(sizeof(struct data), GFP_ATOMIC);
		if (!data) {
			result = -ENOMEM;
			spin_unlock(&some_lock);
			goto err_tmp;
		}
		data->length = to_copy;
		
		for (j = 0; j < to_copy; j++) {
			data->contents[j] = tmp_buf[i+j];
		}
		
		if (strncmp(data->contents, "xxx&", 4) == 0) {
			clean_list();
			result = count;
			spin_unlock(&some_lock);
			goto err_contents;
		}
		list_add_tail_rcu(&(data->list), &buffer);
		total_length += to_copy;
		*f_pos += to_copy;
		
		mdelay(10);
	}
	
	spin_unlock(&some_lock);
	synchronize_rcu();
	
	write_count++;
	return count;
	
err_contents:
	kfree(data);
err_tmp:
	kfree(tmp_buf);
err_data:
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

