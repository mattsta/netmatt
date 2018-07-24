#include <linux/fdtable.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/sched/signal.h>
#include <linux/seq_file.h>

/* Works with a 2018-era 4.15.0 kernel. ymmv going back in time. */

static const char *procFilename = "pid_inode_map";

static void iterate_inodes(struct seq_file *m, struct task_struct *task) {
    struct files_struct *files;
    struct fdtable *fdt;
    uint32_t i;

    seq_printf(m, "%d %s ", task->pid, task->comm);

    files = task->files;
    if (!files) {
        return;
    }

    rcu_read_lock();
    fdt = files_fdtable(files);

    for (i = 0; i < fdt->max_fds; i++) {
        const struct file *file;

        file = fdt->fd[i];
        if (file) {
            seq_printf(m, "%zu ", file->f_inode->i_ino);
        }
    }

    rcu_read_unlock();
    seq_printf(m, "\n");
}

static int generate_mapping(struct seq_file *m, void *data) {
    struct task_struct *task;

    for_each_process(task) {
        iterate_inodes(m, task);
    }

    return 0;
}

static int pid_inode_map_open(struct inode *inode, struct file *file) {
    return single_open(file, generate_mapping, NULL);
}

static const struct file_operations ops = {.owner = THIS_MODULE,
                                           .open = pid_inode_map_open,
                                           .read = seq_read,
                                           .llseek = seq_lseek,
                                           .release = single_release};

int __init pid_inode_map_init(void) {
    proc_create(procFilename, 0, NULL, &ops);
    return 0;
}

void __exit pid_inode_map_exit(void) {
    remove_proc_entry(procFilename, NULL);
}

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Matt Stancliff <matt@genges.com>");
MODULE_DESCRIPTION(
    "Creates /proc/pid_inode_map showing all inodes a pid has open.");
module_init(pid_inode_map_init);
module_exit(pid_inode_map_exit);
