#include <uapi/linux/proc.h>
#include <linux/errno.h>
#include <linux/proc_fs.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>
#include <linux/fdtable.h>
#include <linux/syscalls.h>

#include "internal.h"

static __always_inline long __must_check
__copy_to_user_rcu(void __user *to, const void *from, unsigned long n)
{
	long ret;

	ret = __copy_to_user_inatomic(to, from, n);
	if (ret || need_resched()) {
		rcu_read_unlock();
		pagefault_enable();
		if (ret)
			ret = __copy_to_user(to, from, n) ? -EFAULT : 1;
		else
			ret = 1;
		cond_resched();
		pagefault_disable();
		rcu_read_lock();
	}
	return ret;
}

static __always_inline long __must_check
__copy_to_user_tll(void __user *to, const void *from, unsigned long n)
{
	long ret;

	ret = __copy_to_user_inatomic(to, from, n);
	if (ret || need_resched()) {
		read_unlock(&tasklist_lock);
		pagefault_enable();
		if (ret)
			ret = __copy_to_user(to, from, n) ? -EFAULT : 1;
		else
			ret = 1;
		cond_resched();
		pagefault_disable();
		read_lock(&tasklist_lock);
	}
	return ret;
}

static ssize_t proc_pids(struct pid_namespace *ns, bool leaders,
			 struct pid_namespace *out_ns, pid_t start,
			 void __user *buf, size_t size)
{
	pid_t *cur = buf, *end = (pid_t *)buf + size / sizeof(pid_t);
	pid_t pid_nr = start;
	struct pid *pid;
	ssize_t ret = 0;

	pagefault_disable();
	rcu_read_lock();
	while ((pid = find_ge_pid(pid_nr + 1, ns))) {
		pid_nr = pid_nr_ns(pid, out_ns);
		if (leaders) {
			struct task_struct *task = pid_task(pid, PIDTYPE_PID);
			if (!task || !has_group_leader_pid(task))
				continue;
		}
		ret = __copy_to_user_rcu(cur++, &pid_nr, sizeof(pid_t));
		if (ret < 0 || cur == end)
			break;
	}
	rcu_read_unlock();
	pagefault_enable();

	if (ret >= 0)
		ret = (void *)cur - buf;
	return ret;
}

static size_t proc_threads(struct task_struct *leader,
			   struct pid_namespace *out_ns, pid_t start,
			   void __user *buf, size_t size)
{
	pid_t *cur = buf, *end = (pid_t *)buf + size / sizeof(pid_t);
	struct task_struct *thread = leader;
	ssize_t ret = 0;
	pid_t pid_nr;

	pagefault_disable();
	rcu_read_lock();
	if (start) {
restart:
		thread = find_task_by_pid_ns(start, out_ns);
		if (!thread || thread->group_leader != leader) {
			if ((void *)cur == buf)
				ret = -ECHILD;
			goto out_unlock;
		}
		thread = next_thread(thread);
		if (thread == leader)
			goto out_unlock;
	}
	do {
		pid_nr = task_pid_nr_ns(thread, out_ns);
		if (!pid_nr)
			continue;
		ret = __copy_to_user_rcu(cur++, &pid_nr, sizeof(pid_t));
		if (ret < 0 || cur == end)
			break;
		if (ret > 0) {
			start = pid_nr;
			goto restart;
		}
	} while ((thread = next_thread(thread)) != leader);
out_unlock:
	rcu_read_unlock();
	pagefault_enable();

	if (ret >= 0)
		ret = (void *)cur - buf;
	return ret;
}

static size_t proc_childs(struct task_struct *parent,
			  struct pid_namespace *out_ns, pid_t start,
			  void __user * buf, size_t size)
{
	pid_t *cur = buf, *end = (pid_t *)buf + size / sizeof(pid_t);
	struct task_struct *child;
	ssize_t ret = 0;
	pid_t pid_nr;

	pagefault_disable();
	read_lock(&tasklist_lock);
	if (start) {
restart:
		child = find_task_by_pid_ns(start, out_ns);
		if (!child || child->real_parent != parent) {
			if ((void *)cur == buf)
				ret = -ECHILD;
			goto out_unlock;
		}
	} else
		child = list_entry(&parent->children,
				   struct task_struct, sibling);
	list_for_each_entry_continue(child, &parent->children, sibling) {
		pid_nr = task_pid_nr_ns(child, out_ns);
		ret = __copy_to_user_tll(cur++, &pid_nr, sizeof(pid_t));
		if (ret < 0 || cur == end)
			break;
		if (ret > 0) {
			start = pid_nr;
			goto restart;
		}
	}
out_unlock:
	read_unlock(&tasklist_lock);
	pagefault_enable();

	if (ret >= 0)
		ret = (void *)cur - buf;
	return ret;
}

static size_t proc_files(struct task_struct *task, int start,
			 void __user * buf, size_t size)
{
	int *cur = buf, *end = (int *)buf + size / sizeof(pid_t);
	struct files_struct *files;
	ssize_t ret = 0;
	int fd;

	if (!ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS))
		return -EACCES;

	files = get_files_struct(task);
	if (!files)
		return 0;

	pagefault_disable();
	rcu_read_lock();
	for (fd = start; fd < files_fdtable(files)->max_fds; fd++) {
		if (!fcheck_files(files, fd))
			continue;
		ret = __copy_to_user_rcu(cur++, &fd, sizeof(int));
		if (ret < 0 || cur == end)
			break;
	}
	rcu_read_unlock();
	pagefault_enable();

	put_files_struct(files);

	if (ret >= 0)
		ret = (void *)cur - buf;
	return ret;
}

SYSCALL_DEFINE5(proc, int, op, pid_t, pid, pid_t, start,
		void __user *, buf, size_t, size)
{
	struct task_struct *task = current;
	struct pid_namespace *task_ns = current->nsproxy->pid_ns_for_children;
	struct pid_namespace *out_ns = task_ns;

	int ret;

	if (!access_ok(VERIFY_WRITE, buf, size))
		return -EFAULT;

	if (pid > 0) {
		rcu_read_lock();
		task = find_task_by_pid_ns(pid, task_ns);
		if (task)
			get_task_struct(task);
		rcu_read_unlock();
		if (!task)
			return -ESRCH;
		task_ns = task_active_pid_ns(task);
	}

	switch (op) {
	case PROC_PROCESSES:
		ret = proc_pids(task_ns, true, out_ns, start, buf, size);
		break;
	case PROC_TASKS:
		ret = proc_pids(task_ns, false, out_ns, start, buf, size);
		break;
	case PROC_THREADS:
		ret = proc_threads(task, out_ns, start, buf, size);
		break;
	case PROC_CHILDS:
		ret = proc_childs(task, out_ns, start, buf, size);
		break;
	case PROC_FILES:
		ret = proc_files(task, start, buf, size);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (pid > 0)
		put_task_struct(task);

	return ret;
}
