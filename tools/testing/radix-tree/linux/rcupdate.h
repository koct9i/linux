#ifndef _RCUPDATE_H
#define _RCUPDATE_H

#include <urcu.h>

/* urcu.h includes errno.h which undefines ERANGE */
#ifndef ERANGE
#define ERANGE 34
#endif

#define RCU_INIT_POINTER(p, v) rcu_assign_pointer(p, v)
#define rcu_dereference_raw(p) rcu_dereference(p)
#define rcu_dereference_protected(p, cond) rcu_dereference(p)

#endif
