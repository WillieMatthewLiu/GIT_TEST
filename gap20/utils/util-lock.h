#include <pthread.h>

static inline int mutex_init(pthread_mutex_t *lock)
{
	return pthread_mutex_init(lock, NULL);
}

static inline void mutex_destory(pthread_mutex_t *lock)
{
	//pthread_mutex_destory(lock);
}

static inline int mutex_lock(pthread_mutex_t *lock)
{
	return pthread_mutex_lock(lock);
}

static inline int mutex_unlock(pthread_mutex_t *lock)
{
	return pthread_mutex_unlock(lock);
}

static inline int spin_init(pthread_spinlock_t *lock)
{
	return pthread_spin_init(lock, 0);
}

static inline void spin_destory(pthread_spinlock_t *lock)
{
	//pthread_spin_destory(lock);
}

static inline int spin_lock(pthread_spinlock_t *lock)
{
	return pthread_spin_lock(lock);
}

static inline int spin_unlock(pthread_spinlock_t *lock)
{
	return pthread_spin_unlock(lock);
}

static inline int spin_rw_init(pthread_rwlock_t *lock)
{
	return pthread_rwlock_init(lock, 0);
}

static inline void spin_rw_destory(pthread_rwlock_t *lock)
{
	pthread_rwlock_destroy(lock);
}

static inline int spin_w_lock(pthread_rwlock_t *lock)
{
	return pthread_rwlock_wrlock(lock);
}

static inline int spin_w_unlock(pthread_rwlock_t *lock)
{
	return pthread_rwlock_unlock(lock);
}

static inline int spin_r_lock(pthread_rwlock_t *lock)
{
	return pthread_rwlock_rdlock(lock);
}

static inline int spin_r_unlock(pthread_rwlock_t *lock)
{
	return pthread_rwlock_unlock(lock);
}

