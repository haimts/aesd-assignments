#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>

/////////
// DEFINE
/////////
#define D_MSEC_TO_USEC 1000

/////////
// MACROS
/////////
// Optional: use these functions to add debug or error prints to your application
#if !defined(DEBUG)
#define DEBUG_LOG(msg,...)
#define ERROR_LOG(msg,...)
#else
#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)
#endif

void*
threadfunc(void *thread_param) {
	DEBUG_LOG ("in thread %lx", pthread_self ());
	// TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
	// hint: use a cast like the one below to obtain thread arguments from your parameter
	//struct thread_data* thread_func_args = (struct thread_data *) thread_param;
	struct thread_data *thr_data = (struct thread_data*) thread_param;
	if (thread_param == NULL) {
		ERROR_LOG ("pthread param not setisfy!\n");
		thr_data->thread_complete_success = false;
	} else {
		usleep(thr_data->wait_to_obtain_ms * D_MSEC_TO_USEC);
		if (pthread_mutex_lock(thr_data->mutex) != 0) {
			ERROR_LOG ("pthread mutex lock fail!\n");
			thr_data->thread_complete_success = false;
		}
		usleep(thr_data->wait_to_release_ms * D_MSEC_TO_USEC);
		if (pthread_mutex_unlock(thr_data->mutex) != 0) {
			ERROR_LOG ("pthread mutex unlock fail!\n");
			thr_data->thread_complete_success = false;
		} else {
			thr_data->thread_complete_success = true;
		}
	}

	return thread_param;
}

bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,
		int wait_to_obtain_ms, int wait_to_release_ms) {
	/**
	 * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
	 * using threadfunc() as entry point.
	 *
	 * return true if successful.
	 *
	 * See implementation details in threading.h file comment block
	 */
	struct thread_data *thr_data /*, *ret_data */;

	int s;
	bool retVal = true;

	assert(thread != NULL);
	assert(mutex != NULL);

	thr_data = (void*) malloc(sizeof(struct thread_data));
	thr_data->mutex = mutex;
	thr_data->wait_to_obtain_ms = wait_to_obtain_ms;
	thr_data->wait_to_release_ms = wait_to_release_ms;
	s = pthread_create(thread, NULL, &threadfunc, (void*) thr_data);
	if (s != 0) {
		ERROR_LOG ("pthread_create, %d", s);
	} DEBUG_LOG ("New thread tid: %0lx,%0lx", *(uint64_t *) thread,
			(uint64_t) thr_data->mutex);

	return retVal;
}

