#include <assert.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <unistd.h>
#include <x86gprintrin.h>

#include "common/common.h"

#ifndef __NR_uintr_register_handler
#define __NR_uintr_register_handler	449
#define __NR_uintr_unregister_handler	450
#define __NR_uintr_create_fd		451
#define __NR_uintr_register_sender	452
#define __NR_uintr_unregister_sender	453
#define __NR_uintr_wait			454
#endif

#define uintr_register_handler(handler, flags)	syscall(__NR_uintr_register_handler, handler, flags)
#define uintr_unregister_handler(flags)		syscall(__NR_uintr_unregister_handler, flags)
#define uintr_create_fd(vector, flags)		syscall(__NR_uintr_create_fd, vector, flags)
#define uintr_register_sender(fd, flags)	syscall(__NR_uintr_register_sender, fd, flags)
#define uintr_unregister_sender(fd, flags)	syscall(__NR_uintr_unregister_sender, fd, flags)
#define uintr_wait(flags)			syscall(__NR_uintr_wait, flags)

#define SERVER_TOKEN 0
#define CLIENT_TOKEN 1

volatile unsigned long uintr_received[2];
int uintrfd_client;
int uintrfd_server;
int uipi_index[2];

void __attribute__ ((interrupt))
     __attribute__((target("general-regs-only", "inline-all-stringops")))
     ui_handler(struct __uintr_frame *ui_frame,
		unsigned long long vector) {

		// The vector number is same as the token
		uintr_received[vector] = 1;
}

void cleanup(char* shared_memory) {
	// Detach the shared memory from this process' address space.
	// If this is the last process using this shared memory, it is removed.
	shmdt(shared_memory);
}

void shm_wait(atomic_char* guard) {
	while (atomic_load(guard) != 'c')
		;
}

void shm_notify(atomic_char* guard) {
	atomic_store(guard, 's');
}

int setup_handler_with_vector(int vector) {
	int fd;

	if (uintr_register_handler(ui_handler, 0))
		throw("Interrupt handler register error\n");

	// Create a new uintrfd object and get the corresponding
	// file descriptor.
	fd = uintr_create_fd(vector, 0);

	if (fd < 0)
		throw("Interrupt vector registration error\n");

	return fd;
}

void setup_client(char* shared_memory, atomic_char* guard) {

	uintrfd_client = setup_handler_with_vector(CLIENT_TOKEN);

	//  Read uintrfd_server
	shm_wait(guard);
	uintrfd_server = ((u_int32_t *)(shared_memory + 1))[0];
	//  Write back uintrfd_client
	((u_int32_t *)(shared_memory + 1))[0] = uintrfd_client;
	shm_notify(guard);

	uipi_index[SERVER_TOKEN] = uintr_register_sender(uintrfd_server, 0);
	if (uipi_index[SERVER_TOKEN] < 0)
		throw("Sender register error\n");

	// Enable interrupts
	_stui();
}

void destroy_client() {
	close(uintrfd_client);
	uintr_unregister_handler(0);
}

void uintrfd_wait(unsigned int token) {

	// Keep spinning until the interrupt is received
	while (!uintr_received[token]);

	uintr_received[token] = 0;
}

void uintrfd_notify(unsigned int token) {
	_senduipi(uipi_index[token]);
}

void communicate(char* shared_memory, struct Arguments* args) {
	// Buffer into which to read data
	void* buffer = malloc(args->size);

	atomic_char* guard = (atomic_char*)shared_memory;
	atomic_init(guard, 's');
	assert(sizeof(atomic_char) == 1);

	setup_client(shared_memory, guard);

	for (; args->count > 0; --args->count) {
		//shm_wait(guard);
		uintrfd_wait(CLIENT_TOKEN);
		// Read
		memcpy(buffer, shared_memory + 1, args->size);

		// Write back
		memset(shared_memory + 1, '*', args->size);

		//shm_notify(guard);
		uintrfd_notify(SERVER_TOKEN);
	}

	free(buffer);

	destroy_client();

}

int main(int argc, char* argv[]) {
	// The identifier for the shared memory segment
	int segment_id;

	// The *actual* shared memory, that this and other
	// processes can read and write to as if it were
	// any other plain old memory
	char* shared_memory;

	// Key for the memory segment
	key_t segment_key;

	// Fetch command-line arguments
	struct Arguments args;

	parse_arguments(&args, argc, argv);

	segment_key = generate_key("uintr-shm");

	/*
		The call that actually allocates the shared memory segment.
		Arguments:
			1. The shared memory key. This must be unique across the OS.
			2. The number of bytes to allocate. This will be rounded up to the OS'
				 pages size for alignment purposes.
			3. The creation flags and permission bits, we pass IPC_CREAT to ensure
				 that the segment will be created if it does not yet exist. Using
				 0666 for permission flags means read + write permission for the user,
				 group and world.
		The call will return the segment ID if the key was valid,
		else the call fails.
	*/
	segment_id = shmget(segment_key, 1 + args.size, IPC_CREAT | 0666);

	if (segment_id < 0) {
		throw("Could not get segment");
	}

	/*
	Once the shared memory segment has been created, it must be
	attached to the address space of each process that wishes to
	use it. For this, we pass:
		1. The segment ID returned by shmget
		2. A pointer at which to attach the shared memory segment. This
			 address must be page-aligned. If you simply pass NULL, the OS
			 will find a suitable region to attach the segment.
		3. Flags, such as:
			 - SHM_RND: round the second argument (the address at which to
				 attach) down to a multiple of the page size. If you don't
				 pass this flag but specify a non-null address as second argument
				 you must ensure page-alignment yourself.
			 - SHM_RDONLY: attach for reading only (independent of access bits)
	shmat will return a pointer to the address space at which it attached the
	shared memory. Children processes created with fork() inherit this segment.
*/
	shared_memory = (char*)shmat(segment_id, NULL, 0);

	if (shared_memory < (char*)0) {
		throw("Could not attach segment");
	}

	communicate(shared_memory, &args);

	cleanup(shared_memory);

	return EXIT_SUCCESS;
}
