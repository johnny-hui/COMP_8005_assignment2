import crypt
import itertools
import queue
import time
from collections import deque
import numpy as np
import threading

ZERO = 0
START_LENGTH = 1
MAX_CHAR_LENGTH = 9999
BRUTE_FORCE_ATK_MSG = "[+] [ATTACK 2]: Now launching a Brute Force Attack. Please wait..."
characters_map = ('!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '=', "'\'", '/', '.',
                  ',', '<', '>', ':', ':', '{', '}', '[', ']', '|', '"', '\'', '?', '~', '`',
                  '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f',
                  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                  'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F',
                  'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                  'W', 'X', 'Y', 'Z', ' ')


def create_char_chunk_index_list(num_of_threads: int):
    counter = ZERO
    chunk_index = []
    chunk_list = np.array_split(characters_map, num_of_threads)

    for chunk in chunk_list:
        for letter in characters_map:
            if chunk[0] == letter:
                chunk_index.append(counter)
                break
            counter += 1

    return chunk_index


def brute_force(salt, user_hash, max_attempts):
    print(BRUTE_FORCE_ATK_MSG)
    attempts = ZERO

    for length in range(START_LENGTH, MAX_CHAR_LENGTH):
        for guess in itertools.product(characters_map, repeat=length):
            attempts += 1
            password = ''.join(guess)

            if crypt.crypt(password, salt) == user_hash:
                print(f"[+] CRACK COMPLETE: Password has been found!")
                print(f"[+] Number of Attempts Made: {attempts}")
                return password, attempts

            if attempts == max_attempts:
                print(f"[+] CRACK FAILED: Max attempts of {max_attempts} has been reached!")
                password = None
                return password, attempts

            # print(f"[+] Attempt {attempts}: {password}")


# HYPOTHESIS: Heavily Compute-Bound Functions in Multi-threading will result in decrease performance
# Threads operate in parallel; this - the CPU has to maintain the original workload for each thread.
def brute_force_multithread(salt, user_hash, max_attempts, thread_id: int, index_start: int, bf_pw_deque: deque,
                            bf_total_time_q: queue.Queue, bf_total_attempt_q: queue.Queue, bf_pw_lock: threading.Lock,
                            bf_time_lock: threading.Lock, bf_attempt_lock: threading.Lock):
    # Print to specify which starting index
    print(f"[+] [Thread {thread_id}] - Starting guess at the following character: {characters_map[index_start]}")

    # Start Timer
    s_time = time.process_time()
    attempts = ZERO

    for length in range(START_LENGTH, MAX_CHAR_LENGTH):
        for guess in itertools.product(characters_map[index_start:], repeat=length):
            attempts += 1

            # SIGNAL - Check if password is found
            if len(bf_pw_deque) is not ZERO:
                for pw in bf_pw_deque:
                    if pw is not None:
                        total_time = (time.process_time() - s_time)
                        _put_in_queue(attempts, bf_attempt_lock, bf_total_attempt_q)
                        _put_in_queue(total_time, bf_time_lock, bf_total_time_q)
                        print(f"[+] [Thread {thread_id}] Number of Attempts Made: {attempts}")
                        print(f"[+] [Thread {thread_id}] Time: {total_time} seconds")
                        print(f"[+] [Thread {thread_id}] - PW FOUND: Now Terminating...")
                        return None

            password = ''.join(guess)

            if crypt.crypt(password, salt) == user_hash:
                total_time = (time.process_time() - s_time)

                print(f"[+] [PW Thread {thread_id}] CRACK COMPLETE: Password has been found!")
                print(f"[+] [PW Thread {thread_id}] Number of Attempts Made: {attempts}")
                print(f"[+] [PW Thread {thread_id}] Time: {total_time} seconds")

                _put_in_queue(attempts, bf_attempt_lock, bf_total_attempt_q)
                _put_in_queue(total_time, bf_time_lock, bf_total_time_q)
                _put_in_deque(password, bf_pw_lock, bf_pw_deque)

                return password, attempts

            if attempts == max_attempts:
                total_time = (time.process_time() - s_time)

                print(f"[+] [Thread {thread_id}] CRACK FAILED: Max attempts of {max_attempts} has been reached!")
                print(f"[+] [Thread {thread_id}] Time: {total_time} seconds")

                password = None

                _put_in_queue(attempts, bf_attempt_lock, bf_total_attempt_q)
                _put_in_queue(total_time, bf_time_lock, bf_total_time_q)
                _put_in_deque(password, bf_pw_lock, bf_pw_deque)

                return password, attempts

            # print(f"[+] [Thread {thread_id}] Attempt {attempts}: {password}")

    # If no password was found within range(given index -> end)
    total_time = (time.process_time() - s_time)
    password = None
    _put_in_queue(attempts, bf_attempt_lock, bf_total_attempt_q)
    _put_in_queue(total_time, bf_time_lock, bf_total_time_q)
    _put_in_deque(password, bf_pw_lock, bf_pw_deque)


def _put_in_deque(x, lock, some_deque: deque):
    lock.acquire()
    some_deque.append(x)
    lock.release()


def _put_in_queue(x, lock, some_queue):
    lock.acquire()
    some_queue.put(x)
    lock.release()

# SOURCE USED: https://stackoverflow.com/questions/40269605/how-to-create-a-brute-force-password-cracker-for-alphabetical-and-alphanumerical
