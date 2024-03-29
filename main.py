import signal
from multiprocessing import Process
import Algorithms
import cpuinfo
import constants
from constants import WELCOME_MSG, WELCOME_DECORATION, DICTIONARY_ATK_MSG, ZERO, TWO, BACK_TO_START, \
    BRUTE_FORCE_LAUNCH, PROGRAM_TERMINATE_MSG_1, PROGRAM_TERMINATE_MSG_2
from Cracker import *
import crypt
import getopt
import multiprocessing
import os
import sys
import time
import threading


def _algorithm_not_found():
    print("[+] ALGORITHM_NOT_FOUND_ERROR: This algorithm type is not supported!")
    print("[+] Now checking for next user...")


def _calculate_dictionary_thread_time(s_time, thread_id, total_thread_time_lck):
    global dictionary_total_thread_time
    total_time = (time.process_time() - s_time)
    total_thread_time_lck.acquire()
    dictionary_total_thread_time += total_time
    total_thread_time_lck.release()
    print(f"[+] [Thread {thread_id}] Time: {total_time} seconds")


def _calculate_pw_dictionary_thread_time(s_time, thread_id, total_thread_time_lck):
    global dictionary_total_thread_time
    total_time = (time.process_time() - s_time)
    total_thread_time_lck.acquire()
    dictionary_total_thread_time += total_time
    total_thread_time_lck.release()
    print(f"[+] [PW Thread {thread_id}] Time: {total_time} seconds")


def _check_args(opts):
    if len(opts) == ZERO:
        sys.exit("[+] NO_ARG_ERROR: No arguments were passed in!")


def _check_if_files_exists(file_dir, pw_list_dir):
    try:
        if not os.path.exists(file_dir):
            sys.exit(f"[+] ERROR: {file_dir} Doesn't Exist or Invalid Argument!")
        elif not os.path.exists(pw_list_dir) or pw_list_dir == "":
            print(f"[+] ERROR: Password File Doesn't Exist or Invalid Argument!")
        else:
            print(f"[+] Now reading the {file_dir} file...")
    except FileNotFoundError:
        sys.exit("[+] ERROR: File Doesn't Exist!")


def check_if_root_user():
    if not os.geteuid() == 0:
        sys.exit("[+] ERROR: Only the 'root' user can run this script "
                 "[Please run this script again using sudo command].")


def _check_user_parameters(user_list):
    if len(user_list) == ZERO:
        sys.exit("[+] No users were passed in as arguments!")


def _check_valid_user(file_entry, user_name, user_list):
    if '$' not in file_entry and len(user_list) >= TWO:
        print(f"[+] INVALID USER: {user_name} is a service, utility, or process and cannot be cracked!")
        print("[+] Now moving on to the next user...")
        return False
    elif '$' not in file_entry and len(user_list) < TWO:
        print(f"[+] INVALID USER: {user_name} is a service, utility, or process and cannot be cracked!")
        return False
    else:
        return True


def dictionary_attack(input_hash, input_salt, max_attempt, pw_deque: multiprocessing.Queue,
                      list_lock: threading.Lock, attempt_lock: threading.Lock,
                      pw_stop_q: multiprocessing.Queue, thread_id: int):
    # Start Local timer
    s_time = time.process_time()

    # Initialize variables
    global total_attempts, \
        dictionary_thread_total_attempts,\
        dictionary_total_thread_time, \
        total_thread_time_lck
    attempt = ZERO
    thread_id += 1

    # If no max number of attempts set in command args (-a)
    if max_attempt == ZERO:
        while pw_deque.qsize() is not ZERO:
            list_lock.acquire()
            pw = str(pw_deque.get()).strip()
            list_lock.release()

            if crypt.crypt(pw, input_salt) == input_hash:
                # Calculate Time
                _calculate_pw_dictionary_thread_time(s_time, thread_id, total_thread_time_lck)

                print(f"[+] [PW Thread {thread_id}] CRACK COMPLETE: Password has been found!")
                print(f"[+] [PW Thread {thread_id}] Number of Attempts Made: {attempt}")

                # Erase all pw in deque to stop all concurrent threads
                list_lock.acquire()
                pw_deque.empty()
                list_lock.release()

                # Put password in stop_queue
                pw_lck.acquire()
                pw_stop_q.put(pw)
                pw_lck.release()

                # Update total attempts global
                attempt_lock.acquire()
                dictionary_thread_total_attempts += attempt
                total_attempts += attempt
                attempt_lock.release()

                return pw
            else:
                attempt += 1

        # If no password is found in dictionary
        attempt_lock.acquire()
        dictionary_thread_total_attempts += attempt
        total_attempts += attempt
        attempt_lock.release()

        _calculate_dictionary_thread_time(s_time, thread_id, total_thread_time_lck)

        if pw_stop_q.empty():
            pw_stop_q.put(None)
            return
    else:
        while pw_deque.qsize() is not ZERO:
            list_lock.acquire()
            pw = str(pw_deque.get()).strip()
            list_lock.release()

            if crypt.crypt(pw, input_salt) == input_hash:
                # Calculate Time
                _calculate_pw_dictionary_thread_time(s_time, thread_id, total_thread_time_lck)

                print(f"[+] [PW Thread {thread_id}] CRACK COMPLETE: Password has been found!")
                print(f"[+] [PW Thread {thread_id}] Number of Attempts Made: {attempt}")

                # Erase all pw in deque to stop all concurrent threads
                list_lock.acquire()
                pw_deque.empty()
                list_lock.release()

                # Put password in stop_queue
                pw_lck.acquire()
                pw_stop_q.put(pw)
                pw_lck.release()

                # Update total attempts global
                attempt_lock.acquire()
                dictionary_thread_total_attempts += attempt
                total_attempts += attempt
                attempt_lock.release()

                return pw
            elif attempt == max_attempt:
                _calculate_dictionary_thread_time(s_time, thread_id, total_thread_time_lck)

                print(f"[+] [Thread {thread_id}] CRACK FAILED: Max attempts of {attempt} has been reached!")

                attempt_lock.acquire()
                dictionary_thread_total_attempts += attempt
                total_attempts += attempt
                attempt_lock.release()

                pw_stop_q.put(None)
                return
            else:
                attempt += 1

        # If no password is found in dictionary
        attempt_lock.acquire()
        dictionary_thread_total_attempts += attempt
        total_attempts += attempt
        attempt_lock.release()

        _calculate_dictionary_thread_time(s_time, thread_id, total_thread_time_lck)

        if pw_stop_q.empty():
            pw_stop_q.put(None)
            return


def dictionary_atk_results_check(process_list: list[multiprocessing.Process]):
    global password, num_of_threads, pw_queue

    while pw_queue.qsize() != num_of_threads:
        break

    while True:
        item = pw_queue.get()
        if item is not None:
            for process in process_list:
                time.sleep(1)
                process.join()
            password = item
            break


def _ioerror_handler(file_directory):
    if file_directory == "":
        print("[+] IOError: No password file has been specified in command args!")
    else:
        print(f"[+] IOError: Cannot open the following password file: {file_directory}!")


def display_welcome_msg():
    print(WELCOME_MSG)
    print(WELCOME_DECORATION)
    print(f"[+] CPU Info: {cpuinfo.get_cpu_info()['brand_raw']}")
    print(f"[+] Number of Cores Available: {multiprocessing.cpu_count()}")


def make_pw_deque(pw_list_dir):
    global brute_force_flag

    if pw_list_dir == "":
        brute_force_flag = True

    pw_q = Queue()

    try:
        password_file = open(pw_list_dir, 'r')
        for line in password_file:
            pw_q.put(line.strip())
    except IOError:
        _ioerror_handler(pw_list_dir)
        brute_force_flag = True

    return pw_q


def open_shadow_file(file_dir):
    try:
        file = open(file_dir, 'r')
        return file
    except IOError:
        if file_dir == "":
            sys.exit("[+] IOError: The '/etc/shadow' file is not specified in command args!")
        else:
            sys.exit(f"[+] IOError: Cannot open the following file: {file_dir}")


def parse_arguments():
    cleansed_user_list_args = []
    file_directory = ""
    password_list = ""
    num_of_threads = multiprocessing.cpu_count()
    max_attempts = ZERO

    # Remove file name from argument list
    arguments = sys.argv[1:]

    # Getting the file directory from (-f flag) and users (as args)
    opts, user_list_args = getopt.getopt(arguments, 'f:l:a:t:')

    # Check if empty parameters
    _check_args(opts)

    # Check if users are passed in
    _check_user_parameters(user_list_args)

    # Parsing command-line args
    for opt, argument in opts:
        if opt == '-f':
            file_directory = argument
        if opt == '-l':
            password_list = argument
        if opt == '-t':
            try:
                if int(argument) < ZERO:
                    print("[+] ERROR: Number of threads (-t) cannot be negative integer!")
                elif int(argument) > multiprocessing.cpu_count():
                    print(f"[+] ERROR: Number of threads (-t) cannot be greater than the "
                          f"max number of cores: {multiprocessing.cpu_count()}")
                else:
                    num_of_threads = int(argument)
            except ValueError:
                sys.exit(f"[+] Must be an integer for -t option!")
        if opt == '-a':
            try:
                max_attempts = int(argument)
                print(f"[+] MAX ATTEMPTS for each algorithm: {max_attempts}")
            except ValueError:
                sys.exit(f"[+] Invalid Argument for -a option!")

    # Check number of threads (if default)
    if num_of_threads == multiprocessing.cpu_count():
        print(f"[+] [DEFAULT] Program is now creating and using {num_of_threads} threads...")
    else:
        print(f"[+] [CUSTOM] Program is now creating and using {num_of_threads} threads...")

    # Check for duplicate users in arguments (prevent cracking duplicate users)
    cleansed_user_list_args = _remove_duplicate_users(cleansed_user_list_args, user_list_args)

    return file_directory, cleansed_user_list_args, password_list, max_attempts, num_of_threads


def print_end():
    print(f"\n{WELCOME_DECORATION}")
    print(PROGRAM_TERMINATE_MSG_1)
    print(f"[+] Total Number of Attempts: {total_attempts + total_brute_force_attempts}")
    print(f"[+] Total Time Elapsed: {round(total_time, 2)} seconds")
    print(PROGRAM_TERMINATE_MSG_2)


def _print_results(elapsed_time, d_thread_attempts, d_thread_time):
    if d_thread_attempts != ZERO and d_thread_time != ZERO:
        print(f"[+] Total Thread Attempts (Dictionary Attack): {d_thread_attempts}")
        print(f"[+] Total Thread Time: {round(d_thread_time, 3)} seconds")
        return

    print(f"[+] Time elapsed: {elapsed_time} seconds")


def process_statistics(pw):
    global stop_time, total_time, dictionary_thread_total_attempts, dictionary_total_thread_time

    stop_time = time.perf_counter()
    total_time += (stop_time - start_time)
    _print_results(round(total_time, 2), dictionary_thread_total_attempts, dictionary_total_thread_time)

    if pw != "":
        print(f"[+] The password is {constants.BOLD_START}{pw}{constants.BOLD_END}")


def _remove_duplicate_users(cleansed_user_list_args, orig_user_list_args):
    for user in orig_user_list_args:
        if user not in cleansed_user_list_args:
            cleansed_user_list_args.append(user)

    print(f"[+] The following users are to have their passwords cracked: {cleansed_user_list_args}")
    return cleansed_user_list_args


def remove_user_from_list(user_list):
    return user_list[1:]


def reset_variables():
    global start_time, password, dictionary_thread_total_attempts, \
        dictionary_total_thread_time, brute_force_counter, pw_deque, \
        bf_pw_deque, bf_total_time_queue, bf_total_attempt_queue, bf_total_thread_time, \
        processes

    # Empty the queues
    while True:
        if pw_queue.qsize() is ZERO:
            break
        pw_queue.get()

    start_time = time.perf_counter()
    password = None
    shadow_file.seek(BACK_TO_START)
    dictionary_thread_total_attempts = ZERO
    dictionary_total_thread_time = ZERO
    brute_force_counter = ZERO
    bf_total_thread_time = ZERO
    pw_queue.empty()
    bf_pw_deque.empty()
    bf_total_time_queue.empty()
    bf_total_attempt_queue.empty()
    processes.clear()


def user_not_found_check(user_info, user_list, user_name, file_dir):
    if len(user_info) is ZERO and len(user_list) >= TWO:
        print(f"\n[+] ERROR: {user_name} has not been found in {file_dir}! "
              f"Now moving on to the next user...\n")
        return True
    elif len(selected_user_info) is ZERO and len(user_list) < TWO:
        print(f"\n[+] ERROR: The last user: '{user_name}' has not been found in {file_dir}!")
        return True


def init_bf_variables():
    start_index_list = create_char_chunk_index_list(num_of_threads)
    bf_pw_lock = threading.Lock()
    bf_total_time_lock = threading.Lock()
    bf_total_attempt_lock = threading.Lock()

    return start_index_list, bf_pw_lock, bf_total_time_lock, bf_total_attempt_lock


def bf_pw_results_check(process_list: list[multiprocessing.Process]):
    global password, bf_pw_deque, num_of_threads

    while bf_pw_deque.qsize() != num_of_threads:
        break

    while True:  # CONSTRAINT: Since processes end so fast, wait 3 seconds before killing each process.
        item = bf_pw_deque.get()
        if item is not None:
            for process in process_list:
                time.sleep(3)  # To avoid zombie processes from stalling main thread
                os.kill(process.pid, signal.SIGKILL)
            password = item
            break


# Main Program
if __name__ == "__main__":
    # Declare Variables
    brute_force_attempts = ZERO
    brute_force_flag = False
    thread_total_attempts = ZERO
    total_brute_force_attempts = ZERO
    total_attempts = ZERO
    total_attempt_lock = threading.Lock()
    total_thread_time = ZERO
    total_thread_time_lck = threading.Lock()
    brute_force_counter_lock = threading.Lock()
    brute_force_counter = ZERO
    password = ""
    start_time = ZERO  # Time (main) gets suspended when entering a process
    stop_time = ZERO
    total_time = ZERO
    pw_list_lock = threading.Lock()
    pw_queue = Queue()
    pw_lck = threading.Lock()
    bf_pw_deque = Queue()
    bf_total_time_queue = Queue()
    bf_total_attempt_queue = Queue()
    bf_total_thread_time = ZERO
    bf_total_thread_attempts = ZERO

    # Initialize Program
    display_welcome_msg()
    # check_if_root_user()
    file_directory, user_list_args, password_list_dir, max_attempts, num_of_threads = parse_arguments()
    _check_if_files_exists(file_directory, password_list_dir)

    # Read contents of the /etc/shadow
    shadow_file = open_shadow_file(file_directory)

    # Process Array
    processes = []

    # Check if users exist and handle each
    for user in user_list_args:
        selected_user_info = ""
        reset_variables()
        pw_deque = make_pw_deque(password_list_dir)

        for entry in shadow_file:
            if user == entry.split(':')[0]:
                print(f"\n[+] {user} has been found! Now attempting to determine a suitable hashing algorithm...")
                selected_user_info = entry.split('$')

                # Check if user is valid (and not a service/process/utility)
                if _check_valid_user(entry, user, user_list_args) is False:
                    break

                # Determine the type of algorithm for user and extract salt
                algorithm = Algorithms.Algorithm()
                if algorithm.algorithm_checker(selected_user_info) == Algorithms.Algorithm.ERROR_CODE:
                    _algorithm_not_found()
                    break

                print(DICTIONARY_ATK_MSG)

                # Retrieve the Hash
                user_hash = entry.split(':')[1]

                # Retrieve the salt
                salt = algorithm.extract_salt(selected_user_info[1], entry)

                # a) [ATTACK 1] - Dictionary Attack (multi-thread)
                if not brute_force_flag:
                    for index in range(num_of_threads):
                        proc = Process(target=dictionary_attack, args=(user_hash,
                                                                       salt, max_attempts,
                                                                       pw_deque, pw_list_lock,
                                                                       total_attempt_lock, pw_queue,
                                                                       index))
                        processes.append(proc)
                        proc.start()

                    # Wait until password has been found
                    dictionary_atk_results_check(processes)

                    # Clear processes from array for brute force (in case)
                    processes.clear()

                # b) [ATTACK 2] - Use Brute-Force if dictionary fails or Password File is not valid
                if (password is None) or (password is BRUTE_FORCE_LAUNCH):
                    print(BRUTE_FORCE_ATK_MSG)
                    start_index_list, bf_pw_lock, bf_total_time_lock, bf_total_attempt_lock = init_bf_variables()

                    thread_id = 1
                    for index in range(len(start_index_list)):
                        proc = Process(target=brute_force_multithread, args=(salt, user_hash, max_attempts, thread_id,
                                                                             start_index_list[index], bf_pw_deque,
                                                                             bf_total_time_queue,
                                                                             bf_total_attempt_queue, bf_pw_lock,
                                                                             bf_total_time_lock,
                                                                             bf_total_attempt_lock))
                        thread_id += 1
                        processes.append(proc)
                        proc.start()

                    # Wait until password has been found
                    bf_pw_results_check(processes)

                    for i in range(bf_total_time_queue.qsize()):
                        bf_total_thread_time += bf_total_time_queue.get()

                    print(f"[+] Total Thread Time (Brute Force): {bf_total_thread_time} seconds")

                    # WHILE LOOP (ATTEMPTS) to wait for total number of attempts to be equal total num of threads
                    while bf_total_attempt_queue.qsize() != num_of_threads:
                        break

                    for i in range(bf_total_attempt_queue.qsize()):
                        bf_total_thread_attempts += bf_total_attempt_queue.get()

                    total_brute_force_attempts += bf_total_thread_attempts
                    print(f"[+] Total Number of Attempts For All Threads (Brute Force): {bf_total_thread_attempts}")

        if user_not_found_check(selected_user_info, user_list_args, user, file_directory):
            pass
        else:
            process_statistics(password)

        user_list_args = remove_user_from_list(user_list_args)

    # Program Terminate
    print_end()
