import queue
from concurrent.futures import ThreadPoolExecutor
import Algorithms
from collections import deque
import cpuinfo
from constants import WELCOME_MSG, WELCOME_DECORATION, DICTIONARY_ATK_MSG, ZERO, TWO, BACK_TO_START, BRUTE_FORCE_LAUNCH, \
    PROGRAM_TERMINATE_MSG_1, PROGRAM_TERMINATE_MSG_2
from Cracker import brute_force
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
    global total_thread_time
    total_time = (time.process_time() - s_time)
    total_thread_time_lck.acquire()
    total_thread_time += total_time
    total_thread_time_lck.release()
    print(f"[+] [Thread {thread_id}] Time: {total_time} seconds")


def _check_args(opts):
    if len(opts) == ZERO:
        sys.exit("[+] NO_ARG_ERROR: No arguments were passed in!")


def _check_if_files_exists(file_dir, pw_list_dir):
    try:
        if not os.path.exists(file_dir):
            sys.exit(f"[+] ERROR: {file_dir} Doesn't Exist or Invalid Argument!")
        elif not os.path.exists(pw_list_dir) or pw_list_dir == "":
            print(f"[+] ERROR: {pw_list_dir} Doesn't Exist or Invalid Argument!")
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


def create_dictionary_thread_pool():
    with ThreadPoolExecutor() as executor:
        for i in range(num_of_threads):
            _execute_dictionary_threads(executor, i)


def async_dictionary_attack():
    create_dictionary_thread_pool()


def dictionary_attack_helper(input_hash, input_salt, max_attempt, pw_deque: deque,
                             list_lock: threading.Lock, attempt_lock: threading.Lock,
                             pw_stop_q: queue.Queue, thread_id: int):
    # Start Local timer
    s_time = time.process_time()

    # Initialize variables
    global total_attempts, thread_total_attempts, total_thread_time, total_thread_time_lck
    attempt = ZERO
    thread_id += 1

    # If no max number of attempts set in command args (-a)
    if max_attempt == ZERO:
        if pw_deque is not None:
            while len(pw_deque) is not ZERO:
                list_lock.acquire()
                pw = str(pw_deque.popleft()).strip()
                list_lock.release()

                if crypt.crypt(pw, input_salt) == input_hash:
                    print(f"[+] [PW Thread {thread_id}] CRACK COMPLETE: Password has been found!")
                    print(f"[+] [PW Thread {thread_id}] Number of Attempts Made: {attempt}")

                    # Erase all pw in deque to stop all concurrent threads
                    list_lock.acquire()
                    pw_deque.clear()
                    list_lock.release()

                    # Put password in stop_queue
                    pw_lck.acquire()
                    pw_stop_q.put(pw)
                    pw_lck.release()

                    # Update total attempts global
                    attempt_lock.acquire()
                    thread_total_attempts += attempt
                    total_attempts += attempt
                    attempt_lock.release()

                    # Calculate Time
                    _calculate_dictionary_thread_time(s_time, thread_id, total_thread_time_lck)

                    return pw
                else:
                    attempt += 1

            # If no password is found in dictionary
            attempt_lock.acquire()
            thread_total_attempts += attempt
            total_attempts += attempt
            attempt_lock.release()

            _calculate_dictionary_thread_time(s_time, thread_id, total_thread_time_lck)

            if pw_stop_q.empty():
                pw_stop_q.put(None)
                return
    else:
        if pw_deque is not None:
            while len(pw_deque) is not ZERO:
                list_lock.acquire()
                pw = str(pw_deque.popleft()).strip()
                list_lock.release()

                if crypt.crypt(pw, input_salt) == input_hash:
                    print(f"[+] [PW Thread {thread_id}] CRACK COMPLETE: Password has been found!")
                    print(f"[+] [PW Thread {thread_id}] Number of Attempts Made: {attempt}")

                    # Erase all pw in deque to stop all concurrent threads
                    list_lock.acquire()
                    pw_deque.clear()
                    list_lock.release()

                    # Put password in stop_queue
                    pw_lck.acquire()
                    pw_stop_q.put(pw)
                    pw_lck.release()

                    # Update total attempts global
                    attempt_lock.acquire()
                    thread_total_attempts += attempt
                    total_attempts += attempt
                    attempt_lock.release()

                    # Calculate Time
                    _calculate_dictionary_thread_time(s_time, thread_id, total_thread_time_lck)

                    return pw
                elif attempt == max_attempt:
                    print(f"[+] [Thread {thread_id}] CRACK FAILED: Max attempts of {attempt} has been reached!")

                    attempt_lock.acquire()
                    thread_total_attempts += attempt
                    total_attempts += attempt
                    attempt_lock.release()

                    _calculate_dictionary_thread_time(s_time, thread_id, total_thread_time_lck)

                    pw_stop_q.put(None)
                    return
                else:
                    attempt += 1

            # If no password is found in dictionary
            attempt_lock.acquire()
            thread_total_attempts += attempt
            total_attempts += attempt
            attempt_lock.release()

            _calculate_dictionary_thread_time(s_time, thread_id, total_thread_time_lck)

            if pw_stop_q.empty():
                pw_stop_q.put(None)
                return


def _execute_dictionary_threads(executor, i):
    executor.submit(dictionary_attack_helper, user_hash, salt, max_attempts, pw_deque,
                    list_lock=pw_list_lock, attempt_lock=total_attempt_lock,
                    pw_stop_q=pw_queue, thread_id=i)


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


def init_variables():
    brute_force_attempts = ZERO
    brute_force_flag = False
    thread_total_attempts = ZERO
    total_brute_force_attempts = ZERO
    total_attempts = ZERO
    total_thread_time = ZERO
    total_thread_time_lck = threading.Lock()
    password = ""
    start_time = ZERO
    stop_time = ZERO
    total_time = ZERO
    pw_list_lock = threading.Lock()
    total_attempt_lock = threading.Lock()
    pw_queue = queue.Queue()
    pw_lck = threading.Lock()

    return total_attempts, brute_force_attempts, total_brute_force_attempts, thread_total_attempts, brute_force_flag, \
        start_time, stop_time, total_time, password, pw_list_lock, total_attempt_lock, pw_queue, pw_lck, \
        total_thread_time, total_thread_time_lck


def make_pw_deque(pw_list_dir):
    global brute_force_flag

    if pw_list_dir == "":
        return None

    pw_q = deque()

    try:
        password_file = open(pw_list_dir, 'r')
        for line in password_file:
            pw_q.append(line.strip())
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


def _print_results(elapsed_time, thread_attempts, thread_time):
    print(f"[+] Total Thread Attempts: {thread_attempts}")
    print(f"[+] Total Thread Time: {round(thread_time, 3)} seconds")
    print(f"[+] Time elapsed: {elapsed_time} seconds")


def process_statistics(pw):
    global stop_time, total_time, thread_total_attempts, total_thread_time

    stop_time = time.process_time()
    _print_results(round(stop_time - start_time, 2), thread_total_attempts, total_thread_time)
    total_time += (stop_time - start_time)

    if pw != "":
        print(f"[+] The password is {pw}")


def _remove_duplicate_users(cleansed_user_list_args, orig_user_list_args):
    for user in orig_user_list_args:
        if user not in cleansed_user_list_args:
            cleansed_user_list_args.append(user)

    print(f"[+] The following users are to have their passwords cracked: {cleansed_user_list_args}")
    return cleansed_user_list_args


def remove_user_from_list(user_list):
    return user_list[1:]


def user_not_found_check(user_info, user_list, user_name, file_dir):
    if len(user_info) is ZERO and len(user_list) >= TWO:
        print(f"\n[+] ERROR: {user_name} has not been found in {file_dir}! "
              f"Now moving on to the next user...\n")
        return True
    elif len(selected_user_info) is ZERO and len(user_list) < TWO:
        print(f"\n[+] ERROR: The last user: '{user_name}' has not been found in {file_dir}!")
        return True


def dictionary_atk_signal_check():
    global password

    while pw_queue.empty():
        pass

    pw_queue_list = []

    for i in range(pw_queue.qsize()):
        pw_queue_list.append(pw_queue.get())

    for item in pw_queue_list:
        if item is not None:
            password = item


# Main Program
if __name__ == "__main__":
    # Declare Variables
    total_attempts, brute_force_attempts, total_brute_force_attempts, thread_total_attempts, \
        brute_force_flag, start_time, stop_time, total_time, password, pw_list_lock, \
        total_attempt_lock, pw_queue, pw_lck, total_thread_time, total_thread_time_lck = init_variables()

    # Initialize Program
    display_welcome_msg()
    # check_if_root_user()
    file_directory, user_list_args, password_list_dir, max_attempts, num_of_threads = parse_arguments()
    _check_if_files_exists(file_directory, password_list_dir)

    # Make a deque of dictionary words (password list)
    pw_deque = make_pw_deque(password_list_dir)
    backup_deque = pw_deque.copy()

    # Read contents of the /etc/shadow
    shadow_file = open_shadow_file(file_directory)

    # Check if users exist and handle each
    for user in user_list_args:
        start_time = time.process_time()
        selected_user_info = ""
        password = None
        shadow_file.seek(BACK_TO_START)
        thread_total_attempts = ZERO
        total_thread_time = ZERO

        # Refresh the queues
        pw_deque = backup_deque.copy()
        pw_queue.empty()

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

                # Dictionary Attack (multi-thread)
                if not brute_force_flag:
                    async_dictionary_attack()
                    dictionary_atk_signal_check()

                # Use Brute-Force if dictionary fails or Password File is not valid
                # INCLUDE thread_total_attempts + total_thread_time here
                if (password is None) or (password is BRUTE_FORCE_LAUNCH):
                    password, brute_force_attempts = brute_force(salt, user_hash, max_attempts)
                    total_brute_force_attempts += brute_force_attempts

        if user_not_found_check(selected_user_info, user_list_args, user, file_directory):
            pass
        else:
            process_statistics(password)

        user_list_args = remove_user_from_list(user_list_args)

    # Program Terminate
    print_end()
