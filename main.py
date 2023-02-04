import Algorithms
from Cracker import brute_force
import crypt
import getopt
import os
import sys
import time

WELCOME_MSG = "A basic single-threaded password cracker program (v1.0) \nBy Johnny Hui (A00973103)"
WELCOME_DECORATION = "=============================================================================================" \
                     "=============="
DICTIONARY_ATK_MSG = "[+] [ATTACK 1]: Now beginning the cracking " \
                     "process with a Dictionary Attack..."
ZERO = 0
TWO = 2
BACK_TO_START = 0
BRUTE_FORCE_LAUNCH = True
PROGRAM_TERMINATE_MSG_1 = "[+] All users have been processed!"
PROGRAM_TERMINATE_MSG_2 = "[+] PROGRAM_EXIT: Now terminating program..."


def algorithm_not_found():
    print("[+] ALGORITHM_NOT_FOUND_ERROR: This algorithm type is not supported!")
    print("[+] Now checking for next user...")


def check_args(opts):
    if len(opts) == ZERO:
        sys.exit("[+] NO_ARG_ERROR: No arguments were passed in!")


def check_if_file_exists(file_dir):
    try:
        if not os.path.exists(file_dir):
            sys.exit("[+] ERROR: File Doesn't Exist or Invalid Argument!")
        else:
            print(f"[+] Now reading the {file_dir} file...")
    except FileNotFoundError:
        sys.exit("[+] ERROR: File Doesn't Exist!")


def check_if_root_user():
    if not os.geteuid() == 0:
        sys.exit("[+] ERROR: Only the 'root' user can run this script "
                 "[Please run this script again using sudo command].")


def check_user_parameters(user_list):
    if len(user_list) == ZERO:
        sys.exit("[+] No users were passed in as arguments!")


def check_valid_user(file_entry, user_name, user_list):
    if '$' not in file_entry and len(user_list) >= TWO:
        print(f"[+] INVALID USER: {user_name} is a service, utility, or process and cannot be cracked!")
        print("[+] Now moving on to the next user...")
        return False
    elif '$' not in file_entry and len(user_list) < TWO:
        print(f"[+] INVALID USER: {user_name} is a service, utility, or process and cannot be cracked!")
        return False
    else:
        return True


def dictionary_attack(file_directory, input_hash, input_salt, max_attempt):
    global total_attempts
    attempt = ZERO

    # If no max number of attempts set in command args (-a)
    if max_attempt == ZERO:
        try:
            password_file = open(file_directory, 'r')

            for line in password_file:
                if crypt.crypt(line.strip(), input_salt) == input_hash:
                    print(f"[+] CRACK COMPLETE: Password has been found!")
                    print(f"[+] Number of Attempts Made: {attempt}")
                    total_attempts += attempt
                    return line.strip()
                else:
                    attempt += 1

            print(f"[+] CRACK FAILED: Password isn't present in the file provided!")
            print(f"[+] Number of Attempts Made: {attempt}")
            total_attempts += attempt
        except IOError:
            ioerror_handler(file_directory)
            return BRUTE_FORCE_LAUNCH
    else:
        try:
            password_file = open(file_directory, 'r')

            for line in password_file:
                if crypt.crypt(line.strip(), input_salt) == input_hash:
                    print(f"[+] CRACK COMPLETE: Password has been found!")
                    total_attempts += attempt
                    return line.strip()
                elif attempt == max_attempt:
                    print(f"[+] CRACK FAILED: Max attempts of {attempt} has been reached!")
                    total_attempts += attempt
                    return None
                else:
                    attempt += 1

            print(f"[+] CRACK FAILED: Password isn't present in the file provided!")
            print(f"[+] Number of Attempts Made: {attempt}")
            total_attempts += attempt
        except IOError:
            ioerror_handler(file_directory)
            return BRUTE_FORCE_LAUNCH


def ioerror_handler(file_directory):
    if file_directory == "":
        print("[+] IOError: No password file has been specified in command args!")
    else:
        print(f"[+] IOError: Cannot open the following password file: {file_directory}!")


def display_welcome_msg():
    print(WELCOME_MSG)
    print(WELCOME_DECORATION)


def init_variables():
    brute_force_attempts = ZERO
    total_brute_force_attempts = ZERO
    total_attempts = ZERO
    password = ""
    start_time = ZERO
    stop_time = ZERO
    total_time = ZERO

    return total_attempts, brute_force_attempts, total_brute_force_attempts, start_time, stop_time, total_time, password


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
    max_attempts = ZERO

    # Remove file name from argument list
    arguments = sys.argv[1:]

    # Getting the file directory from (-f flag) and users (as args)
    opts, user_list_args = getopt.getopt(arguments, 'f:l:a:')

    # Check if empty parameters
    check_args(opts)

    # Check if users are passed in
    check_user_parameters(user_list_args)

    # Check for duplicate users in arguments (prevent cracking duplicate users)
    remove_duplicate_users(cleansed_user_list_args, user_list_args)

    # Get file directory
    for opt, argument in opts:
        if opt == '-f':
            file_directory = argument
        if opt == '-l':
            password_list = argument
        if opt == '-a':
            try:
                max_attempts = int(argument)
                print(f"[+] MAX ATTEMPTS for each algorithm: {max_attempts}")
            except ValueError:
                sys.exit(f"[+] Invalid Argument for -a option!")

    return file_directory, cleansed_user_list_args, password_list, max_attempts


def print_end():
    print(f"\n{WELCOME_DECORATION}")
    print(PROGRAM_TERMINATE_MSG_1)
    print(f"[+] Total Number of Attempts: {total_attempts + total_brute_force_attempts}")
    print(f"[+] Total Time Elapsed: {round(total_time, 2)} seconds")
    print(PROGRAM_TERMINATE_MSG_2)


def process_statistics(pw):
    global stop_time, total_time

    stop_time = time.process_time()
    print_results(round(stop_time - start_time, 2))
    total_time += (stop_time - start_time)

    if pw != "":
        print(f"[+] The password is {pw}")


def print_results(elapsed_time):
    print(f"[+] Time elapsed: {elapsed_time} seconds")


def remove_duplicate_users(cleansed_user_list_args, orig_user_list_args):
    for user in orig_user_list_args:
        if user not in cleansed_user_list_args:
            cleansed_user_list_args.append(user)

    print(f"[+] The following users are to have their passwords cracked: {cleansed_user_list_args}")


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


# Main Program
if __name__ == "__main__":
    # Declare Variables
    total_attempts, brute_force_attempts, total_brute_force_attempts, start_time, stop_time, total_time, \
        password = init_variables()

    # Initialize Program
    display_welcome_msg()
    # check_if_root_user()
    file_directory, user_list_args, password_list_dir, max_attempts = parse_arguments()
    check_if_file_exists(file_directory)

    # Read contents of the /etc/shadow
    shadow_file = open_shadow_file(file_directory)

    # Check if users exist and handle each
    for user in user_list_args:
        start_time = time.process_time()
        selected_user_info = ""
        password = ""
        shadow_file.seek(BACK_TO_START)

        for entry in shadow_file:
            if user == entry.split(':')[0]:
                print(f"\n[+] {user} has been found! Now attempting to determine a suitable hashing algorithm...")
                selected_user_info = entry.split('$')

                # Check if user is valid (and not a service/process/utility)
                if check_valid_user(entry, user, user_list_args) is False:
                    break

                # Determine the type of algorithm for user and extract salt
                algorithm = Algorithms.Algorithm()
                if algorithm.algorithm_checker(selected_user_info) == Algorithms.Algorithm.ERROR_CODE:
                    algorithm_not_found()
                    break

                print(DICTIONARY_ATK_MSG)

                # Retrieve the Hash
                user_hash = entry.split(':')[1]

                # Retrieve the salt
                salt = algorithm.extract_salt(selected_user_info[1], entry)

                # # Find the password (via. dictionary attack)
                password = dictionary_attack(password_list_dir, user_hash, salt, max_attempts)

                # Use Brute-Force if dictionary fails or Password File is not
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
