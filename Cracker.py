import crypt
import itertools

ZERO = 0
START_LENGTH = 1
MAX_CHAR_LENGTH = 9999
BRUTE_FORCE_ATK_MSG = "[+] [ATTACK 2]: Now launching a Brute Force Attack. Please wait..."


def brute_force(salt, user_hash, max_attempts):
    print(BRUTE_FORCE_ATK_MSG)
    attempts = ZERO

    characters_map = ('!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '=', "'\'", '/', '.',
                      ',', '<', '>', ':', ':', '{', '}', '[', ']', '|', '"', '\'', '?', '~', '`',
                      '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f',
                      'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                      'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F',
                      'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                      'W', 'X', 'Y', 'Z', ' ')

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

# SOURCE USED: https://stackoverflow.com/questions/40269605/how-to-create-a-brute-force-password-cracker-for-alphabetical-and-alphanumerical