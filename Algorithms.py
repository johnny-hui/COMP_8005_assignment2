import crypt


class Algorithm:
    YESCRYPT = 'y'
    SHA_256 = '5'
    SHA_512 = '6'
    MD5 = '1'
    BCRYPT_A = "2a"
    BCRYPT_B = "2b"
    BCRYPT_Y = "2y"
    ROUNDS = "rounds"
    ERROR_CODE = 69

    def algorithm_checker(self, prefix):
        match prefix[1]:
            case self.YESCRYPT:
                print("[+] Algorithm Used: [Yescrypt]")
            case self.SHA_256:
                print("[+] Algorithm Used: [SHA-256]")
            case self.SHA_512:
                print("[+] Algorithm Used: [SHA-512]")
            case self.MD5:
                print("[+] Algorithm Used: [MD5]")
            case self.BCRYPT_A:
                print("[+] Algorithm Used: [BCrypt]")
            case self.BCRYPT_B:
                print("[+] Algorithm Used: [BCrypt/Blowfish]")
            case self.BCRYPT_Y:
                print("[+] Algorithm Used: [BCrypt]")
            case _:
                return self.ERROR_CODE

    def extract_salt(self, prefix, user_info):
        match prefix:
            case self.YESCRYPT:
                password = str(user_info).split(':')[1]
                return self.__extract_salt_after_4th_occurance(password)
            case self.SHA_256:
                password = str(user_info).split(':')[1]
                if password.split('$')[2].split('=')[0] == self.ROUNDS:
                    return self.__extract_salt_after_4th_occurance(password)
                else:
                    return self.__extract_salt_after_3rd_occurance(password)
            case self.SHA_512:
                password = str(user_info).split(':')[1]
                if password.split('$')[2].split('=')[0] == self.ROUNDS:
                    return self.__extract_salt_after_4th_occurance(password)
                else:
                    return self.__extract_salt_after_3rd_occurance(password)
            case self.MD5:
                password = str(user_info).split(':')[1]
                return self.__extract_salt_after_3rd_occurance(password)
            case self.BCRYPT_A | self.BCRYPT_B | self.BCRYPT_Y:
                return str(user_info).split(':')[1].split('/')[0]

    @staticmethod
    def __extract_salt_after_4th_occurance(password):
        counter = 0
        salt = ""
        for letter in password:
            if letter == '$':
                counter += 1
            if counter == 4:
                break
            salt = salt + letter
        return salt

    @staticmethod
    def __extract_salt_after_3rd_occurance(password):
        counter = 0
        salt = ""
        for letter in password:
            if letter == '$':
                counter += 1
            if counter == 3:
                break
            salt = salt + letter
        return salt
