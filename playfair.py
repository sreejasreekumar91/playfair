import os, re


def print_table():
    table = ''
    for r in range(5):
        table += '\n'
        for c in range(5):
            table += main_table[r][c] + '\t'
    print(table)


# Function called table_has(letter) which checks if a letter already exists in the table
def table_has(letter):
    mweli_oba = False
    exit = False
    for r in range(5):
        if exit == False:
            for c in range(5):
                if main_table[r][c] == letter:
                    mweli_oba = True
                    exit = True
                    break

    return mweli_oba


# Function set_cell(letter) which sets a table cell to a specific letter
def set_cell(letter, new_table):
    exit = False
    for r in range(5):
        if not exit:
            for c in range(5):
                if new_table[r][c] == '*':
                    new_table[r][c] = letter
                    exit = True
                    break


# Function called init_table() initializes the table with stars [*]
def init_table():
    char = '*'
    for i in range(5):
        for j in range(5):
            main_table[i][j] = char
    return main_table


# Function clean_secret_key(secret_key) which changes the secret_message secret_key to uppercase and replace I by J
def clean_secret_key(secret_key):
    # remove non-alpha character
    secret_key = re.sub(r'[^a-zA-Z]+', '', secret_key)
    # change to upper case
    secret_key = secret_key.upper()
    # replace spaces with no space
    secret_key = secret_key.replace(" ", "")

    if secret_key:
        for J in secret_key:
            secret_key = secret_key.replace('J', 'I')

    print(secret_key)
    return secret_key


# Function to create the table, first inserts the secret_key and then adds the rest of the alphabet
def create_table(secret_key):
    # Get the new secret_key by calling the clean secret_key function
    new_secret_key = clean_secret_key(secret_key)
    # Initialize the table to create a new table instance
    new_table = init_table()

    # Add the secret_key into the table
    key_chars = []
    for char in new_secret_key:
        if len(key_chars) == 0:
            key_chars.append(char)
        else:
            exist = False
            for c in key_chars:
                if c == char:
                    exist = True
                    break
            if exist == False:
                key_chars.append(char)

    for c in key_chars:
        set_cell(c, new_table)

    main_table = new_table
    for char in alphabet.upper():
        if table_has(char) == False:
            set_cell(char, main_table)

    return (main_table)


def find_letter(letter):
    position = []
    for i in range(5):
        for j in range(5):
            if main_table[i][j] == letter:
                position = [i, j]
    return position


def clean_secret_message(message):
    # Remove spaces from the message
    message = message.upper()
    message = message.replace('J', 'I')
    message = message.replace(" ", "")
    new_message = []
    new_message = message
    # Convert string into a list so it's mutable and be able to manipulate it
    ch = []
    for cr in new_message:
        if len(ch) == 0:
            ch.append(cr)
        else:
            ch.append(cr)
    # Go through the message to separate similar letters with an X or a Q
    count = len(ch)
    for index in range(len(ch)):
        if index < count:
            ins_position = index + 1
            if ins_position < count:
                letter = ch[index]
                new_letter = ch[ins_position]
                if new_letter == letter and new_letter != 'X':
                    ch.insert(ins_position, 'X')
                elif new_letter == letter and new_letter == 'X':
                    ch.insert(ins_position, 'Q')
                index += 1
    # If range is odd number and a Z was added to a string that ended with Z, replace the second Z with a Q
    if len(ch) % 2 != 0:
        if ch[len(ch) - 1] == 'Z':
            ch.append('Q')
        else:
            ch.append('Z')
    ch = ''.join(ch)
    print(ch)
    return ch


def encode_pair(l1, l2):
    position1 = find_letter(l1)
    position2 = find_letter(l2)
    row_a = position1[0]
    col_a = position1[1]
    row_b = position2[0]
    col_b = position2[1]
    # Same row characters
    if position1[0] == position2[0]:
        if col_a == 4:
            char1 = main_table[row_a][col_a - col_a]
            char2 = main_table[row_b][col_b + 1]
        elif col_b == 4:
            char1 = main_table[row_a][col_a + 1]
            char2 = main_table[row_b][col_b - col_b]
        else:
            char1 = main_table[row_a][col_a + 1]
            char2 = main_table[row_b][col_b + 1]
    # Same column characters
    elif position1[1] == position2[1]:
        if row_a == 4:
            char1 = main_table[row_a - row_a][col_a]
            char2 = main_table[row_b + 1][col_b]
        elif row_b == 4:
            char1 = main_table[row_a + 1][col_a]
            char2 = main_table[row_b - row_b][col_b]
        else:
            char1 = main_table[row_a + 1][col_a]
            char2 = main_table[row_b + 1][col_b]
    # Rectangle encode
    else:
        char1 = main_table[row_a][col_b]
        char2 = main_table[row_b][col_a]
    pair = char1, char2
    pair = ''.join(pair)
    return pair


def decode_pair(l1, l2):
    position1 = find_letter(l1)
    position2 = find_letter(l2)
    row_a = position1[0]
    col_a = position1[1]
    row_b = position2[0]
    col_b = position2[1]
    # Same row characters
    if position1[0] == position2[0]:
        if col_a == 0:
            char1 = main_table[row_a][col_a + 4]
            char2 = main_table[row_b][col_b - 1]
        elif col_b == 0:
            char1 = main_table[row_a][col_a - 1]
            char2 = main_table[row_b][col_b + 4]
        else:
            char1 = main_table[row_a][col_a - 1]
            char2 = main_table[row_b][col_b - 1]
    # Same column characters
    elif position1[1] == position2[1]:
        if row_a == 0:
            char1 = main_table[row_a + 4][col_a]
            char2 = main_table[row_b - 1][col_b]
        elif row_b == 0:
            char1 = main_table[row_a - 1][col_a]
            char2 = main_table[row_b + 4][col_b]
        else:
            char1 = main_table[row_a - 1][col_a]
            char2 = main_table[row_b - 1][col_b]
    # Rectangle encode
    else:
        char1 = main_table[row_a][col_b]
        char2 = main_table[row_b][col_a]
    pair = char1, char2
    pair = ''.join(pair)
    return pair


def encrypt(plaintext, secret_key):
    message = plaintext
    create_table(secret_key)
    print_table()
    new_message = clean_secret_message(message)
    final_message = []
    for k in new_message:
        if len(new_message) > 0:
            l1 = new_message[:1]
            new_message = new_message[1:]
            l2 = new_message[:1]
            new_message = new_message[1:]
            new_pair = encode_pair(l1, l2)
            final_message.append(new_pair)
            string1 = ''.join(final_message)
    # Split the cipher message in 5 X 5 characters
    cipher_text = ''
    x = 1
    for char in string1:
        cipher_text += char
        if x % 5 == 0:
            cipher_text += ' '
        x += 1

    print(cipher_text)


def decrypt(ciphertext, secret_key):
    message = ciphertext.upper()
    message = message.replace(' ', '')
    create_table(secret_key)
    print_table()
    final_message = []
    string1 = ''
    x = 1
    for k in message:
        while x < len(message) + 1:
            l1 = message[:1]
            message = message[1:]
            l2 = message[:1]
            message = message[1:]
            new_pair = decode_pair(l1, l2)
            final_message.append(new_pair)
            string1 = ''.join(final_message)
            # x += 1
    # Split the plain text message in 5 X 5 characters
    plain_text = ''
    x = 1
    for char in string1:
        plain_text += char
        if x % 5 == 0:
            plain_text += ' '
        x += 1

    print(plain_text)


# Starting point
if __name__ == '__main__':
    while True:
        alphabet = 'abcdefghiklmnopqrstuvwxyz'  # J was removed
        secrata = []
        main_table = [['', '', '', '', ''],
                   ['', '', '', '', ''],
                   ['', '', '', '', ''],
                   ["", "", "", "", ""],
                   ['', '', '', '', '']]
        action = input('What do you want to do, Encrypt or Decrypt? Type (e or d)')
        if action == 'e':
            secret_key = input('Create a Secret key first: ')
            secret_message = input('Enter secret message in Plain text: ')
            encrypt(secret_message, secret_key)
        elif action == 'd':
            secret_key = input('Provide a Secret key to decode cipher: ')
            secret_cipher = input('Enter the Cipher text you need to decode here: ')
            decrypt(secret_cipher, secret_key)
        else:
            print('Error')
            break

        selection = input('Do you want to try that again...encrypt or decrypt? Type (y or n)')
        if selection == 'y':
            continue
        elif selection == 'n':
            break
        else:
            print('Error, program will terminate now')
            os.system('pause')
            break
