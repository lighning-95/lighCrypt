#  imports for encryption and decryption
import secrets
import hashlib
import hmac
import os
import string
import re
import base64

# imports for cli interface
import textwrap
import time
from getpass import getuser
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.spinner import Spinner
from rich.live import Live
from rich.align import Align
from rich.markup import escape

SALT_LEN = 16   # Bytes of salt we generate
Hex_SALT_LEN = SALT_LEN * 2   #length once salt is turned into hex string
ITERATION = 1000000   # pbkdf2 rounds , slows down brute force

ENCRYPTED_LIMIT = 4000 #encrypted text longer this goes to a file
DECRYPTED_LIMIT = 10000 # decrypted text longer this goes to a file

#  Custom exceptions for convinience
class AuthenticationError(ValueError):
    ...
class EmptyPasswordError(ValueError):
    ...
class ShortPasswordError(ValueError):
    ...
class PasswordFormatError(ValueError):
    ...

# #### _____________characters_for_encryption___________##########

# two scrambled char sets used as building blocks for obfuscation
chars_for_protection = '''b{>o#IyG)-xR+L@0N`q12m7s/}*|rDzX5A=,.S?C6t9lP]w'Q(_$f&4JhW:~n"Zjpdi;VU[HTaFv%<3cK!kE8eYOuBMg^'''
chars_for_enc_dec = '''U[HTaFv%<3cb{>o#IlP]w\\'Q(_$f&4JhW:~"nZjpdi;VyG)- xR+L@0N`q\n12m7s/}*|rDzX5A=,.\tS?C6t9K!kE8eYOuBMg^'''

len_enc_dec_char = len(chars_for_enc_dec)


class Unicode:
    """
    It changge one \\ to \\\\
    it passes characters in char_for_enc_dec as it is
    it escapes charscaters not in char_in_enc_dec
    """

    @staticmethod
    def escape_text(text: str) -> str:
        '''it takes char and processes as per logic below'''
        out = []
        for ch in text:
            if ch == '\\':
                out.append('\\\\')
            elif ch in chars_for_enc_dec:
                out.append(ch)
            else:
                out.append(f'\\x{ord(ch):x};')  # makes char-> \x...;
        return ''.join(out)
        
    def unescape_text(text: str) -> str:
        '''reverses the escape_text function'''
        out = []
        i = 0
        while i < len(text):
            if text[i] == '\\' and (i + 1 <len(text)):
                if text[i+1] == '\\':   # two backslashes -> one
                    out.append('\\')
                    i += 2
                elif text[i+1] == 'x':     # \x....; -> the char
                    end = text.index(';', i)
                    hex_part = text[i+2:end]    # skip \x
                    out.append(chr(int(hex_part, 16)))
                    i = end + 1
                else:    # stray backslash, keep it as is
                    out.append(text[i])
                    i += 1
            else:   #supportred char from char_for_enc_dec
                out.append(text[i])
                i += 1
        return ''.join(out)



#####___________Seed and key-stream generator functions________#####

class Generator:
    '''Functions for generating seed, keys'''
    @staticmethod
    def get_seed(password: str,salt: bytes,purpose: bytes) -> bytes:
        '''Derives a 32-byte key from
        password + salt + purpose using pbkdf2 
        "purpose" lets us different keys for different jobs '''

        return hashlib.pbkdf2_hmac(
            'sha256',password.encode(),
            salt + purpose,
            ITERATION,
            dklen=32
        )


    @staticmethod
    def get_key_series(seed: int):
        '''Turns a seed into infinite pseudo random numbers'''
        key = seed.to_bytes(32,'big')
        counter = 0
        while True:
            block = hmac.new(
                key,
                counter.to_bytes(8,'little'), 
                hashlib.sha256).digest()

            for i in range(0,32,4):
                yield int.from_bytes(block[i:i+4],'little')
          
            counter +=1

########________Encryption and Decryption functons________#######

class Crypt:
    '''Functions for encrypting and decrypting'''
    @staticmethod
    def do_encrypt_decrypt(text: str,mode: str,key: int) -> str: 
        '''shifts each char's positoin according to key stream'''
        result =''
        for char in text:
            
            index = chars_for_enc_dec.find(char)
            
            if index == -1:  # char not found in enc_dec_char remains untouched
                result +=char
            
            else:
                
                if mode == 'encrypt':
                    new_index = (index + next(key)) % len_enc_dec_char
                elif mode == 'decrypt':
                    new_index = (index - next(key)) % len_enc_dec_char
                result +=chars_for_enc_dec[new_index]
        return result
    


    @staticmethod
    def encrypt(plain_text: str,password: str) -> str:
        '''main encrypt entry point: makes a salt, scrambles the plain text
        and encrypts it.
        tags it for integrity and glues it to the out put in encrypted form'''

        # generatsalt random salt
        salt = os.urandom(16)

        encrypted_salt = Salt.protect_salt(salt,password)

        # seed for plain text encryption 
        seed = Generator.get_seed(password,salt,b'encrypt-decrypt')
        # converting bytes to int form of generated seed
        int_seed = int.from_bytes(seed, 'big')
    
        keys = Generator.get_key_series(int_seed) #generating key stream

        #escaping the plain text

        plain_text = Unicode.escape_text(plain_text)

        # encrypting plain text
        layered_encrypted_text = Nonce.add_protection(plain_text,int_seed)
        encrypted_plain_text = Crypt.do_encrypt_decrypt(layered_encrypted_text,'encrypt',keys)
    
        # generating authentication key for tag
        auth_key = Generator.get_seed(password,salt,b'authentication')
        tag = hmac.new(
            auth_key,encrypted_plain_text.encode(),
            hashlib.sha256
        ).hexdigest()
        # generating seed for tag encryption 
        tag_seed = Generator.get_seed(password,b'',b'tag-seed')
        int_tag_seed = int.from_bytes(tag_seed,'big')
        tag_keys = Generator.get_key_series(int_tag_seed)
        encrypted_tag = Crypt.do_encrypt_decrypt(tag,'encrypt',tag_keys)

        # adding a dummy char to the end to preserve space which may be generated during encryption
        trailer = secrets.choice(chars_for_protection)  

        # encoding to base64 for safe copy/paste in terminal
        raw = encrypted_salt + encrypted_plain_text + encrypted_tag +trailer
        return base64.urlsafe_b64encode(raw.encode()).decode()
        

    @staticmethod
    def decrypt(data: str, password: str) -> str:
        '''main decrypt entry point: reverses the process of encrypt()
        '''

        data = base64.urlsafe_b64decode(''.join(data.split()).encode()).decode()

        encrypted_salt = data[:Hex_SALT_LEN+1] #hex_salt_len +1 cuz we added 1 extra char in salt_protection function 
        encrypted_tag = data[-65:-1] # last one is trailer so we don't need it
        encrypted_text = data[Hex_SALT_LEN+1:-65]  # staring is salt and ending is tag .
                                                #  64 chars for tag and extra 1 for trailer 
        # decrypting salt
        decrypted_salt = Salt.remove_salt_protection(encrypted_salt,password)
        
        # generating tag seed , tag keys for decryption of recieved tag
        received_tag_seed = Generator.get_seed(password,b'',b'tag-seed')
        int_received_tag_seed = int.from_bytes(received_tag_seed,'big')
        received_tag_keys = Generator.get_key_series(int_received_tag_seed)

        decrypted_received_tag = Crypt.do_encrypt_decrypt(encrypted_tag,'decrypt',received_tag_keys)
        
        #generating same auth_key , expected_tag to verify with decrypted_recieved_tag
        auth_key = Generator.get_seed(password,decrypted_salt,b'authentication')
        expected_tag = hmac.new(
            auth_key,encrypted_text.encode(),
            hashlib.sha256
        ).hexdigest()
        # verifying if both tags are same
        if not hmac.compare_digest(expected_tag,decrypted_received_tag):
            raise AuthenticationError
        # if both tags are same, we continue
        #generating seed for txt decryption 
        seed = Generator.get_seed(password,decrypted_salt,b'encrypt-decrypt')
        int_seed = int.from_bytes(seed,'big')

        keys = Generator.get_key_series(int_seed) #generating key steram
        # decrypting the encryted text
        decrypted_text= Crypt.do_encrypt_decrypt(encrypted_text,'decrypt',keys)
        plain_text = Nonce.remove_protection(decrypted_text,int_seed) 
        
        # u escaping plain text
        plain_text = Unicode.unescape_text(plain_text)

        return plain_text 

############--------------Salt protection/for encryption-decryption functions-----------##########

class Salt:
    @staticmethod
    def protect_salt(salt: bytes,password: str) -> str:
        '''hides the salt itself so it's not
        sitting in plain hex form in the output '''

        salt_hex = salt.hex()

        seed = Generator.get_seed(password,b'unknown',b'protect-salt')
        int_seed = int.from_bytes(seed,'big')  
        keys = Generator.get_key_series(int_seed)
        encrypted_salt = Crypt.do_encrypt_decrypt(salt_hex,'encrypt',keys)
        # stick 1 dummy char in front to preserve space which may be created by do_encrypt_decrypt function
        layered_salt = secrets.choice(chars_for_protection) + encrypted_salt
        return  layered_salt

    @staticmethod
    def remove_salt_protection(protected__salt: str,password: str) -> bytes:
        '''reverse of protect_salt function'''
        # discarding the front dummy char
        unlayered_salt = protected__salt[1:Hex_SALT_LEN+1]
        
        seed =Generator.get_seed(password,b'unknown',b'protect-salt')
        int_seed= int.from_bytes(seed, 'big')
        keys = Generator.get_key_series(int_seed)

        decrypted_salt_hex =Crypt.do_encrypt_decrypt(unlayered_salt,'decrypt',keys)

        return bytes.fromhex(decrypted_salt_hex)


# ####---------------------protection/nonce functions--------------#########

class Nonce:
    '''Functions for addingand removing nonce'''
    @staticmethod
    def starter(fx):
        '''Decorator: splits text into tokens and picks a "protection key"
        number based on seeds divisibility'''

        def wrapper(text: str,key: int) -> str:
            
            tokens = [t for t in re.split(r'(\s+)',text) if t]

            if key%11==0:
                protection_key = 3
            elif key%7==0:
                protection_key = 4
            elif key%5==0:
                protection_key =7
            elif key%3==0:
                protection_key = 5
            elif key%2==0:
                protection_key = 6
            else:
                protection_key = 8

            
            return fx(tokens,protection_key)
        return wrapper

    @staticmethod
    @starter
    def add_protection(plain_text: str,protection_key: int) -> str:
        '''scrambles each word and adds dummy chars 
        based on word length '''
        protected_text= ''
        for word in plain_text:
            if word.isspace(): # white spaces remain untouch
                protected_text+=word
            else:    
                if len(word) ==1:
                    randomised_left = secrets.choice(chars_for_protection)
                    randomised_right = secrets.choice(chars_for_protection)
                    added_nonce = randomised_left+ word + randomised_right      
                    protected_text += added_nonce

                elif len(word) ==2:
                    randomised_left = secrets.choice(chars_for_protection)
                    randomised_right = secrets.choice(chars_for_protection)
                    randomised_middle = secrets.choice(chars_for_protection)
                    added_nonce = randomised_left+word[0]+randomised_middle+word[1]+randomised_right   #len got to 5
                    protected_text+= added_nonce[::-1]
                
                elif len(word) ==3:
                    randomised_left ="".join(secrets.choice(chars_for_protection) for _ in range(2))
                    randomised_right ="".join(secrets.choice(chars_for_protection) for _ in range(2))
                    randomised_middle =secrets.choice(chars_for_protection)
                    added_nonce = randomised_left+word[1]+randomised_middle+word[0]+randomised_right+word[2]  #len got to 8
                    protected_text += added_nonce   

                else:
                    randomised_left ="".join(secrets.choice(chars_for_protection) for _ in range(protection_key))
                    randomised_right ="".join(secrets.choice(chars_for_protection) for _ in range(protection_key))
                    shuffled_word = word[0] + word[:0:-1]
                    added_nonce =randomised_left+ shuffled_word + randomised_right
                    protected_text +=  added_nonce

                
        return protected_text


    @staticmethod
    @starter
    def remove_protection(encrypted_text: str,protection_key: int) -> str:
        '''undoes add_protection word by word, using word length
        to know which scrambling ,ethod was used'''

        deprotected_text =''
        for word in encrypted_text:
            if word.isspace(): #white spaces remain untouched
                deprotected_text += word
                continue
            else:
                if len(word) ==3:
                    removed_nonce = word[1:-1]
                    deprotected_text +=removed_nonce
                elif len(word) ==5:
                    removed_nonce = word[1::2]   #to remove those left middle and right nonce
                    deprotected_text+=removed_nonce[::-1]
                
                elif len(word) == 8:
                    # just taking with index of original word 
                    removed_nonce = word[4] + word[2] +word[7]
                    deprotected_text += removed_nonce

                else:
                    
                    original_word = word[protection_key:-(protection_key)]
                    deprotected_text += original_word[0]+original_word[:0:-1]
                
        return deprotected_text



#############__________CLI INTRFACE___________#############

class PasswordCheck:
    @staticmethod
    def is_valid(password: str) -> bool:
        '''a basic password validation check'''
        if password=='':
            raise EmptyPasswordError
        if len(password) <3:
            raise ShortPasswordError
        
        allowed_chars = string.ascii_letters+ string.digits + string.punctuation
        is_valid = all(char in allowed_chars for char in password)
        
        if not is_valid:
            raise PasswordFormatError
        return True

class File:
    @staticmethod
    def take_file_input(_path: str):
        '''takes file path and read contents from that file'''

        _path = os.path.expanduser(_path.strip())
        if not os.path.exists(_path):
            console.print(f'[bold red]File {escape(_path)} not found![/]')
            return False,False
        if os.path.isdir(_path):
            console.print(f'[bold red]{escape(_path)} is a directory[/]')
            return False,False
        try:
            with open(_path, 'r', encoding='utf-8') as f:
                return f.read(),_path
        
        except PermissionError:
            console.print('[bold red]Permission denied![/]')
        except UnicodeError:
            console.print('[red]File contains unsupported data![/]')
        except OSError:
            console.print('[red]Cannot read this file![/]')
        return False,False

    

    @staticmethod
    def give_file_name(_path: str, mode: str) -> str:
        '''generates a unique file name based on encryption or decryption mode.
        if filename already exists it adds a numbered prefix'''

        basename = os.path.basename(_path)
        directory = os.path.dirname(_path)
        old , new = ('decrypted', 'encrypted') if mode == 'encrypt' else ('encrypted', 'decrypted')

        if new in basename:
            basename = basename.replace(new, '')
        if old in basename:
            new_name = basename.replace(old, new, 1)
        else:
            new_name = new + '_' + basename
        try:
            pref = int(new_name[0])
            if new_name[1] == '_':
                new_name = new_name[2:]
            i = pref
        except ValueError:
            i = 1
        
        final_name = new_name
        while os.path.exists(os.path.join(directory,final_name)):
            final_name = f'{i}_{new_name}'
            i +=1
        return final_name


    @staticmethod
    def file_save_or_not(text: str, from_file: bool,
        limit: int, recieved_file_path: str,
        mode: str, 
        wrap: bool=False) ->bool:
        '''Saves to filename if it came from file or text > limit.
        Otherwise prints it.
        returns True if text is saved in a file'''

        if from_file or len(text) > limit:
            try:
                file_name = File.give_file_name(recieved_file_path,mode)
                with open(file_name, 'w', encoding='utf-8') as f:
                    f.write(text)
                    console.print(f'[bold green] Saved to {escape(file_name)}')
                    return True
            except OSError:
                console.print('[bold red] Could not save the file. Showing it here instead!\n')
                print(text)
                return False
        print(''.join(textwrap.wrap(text, 75)) if wrap else text)
        return False


class Input:

    @staticmethod
    def take_multi_line_input(input_prompt: str, empty_input_prompt: str):
        '''takes input in multi lines and file input'''
        console.print(input_prompt, end='')
        lines = []
        while True:
            line = console.input()
            command = line.strip().lower()

            if command in (':q', ':quit'):
                return None

            parts = line.strip().split(maxsplit=1)
            if parts and parts[0].lower() in (':f', ':file'):
                if len(parts) < 2:
                    console.print('[yellow]Usage: :file path/to/file.txt[/]')
                    console.print(input_prompt, end='')
                    continue
                content, file_name = File.take_file_input(parts[1])
                if not content:
                    console.print(input_prompt, end='')
                    continue
                if not content.strip():
                    console.print(empty_input_prompt)
                    continue
                return content,file_name, True

            if command in (':done', ':d'):
                if lines:
                    return '\n'.join(lines),None, False
                console.print(empty_input_prompt)
                continue

            lines.append(line)


class CLI:
    '''command line interactivity functions'''
    @staticmethod
    def clear() -> None:
        '''Function for clearing terminal screen'''
        console.clear()

    @staticmethod
    def animate(prompt: str,pattern: str,delay: float) -> None:
        '''animates the given prompt with given pattern and duration'''
        spinner = Spinner(pattern,text=prompt)

        with Live(
            spinner, console=console, refresh_per_second=20
        ):
            time.sleep(delay)

    @staticmethod
    def _panel(prompt: str,title=None,subtitle=None,border_style='blue',expand=False) -> None:
        console.print(
            Panel(
                prompt,title=title,subtitle=subtitle,
                border_style=border_style,expand=expand
            )
        )
    @staticmethod
    def pause():
        '''asks user to press enter to continue'''
        asking = Prompt.ask('[dim]Press enter to continue',default="")



    @staticmethod
    def check_surity(
        prompt= "[italic bright_white]Are you sure to continue with this text and password?[/]"
    ) -> bool:
        """Checks for surity"""
        while True:
            console.print(f"{prompt}[green] (y/n)")
            surity = Prompt.ask("[pink1]>> ")
            if not surity or surity == 'y' or surity == 'yes':
                return True
            return False
            

  
    def encrypt_screen(self) -> None:
        """cli nterface for encryption screen"""
        while True:
            CLI.clear()
            CLI._panel(prompt="[cyan]Enter text to encrypt [/]")
            result = Input.take_multi_line_input(
                input_prompt = '[blue]>> ',
                empty_input_prompt = '[bold yellow]Please enter some text[/bold yellow]\n[bright_yellow]>> '
            )

            if result is None:
                return
            plain_text, file_name, from_file = result
            
            while True:
                # asking for passwd
                CLI._panel('[cyan]Enter a password',border_style='bright_blue')
                passwd = Prompt.ask('[bright_blue]>> ',password=True)
                if passwd.lower() in ('q',':q','quit',':quit'):
                    break
                try:
                    PasswordCheck.is_valid(passwd)
                    # checking for surity
                    sure = CLI.check_surity() 
                    if sure:
                        break
                    continue                   

                except EmptyPasswordError:
                    passwd = console.print('[bold yellow]Please enter a password you want[/bold yellow] ')
                    continue
                except ShortPasswordError:
                    passwd = console.print('[bold yellow]Password must contain at least 3 characters[/bold yellow]  ')
                    continue
                except PasswordFormatError:
                    passwd = console.print('[bold yellow]Password contains invalid characters[/bold yellow] ')
                    continue
                if surity in ('y','yes'):
                    break
            if passwd.lower() in ('q',':q','quit',':quit'):
                continue
            
            try:
                encrypted_text =  Crypt.encrypt(plain_text,password=passwd)
            
            except (ValueError,IndexError,TypeError):
                CLI._panel(prompt='[bold]Invalid text',
                title='[bold red]Encryption unsessessfull![/bold red]',border_style='dark_red')
                CLI.pause()
                continue
            print()
            CLI.animate('Encrypting','dots',1.5)
            console.print('[green]Successfully Encrypted!\n')
            
            saved = File.file_save_or_not(encrypted_text,from_file,ENCRYPTED_LIMIT,file_name,mode='encrypt',wrap=True)
            print()

            if not saved:
                console.print("[dim]Make sure to copy the encrypted text[/]")
                print()
            CLI.pause()
            CLI.clear()

    def decrypt_screen(self) -> None:
        """cli nterface for encryption screen"""

        while True:
            CLI.clear()
            CLI._panel(prompt="[bright_green]Enter text to Decrypt[/]",border_style='bright_cyan')
            result = Input.take_multi_line_input(
                input_prompt='[bright_cyan]>> ',
                empty_input_prompt='[bold yellow]Please enter some text[/bold yellow]'
            )
            if result is None:
                return
            encrypted_text, file_name, from_file = result
            
            while True:
                # asking for passwd
                CLI._panel('[deep_sky_blue1]Enter your password',border_style='bright_blue')
                passwd = Prompt.ask('[bright_blue]>>',password=True)
                if passwd.lower() in ('q',':q','quit',':quit'):
                    break
                try:
                    PasswordCheck.is_valid(passwd)
                    # checking for surity                    
                    sure = CLI.check_surity() 
                    if sure:
                        break
                    continue                   

                except EmptyPasswordError:
                    passwd = console.print('[bold yellow]Please enter a password you want[/bold yellow] ')
                    continue
                except ShortPasswordError:
                    passwd = console.print('[bold yellow]Password must contain at least 3 characters[/bold yellow]  ')
                    continue
                except PasswordFormatError:
                    passwd = console.print('[bold yellow]Password contains invalid characters[/bold yellow] ')
                    continue
            
                if surity:
                    break
                continue
            if passwd.lower() in ('q',':q','quit',':quit'):
                continue
            
            try:
                decrypted_text = Crypt.decrypt(data=encrypted_text.strip(), password=passwd)

            except AuthenticationError:
                CLI._panel(title='[bold red]Decryption unsessessfull![/bold red]',
                prompt='Authentication Failed!\nInvalid password or corrupted data!',
                border_style='magenta')
                CLI.pause()
                continue
            except (ValueError,IndexError) as e:
                CLI._panel(title='[bold red]Decryption unsessessfull![/bold red]',
                prompt='Invalid password or corrupted data!',
                border_style='dark_red')
                CLI.pause()
                continue

            print()
            CLI.animate('Decrypting','dots',1.5)
            console.print('[green]Successfully Decrypted!\n')
            
            saved = File.file_save_or_not(decrypted_text,from_file,DECRYPTED_LIMIT,file_name,mode='decrypt')
            print()
            if not saved:
                console.print("[dim]Make sure to copy the encrypted text[/]")
                print()
            CLI.pause()
            CLI.clear()

    def welcome(self) -> None:
        """welcome screen"""
        msg = f"""       [dim italic]Custom Encryption & Decryption[/]\n
            [sky_blue2]Welcome back,[/] [bold bright_white]{username}[/]\n
    [dim]Your text. Your password. Your control.[/]"""
        
        console.print(
        Panel(
            Align.center(
                msg
            ),
            title="[bold light_goldenrod1]⚡ lighCrypt [/]",
            subtitle="[dim]v1.0[/]",
            border_style="gold1",
            padding=(1,5),
            expand=True
    )
)



    def bye(self)->None:
        '''Bye screen'''
        msg = f"""    [dim]Session closed for[/] [bold white]{username}[/]!\n
    [italic navajo_white1]Thanks for using lighCrypt![/]\n\
        [bold italic deep_sky_blue1]✨See you next time![/]\n
    [dim]Keep exploring. Keep creating.[/]"""
        
        console.print(
        Panel(
            Align.center(
                msg
            ),
            title="[gold1] ⚡ lighCrypt [/]",
            subtitle="[bright_green]BYE[/]",
            border_style="sky_blue1",
            padding=(1, 7),
            expand=True
    )
)


    def main_menu(self) -> None:
        menu =  """[bold bright_green]1[/]  Encrypt\n
[bold bright_magenta]2[/]  Decrypt\n
[bold bright_blue]3[/]  Help\n
[bold bright_red]4[/]  Exit\n\n
[iitalic]Enter q anywhere to get 1 step back """
        CLI.clear()
        while True:
            console.print(
            Panel(
                Align.center(
                menu
                ),
                title="[bold deep_sky_blue1] HOME [/]",
                border_style="turquoise2",
                padding=(1, 6),
                expand=False
                )
            )
            option = console.input('[dim]>> ')
                       
            if option == '1':
                self.encrypt_screen()
                CLI.clear()
            elif option =='2':
                self.decrypt_screen()
                CLI.clear()
            elif option == '3':
                self.help_screen()
                CLI.clear()
            elif option == '4':
                raise KeyboardInterrupt #for exiting
            else:
                CLI.clear()
                console.print('[bright yellow]Enter a valid option[/] [green](1/2/3/4)[/] ')


    def help_screen(self) -> None:
        help_menu = f'''    [bold blue]1[/] About lighCrypt\n
    [bold green]2[/] Password\n
    [bold dark_green]3[/] Navigation\n
    [bold bright_yellow]4[/] How lighCrypt Works? 
        '''

        while True:
            CLI.clear()
            console.print(
                Panel(
                Align.center(
                    help_menu
                ),
                title='[bold pink1]HELP',
                expand=False,
                padding=(1,5),
                border_style='hot_pink'
            
            )    
        )
            option = console.input('[dim]>>  ')

            while not option in ('1','2','3','4','q',':q','quit',':quit'):
                CLI.clear()        
                console.print(
                Panel(
                Align.center(
                    help_menu
                ),
                title='[bold pink1]HELP',
                expand=False,
                padding=(1,5),
                border_style='hot_pink'

            )
        )

                console.print("[yellow]Choose[/] [bright_green](1/2/3/q)")
                option = console.input('[pink1]>>  ')
            if option.lower() in  ('q',':q','quit',':quit'):
                return
            elif option =='1':
                about_lighCrypt = (

    "[bold blue]Hey there! 👋[/]\n"
    "[white]Welcome to lighCrypt — a custom Python project built "
    "to learn, experiment with cryptography, and have some fun "
    "in the terminal.[/]\n\n"

    "[bold bright_blue]About the Project[/]\n"
    "[white]lighCrypt is a personal project created by "
    "[bright_blue]lighning95[/]. It is fully open source and was built "
    "as a way to explore Python, encryption, and custom cryptographic "
    "ideas through a real working project.[/]\n\n"

    "[bold bright_blue]What Makes lighCrypt Different?[/]\n"
    "[white]lighCrypt combines established building blocks such as "
    "[bright_green]PBKDF2-HMAC-SHA256[/] and [bright_green]HMAC-SHA256[/] "
    "with a 16-byte random salt and 32-byte authentication tag, alongside its "
    "own custom key-stream,  character-encryption and text-protection systems.[/]\n\n"

    "[red]⚠[/] [bold bright_yellow]Important Security Note[/]\n"
    "[yellow]lighCrypt has not been tested or audited by professional "
    "cryptographers. It is intended for learning, experimenting, "
    "casual use, and educational purposes — not for sensitive, "
    "private, or critical data.[/]\n\n"

    "[bold bright_blue]Responsible Use[/]\n"
    "lighCrypt is provided for learning, experimentation, "
    "casual use, and educational purposes. Please use it responsibly "
    "and [italic red]do not use it for harmful, illegal, or unauthorized activities.[/]\n"
    "[yellow2]Any misuse of lighCrypt or its features is the responsibility "
    "of the person using the software.[/]\n\n"

    "[bold bright_green]🔐 Keep Your Password Safe[/]\n"
    "[white]Your password is important. Keep it secret, keep it safe, "
    "and don't forget it. The same password is needed to decrypt "
    "your encrypted data.[/]\n\n"

    "[bold bright_blue]Open Source[/]\n"
    "[white]lighCrypt is fully open source. Feel free to explore "
    "the code, learn from it, experiment with it, and see how "
    "everything works under the hood.[/]\n\n"

    "[bold bright_cyan]💡 Feedback & GitHub[/]\n"
    "[white]Found a bug, have an idea, or think something could be "
    "better? I'd genuinely love to hear from you![/]\n"
    "[bright_green]GitHub:[/] [white]lighning-95[/]\n"
    "[bright_green]Repository:[/] [white]https://github.com/lighning-95/lighCrypt.git[/]\n\n"

    "[italic turquoise2]Thanks for trying lighCrypt — "
    "have fun exploring! 💚[/]"
)
                CLI.clear()
                console.print(
                    Panel(
                        about_lighCrypt,
                        title="[bold bright_cyan] ABOUT [/]",
                        border_style="dark_green"
                    )
                )

                CLI.pause()
                

            elif option =='2':
                about_password=(
    "[bold bright_blue]Password Rules[/]\n\n"

    "[bright_green]•[/] [white]Minimum length:[/] "
    "[yellow1]3 characters[/]\n"
    "[bright_green]•[/] [white]Letters, numbers, and punctuation are allowed.[/]\n"
    "[bright_green]•[/] [white]Passwords are case-sensitive.[/]\n\n"

    "[bold bright_blue]Password Privacy[/]\n\n"

    "[bright_green]•[/] [white]Your password is hidden while typing "
    "for better privacy.[/]\n"
    "[bright_green]•[/] [white]Your password is not displayed on screen.[/]\n"
    "[bright_green]•[/] [white]Never share your password with others.[/]\n\n"

    "[bold bright_blue]Password Confirmation[/]\n\n"

    "[white]When creating a password, lighCrypt asks you to "
    "confirm it using a [yellow1]Y/N[/] choice.[/]\n"
    "[white]This helps prevent accidental password typos.[/]\n\n"

    "[bold bright_blue]During Decryption[/]\n\n"

    "[bright_green]•[/] [white]Use the exact same password used during encryption.[/]\n"
    "[bright_green]•[/] [white]A wrong password will fail authentication.[/]\n"
    "[bright_green]•[/] [white]There is no password recovery.[/]\n\n"

    "[bold bright_blue]Important[/]\n\n"

    "[yellow1]🔑 Keep your password safe and secret.[/]\n"
    "[yellow1]🔑 Don't forget your password.[/]\n"
    "[yellow1]🔑 The same password is required for decryption.[/]\n\n"

    "[bold bright_blue]Going Back[/]\n\n"

    "[white]Enter[/][blue] q [/]or[blue] :quit [/][white]to go back one step while entering a password.[/]\n\n"

    "[italic turquoise2]Choose a password you can remember, "
    "but others cannot easily guess.[/]"
)
                CLI.clear()
                console.print(
                    Panel(
                        about_password,
                        title="[bold bright_cyan] PASSWORD [/]",
                        border_style="pink1"
                    )
                )
                CLI.pause()
            elif option =='3':
                navigation = (
"\n"
"[cyan]Main Menu[/]\n\n"
"[pink1]1[/] [white]Encrypt[/] - Encrypt text\n"
"[pink1]2[/] [white]Decrypt[/] - Decrypt text\n"
"[pink1]3[/] [white]Help[/] - Show help\n"
"[pink1]4[/] [white]Exit[/] - Exit lighCrypt\n\n"

"[cyan]↩ Going Back[/]\n\n"
"[white]While entering text in Encrypt/Decrypt:[/]\n"
"[dim]│[/] [yellow]:q[/] [white]or[/] [yellow]:quit[/] - Cancel text input and go back\n\n"

"[white]In other screens:[/]\n"
"[dim]│[/] [yellow]q[/] [white]or[/] [yellow]:q[/] [white]or[/][yellow] quit [/] [white]or[/] [yellow]:quit[/] - Go back\n\n"

"[cyan]✏ Text Input Commands[/]\n\n"
"[dim]│[/] [yellow]:d[/] [white]or[/] [yellow]:done[/] - Finish entering text\n\n"
"[dim]│[/] [yellow]:f path/to/file.txt[/] [white]or[/] "
"[yellow]:file path/to/file.txt[/] - Load text from a file"

)               
                CLI.clear()
                console.print(
                    Panel(navigation,
                      title="[bold blue]🧭 Navigation[/]",
                      border_style='magenta'
  )
)
                CLI.pause()    

            elif option== '4':
                how_it_works = (
"[bold bright_cyan]⚡ How lighCrypt Works[/]\n\n"

"[bold bright_blue]🔐 Encryption[/]\n\n"

"[bold bright_magenta]1. Plaintext & Password[/]\n"
"[white]The user provides text and a password.[/]\n\n"

"[bold bright_magenta]2. Random Salt[/]\n"
"[white]lighCrypt generates a random [/]"
"[bold green]16-byte salt[/] "
"[white]using [/][bold yellow]os.urandom()[/].\n\n"

"[bold bright_magenta]3. Key Generation[/]\n"
"[white]PBKDF2-HMAC-SHA256 with [/]"
"[bold green]1,000,000 iterations[/] "
"[white]derives 32-byte seeds from the password, "
"salt, and different purposes.[/]\n\n"

"[bold bright_magenta]4. Text Protection[/]\n"
"[white]The text is escaped, rearranged, and padded with "
"random characters using lighCrypt's custom algorithms.[/]\n\n"

"[bold bright_magenta]5. Encryption[/]\n"
"[white]A custom [/][bold green]HMAC-SHA256[/][white]-based key stream "
"shifts characters through lighCrypt's character set.[/]\n\n"

"[bold bright_magenta]6. Authentication[/]\n"
"[white]HMAC-SHA256 creates an [/]"
"[bold green]authentication tag[/] "
"[white]to detect an incorrect password or modified data.[/]\n\n"

"[bold bright_magenta]7. Final Output[/]\n"
"[white]Protected salt, encrypted text, and encrypted tag are "
"combined and encoded with [/][bold yellow]URL-safe Base64[/]\n\n"

"[bold bright_green]🔓 Decryption[/]\n\n"
"[white]The process is reversed: the salt is recovered, the "
"authentication tag is verified, the same key stream is "
"regenerated, and the encrypted text is decrypted and "
"restored to its original form.[/]\n\n"

"[bold bright_yellow]⚠ Security Note[/]\n"
"[yellow]lighCrypt uses established cryptographic building blocks, "
"but its overall encryption design is custom and has not been "
"professionally audited. It is intended for learning and "
"experimentation, not highly sensitive data.[/]"

)
               
                CLI.clear()
                console.print(
                Panel(
                    how_it_works,
                    title="[bold bright_cyan] HOW IT WORKS [/]",
                    border_style="dark_green"
                    )
                )
                CLI.pause()

            else:
                console.print('[dim]Enter any of the following options[dim] [green](1/2/3)')

def main()->None:

    CLI.clear()
    app.welcome()
    CLI.pause()
    app.main_menu()


if __name__=='__main__':
    app =CLI()
    console = Console()

    try:
        username = getuser()
        main()

    except (KeyboardInterrupt,EOFError):
        CLI.clear()
        app.bye()

