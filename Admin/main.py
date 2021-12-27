# импорты для GUI
from tkinter import *
from tkinter import scrolledtext
from tkinter.ttk import Combobox
from tkinter import messagebox
from tkinter.filedialog import askopenfilename
from tkinter.filedialog import asksaveasfilename

import secrets
import string
import datetime
import base64
from os import urandom
import binascii
# импорты для EDCSA
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
# импорты для GOST
from pygost.gost3410 import CURVES
from pygost.gost3410 import prv_unmarshal
from pygost import gost3412
from pygost.gost3410 import public_key
from pygost import gost34112012512
from pygost.gost3410 import sign

# Список глобальных переменных
global privkey
global cert
global algorithm

# Насройки окна
window = Tk()
window.title('Система электронная зачетка: Удостоверяющий центр')
window.geometry('1730x640')

# Список фреймов
# 1. Левая часть окна
Base_frame_left = Frame(window)
Base_frame_left.grid(row=0, column=0)

# 2. Правая часть окна
Base_frame_right = Frame(window)
Base_frame_right.grid(row=0, column=1)

# 3. Фрейм по работе с подписями
Sign_frame = Frame(Base_frame_left)
Sign_frame.grid(row=0, column=0)

# 4. Фрейм по созданию закрытого ключа
Create_private_key_frame = Frame(Base_frame_right)
Create_private_key_frame.grid(row=0, column=0)

# 5. Фрейм с созданием сертификата
Create_certificate_frame = Frame(Base_frame_right)
Create_certificate_frame.grid(row=1, column=0)

# Список используемых Лейблов(текстовых полей)
# 1. Labels для создания закрытого ключа
Create_key_header = Label(Create_private_key_frame, text="ФОРМИРОВАНИЕ СЕКРЕТНОГО КЛЮЧА")
Create_key_header.grid(row=0, column=0, columnspan=3, pady=10)

Elliptic_curve = Label(Create_private_key_frame, text="Выберите эллиптическую кривую: ")
Elliptic_curve.grid(row=2, column=0, pady=5, padx=70)

Password_select = Label(Create_private_key_frame, text="Задайте пароль для работы с секретным ключом: ")
Password_select.grid(row=3, column=0, pady=5)

Create_key_result = Label(Create_private_key_frame, text="Результат формирования секретного ключа:")
Create_key_result.grid(row=1, column=2)

# 2. Labels для создания сертификата
Create_cert_header = Label(Create_certificate_frame, text="ФОРМИРОВАНИЕ СЕРТИФИКАТА")
Create_cert_header.grid(row=0, column=0, columnspan=3, pady=10)

Password_point = Label(Create_certificate_frame, text="Введите пароль для работы с секретным ключом: ")
Password_point.grid(row=3, column=0, pady=5)

Name_select = Label(Create_certificate_frame, text="Введите имя, фамилию и отчество владельца сертификата: ")
Name_select.grid(row=4, column=0, pady=5)

Email_select = Label(Create_certificate_frame, text="Введите адрес электронной почты владельца сертификата: ")
Email_select.grid(row=5, column=0, pady=5)

Data_select = Label(Create_certificate_frame, text="Введите срок действия сертификата (в днях): ")
Data_select.grid(row=6, column=0, pady=5)

Cert_result = Label(Create_certificate_frame, text="Результат формирования сертификата:")
Cert_result.grid(row=1, column=2)

# 3. Labels для работы с подписями
header_sign = Label(Sign_frame, text="ФОРМИРОВАНИЕ ПОДПИСИ")
header_sign.grid(row=0, column=0, columnspan=4, pady=10)

result = Label(Sign_frame, text="Результат формирования подписи:", pady=5)
result.grid(row=1, column=2)

password = Label(Sign_frame, text="Введите пароль для работы с секретным ключом:", pady=5)
password.grid(row=4, column=0)

verefy_sign = Label(Sign_frame, text="ПРОВЕРКА ПОДПИСИ")
verefy_sign.grid(row=9, column=0, columnspan=4, pady=10)

verefy_result = Label(Sign_frame, text="Результат проверки подписи:", pady=5)
verefy_result.grid(row=10, column=2)


# Список используемых Энтри (Полей ввода)
# 1. Entry для создания закрытого ключа
Elliptic_curve_entry = Combobox(Create_private_key_frame, width=25)
Elliptic_curve_entry['values'] = ('NIST P-256',
                                  'NIST P-384',
                                  'NIST P-521',
                                  'NIST P-224',
                                  'NIST P-192',
                                  'ГОСТ 34.10-2012, 256 бит, А',
                                  'ГОСТ 34.10-2012, 256 бит, Б',
                                  'ГОСТ 34.10-2012, 256 бит, В',
                                  'ГОСТ 34.10-2012, 512 бит, А',
                                  'ГОСТ 34.10-2012, 512 бит, Б',
                                  'ГОСТ 34.10-2012, 512 бит, В',
                                  )
Elliptic_curve_entry.grid(row=2, column=1)

Password_select_entry = Entry(Create_private_key_frame, width=29)
Password_select_entry.grid(row=3, column=1)

Private_key_entry = scrolledtext.ScrolledText(Create_private_key_frame, width=40, height=15)
Private_key_entry.grid(row=2, column=2, rowspan=5, padx=10)

# 2. Entry для создания сертификата
Load_key_point_entry = Entry(Create_certificate_frame, width=29)
Load_key_point_entry.grid(row=2, column=1)

Password_entry = Entry(Create_certificate_frame, width=29)
Password_entry.grid(row=3, column=1)

Name_select_entry = Entry(Create_certificate_frame, width=29)
Name_select_entry.grid(row=4, column=1)

Email_select_entry = Entry(Create_certificate_frame, width=29)
Email_select_entry.grid(row=5, column=1)

Data_select_entry = Entry(Create_certificate_frame, width=29)
Data_select_entry.grid(row=6, column=1)

Cert_result_entry = scrolledtext.ScrolledText(Create_certificate_frame, width=40, height=15)
Cert_result_entry.grid(row=2, column=2, rowspan=7, padx=10)

chk_state_ECDSA_cert = BooleanVar()
chk_state_ECDSA_cert.set(False)
ECDSA_check_cert = Checkbutton(Create_certificate_frame, text="ECDSA", var=chk_state_ECDSA_cert)
ECDSA_check_cert.grid(row=7, column=0)

chk_state_GOST_cert = BooleanVar()
chk_state_GOST_cert.set(False)
GOST_check_cert = Checkbutton(Create_certificate_frame, text="ГОСТ 34.10-12", var=chk_state_GOST_cert)
GOST_check_cert.grid(row=8, column=0)

# 3. Entry для работы с подписями
subscribe_file_entry = Entry(Sign_frame, width=29)
subscribe_file_entry.grid(row=2, column=1, padx=10)

priv_key_entry = Entry(Sign_frame, width=29)
priv_key_entry.grid(row=3, column=1)

password_entry = Entry(Sign_frame, width=29)
password_entry.grid(row=4, column=1)

chk_state_ECDSA = BooleanVar()
chk_state_ECDSA.set(False)
ECDSA_check = Checkbutton(Sign_frame, text="ECDSA", var=chk_state_ECDSA)
ECDSA_check.grid(row=5, column=0)

chk_state_GOST = BooleanVar()
chk_state_GOST.set(False)
GOST_check = Checkbutton(Sign_frame, text="ГОСТ 34.10-12", var=chk_state_GOST)
GOST_check.grid(row=6, column=0)

sign_result = scrolledtext.ScrolledText(Sign_frame, width=40, height=15)
sign_result.grid(row=2, column=2, rowspan=7, padx=10)

verefy_file_entry = Entry(Sign_frame, width=29)
verefy_file_entry.grid(row=11, column=1, pady=5)

sign_file_entry = Entry(Sign_frame, width=29)
sign_file_entry.grid(row=12, column=1, pady=5)

cert_file_entry = Entry(Sign_frame, width=29)
cert_file_entry.grid(row=13, column=1, pady=5)

verefy_result = scrolledtext.ScrolledText(Sign_frame, width=40, height=15)
verefy_result.grid(row=11, column=2, rowspan=7, padx=10)

chk_state_ECDSA_verefy = BooleanVar()
chk_state_ECDSA_verefy.set(False)
ECDSA_check_verefy = Checkbutton(Sign_frame, text="ECDSA", var=chk_state_ECDSA_verefy)
ECDSA_check_verefy.grid(row=14, column=0)

chk_state_GOST_verefy = BooleanVar()
chk_state_GOST_verefy.set(False)
GOST_check_verefy = Checkbutton(Sign_frame, text="ГОСТ 34.10-12", var=chk_state_GOST_verefy)
GOST_check_verefy.grid(row=15, column=0)


# Список функций работы приложения
# 1. Функция генерации пароля
def password_gen():
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(10))
    Password_select_entry.delete(0, END)
    Password_select_entry.insert(0, password)

# 2. Функция генерации закрытого ключа
def create_private_key():
    global privkey
    global algorithm

    if Elliptic_curve_entry.get() == 'NIST P-256':
        curve = ec.SECP256R1()
        algorithm = "ECDSA"
    elif Elliptic_curve_entry.get() == 'NIST P-384':
        curve = ec.SECP384R1()
        algorithm = "ECDSA"
    elif Elliptic_curve_entry.get() == 'NIST P-521':
        curve = ec.SECP521R1()
        algorithm = "ECDSA"
    elif Elliptic_curve_entry.get() == 'NIST P-224':
        curve = ec.SECP224R1()
        algorithm = "ECDSA"
    elif Elliptic_curve_entry.get() == 'NIST P-192':
        curve = ec.SECP192R1()
        algorithm = "ECDSA"
    elif Elliptic_curve_entry.get() == 'ГОСТ 34.10-2012, 256 бит, А':
        curve = CURVES["id-tc26-gost-3410-2012-256-paramSetA"]
        algorithm = "GOST"
    elif Elliptic_curve_entry.get() == 'ГОСТ 34.10-2012, 256 бит, Б':
        curve = CURVES["id-tc26-gost-3410-2012-256-paramSetB"]
        algorithm = "GOST"
    elif Elliptic_curve_entry.get() == 'ГОСТ 34.10-2012, 256 бит, В':
        curve = CURVES["id-tc26-gost-3410-2012-256-paramSetC"]
        algorithm = "GOST"
    elif Elliptic_curve_entry.get() == 'ГОСТ 34.10-2012, 512 бит, А':
        curve = CURVES["id-tc26-gost-3410-12-512-paramSetA"]
        algorithm = "GOST"
    elif Elliptic_curve_entry.get() == 'ГОСТ 34.10-2012, 512 бит, Б':
        curve = CURVES["id-tc26-gost-3410-12-512-paramSetB"]
        algorithm = "GOST"
    elif Elliptic_curve_entry.get() == 'ГОСТ 34.10-2012, 512 бит, В':
        curve = CURVES["id-tc26-gost-3410-2012-512-paramSetC"]
        algorithm = "GOST"
    else:
        messagebox.showinfo('Ошибка!', 'Выбрана неверная эллептическая кривая!')
        return

    if Password_select_entry.get() == '':
        messagebox.showinfo('Ошибка!', 'Неверно задан пароль! Минимальная длинна пароля – 10 символов. Пароль должен содержать буквы нижнего и верхнего регистров, а также хотя бы одну цифру.')
        return
    if len(Password_select_entry.get()) < 10:
        messagebox.showinfo('Ошибка!', 'Неверно задан пароль! Минимальная длинна пароля – 10 символов. Пароль должен содержать буквы нижнего и верхнего регистров, а также хотя бы одну цифру.')
        return

    if algorithm == "ECDSA":
        private_key = ec.generate_private_key(curve, backend=default_backend())
        key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(bytes(Password_select_entry.get(), encoding='utf-8')),
        )
        privkey = private_key
        Private_key_entry.delete(0.0, END)
        Private_key_entry.insert(0.0, key)
    else:
        #задать пароль, который будет ключем для магмы 32 символа
        password = Password_select_entry.get()
        while len(password) < 32:
            password = password + password
        password = password[:32:]
        magma_key = binascii.hexlify(bytes(str.encode(password)))

        key = prv_unmarshal(urandom(64))
        while len(binascii.hexlify(bytes(str.encode(str(key))))) % 2 != 0:
            key = prv_unmarshal(urandom(64))
        plaintext = binascii.hexlify(bytes(str.encode(str(key))))
        cipher = gost3412.GOST3412Magma(magma_key)
        chirt_text = b''
        text_to_magma = b''

        # Шифрование Магма
        while len(plaintext) > 0:
            if len(plaintext) < 8:
                while len(plaintext) < 8:
                    plaintext = plaintext + b'00'
            text_to_magma = plaintext[:8:]
            chirt_text = chirt_text + cipher.encrypt(text_to_magma)
            plaintext = plaintext[8:]
        chirt_text = base64.b64encode(chirt_text)

        Private_key_entry.delete(0.0, END)
        Private_key_entry.insert(1.0, '-----BEGIN EC PRIVATE KEY-----\n')
        Private_key_entry.insert(2.0, 'Type: ENCRYPTED\n')
        Private_key_entry.insert(3.0, 'Info: GOST R 34.12-2015\n')
        Private_key_entry.insert(4.0, 'Curve: ' + Elliptic_curve_entry.get() + '\n')
        Private_key_entry.insert(5.0, '\n')
        Private_key_entry.insert(6.0, chirt_text)
        Private_key_entry.insert(7.0, '\n-----END EC PRIVATE KEY-----')

# 3. Функция сохранения приватного ключа
def save_private_key():
    global privkey
    global algorithm

    if algorithm == "ECDSA":
        filepath = asksaveasfilename(
            filetypes=[("PEM Files", "*.pem")],
        )
        if not filepath:
            return
        with open("" + filepath + ".pem", 'wb') as save_file:
            save_file.write(privkey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(str.encode(Password_select_entry.get())),
            ))
            save_file.close()
    else:
        filepath = asksaveasfilename(
            filetypes=[("PEM Files", "*.pem")],
        )
        if not filepath:
            return
        with open("" + filepath + ".pem", 'w') as save_file:
            save_file.write(Private_key_entry.get(0.0, END))
            save_file.close()

# 4. Функция загрузки закрытого ключа
def open_private_key():
    filepath = askopenfilename(
        filetypes=[("PEM Files", "*.pem")]
    )
    if not filepath:
        return
    Load_key_point_entry.delete(0, END)
    Load_key_point_entry.insert(0, filepath)

# 5. Функция генерации сертификата
def create_Certificate():
    global cert
    global algorithm

    Cert_result_entry.delete(0.0, END)

    if (chk_state_ECDSA_cert.get() == True) and (chk_state_GOST_cert.get() == True):
        messagebox.showinfo('Ошибка!', 'Выберите один из алгоритмов.')
        return
    elif (chk_state_ECDSA_cert.get() != True) and (chk_state_GOST_cert.get() != True):
        messagebox.showinfo('Ошибка!', 'Выберите один из алгоритмов.')
        return
    elif chk_state_ECDSA_cert.get() == True:
        algorithm = 'ECDSA'
    else:
        algorithm = 'GOST'

    country = "RU"
    area = "KLD"
    city = "KLGD"
    organization = "BFU"
    name = Name_select_entry.get()
    email = Email_select_entry.get()
    time = int(Data_select_entry.get())

    if algorithm == 'ECDSA':
        private_key_file = open(Load_key_point_entry.get(), 'rb')
        pem_data = private_key_file.read()
        private_key = load_pem_private_key(pem_data, password=bytes(Password_entry.get(), encoding='utf-8'))
        private_key_file.close()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, area),
            x509.NameAttribute(NameOID.LOCALITY_NAME, city),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=time)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        Cert_result_entry.insert(0.0, cert.public_bytes(serialization.Encoding.PEM))
    else:
        # задать пароль, который будет ключем для магмы 32 символа
        password = Password_entry.get()
        while len(password) < 32:
            password = password + password
        password = password[:32:]
        magma_key = binascii.hexlify(bytes(str.encode(password)))

        cipher = gost3412.GOST3412Magma(magma_key)
        plaintext = b''

        private_key_PEM = open(Load_key_point_entry.get(), 'r')
        count = 0
        while True:
            line = private_key_PEM.readline()
            if count == 3:
                curve = line[7:34]
                curve_str = curve
            if count == 5:
                chirt_text = base64.b64decode(bytes(line, encoding='utf-8'))
                break
            if count > 5:
                break
            count += 1
        private_key_PEM.close()

        while len(chirt_text) > 0:
            text_to_magma = chirt_text[:8:]
            plaintext = plaintext + cipher.decrypt(text_to_magma)
            chirt_text = chirt_text[8:]
        if plaintext.find(b'00'):
            plaintext = plaintext[:plaintext.find(b'00')]

        private_key = int(binascii.unhexlify(plaintext).decode())

        if curve.join('ГОСТ 34.10-2012, 256 бит, А'):
            curve = CURVES["id-tc26-gost-3410-2012-256-paramSetA"]
        elif curve.join('ГОСТ 34.10-2012, 256 бит, Б'):
            curve = CURVES["id-tc26-gost-3410-2012-256-paramSetB"]
        elif curve.join('ГОСТ 34.10-2012, 256 бит, В'):
            curve = CURVES["id-tc26-gost-3410-2012-256-paramSetC"]
        elif curve.join('ГОСТ 34.10-2012, 512 бит, А'):
            curve = CURVES["id-tc26-gost-3410-12-512-paramSetA"]
        elif curve.join('ГОСТ 34.10-2012, 512 бит, Б'):
            curve = CURVES["id-tc26-gost-3410-12-512-paramSetB"]
        elif curve.join('ГОСТ 34.10-2012, 512 бит, В'):
            curve = CURVES["id-tc26-gost-3410-2012-512-paramSetC"]

        pub = public_key(curve, private_key)
        pub = str(pub)
        Cert_result_entry.insert(1.0, '-----BEGIN CERTIFICATE-----\n')
        Cert_result_entry.insert(2.0, base64.b64encode(bytes(curve_str, encoding='utf-8')))
        Cert_result_entry.insert(3.0, base64.b64encode(bytes(country, encoding='utf-8')))
        Cert_result_entry.insert(4.0, base64.b64encode(bytes(area, encoding='utf-8')))
        Cert_result_entry.insert(5.0, base64.b64encode(bytes(city, encoding='utf-8')))
        Cert_result_entry.insert(6.0, base64.b64encode(bytes(organization, encoding='utf-8')))
        Cert_result_entry.insert(7.0, base64.b64encode(bytes(name, encoding='utf-8')))
        Cert_result_entry.insert(8.0, base64.b64encode(bytes(email, encoding='utf-8')))
        Cert_result_entry.insert(9.0, base64.b64encode(bytes(pub, encoding='utf-8')))
        Cert_result_entry.insert(10.0, '\n-----END CERTIFICATE-----')

# 6. Функция сохранения сертификата
def save_cert():
    global algorithm
    if algorithm == 'ECDSA':
        global cert

        filepath = asksaveasfilename(
            filetypes=[("PEM Files", "*.pem")],
        )
        if not filepath:
            return
        with open("" + filepath + ".pem", 'wb') as save_file:
            save_file.write(cert.public_bytes(serialization.Encoding.PEM))
            save_file.close()
    else:
        filepath = asksaveasfilename(
            filetypes=[("PEM Files", "*.pem")],
        )
        if not filepath:
            return
        with open("" + filepath + ".pem", "w") as f:
            f.write(Cert_result_entry.get(0.0, END))
            f.close()

# 7. Функция открытия файла для подписи
def open_file():
    filepath = askopenfilename(
        filetypes=[("PDF Files", "*.pdf")]
    )
    subscribe_file_entry.delete(0, END)
    subscribe_file_entry.insert(0, filepath)

# 8. Функция открытия закрытого ключа для подписи
def open_private_key_sign():
    filepath = askopenfilename(
        filetypes=[("PEM Files", "*.pem")]
    )
    if not filepath:
        return
    priv_key_entry.delete(0, END)
    priv_key_entry.insert(0, filepath)

# 9. Функция генерации подписи
def create_signature():
    global algorithm

    if (chk_state_ECDSA.get() == True) and (chk_state_GOST.get() == True):
        messagebox.showinfo('Ошибка!', 'Выберите один из алгоритмов.')
        return
    elif (chk_state_ECDSA.get() != True) and (chk_state_GOST.get() != True):
        messagebox.showinfo('Ошибка!', 'Выберите один из алгоритмов.')
        return
    elif chk_state_ECDSA.get() == True:
        algorithm = 'ECDSA'
    else:
        algorithm = 'GOST'

    sign_result.delete(0.0, END)

    if algorithm == 'ECDSA':
        pas = password_entry.get()
        private_key_PEM = open(priv_key_entry.get(), 'rb')
        pem_data = private_key_PEM.read()
        private_key = load_pem_private_key(pem_data, password=str.encode(pas))
        private_key_PEM.close()

        sign_file = open(subscribe_file_entry.get(), 'rb')
        data = sign_file.read()
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        encodet_signature = base64.b64encode(signature)
        sign_result.insert(0.0, encodet_signature)
        sign_file.close()
    else:
        # задать пароль, который будет ключем для магмы 32 символа
        password = password_entry.get()
        while len(password) < 32:
            password = password + password
        password = password[:32:]
        magma_key = binascii.hexlify(bytes(str.encode(password)))

        cipher = gost3412.GOST3412Magma(magma_key)
        plaintext = b''

        private_key_PEM = open(priv_key_entry.get(), 'r')
        count = 0
        while True:
            line = private_key_PEM.readline()
            if count == 3:
                curve = line[7:34]
            if count == 5:
                chirt_text = base64.b64decode(bytes(line, encoding='utf-8'))
                break
            if count > 5:
                break
            count += 1
        private_key_PEM.close()

        while len(chirt_text) > 0:
            text_to_magma = chirt_text[:8:]
            plaintext = plaintext + cipher.decrypt(text_to_magma)
            chirt_text = chirt_text[8:]
        if plaintext.find(b'00'):
            plaintext = plaintext[:plaintext.find(b'00')]

        private_key = int(binascii.unhexlify(plaintext).decode())

        if curve.join('ГОСТ 34.10-2012, 256 бит, А'):
            curve = CURVES["id-tc26-gost-3410-2012-256-paramSetA"]
        elif curve.join('ГОСТ 34.10-2012, 256 бит, Б'):
            curve = CURVES["id-tc26-gost-3410-2012-256-paramSetB"]
        elif curve.join('ГОСТ 34.10-2012, 256 бит, В'):
            curve = CURVES["id-tc26-gost-3410-2012-256-paramSetC"]
        elif curve.join('ГОСТ 34.10-2012, 512 бит, А'):
            curve = CURVES["id-tc26-gost-3410-12-512-paramSetA"]
        elif curve.join('ГОСТ 34.10-2012, 512 бит, Б'):
            curve = CURVES["id-tc26-gost-3410-12-512-paramSetB"]
        elif curve.join('ГОСТ 34.10-2012, 512 бит, В'):
            curve = CURVES["id-tc26-gost-3410-2012-512-paramSetC"]

        data_for_signing = open(subscribe_file_entry.get(), 'rb')
        data = data_for_signing.read()
        data_for_signing.close()
        dgst = gost34112012512.new(data).digest()[::-1]
        signature = sign(curve, private_key, dgst)
        dgst = base64.b64encode(dgst)
        signature = base64.b64encode(signature)
        sign_result.insert(1.0, signature)
        sign_result.insert(2.0, dgst)

# 10. Функция сохранения подписи
def save_signature():
    global algorithm
    if algorithm == 'ECDSA':
        encodet_signature = sign_result.get(0.0, END)
        encodet_signature = base64.b64decode(encodet_signature)
        filepath = asksaveasfilename(
            filetypes=[("Текстовые файлы", "*.txt")],
        )
        if not filepath:
            return
        with open("" + filepath + ".txt", "wb") as f:
            f.write(encodet_signature)
            f.close()
    else:
        filepath = asksaveasfilename(
            filetypes=[("Текстовые файлы", "*.txt")],
        )
        if not filepath:
            return
        with open("" + filepath + ".txt", "w") as f:
            f.write(sign_result.get(0.0, END))
            f.close()

# 11. Функция загрузки подписанного файла
def open_signed_file():
    filepath = askopenfilename(
        filetypes=[("PDF Files", "*.pdf")]
    )
    if not filepath:
        return
    verefy_file_entry.delete(0, END)
    verefy_file_entry.insert(0, filepath)

# 12. Функция открытия подписи для проверки
def open_sign():
    filepath = askopenfilename(
        filetypes=[("Текстовые файлы", "*.txt")]
    )
    if not filepath:
        return
    sign_file_entry.delete(0, END)
    sign_file_entry.insert(0, filepath)

# 13. Функция открытия сертификата для проверки
def open_cert():
    filepath = askopenfilename(
        filetypes=[("PEM Files", "*.pem")]
    )
    if not filepath:
        return
    cert_file_entry.delete(0, END)
    cert_file_entry.insert(0, filepath)

# 14. Функция для проверки подписи
def verify_signature():
    global algorithm

    verefy_result.delete(0.0, END)

    if (chk_state_ECDSA_verefy.get() == True) and (chk_state_GOST_verefy.get() == True):
        messagebox.showinfo('Ошибка!', 'Выберите один из алгоритмов.')
        return
    elif (chk_state_ECDSA_verefy.get() != True) and (chk_state_GOST_verefy.get() != True):
        messagebox.showinfo('Ошибка!', 'Выберите один из алгоритмов.')
        return
    elif chk_state_ECDSA_verefy.get() == True:
        algorithm = 'ECDSA'
    else:
        algorithm = 'GOST'

    if algorithm == 'ECDSA':
        signature = open(sign_file_entry.get(), 'rb')
        signature_data = signature.read()
        signature.close()

        sign_file = open(verefy_file_entry.get(), 'rb')
        sign_file_data = sign_file.read()
        sign_file.close()

        certificate = open(cert_file_entry.get(), 'rb')
        cert_data = certificate.read()
        certificate.close()
        certificate = x509.load_pem_x509_certificate(cert_data)

        public_key = certificate.public_key()
        if public_key.verify(signature_data,
                                 sign_file_data,
                                 ec.ECDSA(hashes.SHA256())
                                 ) == None:
            verefy_result.insert(0.0, 'Проверка подписи прошла успешно.')
        else:
            verefy_result.insert(0.0, 'Ошибка! Проверьте введенные данные!')
    else:
        signature = open(sign_file_entry.get(), 'r')
        signature_data = signature.read()
        signature.close()

        #dgst = bytes(signature_data[:signature_data.find('=') + 2], encoding='utf-8')
        signature = bytes(signature_data[signature_data.find('=') + 2:], encoding='utf-8')




# Список используемых кнопок
# 1. Кнопки для создания закрытого ключа
Password_gen_button = Button(Create_private_key_frame, width=25, text="Сгенерировать пароль", command=password_gen)
Password_gen_button.grid(row=4, column=1, pady=2)

Create_key_button = Button(Create_private_key_frame, text="Сформировать секретный ключ", command=create_private_key)
Create_key_button.grid(row=5, column=1, pady=2)

Save_key_button = Button(Create_private_key_frame, width=25, text="Сохранить секретный ключ", command=save_private_key)
Save_key_button.grid(row=6, column=1, pady=2)

# 2. Кнопки для создания создания сертификата
Load_key_button = Button(Create_certificate_frame, width=46, text="Загрузить секретный ключ", command=open_private_key)
Load_key_button.grid(row=2, column=0, pady=2)

Cert_gen_button = Button(Create_certificate_frame, width=25, text="Сформировать сертификат", command=create_Certificate)
Cert_gen_button.grid(row=7, column=1, pady=2)

Save_cert_button = Button(Create_certificate_frame, width=25, text="Сохранить сертификат", command=save_cert)
Save_cert_button.grid(row=8, column=1, pady=2)

# 3. Кнопки для работы с подписями
subscribe_file_button = Button(Sign_frame, width=40, text="Загрузить файл для подписи", command=open_file)
subscribe_file_button.grid(row=2, column=0, pady=5)

Load_key_button = Button(Sign_frame, width=40, text="Загрузить секретный ключ", command=open_private_key_sign)
Load_key_button.grid(row=3, column=0, pady=5)

Signed_gen_button = Button(Sign_frame, text="Сформировать подпись", width=25, command=create_signature)
Signed_gen_button.grid(row=5, column=1, pady=5)

Signed_save_button = Button(Sign_frame, text="Сохранить подпись", width=25, command=save_signature)
Signed_save_button.grid(row=6, column=1, pady=5)

Signed_file_button = Button(Sign_frame, width=40, text="Загрузить подписанный файл", command=open_signed_file)
Signed_file_button.grid(row=11, column=0, pady=5)

Signed_button = Button(Sign_frame, width=40, text="Загрузить подпись для данного файла", command=open_sign)
Signed_button.grid(row=12, column=0, pady=5)

Cert_button = Button(Sign_frame, width=40, text="Загрузить сертификат для данной подписи", command=open_cert)
Cert_button.grid(row=13, column=0, pady=5)

Verefy_button = Button(Sign_frame, text="Проверить подпись", width=25, command=verify_signature)
Verefy_button.grid(row=14, column=1, pady=5)


window.mainloop()
