import base64

from tkinter import *
from tkinter import ttk, scrolledtext
from tkinter.ttk import Combobox
from tkinter.filedialog import asksaveasfilename, askopenfilename
from tkcalendar import DateEntry
from fpdf import FPDF

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509


# Список глобальных переменных
# Данные из таблицы для создания PDF
global dataPDF
dataPDF = [['Номер',
            'Имя',
            'Фамилия',
            'Отчество',
            'Номер зачетной книжки',
            'Оценка']]
# Подсчет записей в таблце
global count
count = 0
global excellent
excellent = 0
global well
well = 0
global okay
okay = 0
global bad
bad = 0
global credit
credit = 0
global failed
failed = 0

# Насройки окна
window = Tk()
window.title('Система электронная зачетка: пользователь')
window.geometry('1200x640')


# Список фреймов
# 1. Фрейм с ведомостью
Statement_frame = Frame(window)
Statement_frame.grid(row=0, column=0)
Statement_frame_top = Frame(Statement_frame)
Statement_frame_top.pack()
Statement_frame_bottom = Frame(Statement_frame)
Statement_frame_bottom.pack()

# 2. Фрейм с данными о ведомости
Statement_data_frame = Frame(window)
Statement_data_frame.grid(row=0, column=1)

# 3. Фрейм с подписью
Signature_frame = Frame(window)
Signature_frame.grid(row=1, column=0, columnspan=2)

# Создание таблицы
data = []
table = ttk.Treeview(Statement_frame_top)
table.grid(row=0, column=0)
table['columns'] = ('id', 'name', 'surname', 'patronymic', 'matriculation_book', 'score')
table.column("#0", width=0, stretch=NO)
table.column("id", anchor=CENTER, width=130)
table.column("name", anchor=CENTER, width=130)
table.column("surname", anchor=CENTER, width=130)
table.column("patronymic", anchor=CENTER, width=130)
table.column("matriculation_book", anchor=CENTER, width=130)
table.column("score", anchor=CENTER, width=130)

table.heading("#0", text="", anchor=CENTER)
table.heading("id", text="Номер", anchor=CENTER)
table.heading("name", text="Имя", anchor=CENTER)
table.heading("surname", text="Фамилия", anchor=CENTER)
table.heading("patronymic", text="Отчество", anchor=CENTER)
table.heading("matriculation_book", text="Номер зачетной \n          книжки", anchor=CENTER)
table.heading("score", text="Оценка", anchor=CENTER)

# Список используемых Лейблов(текстовых полей)
# 1. Labels для записи в таблицу
id = Label(Statement_frame_bottom, text="Номер")
id.grid(row=0, column=0, pady=5)

name = Label(Statement_frame_bottom, text="Имя")
name.grid(row=0, column=1)

surname = Label(Statement_frame_bottom, text="Фамилия")
surname.grid(row=0, column=2)

patronymic = Label(Statement_frame_bottom, text="Отчество")
patronymic.grid(row=0, column=3)

matriculation_book = Label(Statement_frame_bottom, text="Номер зачетной \nкнижки")
matriculation_book.grid(row=0, column=4)

score = Label(Statement_frame_bottom, text="Оценка")
score.grid(row=0, column=5)

# 2. Labels для заполнения ведомости
group = Label(Statement_data_frame, text="Группа:", pady=5)
group.grid(row=0, column=0)

form_of_study = Label(Statement_data_frame, text="Форма обучения:", pady=5)
form_of_study.grid(row=1, column=0)

year_of_study = Label(Statement_data_frame, text="Курс:", pady=5)
year_of_study.grid(row=2, column=0)

discipline = Label(Statement_data_frame, text="Дисциплина:", pady=5)
discipline.grid(row=3, column=0)

monitoring = Label(Statement_data_frame, text="Вид контроля:", pady=5)
monitoring.grid(row=4, column=0)

examiner = Label(Statement_data_frame, text="Экзаменатор:", pady=5)
examiner.grid(row=5, column=0)

date = Label(Statement_data_frame, text="Дата проведения:", pady=5)
date.grid(row=6, column=0)

term = Label(Statement_data_frame, text="Семестр:", pady=5)
term.grid(row=7, column=0)

hours = Label(Statement_data_frame, text="Количсетво часов:", pady=5)
hours.grid(row=8, column=0)

units = Label(Statement_data_frame, text="Количество зачетных едениц:", pady=5)
units.grid(row=9, column=0)

# 3. Labels для подписи и ее проверки
header_sign = Label(Signature_frame, text="ФОРМИРОВАНИЕ ПОДПИСИ", pady=5)
header_sign.grid(row=0, column=0, columnspan=4)

subscribe_file = Label(Signature_frame, text="Загрузите файл для подписи:", pady=5)
subscribe_file.grid(row=1, column=0)

result = Label(Signature_frame, text="Результат формирования подписи:", pady=5)
result.grid(row=1, column=3)

priv_key = Label(Signature_frame, text="Загрузите секретный ключ:", pady=5)
priv_key.grid(row=2, column=0)

password = Label(Signature_frame, text="Введите пароль для работы с секретным ключом:", pady=5)
password.grid(row=3, column=0)

verefy_sign = Label(Signature_frame, text="ПРОВЕРКА ПОДПИСИ", pady=5)
verefy_sign.grid(row=5, column=0, columnspan=4)

signed_file = Label(Signature_frame, text="Загрузите подписанный файл:", pady=5)
signed_file.grid(row=6, column=0)

signed = Label(Signature_frame, text="Загрузите подпись для данного файла:", pady=5)
signed.grid(row=7, column=0)

cert = Label(Signature_frame, text="Загрузите Ваш сертификат:", pady=5)
cert.grid(row=8, column=0)

verefy = Label(Signature_frame, text="Результат проверки подписи:", pady=5)
verefy.grid(row=6, column=3)


# Список используемых Энтри (Полей ввода)
# 1. Entry для заполнения ведомости
group_entry = Entry(Statement_data_frame, width=23)
group_entry.grid(row=0, column=1, padx=10)

form_of_study_entry = Entry(Statement_data_frame, width=23)
form_of_study_entry.grid(row=1, column=1, padx=10)

year_of_study_entry = Entry(Statement_data_frame, width=23)
year_of_study_entry.grid(row=2, column=1)

discipline_entry = Entry(Statement_data_frame, width=23)
discipline_entry.grid(row=3, column=1, padx=10)

monitoring_entry = Combobox(Statement_data_frame)
monitoring_entry['values'] = ('Зачет', 'Зачет с оценкой', 'Экзамен', 'Курсовая работа')
monitoring_entry.grid(row=4, column=1, padx=10)

examiner_entry = Entry(Statement_data_frame, width=23)
examiner_entry.grid(row=5, column=1)

date_entry = DateEntry(Statement_data_frame, width=20)
date_entry.grid(row=6, column=1)

term_entry = Entry(Statement_data_frame, width=23)
term_entry.grid(row=7, column=1)

hours_entry = Entry(Statement_data_frame, width=23)
hours_entry.grid(row=8, column=1, padx=10)

units_entry = Entry(Statement_data_frame, width=23)
units_entry.grid(row=9, column=1, padx=10)

# 2. Entry для записи в таблицу
id_entry = Entry(Statement_frame_bottom)
id_entry.grid(row=1, column=0, padx=5, pady=5)

name_entry = Entry(Statement_frame_bottom)
name_entry.grid(row=1, column=1, padx=5, pady=5)

surname_entry = Entry(Statement_frame_bottom)
surname_entry.grid(row=1, column=2, padx=5, pady=5)

patronymic_entry = Entry(Statement_frame_bottom)
patronymic_entry.grid(row=1, column=3, padx=5, pady=5)

matriculation_book_entry = Entry(Statement_frame_bottom)
matriculation_book_entry.grid(row=1, column=4, padx=5, pady=5)

score_entry = Combobox(Statement_frame_bottom)
score_entry['values'] = ('Отлично', 'Хорошо', 'Удволетворительно', 'Неудовлетворительно', 'Зачтено', 'Незачтено')
score_entry.grid(row=1, column=5, padx=5, pady=5)

# 3. Entry для подписи и ее проверки
subscribe_file_entry = Entry(Signature_frame, width=40)
subscribe_file_entry.grid(row=1, column=1, padx=5, pady=5)

priv_key_entry = Entry(Signature_frame, width=40)
priv_key_entry.grid(row=2, column=1, padx=5, pady=5)

password_entry = Entry(Signature_frame, width=40)
password_entry.grid(row=3, column=1, padx=5, pady=5)

chk_state_ECDSA = BooleanVar()
chk_state_ECDSA.set(False)
ECDSA_check = Checkbutton(Signature_frame, text="ECDSA", var=chk_state_ECDSA)
ECDSA_check.grid(row=4, column=0)

chk_state_GOST = BooleanVar()
chk_state_GOST.set(False)
GOST_check = Checkbutton(Signature_frame, text="ГОСТ 34.10-12", var=chk_state_GOST)
GOST_check.grid(row=4, column=1)

sign_result = scrolledtext.ScrolledText(Signature_frame, width=60, height=5)
sign_result.grid(row=2, column=3, rowspan=3)

signed_file_entry = Entry(Signature_frame, width=40)
signed_file_entry.grid(row=6, column=1, padx=5, pady=5)

signed_entry = Entry(Signature_frame, width=40)
signed_entry.grid(row=7, column=1, padx=5, pady=5)

cert_entry = Entry(Signature_frame, width=40)
cert_entry.grid(row=8, column=1, padx=5, pady=5)

chk_state_ECDSA_verefy = BooleanVar()
chk_state_ECDSA_verefy.set(False)
ECDSA_check_verefy = Checkbutton(Signature_frame, text="ECDSA", var=chk_state_ECDSA_verefy)
ECDSA_check_verefy.grid(row=9, column=0)

chk_state_GOST_verefy = BooleanVar()
chk_state_GOST_verefy.set(False)
GOST_check_verefy = Checkbutton(Signature_frame, text="ГОСТ 34.10-12", var=chk_state_GOST_verefy)
GOST_check_verefy.grid(row=9, column=1)

verefy_result = scrolledtext.ScrolledText(Signature_frame, width=60, height=5)
verefy_result.grid(row=7, column=3, rowspan=3)

# Список функций работы приложения
# 1. Функция добавления записи в таблицу
def input_record():
    global count
    global excellent
    global well
    global okay
    global bad
    global credit
    global failed

    table.insert(parent='', index='end', iid=count, text='',
               values=(id_entry.get(),
                       name_entry.get(),
                       surname_entry.get(),
                       patronymic_entry.get(),
                       matriculation_book_entry.get(),
                       score_entry.get()))
    count += 1
    if score_entry.get() == 'Отлично':
        excellent += 1

    elif score_entry.get() == 'Хорошо':
        well += 1

    elif score_entry.get() == 'Удовлетворительно':
        okay += 1

    elif score_entry.get() == 'Зачтено':
        credit += 1

    elif score_entry.get() == 'Незачтено':
        failed += 1
    else:
        bad += 1

    dataPDF.insert(count, [id_entry.get(),
                       name_entry.get(),
                       surname_entry.get(),
                       patronymic_entry.get(),
                       matriculation_book_entry.get(),
                       score_entry.get()])

    id_entry.delete(0, END)
    name_entry.delete(0, END)
    surname_entry.delete(0, END)
    patronymic_entry.delete(0, END)
    matriculation_book_entry.delete(0, END)
    score_entry.delete(0, END)

# 2. Функция выбора записи из таблицы двойным кликом
def double_click(event):
    id_entry.delete(0, END)
    name_entry.delete(0, END)
    surname_entry.delete(0, END)
    patronymic_entry.delete(0, END)
    matriculation_book_entry.delete(0, END)
    score_entry.delete(0, END)

    selected = table.focus()
    values = table.item(selected, 'values')

    id_entry.insert(0, values[0])
    name_entry.insert(0, values[1])
    surname_entry.insert(0, values[2])
    patronymic_entry.insert(0, values[3])
    matriculation_book_entry.insert(0, values[4])
    score_entry.insert(0, values[5])

# 3. Функция изменения записи в таблице
def update_record():
    global excellent
    global well
    global okay
    global bad
    global credit
    global failed

    selected = table.focus()
    values = list(table.item(selected, 'values'))

    if score_entry.get() != values[5]:
        if values[5] == 'Отлично':
            excellent -= 1

        elif values[5] == 'Хорошо':
            well -= 1

        elif values[5] == 'Удовлетворительно':
            okay -= 1

        elif values[5] == 'Зачтено':
            credit -= 1

        elif values[5] == 'Незачтено':
            failed -= 1

        else:
            bad -= 1

        if score_entry.get() == 'Отлично':
            excellent += 1

        elif score_entry.get() == 'Хорошо':
            well += 1

        elif score_entry.get() == 'Удовлетворительно':
            okay += 1

        elif score_entry.get() == 'Зачтено':
            credit += 1

        elif score_entry.get() == 'Незачтено':
            failed += 1
        else:
            bad += 1

    table.item(selected, values=(
        id_entry.get(),
        name_entry.get(),
        surname_entry.get(),
        patronymic_entry.get(),
        matriculation_book_entry.get(),
        score_entry.get()
    ))

    id_entry.delete(0, END)
    name_entry.delete(0, END)
    surname_entry.delete(0, END)
    patronymic_entry.delete(0, END)
    matriculation_book_entry.delete(0, END)
    score_entry.delete(0, END)
    print(excellent)

# 4. Функция удаления выбранной записи из таблицы
def delete_record():
    global excellent
    global well
    global okay
    global bad
    global credit
    global failed

    selected = table.focus()
    values = list(table.item(selected, 'values'))
    if values[5] == 'Отлично':
        excellent -= 1

    elif values[5] == 'Хорошо':
        well -= 1

    elif values[5] == 'Удовлетворительно':
        okay -= 1

    elif values[5] == 'Зачтено':
        credit -= 1

    elif values[5] == 'Незачтено':
        failed -= 1
    else:
        bad -= 1

    del dataPDF[dataPDF.index(values)]
    table.delete(selected[0])

    id_entry.delete(0, END)
    name_entry.delete(0, END)
    surname_entry.delete(0, END)
    patronymic_entry.delete(0, END)
    matriculation_book_entry.delete(0, END)
    score_entry.delete(0, END)

# 5. Функция сохранения ведомости как PDF
def save_PDF(spacing=1):
    global excellent
    global well
    global okay
    global bad
    global credit
    global failed

    pdf = FPDF(orientation='P', unit='mm', format='A4')
    pdf.add_page()
    pdf.add_font('Times New Roman', '', 'times-new-roman.ttf', uni=True)
    pdf.set_font('Times New Roman', '', 14)
    pdf.cell(200, 10, txt="Балтийский федеральный университет им. И.Канта", ln=1, align="C")
    pdf.cell(200, 10, txt="Институт физико-математических наук и информационных технологий", ln=2, align="C")
    pdf.cell(200, 10, txt=group_entry.get(), ln=3, align="C")
    pdf.cell(200, 10, txt=form_of_study_entry.get() + ' форма обучения', ln=4, align="C")
    pdf.cell(200, 10, txt="Экзаменационная ведомость", ln=5, align="C")
    pdf.cell(200, 10, txt="(Вид контроля: "+monitoring_entry.get()+")", ln=6, align="C")
    pdf.cell(200, 10, txt="Курс: "+year_of_study_entry.get()+"     Семестр: "+term_entry.get(), ln=8, align="L")
    pdf.cell(200, 10, txt="Дисциплина: " + discipline_entry.get(), ln=9, align="L")
    pdf.cell(200, 10, txt="Экзаменатор: " + examiner_entry.get(), ln=10, align="L")
    pdf.cell(200, 10, txt="Дата проведения: " + date_entry.get(), ln=11, align="L")


    col_width = pdf.w / 6.5
    row_height = pdf.font_size
    for row in dataPDF:
        for item in row:
            pdf.cell(col_width, row_height * spacing,
                     txt=item, border=1)
        pdf.ln(row_height * spacing)

    if monitoring_entry.get() == "Экзамен" or "экзамен":
        pdf.cell(200, 10, txt="Итоги: отлично: " + str(excellent) + ", хорошо: " + str(well) +  ", удовлетворительно: " + str(okay) +", неудовлетворительно: " + str(bad), align="L")
    else:
        pdf.cell(200, 10,
                 txt="Итоги: зачет: " + str(credit) + ", незачет: " + str(failed), align="L")

    pdf.close()
    file_name = asksaveasfilename(
        filetypes=[("PDF Files", "*.pdf")],
    )
    if not file_name:
        return
    else:
        pdf.output(name=str(file_name) + '.pdf', dest='')

# 6. Функция открытия файла для подписи
def open_file():
    filepath = askopenfilename(
        filetypes=[("PDF Files", "*.pdf")]
    )
    if not filepath:
        return
    subscribe_file_entry.delete(0, END)
    subscribe_file_entry.insert(0, filepath)

# 7. Функция открытия приватного ключа для подписи
def open_private_key():
    filepath = askopenfilename(
        filetypes=[("PEM Files", "*.pem")]
    )
    if not filepath:
        return
    priv_key_entry.delete(0, END)
    priv_key_entry.insert(0, filepath)

# 8. Функция генерации цифровой подписи
def create_Signature():
    sign_result.delete(0.0, END)

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

# 9. Функция сохранения цифровой подписи
def save_signature():
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

# 10. Функция открытия подписанного файла для проверки
def open_signed_file():
    filepath = askopenfilename(
        filetypes=[("PDF Files", "*.pdf")]
    )
    if not filepath:
        return
    signed_file_entry.delete(0, END)
    signed_file_entry.insert(0, filepath)

# 11. Функция открытия подписи для проверки
def open_sign():
    filepath = askopenfilename(
        filetypes=[("Текстовые файлы", "*.txt")]
    )
    if not filepath:
        return
    signed_entry.delete(0, END)
    signed_entry.insert(0, filepath)

# 12. Функция открытия сертификата для проверки
def open_cert():
    filepath = askopenfilename(
        filetypes=[("PEM Files", "*.pem")]
    )
    if not filepath:
        return
    cert_entry.delete(0, END)
    cert_entry.insert(0, filepath)

# 12. Функция для проверки подписи
def verify_signature():
    verefy_result.delete(0.0, END)
    signature = open(signed_entry.get(), 'rb')
    signature_data = signature.read()
    signature.close()

    sign_file = open(signed_file_entry.get(), 'rb')
    sign_file_data = sign_file.read()
    sign_file.close()

    certificate = open(cert_entry.get(), 'rb')
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


# Список используемых кнопок
# 1. Кнопки для работы с таблицей
Input_button = Button(Statement_frame_bottom, width=35, text="Добавить запись", command=input_record)
Input_button.grid(row=2, column=0, columnspan=2)

Edit_button = Button(Statement_frame_bottom, width=35, text="Изменить запись", command=update_record)
Edit_button.grid(row=2, column=2, columnspan=2)

Edit_button = Button(Statement_frame_bottom, width=35, text="Удалить запись", command=delete_record)
Edit_button.grid(row=2, column=4, columnspan=2)

# 2. Кнопки для работы с ведомостью
Save_button = Button(Statement_data_frame, text="Сохранить файл", width=20, pady=10, command=save_PDF)
Save_button.grid(row=10, column=1, columnspan=2)

# 3. Кнопки для подписи и ее проверки
Search_file_button = Button(Signature_frame, text="Обзор", width=15, command=open_file)
Search_file_button.grid(row=1, column=2)

Search_priv_key_button = Button(Signature_frame, text="Обзор", width=15, command=open_private_key)
Search_priv_key_button.grid(row=2, column=2)

Signed_button = Button(Signature_frame, text="Подписать", width=15, command=create_Signature)
Signed_button.grid(row=3, column=2)

Signed_save_button = Button(Signature_frame, text="Сохранить подпись", width=15, command=save_signature)
Signed_save_button.grid(row=4, column=2)

Signed_file_button = Button(Signature_frame, text="Обзор", width=15, command=open_signed_file)
Signed_file_button.grid(row=6, column=2)

Signed_open_button = Button(Signature_frame, text="Обзор", width=15, command=open_sign)
Signed_open_button.grid(row=7, column=2)

cert_button = Button(Signature_frame, text="Обзор", width=15, command=open_cert)
cert_button.grid(row=8, column=2)

verefy_button = Button(Signature_frame, text="Проверить подпись", width=15, command=verify_signature)
verefy_button.grid(row=9, column=2)

# Бинды кнопок
double_click_flag = False
window.bind('<Double-1>', double_click)

window.mainloop()
