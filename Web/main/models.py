from django.db.models import Model
from django.db.models import CASCADE
from django.db.models import CharField, DateTimeField, IntegerField, FileField, BooleanField
from django.db.models import ForeignKey, OneToOneField

from django.db.models.signals import pre_delete, pre_save
from django.dispatch import receiver

from django.contrib.auth.models import User
import os


# Преподаватель --------------------------------------------------------------------------------------------------------
class Teacher(Model):
    user = OneToOneField(User, on_delete=CASCADE, verbose_name='Пользователь')

    first_name = CharField(max_length=200, verbose_name='Имя')
    last_name = CharField(max_length=200, verbose_name='Фамилия')
    middle_name = CharField(max_length=200, verbose_name='Отчество')

    @property
    def full_name(self):
        return '%s %s %s' % (self.last_name, self.first_name, self.middle_name)
    full_name.fget.short_description = 'Полное имя'

    @property
    def short_name(self):
        return '%s.%s. %s' % (self.first_name[0].upper(), self.middle_name[0].upper(), self.last_name)
    short_name.fget.short_description = 'Сокращённое имя'

    class Meta:
        verbose_name = 'Преподаватель'
        verbose_name_plural = 'Преподаватели'

    def __str__(self):
        return self.full_name

    @ staticmethod
    def get(user):
        try:
            return Teacher.objects.get(user=user)
        except Teacher.DoesNotExist:
            return None

    @staticmethod
    def get_person(user):
        try:
            return Teacher.objects.get(user=user)
        except Teacher.DoesNotExist:
            try:
                return Student.get(user)
            except Student.DoesNotExist:
                return None

    @staticmethod
    def is_teacher(user):
        try:
            Teacher.objects.get(user=user)
            return True
        except Teacher.DoesNotExist:
            return False

# Студент --------------------------------------------------------------------------------------------------------------
class Student(Model):
    user = OneToOneField(User, on_delete=CASCADE, verbose_name='Пользователь')

    first_name = CharField(max_length=200, verbose_name='Имя')
    last_name = CharField(max_length=200, verbose_name='Фамилия')
    middle_name = CharField(max_length=200, verbose_name='Отчество')

    @property
    def full_name(self):
        return '%s %s %s' % (self.last_name, self.first_name, self.middle_name)
    full_name.fget.short_description = 'Полное имя'

    @property
    def short_name(self):
        return '%s.%s. %s' % (self.first_name[0].upper(), self.middle_name[0].upper(), self.last_name)
    short_name.fget.short_description = 'Сокращённое имя'

    class Meta:
        verbose_name = 'Студент'
        verbose_name_plural = 'Студенты'

    def __str__(self):
        return self.full_name

    @ staticmethod
    def get(user):
        try:
            return Student.objects.get(user=user)
        except Student.DoesNotExist:
            return None

    @staticmethod
    def is_student(user):
        try:
            Student.objects.get(user=user)
            return True
        except Student.DoesNotExist:
            return False

# Курс -----------------------------------------------------------------------------------------------------------------
class Course(Model):
    name = CharField(max_length=200, verbose_name='Название')
    order_number = IntegerField(verbose_name='Порядковый номер')

    class Meta:
        verbose_name = 'Курс'
        verbose_name_plural = 'Курсы'

    def __str__(self):
        return self.name

# Предмет --------------------------------------------------------------------------------------------------------------
class Subject(Model):
    name = CharField(max_length=200, verbose_name='Название')

    class Meta:
        verbose_name = 'Предмет'
        verbose_name_plural = 'Предметы'

    def __str__(self):
        return self.name

# Ведомость (документ) -------------------------------------------------------------------------------------------------
class Document(Model):
    teacher = ForeignKey('Teacher', on_delete=CASCADE, verbose_name='Преподаватель')
    course = ForeignKey(Course, on_delete=CASCADE, verbose_name='Курс')
    subject = ForeignKey(Subject, on_delete=CASCADE, verbose_name='Предмет')
    file = FileField(upload_to='main/documents/', verbose_name='Файл')
    approved = BooleanField(default=False, verbose_name='Проверено')
    created_at = DateTimeField(auto_now_add=True, verbose_name='Создано')

    class Meta:
        verbose_name = 'Ведомость'
        verbose_name_plural = 'Ведомости'

    def __str__(self):
        return self.file.path

    @property
    def filename(self):
        return os.path.basename(self.file.name)

# Удаление файла при удалении ведомости
@receiver(pre_delete, sender=Document)
def document_pre_delete(sender, instance, using, **kwargs):
    instance.file.delete(save=False)

# Удаление файла при изменении ведомости
@receiver(pre_save, sender=Document)
def document_pre_save(sender, instance, raw, using, update_fields, **kwargs):

    if not instance.pk:
        return False

    try:
        old_file = Document.objects.get(pk=instance.pk).file
    except Document.DoesNotExist:
        return False

    if not old_file == instance.file:
        old_file.delete(save=False)
