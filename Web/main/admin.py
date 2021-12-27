from django.contrib import admin
from .models import Teacher, Student, Course, Subject, Document
from django.utils.html import escape, mark_safe
from django.urls import reverse

# Преподаватель --------------------------------------------------------------------------------------------------------
@admin.register(Teacher)
class TeacherAdmin(admin.ModelAdmin):
    ordering = ['last_name', 'first_name', 'middle_name']
    list_display = ['full_name', 'user_link']

    # Ссылка на пользователя
    def user_link(self, obj: Teacher):
        if not obj.user_id:
            return '-'
        link = reverse('admin:auth_user_change', args=[obj.user_id])
        return mark_safe(f'<a href="{link}">{escape(obj.user.__str__())}</a>')
    user_link.short_description = 'Пользователь'
    user_link.admin_order_field = 'user'

# Студент --------------------------------------------------------------------------------------------------------------
@admin.register(Student)
class StudentAdmin(admin.ModelAdmin):
    ordering = ['last_name', 'first_name', 'middle_name']
    list_display = ['full_name', 'user_link']

    # Ссылка на пользователя
    def user_link(self, obj: Student):
        if not obj.user_id:
            return '-'
        link = reverse('admin:auth_user_change', args=[obj.user_id])
        return mark_safe(f'<a href="{link}">{escape(obj.user.__str__())}</a>')
    user_link.short_description = 'Пользователь'
    user_link.admin_order_field = 'user'

# Курс -----------------------------------------------------------------------------------------------------------------
@admin.register(Course)
class CourseAdmin(admin.ModelAdmin):
    ordering = ['order_number', 'name']
    list_display = ['name', 'order_number']

# Предмет --------------------------------------------------------------------------------------------------------------
@admin.register(Subject)
class SubjectAdmin(admin.ModelAdmin):
    ordering = ['name']
    list_display = ['name']

# Ведомость ------------------------------------------------------------------------------------------------------------
@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    ordering = ['created_at']
    list_display = ['created_at', 'course_link', 'subject_link', 'teacher_link', 'file', 'approved']

    # Ссылка на курс
    def course_link(self, obj: Document):
        if obj.course:
            link = reverse('admin:main_course_change', args=[obj.course_id])
            return mark_safe(f'<a href="{link}">{escape(obj.course.__str__())}</a>')
        else:
            return '-'
    course_link.short_description = 'Курс'

    # Ссылка на предмет
    def subject_link(self, obj: Document):
        if obj.subject:
            link = reverse('admin:main_subject_change', args=[obj.subject_id])
            return mark_safe(f'<a href="{link}">{escape(obj.subject.__str__())}</a>')
        else:
            return '-'
    subject_link.short_description = 'Предмет'
    subject_link.admin_order_field = 'subject'

    # Ссылка на преподавателя
    def teacher_link(self, obj: Document):
        if obj.subject:
            link = reverse('admin:main_teacher_change', args=[obj.teacher_id])
            return mark_safe(f'<a href="{link}">{escape(obj.teacher.__str__())}</a>')
        else:
            return '-'
    teacher_link.short_description = 'Преподаватель'
    teacher_link.admin_order_field = 'teacher'