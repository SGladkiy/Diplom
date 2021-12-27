from django.shortcuts import render, redirect
from django.contrib.auth.views import LoginView, LogoutView
from django.urls import reverse
from main.models import Teacher, Student, Document
from django.views import View
from main.helpers.verify_signature import verify_signature

from .forms import AddDocumentForm, FindDocumentForm

# Авторизация ==========================================================================================================
# ======================================================================================================================

class AccessLoginView(LoginView):
    template_name = 'main/login.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        return context

    def get_success_url(self):
        if self.request.POST.get('remember_me') == None:
            self.request.session.set_expiry(0)
            self.request.session.modified = True

        if Teacher.is_teacher(self.request.user):
            return reverse('main:add-document')
        else:
            return reverse('main:find-document')

class AccessLogoutView(LogoutView):
    next_page = 'main:access-login'


# Главная (Переадресация) ==============================================================================================
# ======================================================================================================================
def index(request):
    if not request.user.is_authenticated:
        return redirect('main:access-login')
    else:
        if Teacher.is_teacher(request.user):
            return redirect('main:add-document')
        else:
            return redirect('main:find-document')


# Страница преподавателей ==============================================================================================
# ======================================================================================================================
class AddDocumentView(View):
    form_class = AddDocumentForm
    template_name = 'main/add_document.html'

    def _get_context(self, *args, **kwargs):
        context = {}
        context['person'] = Teacher.get(self.request.user)
        context['documents'] = Document.objects.filter(teacher=context['person'], approved=True).order_by('created_at')
        context['form'] = self.form_class(initial={'teacher': context['person'].id})
        return context

    def get(self, request, *args, **kwargs):
        context = self._get_context(request, *args, **kwargs)
        return render(request, self.template_name, context)

    def post(self, request, *args, **kwargs):
        context = self._get_context(request, *args, **kwargs)
        form = self.form_class(request.POST, request.FILES)
        if form.is_valid():
            document = form.save()
            # Проверка подписи
            signature = form.cleaned_data['signature'].open('rb')
            document.approved = verify_signature(document, signature)
            document.save()
            if not document.approved:
                form.add_error(None, 'Подпись не прошла проверку')
                context['form'] = form
        else:
            context['form'] = form
        return render(request, self.template_name, context)


# Страница студентов ===================================================================================================
# ======================================================================================================================
class FindDocumentView(View):
    form_class = FindDocumentForm
    template_name = 'main/find_document.html'

    def _get_context(self, *args, **kwargs):
        context = {}
        context['person'] = Student.get(self.request.user)
        context['form'] = self.form_class()
        return context

    def get(self, request, *args, **kwargs):
        context = self._get_context(request, *args, **kwargs)
        return render(request, self.template_name, context)

    def post(self, request, *args, **kwargs):
        context = self._get_context(request, *args, **kwargs)
        form = self.form_class(request.POST)
        if form.is_valid():
            context['results'] = True
            context['documents'] = Document.objects.filter(approved=True)
            if form.cleaned_data['course']:
                context['documents'] = context['documents'].filter(course=form.cleaned_data['course'])
            if form.cleaned_data['subject']:
                context['documents'] = context['documents'].filter(subject=form.cleaned_data['subject'])
            context['documents'] = context['documents'].order_by('created_at')
        # else:
            context['form'] = form
        return render(request, self.template_name, context)