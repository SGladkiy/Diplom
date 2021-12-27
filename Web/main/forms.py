from django.forms import Form, ModelForm, Select, HiddenInput, ModelChoiceField, FileField, CharField, PasswordInput
from main.models import Document, Teacher, Course, Subject


class AddDocumentForm(ModelForm):
    teacher = ModelChoiceField(queryset=Teacher.objects.all(), widget=HiddenInput())
    signature = FileField()

    def __init__(self, *args, **kwargs):
        super(AddDocumentForm, self).__init__(*args, **kwargs)

    class Meta:
        model = Document
        fields = ['course', 'subject', 'file', 'signature', 'teacher']
        widgets = {
            'course': Select(
                attrs={
                    'class': 'form-select'
                }
            ),
            'subject': Select(
                attrs={
                    'class': 'form-select'
                }
            )
        }

class FindDocumentForm(Form):
    course = ModelChoiceField(queryset=Course.objects.all(), required=False, widget=Select(attrs={'class': 'form-select'}))
    subject = ModelChoiceField(queryset=Subject.objects.all(), required=False, widget=Select(attrs={'class': 'form-select'}))

    def __init__(self, *args, **kwargs):
        super(FindDocumentForm, self).__init__(*args, **kwargs)