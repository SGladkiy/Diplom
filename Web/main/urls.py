from django.urls import path
from main.views import *
# from django.contrib.auth.decorators import login_required


app_name = 'main'
urlpatterns = [
    path('', index, name='index'),
    path('add/', AddDocumentView.as_view(), name='add-document'),
    path('find/', FindDocumentView.as_view(), name='find-document'),

    path('login', AccessLoginView.as_view(redirect_authenticated_user=True), name='access-login'),
    path('logout', AccessLogoutView.as_view(), name='access-logout')
]