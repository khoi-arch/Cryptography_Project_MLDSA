from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('generate-keys/', views.generate_key_pair, name='generate_keys'),
    path('sign-document/', views.sign_document_view, name='sign_document'),
    path('verify-signature/', views.verify_signature_view, name='verify_signature'),
] 