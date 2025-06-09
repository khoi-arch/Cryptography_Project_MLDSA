from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('check-user/', views.check_user, name='check_user'),
    
    path('upload-invoice/', views.upload_invoice, name='upload_invoice'),
    path('list-invoices/', views.list_invoices, name='list_invoices'),
    path('download-invoice/<int:invoice_id>/', views.download_invoice, name='download_invoice'),
    path('get-public-key/', views.get_public_key, name='get_public_key'),
    path('upload-order/', views.upload_order, name='upload_order'),
    path('list-orders/', views.list_orders, name='list_orders'),
    path('download-order/<int:order_id>/', views.download_order, name='download_order'),
    path('register/', views.register, name='register'),
] 