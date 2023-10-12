from django.urls import path
from . import views

urlpatterns = [
    path('', views.Home.as_view(), name='home'),
    path('status/', views.Status.as_view(), name='status'),
    path('check/', views.CheckUrl.as_view(), name='check'),
    path('reports/', views.Reports.as_view(), name='reports'),
    path('pie/', views.Pie.as_view(), name='pie'),
]
