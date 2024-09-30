from django.urls import path
from . import views
from django.contrib.auth import views as auth_views


urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('upload/', views.upload_evidence, name='upload_evidence'),
    path('add-analysis/', views.add_analysis, name='add_analysis'),
    path('evidence-list/', views.evidence_list, name='evidence_list'),
    path('download-report/<int:evidence_id>/', views.download_report, name='download_report'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('analyze-pcap/<int:evidence_id>/', views.analyze_pcap, name='analyze_pcap'),
    path('upload-log/', views.upload_log, name='upload_log'),
    path('analyze-log/<int:log_id>/', views.analyze_log, name='analyze_log'),
    
    path('login/', auth_views.LoginView.as_view(template_name='registration/login.html'), name='login'),
    # path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    # path('logout/', auth_views.LogoutView.as_view(template_name='registration/logged_out.html'), name='logout'),
    # path('logout/', views.logout_view, name='logout'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),

    path('register/', views.register, name='register'),
    
]