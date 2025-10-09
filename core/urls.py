# core/urls.py
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views
from .jwt_views import CustomTokenObtainPairView, CustomTokenRefreshView, LogoutView

urlpatterns = [
    path('auth/login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    path('debug/auth/', views.debug_auth, name='debug_auth'),
    path('test/cookies/', views.test_cookies, name='test_cookies'),
    path('test/auth-simple/', views.test_auth_simple, name='test_auth_simple'),
    path('test/set-cookie/', views.test_set_cookie, name='test_set_cookie'),
    path('test/get-cookies/', views.test_get_cookies, name='test_get_cookies'),
    path('auth/me/', views.current_user, name='current_user'),
    path('auth/change-password/', views.change_password, name='change_password'),  
    
    path('auth/password-reset/request/', views.password_reset_request, name='password_reset_request'),
    path('auth/password-reset/verify/', views.password_reset_verify, name='password_reset_verify'),
    path('auth/password-reset/confirm/', views.password_reset_confirm, name='password_reset_confirm'),

    
    path('auth/register/', views.register_user, name='register_user'),
    path('users/', views.users_list, name='users_list'),
    path('users/stats/', views.users_stats, name='users_stats'),
    path('users/<int:user_id>/', views.user_detail, name='user_detail'),
    
    path('requests/', views.purchase_requests_list, name='requests_list'),
    path('requests/<int:pk>/', views.purchase_request_detail, name='request_detail'),
    path('requests/<int:pk>/validate/', views.validate_request, name='validate_request'),
    path('requests/<int:pk>/update-rejection/', views.update_rejection_reason, name='update_rejection'),
    
    path('attachments/', views.attachments_list, name='attachments_list'),
    path('attachments/<int:pk>/delete/', views.attachment_delete, name='attachment_delete'),
    
    path('dashboard/', views.dashboard, name='dashboard'),
]