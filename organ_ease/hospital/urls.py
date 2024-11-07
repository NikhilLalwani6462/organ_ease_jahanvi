from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import *

router = DefaultRouter()
router.register(r'registration', RegistrationViewSet, basename='registration') 
router.register(r'donors', DonorViewSet, basename='donor')

urlpatterns = [
    path('', include(router.urls)),  
    path('login/', LoginView.as_view(), name='login'),  # Use as_view() directly here
    path('logout/', LogoutView.as_view(), name='logout'),
    path('forgotpassword/', ForgotPasswordView.as_view(), name='forgotpassword'),
    path('resetpassword/', ResetPasswordView.as_view(), name='resetpassword'),
    
]
