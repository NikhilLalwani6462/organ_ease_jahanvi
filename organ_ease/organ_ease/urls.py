from django.urls import path, include
from django.contrib import admin

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('hospital.urls')),  # Include your app’s urls directly
]
