from django.contrib.auth.backends import ModelBackend
from .models import HospitalRegister

class EmailBackend(ModelBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        try:
            user = HospitalRegister.objects.get(email=email)
            if user.check_password(password):
                return user
        except HospitalRegister.DoesNotExist:
            return None
