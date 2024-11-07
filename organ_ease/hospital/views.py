from django.forms import ValidationError
from rest_framework import status
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import HospitalRegister
from .serializers import *
from rest_framework.permissions import AllowAny
from django.contrib.auth import login
from rest_framework import generics, permissions
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from .models import HospitalRegister


class RegistrationViewSet(viewsets.ModelViewSet):
    permission_classes = [AllowAny]
    queryset = HospitalRegister.objects.all()
    serializer_class = RegistrationSerializer

    def list(self, request, *args, **kwargs):  # Use 'list' instead of 'get'
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        instance = self.get_queryset()  # Get the specific instance
        serializer = self.get_serializer(instance, data=request.data, partial=False)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, *args, **kwargs):
        instance = self.get_queryset()  # Get the specific instance
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_queryset()  # Get the specific instance
        instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class LoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        try:
            user = HospitalRegister.objects.get(email=email)
        except HospitalRegister.DoesNotExist:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        if user.check_password(password):
            # Generate or retrieve a token for the user
            token, created = Token.objects.get_or_create(user=user)
            
            # Return token and user details on successful login
            return Response({
                "message": "Login successful",
                "token": token.key
            }, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated before allowing logout

    def post(self, request):
        try:
            # Delete the user's token to log them out
            request.user.auth_token.delete()
            return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
        except Token.DoesNotExist:
            return Response({"error": "Token not found"}, status=status.HTTP_400_BAD_REQUEST)


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from .serializers import ForgotPasswordSerializer, ResetPasswordSerializer

User = get_user_model()

class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            user_id = serializer.validated_data.get('user_id')

            try:
                user = User.objects.get(id=user_id)
                reset_token = str(RefreshToken.for_user(user).access_token)

                return Response({"reset_token": reset_token}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data.get('token')
            new_password = serializer.validated_data.get('new_password')

            try:
                access_token = AccessToken(token)
                user_id = access_token['user_id']
                user = User.objects.get(id=user_id)
                user.set_password(new_password)
                user.save()

                return Response({"message": "Password has been reset successfully"}, status=status.HTTP_200_OK)
            except Exception:
                return Response({"error": "Invalid token or user not found"}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



from rest_framework import viewsets, permissions
from rest_framework.response import Response
from rest_framework import status
from .models import Donor
from .serializers import DonorSerializer

class DonorViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows donors to be viewed, created, updated, or deleted.
    """
    permission_classes = [AllowAny]
    queryset = Donor.objects.all()
    serializer_class = DonorSerializer


    def perform_create(self, serializer):
        """
        Create a new donor instance.
        """
        serializer.save()

    def perform_update(self, serializer):
        """
        Update an existing donor instance.
        """
        serializer.save()

    def perform_destroy(self, instance):
        """
        Delete a donor instance.
        """
        instance.delete()

    def list(self, request, *args, **kwargs):
        """
        Retrieve a list of donors.
        """
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs):
        """
        Retrieve a specific donor by ID.
        """
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        """
        Create a new donor.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        """
        Update an existing donor.
        """
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        """
        Delete a donor.
        """
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)
