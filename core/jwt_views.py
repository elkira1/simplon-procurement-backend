from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from .jwt_serializers import CustomTokenObtainPairSerializer
from .serializers import UserSerializer
import datetime
import logging

logger = logging.getLogger(__name__)

class CustomTokenObtainPairView(TokenObtainPairView):
    """Vue personnalisée pour la connexion avec cookies HttpOnly"""
    serializer_class = CustomTokenObtainPairSerializer
    
    def post(self, request, *args, **kwargs):
        """Override pour définir les cookies HttpOnly"""
        serializer = self.get_serializer(data=request.data)
        
        try:
            serializer.is_valid(raise_exception=True)
        except Exception as e:
            logger.warning(f"Échec d'authentification: {e}")
            return Response(
                {
                    'error': 'Identifiants invalides',
                    'details': 'Vérifiez votre nom d\'utilisateur/email et votre mot de passe'
                },
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        login = request.data.get('login')
        from django.contrib.auth import get_user_model
        from django.db.models import Q
        
        User = get_user_model()
        try:
            user = User.objects.get(
                Q(username__iexact=login) | Q(email__iexact=login)
            )
            user_data = UserSerializer(user).data
            logger.info(f"Connexion réussie pour: {user.username}")
        except User.DoesNotExist:
            user_data = None
            logger.error("Utilisateur non trouvé après validation du serializer")
        
        tokens = serializer.validated_data
        access_token = tokens['access']
        refresh_token = tokens['refresh']
        
        response_data = {
            'user': user_data,
            'message': f'Connexion réussie. Bienvenue {user.first_name or user.username}!',
            'success': True,
            'tokens': {
                'access': access_token,
                'refresh': refresh_token,
            }
        }
        
        response = Response(response_data, status=status.HTTP_200_OK)
        
        cookie_config = {
            'httponly': settings.JWT_COOKIE_HTTPONLY,
            'secure': settings.JWT_COOKIE_SECURE,
            'samesite': settings.JWT_COOKIE_SAMESITE,
            'domain': settings.JWT_COOKIE_DOMAIN,
            'path': '/'
        }

        if not settings.DEBUG:
            cookie_config['partitioned'] = True

        
        try:
            response.set_cookie(
                key='access_token',
                value=access_token,
                max_age=3600,
                **cookie_config
            )

            response.set_cookie(
                key='refresh_token',
                value=refresh_token,
                max_age=604800,
                **cookie_config
            )
            
            logger.info("Cookies d'authentification définis avec succès")
            
        except Exception as e:
            logger.error(f"Erreur lors de la définition des cookies: {e}")
            
        return response


class CustomTokenRefreshView(TokenRefreshView):
   
    def post(self, request, *args, **kwargs):
        refresh_token = request.data.get('refresh') or request.COOKIES.get('refresh_token')
        
        if not refresh_token:
            logger.warning("Tentative de refresh sans token")
            return Response(
                {'error': 'Refresh token manquant'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        try:
            serializer = self.get_serializer(data={'refresh': refresh_token})
            serializer.is_valid(raise_exception=True)
            
            validated_data = serializer.validated_data
            access_token = validated_data.get('access')
            new_refresh_token = validated_data.get('refresh')
            
            response = Response({
                'success': True,
                'message': 'Token rafraîchi avec succès',
                'tokens': {
                    'access': access_token,
                    'refresh': new_refresh_token or refresh_token,
                }
            }, status=status.HTTP_200_OK)
            
            cookie_config = {
                'httponly': True,
                'secure': settings.DEBUG is False,
                'samesite': settings.JWT_COOKIE_SAMESITE,
                'path': '/'
            }

            if settings.DEBUG is False:
                cookie_config['partitioned'] = True
            
            if access_token:
                response.set_cookie(
                    'access_token',
                    access_token,
                    max_age=3600,
                    **cookie_config
                )
            
            if new_refresh_token and new_refresh_token != refresh_token:
                response.set_cookie(
                    'refresh_token',
                    new_refresh_token,
                    max_age=604800,
                    **cookie_config
                )
            
            logger.info("Tokens rafraîchis avec succès")
            return response
            
        except Exception as e:
            logger.error(f"Erreur lors du refresh: {e}")
            return Response(
                {'error': 'Refresh token invalide ou expiré'},
                status=status.HTTP_401_UNAUTHORIZED
            )


class LogoutView(TokenRefreshView):
    def get_cookie_settings(self):
        """Renvoie uniquement les paramètres valides pour delete_cookie"""
        return {
            'path': '/',
            'domain': settings.JWT_COOKIE_DOMAIN,
            'samesite': settings.JWT_COOKIE_SAMESITE
        }

    def post(self, request, *args, **kwargs):
        logger.debug("Logout request received - cookies=%s", list(request.COOKIES.keys()))

        response = Response({
            'message': 'Déconnexion réussie',
            'success': True
        }, status=status.HTTP_200_OK)

        cookie_settings = self.get_cookie_settings()

        response.delete_cookie('access_token', **cookie_settings)
        response.delete_cookie('refresh_token', **cookie_settings)

        logger.debug("Logout completed - cookies supprimés côté serveur")
        return response
