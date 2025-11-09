from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.db.models import Q
from django.utils.deprecation import MiddlewareMixin
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.contrib.auth.models import AnonymousUser
import logging
import re

User = get_user_model()
logger = logging.getLogger(__name__)

class EmailOrUsernameModelBackend(ModelBackend):
    """
    Authentification par email ou username
    """
    
    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None:
            username = kwargs.get(User.USERNAME_FIELD)

        if username is None or password is None:
            return None

        try:
            # Recherche insensible à la casse
            user = User.objects.get(
                Q(username__iexact=username) | Q(email__iexact=username)
            )
            logger.debug(f"[EmailOrUsernameAuth] Utilisateur trouvé: {user.username}")
        except User.DoesNotExist:
            # Pour éviter les attaques temporelles, on crée un hash de mot de passe factice
            User().set_password(password)
            logger.warning(f"[EmailOrUsernameAuth] Aucun utilisateur trouvé pour: {username}")
            return None
        except User.MultipleObjectsReturned:
            # Cas rare où plusieurs utilisateurs auraient le même email/username
            logger.error(f"[EmailOrUsernameAuth] Multiple users found for: {username}")
            return None
        else:
            if user.check_password(password) and self.user_can_authenticate(user):
                logger.info(f"[EmailOrUsernameAuth] Authentification réussie pour: {user.username}")
                return user
            else:
                logger.warning(f"[EmailOrUsernameAuth] Échec authentification pour: {user.username}")
        return None


class CookieJWTAuthentication(JWTAuthentication):
    """
    Authentification JWT via cookies avec fallback sur les headers
    Exclut automatiquement les URLs d'administration
    """
    
    # Chemins exclus de l'authentification JWT
    EXCLUDED_PATHS = [
        re.compile(r'^/admin/'),
        re.compile(r'^/static/'),
        re.compile(r'^/media/'),
        re.compile(r'^/(api/)?auth/login/'),
        re.compile(r'^/(api/)?auth/refresh/'),
        re.compile(r'^/(api/)?auth/password-reset/'),
    ]
    
    def is_excluded_path(self, request):
        """Vérifie si le chemin est exclu de l'authentification JWT"""
        path = request.path_info
        return any(pattern.match(path) for pattern in self.EXCLUDED_PATHS)
    
    def authenticate(self, request):
        # Ne pas authentifier les chemins exclus
        if self.is_excluded_path(request):
            logger.debug(f"[CookieJWT] Chemin exclu: {request.path}")
            return None
        
        # Priorité au header Authorization s'il est présent
        header_result = super().authenticate(request)
        if header_result is not None:
            user, token = header_result
            logger.debug(f"[CookieJWT] Authentification réussie via header pour: {user.username}")
            return (user, token)

        # Sinon, on regarde dans les cookies
        raw_token = request.COOKIES.get('access_token')
        
        if not raw_token:
            logger.debug(
                f"[CookieJWT] Aucun token dans les cookies pour: {request.path}. "
                f"Cookies présents: {list(request.COOKIES.keys())}"
            )
            return None

        try:
            # Valider le token
            validated_token = self.get_validated_token(raw_token)
            user = self.get_user(validated_token)

            if user is None:
                logger.warning(f"[CookieJWT] Utilisateur introuvable pour le token fourni")
                raise InvalidToken("Utilisateur introuvable")

            if not user.is_active:
                logger.warning(f"[CookieJWT] Utilisateur inactif: {user.username}")
                raise InvalidToken("Utilisateur inactif")

            logger.info(f"[CookieJWT] Authentification réussie via cookie pour: {user.username}")
            return (user, validated_token)

        except TokenError as e:
            logger.warning(f"[CookieJWT] TokenError: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"[CookieJWT] Erreur inattendue: {str(e)}", exc_info=True)
            return None
    
    def get_validated_token(self, raw_token):
        """
        Surcharge pour une meilleure gestion des erreurs
        """
        try:
            return super().get_validated_token(raw_token)
        except TokenError as e:
            logger.warning(f"[CookieJWT] Token validation failed: {str(e)}")
            raise


class CookieJWTMiddleware(MiddlewareMixin):
    """
    Middleware pour injecter le token JWT des cookies dans les headers
    Amélioré avec exclusions et meilleure gestion des logs
    """
    
    # Chemins où le middleware ne s'applique pas
    EXCLUDED_PATHS = [
        re.compile(r'^/admin/'),
        re.compile(r'^/static/'),
        re.compile(r'^/media/'),
        re.compile(r'^/(api/)?auth/login/'),
        re.compile(r'^/(api/)?auth/refresh/'),
        re.compile(r'^/(api/)?auth/password-reset/'),
    ]
    
    def is_excluded_path(self, path):
        """Vérifie si le chemin est exclu du middleware"""
        return any(pattern.match(path) for pattern in self.EXCLUDED_PATHS)
    
    def process_request(self, request):
        path = request.path_info
        
        # Ne pas traiter les chemins exclus
        if self.is_excluded_path(path):
            return None
        
        # Vérifier si un header Authorization est déjà présent
        if request.META.get('HTTP_AUTHORIZATION'):
            logger.debug(f"[CookieMiddleware] Header Authorization déjà présent pour: {path}")
            return None
        
        # Injecter le token du cookie dans le header
        access_token = request.COOKIES.get('access_token')
        if access_token:
            request.META['HTTP_AUTHORIZATION'] = f'Bearer {access_token}'
            logger.debug(f"[CookieMiddleware] Token injecté dans header pour: {path}")
        else:
            logger.debug(
                f"[CookieMiddleware] Aucun token dans les cookies pour: {path}. "
                f"Cookies reçus: {list(request.COOKIES.keys())}"
            )
        
        return None


class OptionalJWTAuthentication(CookieJWTAuthentication):
    """
    Version optionnelle de l'authentification JWT
    Ne renvoie pas d'erreur si le token est invalide, retourne simplement None
    Utile pour les endpoints qui peuvent être utilisés avec ou sans authentification
    """
    
    def authenticate(self, request):
        try:
            return super().authenticate(request)
        except Exception as e:
            logger.debug(f"[OptionalJWT] Authentification échouée mais optionnelle: {str(e)}")
            return None


class StrictCookieJWTAuthentication(CookieJWTAuthentication):
    """
    Version stricte qui exige un token valide
    Renvoie une erreur d'authentification si le token est invalide
    """
    
    def authenticate(self, request):
        result = super().authenticate(request)
        
        if result is None and not self.is_excluded_path(request):
            # Pour les chemins non exclus, on exige une authentification
            logger.warning(f"[StrictCookieJWT] Accès refusé à: {request.path}")
            from rest_framework.exceptions import AuthenticationFailed
            raise AuthenticationFailed('Authentification requise')
        
        return result


def get_user_from_token(request):
    """
    Fonction utilitaire pour récupérer l'utilisateur depuis le token
    sans lever d'exception en cas d'échec
    """
    try:
        auth = CookieJWTAuthentication()
        result = auth.authenticate(request)
        if result is not None:
            user, token = result
            return user
    except Exception as e:
        logger.debug(f"[get_user_from_token] Échec: {str(e)}")
    
    return None


# Configuration du logging pour l'authentification
class AuthLogFilter(logging.Filter):
    """
    Filtre pour les logs d'authentification
    """
    
    def filter(self, record):
        if not hasattr(record, 'auth_type'):
            record.auth_type = 'AUTH'
        return True


# Configuration avancée du logging
def setup_auth_logging():
    """
    Configuration spécifique pour les logs d'authentification
    """
    auth_logger = logging.getLogger('auth')
    auth_logger.setLevel(logging.INFO)
    auth_logger.addFilter(AuthLogFilter())
