from django.utils.deprecation import MiddlewareMixin
import re

class CookieJWTMiddleware(MiddlewareMixin):
    """
    Middleware pour gérer l'authentification JWT via les cookies
    S'applique uniquement aux URLs de l'API, pas à l'admin
    """
    
    # URLs à exclure de l'authentification JWT
    EXCLUDED_PATHS = [
        re.compile(r'^/admin/'),
        re.compile(r'^/static/'),
        re.compile(r'^/media/'),
        re.compile(r'^/(api/)?auth/login/'),
        re.compile(r'^/(api/)?auth/refresh/'),
        re.compile(r'^/(api/)?auth/password-reset/'),
    ]
    
    def process_view(self, request, view_func, view_args, view_kwargs):
        # Vérifier si le chemin est exclu
        path = request.path_info
        
        for pattern in self.EXCLUDED_PATHS:
            if pattern.match(path):
                return None  # Ne pas appliquer l'authentification JWT
        
        # Pour les autres chemins, laisser DRF gérer l'authentification
        return None
