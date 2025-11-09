import base64
import json
import logging
from typing import Optional

from django.conf import settings
from supabase import Client, create_client

logger = logging.getLogger(__name__)


class SupabaseStorageError(RuntimeError):
    """Erreur levée lorsque Supabase Storage rencontre un problème."""


class SupabaseStorageService:
    def __init__(self) -> None:
        if not getattr(settings, "SUPABASE_ENABLED", False):
            raise SupabaseStorageError("Supabase Storage n'est pas activé")

        url = getattr(settings, "SUPABASE_URL", None)
        key = getattr(settings, "SUPABASE_SERVICE_KEY", None)
        bucket = getattr(settings, "SUPABASE_BUCKET", None)

        if not all([url, key, bucket]):
            raise SupabaseStorageError(
                "Supabase Storage mal configuré (URL/KEY/BUCKET)"
            )

        if not self._is_service_role_key(key):
            raise SupabaseStorageError(
                "La clé Supabase fournie n'est pas une clé service_role. "
                "Récupérez 'service_role' dans Project Settings → API et placez-la dans "
                "SUPABASE_SERVICE_KEY."
            )

        self.bucket_name = bucket
        self.bucket_public = getattr(settings, "SUPABASE_PUBLIC_BUCKET", False)
        self.signed_url_ttl = getattr(settings, "SUPABASE_SIGNED_URL_TTL", 3600)
        self.client: Client = create_client(url, key)

    def upload(self, file_obj, path: str, content_type: Optional[str] = None) -> str:
        file_obj.seek(0)
        data = file_obj.read()
        file_obj.seek(0)

        response = self.client.storage.from_(self.bucket_name).upload(
            path=path,
            file=data,
            file_options={
                "content-type": content_type or "application/octet-stream",
                # Supabase attend des chaînes pour certains headers (ex: x-upsert).
                "upsert": "true",
            },
        )

        error = getattr(response, "error", None)
        if error:
            message = (
                error
                if isinstance(error, str)
                else getattr(error, "message", str(error))
            )
            raise SupabaseStorageError(message)

        return self.get_file_url(path)

    def delete(self, path: str) -> None:
        if not path:
            return
        result = self.client.storage.from_(self.bucket_name).remove([path])
        error = result.get("error")
        if error:
            logger.warning("Supabase delete error: %s", error.get("message"))

    def get_file_url(self, path: str) -> str:
        if not path:
            raise SupabaseStorageError("Chemin de fichier Supabase manquant.")

        bucket = self.client.storage.from_(self.bucket_name)

        if self.bucket_public:
            return bucket.get_public_url(path)

        response = bucket.create_signed_url(path, self.signed_url_ttl)
        error = response.get("error")
        if error:
            message = (
                error
                if isinstance(error, str)
                else getattr(error, "message", str(error))
            )
            raise SupabaseStorageError(
                f"Impossible de générer l'URL signée: {message}"
            )

        signed_url = (
            response.get("signedURL")
            or response.get("signedUrl")
            or response.get("signed_url")
        )
        if not signed_url:
            raise SupabaseStorageError("Réponse Supabase invalide (signedURL manquant).")

        return signed_url

    @staticmethod
    def _is_service_role_key(key: str) -> bool:
        try:
            payload_b64 = key.split(".")[1]
            padding = "=" * (-len(payload_b64) % 4)
            decoded = base64.urlsafe_b64decode(payload_b64 + padding)
            payload = json.loads(decoded.decode("utf-8"))
            return payload.get("role") == "service_role"
        except Exception:
            return False
