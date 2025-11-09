import os
from typing import List

import django
from django.conf import settings
from dotenv import load_dotenv

from services.supabase_storage_service import (
    SupabaseStorageError,
    SupabaseStorageService,
)


def _print_env_status(keys: List[str]) -> None:
    print("1. VARIABLES D'ENVIRONNEMENT")
    print("-" * 40)
    for key in keys:
        value = os.environ.get(key)
        if value:
            masked = value if "KEY" not in key and "SECRET" not in key else "<secret>"
            print(f"✅ {key}: {masked}")
        else:
            print(f"ℹ️ {key}: non défini")


def diagnose_supabase() -> None:
    print("🔍 DIAGNOSTIC SUPABASE STORAGE")
    print("=" * 60)

    env_keys = [
        "SUPABASE_ENABLED",
        "SUPABASE_URL",
        "SUPABASE_SERVICE_KEY",
        "SUPABASE_BUCKET",
        "SUPABASE_FOLDER",
    ]
    _print_env_status(env_keys)

    print("\n2. PARAMÈTRES DJANGO")
    print("-" * 40)
    enabled = getattr(settings, "SUPABASE_ENABLED", False)
    folder = getattr(settings, "SUPABASE_FOLDER", None)
    print(f"SUPABASE_ENABLED: {enabled}")
    print(f"SUPABASE_FOLDER: {folder}")

    if not enabled:
        print("\n⚠️ Supabase Storage est désactivé (SUPABASE_ENABLED=False).")
        return

    print("\n3. TEST CONNEXION API")
    print("-" * 40)
    try:
        service = SupabaseStorageService()
        bucket = service.bucket_name
        print(f"✅ Connexion réussie au bucket '{bucket}'.")

        try:
            listing = service.client.storage.from_(bucket).list(
                path=folder or "", limit=1
            )
            if isinstance(listing, dict) and listing.get("error"):
                print(f"ℹ️ Impossible de lister le bucket: {listing['error']}")
            else:
                print("📁 Accès lecture OK (list).")
        except Exception as listing_error:  # pragma: no cover
            print(f"ℹ️ Erreur lors de la lecture du bucket: {listing_error}")

    except SupabaseStorageError as exc:
        print(f"❌ Erreur Supabase Storage: {exc}")
    except Exception as exc:  # pragma: no cover
        print(f"❌ Erreur inattendue: {exc}")


if __name__ == "__main__":
    load_dotenv()
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "simplonservice.settings")
    django.setup()
    diagnose_supabase()
