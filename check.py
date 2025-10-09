import os
import django
from dotenv import load_dotenv  # Ajoutez cette ligne
from django.conf import settings

# Charger les variables d'environnement AVANT Django
load_dotenv()  # Cette ligne est cruciale

# Configuration Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'simplonservice.settings')
django.setup()

def diagnose_cloudinary():
    print("🔍 DIAGNOSTIC CLOUDINARY COMPLET")
    print("=" * 60)
    
    # 1. Vérifier les variables d'environnement (après load_dotenv)
    print("1. VARIABLES D'ENVIRONNEMENT (après load_dotenv):")
    print("-" * 40)
    env_vars = ['CLOUDINARY_CLOUD_NAME', 'CLOUDINARY_API_KEY', 'CLOUDINARY_API_SECRET']
    for var in env_vars:
        value = os.environ.get(var)
        if value:
            print(f"✅ {var}: {value}")
        else:
            print(f"❌ {var}: NON DÉFINI")
    
    print("\n2. CONFIGURATION DJANGO:")
    print("-" * 40)
    print(f"CLOUDINARY_CLOUD_NAME: {getattr(settings, 'CLOUDINARY_CLOUD_NAME', 'NON DÉFINI')}")
    print(f"CLOUDINARY_API_KEY: {getattr(settings, 'CLOUDINARY_API_KEY', 'NON DÉFINI')}")
    print(f"CLOUDINARY_API_SECRET: {'DÉFINI' if getattr(settings, 'CLOUDINARY_API_SECRET', None) else 'NON DÉFINI'}")
    
    print("\n3. TEST CLOUDINARY:")
    print("-" * 40)
    try:
        import cloudinary
        cloudinary.config(
            cloud_name=getattr(settings, 'CLOUDINARY_CLOUD_NAME', ''),
            api_key=getattr(settings, 'CLOUDINARY_API_KEY', ''),
            api_secret=getattr(settings, 'CLOUDINARY_API_SECRET', '')
        )
        
        # Test de connexion simple
        from cloudinary import api
        ping_result = api.ping()
        print("✅ Test de connexion Cloudinary: RÉUSSI")
        print(f"✅ Status: {ping_result.get('status')}")
        
    except Exception as e:
        print(f"❌ Erreur Cloudinary: {e}")
        print("💡 Conseil: Vérifiez que vos credentials sont valides dans le dashboard Cloudinary")
    
    print("=" * 60)

if __name__ == "__main__":
    diagnose_cloudinary()