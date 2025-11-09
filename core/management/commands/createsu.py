import os
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db.models import Q
from django.db.utils import IntegrityError
from django.utils.crypto import get_random_string

User = get_user_model()


class Command(BaseCommand):
    help = "Crée (ou promeut) un superutilisateur en s'appuyant sur les variables d'environnement ou les options CLI."

    def add_arguments(self, parser):
        parser.add_argument("--username", "-u", help="Nom d'utilisateur du superuser")
        parser.add_argument("--email", "-e", help="Adresse email du superuser")
        parser.add_argument(
            "--password",
            "-p",
            help="Mot de passe du superuser (sinon un mot de passe aléatoire sera généré)",
        )
        parser.add_argument(
            "--role",
            "-r",
            help="Rôle métier à attribuer au superuser",
        )

    def handle(self, *args, **options):
        username = options.get("username") or os.environ.get("DJANGO_SUPERUSER_USERNAME")
        email = options.get("email") or os.environ.get("DJANGO_SUPERUSER_EMAIL")
        password = options.get("password") or os.environ.get("DJANGO_SUPERUSER_PASSWORD")

        if not username:
            username = "admin"
            self.stdout.write(self.style.WARNING("⚠️  Aucun username fourni, usage du fallback \"admin\"."))

        if not email:
            raise CommandError("Une adresse email est obligatoire (--email ou DJANGO_SUPERUSER_EMAIL).")

        role = options.get("role")
        available_roles = [choice[0] for choice in getattr(User, "ROLES", [])]
        if role and available_roles and role not in available_roles:
            raise CommandError(f"Le rôle '{role}' est invalide. Choix possibles: {', '.join(available_roles)}")

        generated_password = False
        if not password:
            password = get_random_string(16)
            generated_password = True

        try:
            existing_superuser = User.objects.filter(username=username, is_superuser=True).first()
            if existing_superuser:
                self.stdout.write(self.style.WARNING(f'⚠️  Le superuser "{username}" existe déjà.'))
                return

            email_in_use = (
                User.objects.filter(Q(email__iexact=email)).exclude(username=username).exists()
            )
            if email_in_use:
                raise CommandError(f'L\'adresse email "{email}" est déjà utilisée par un autre compte.')

            role_to_assign = role or ("director" if available_roles else None)
            extra_fields = {}
            if role_to_assign and hasattr(User, "role"):
                extra_fields["role"] = role_to_assign

            user = User.objects.create_superuser(
                username=username,
                email=email,
                password=password,
                **extra_fields,
            )

            self.stdout.write(self.style.SUCCESS(f'✅ Superuser "{username}" créé ou promu avec succès !'))
            self.stdout.write(self.style.SUCCESS(f"   Email : {email}"))

            if role_to_assign and hasattr(user, "role"):
                self.stdout.write(self.style.SUCCESS(f"   Rôle appliqué : {user.role}"))

            if generated_password:
                self.stdout.write(
                    self.style.WARNING(
                        "   Un mot de passe aléatoire a été généré ci-dessous. "
                        "Pensez à le modifier rapidement."
                    )
                )
            else:
                self.stdout.write(
                    self.style.WARNING(
                        "   Mot de passe fourni via l'environnement ou les arguments. "
                        "Assurez-vous qu'il reste temporaire."
                    )
                )

            self.stdout.write(self.style.SUCCESS(f"   Mot de passe : {password}"))

        except IntegrityError as exc:
            raise CommandError(f"Erreur d'intégrité lors de la création du superuser : {exc}") from exc
        except CommandError:
            raise
        except Exception as exc:  # pragma: no cover
            raise CommandError(f"Erreur inattendue lors de la création du superuser : {exc}") from exc
