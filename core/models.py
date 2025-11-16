from django.db import models, transaction

# Create your models here.
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.contrib.auth import get_user_model

from django.utils import timezone
from decimal import Decimal
import secrets
import string
from django.conf import settings




class CustomUser(AbstractUser):
    ROLES = [
        ('employee', 'Personnel'),
        ('mg', 'Responsable Moyens Généraux'),
        ('accounting', 'Comptabilité'),
        ('director', 'Direction')
    ]
    role = models.CharField(max_length=20, choices=ROLES, default='employee')
    department = models.CharField(max_length=100, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    
    created_by = models.ForeignKey(
        'self', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='created_users',
        verbose_name='Créé par'
    )
    created_at = models.DateTimeField(default=timezone.now, verbose_name='Date de création')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='Dernière modification')
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"

    class Meta:
        verbose_name = 'Utilisateur'
        verbose_name_plural = 'Utilisateurs'
        ordering = ['-created_at']

class UserActivity(models.Model):
    ACTION_CHOICES = [
        ('created', 'Créé'),
        ('updated', 'Modifié'),
        ('role_changed', 'Rôle modifié'),
        ('deactivated', 'Désactivé'),
        ('reactivated', 'Réactivé'),
    ]
    
    user = models.ForeignKey(
        CustomUser, 
        on_delete=models.CASCADE, 
        related_name='activities'
    )
    performed_by = models.ForeignKey(
        CustomUser, 
        on_delete=models.SET_NULL, 
        null=True,
        related_name='performed_activities'
    )
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    details = models.JSONField(default=dict, blank=True)  # Pour stocker les détails des changements
    timestamp = models.DateTimeField(default=timezone.now)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
    class Meta:
        verbose_name = 'Activité utilisateur'
        verbose_name_plural = 'Activités utilisateurs'
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.user.username} - {self.get_action_display()} par {self.performed_by.username if self.performed_by else 'System'}"
    
class PasswordResetCode(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='reset_codes')
    code = models.CharField(max_length=5)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def is_valid(self):
        return not self.is_used and not self.is_expired()
    
    @classmethod
    def generate_code(cls):
        """Générer un code à 5 chiffres"""
        return ''.join(secrets.choice(string.digits) for _ in range(5))
    
    def save(self, *args, **kwargs):
        if not self.code:
            self.code = self.generate_code()
        if not self.expires_at:
            # Code expire dans 5 minutes
            self.expires_at = timezone.now() + timezone.timedelta(minutes=5)
        super().save(*args, **kwargs)

class PurchaseRequest(models.Model):
    STATUS_CHOICES = [
        ('pending', 'En attente'),
        ('mg_approved', 'Validée par Moyens Généraux'),
        ('accounting_reviewed', 'En étude par Comptabilité'),
        ('director_approved', 'Approuvée par Direction'),
        ('rejected', 'Refusée')
    ]
    
    URGENCY_CHOICES = [
        ('low', 'Faible'),
        ('medium', 'Moyenne'),
        ('high', 'Élevée'),
        ('critical', 'Critique')
    ]
    
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='requests')
    item_description = models.TextField("Description du produit/service")
    quantity = models.IntegerField("Quantité")
    estimated_cost = models.DecimalField("Coût estimé", max_digits=12, decimal_places=2, null=True, blank=True)
    urgency = models.CharField("Urgence", max_length=20, choices=URGENCY_CHOICES, default='medium')
    justification = models.TextField("Justification de la demande")
    
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default='pending')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    budget_available = models.BooleanField("Budget disponible", null=True, blank=True)
    final_cost = models.DecimalField("Coût final", max_digits=12, decimal_places=2, null=True, blank=True)
    accounting_validated_by = models.ForeignKey(
        CustomUser, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='accounting_validated_requests'
    )
    accounting_validated_at = models.DateTimeField("Date validation comptable", null=True, blank=True)
    
    approved_by = models.ForeignKey(
        CustomUser, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='approved_requests'
    )  
    approved_at = models.DateTimeField("Date approbation", null=True, blank=True)  
    
    mg_validated_by = models.ForeignKey(
        CustomUser, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='mg_validated_requests'
    )  
    mg_validated_at = models.DateTimeField("Date validation MG", null=True, blank=True)  

    
    rejection_reason = models.TextField("Motif du refus", blank=True, null=True)
    rejected_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='rejected_requests')
    rejected_at = models.DateTimeField("Date de refus", null=True, blank=True)
    rejected_by_role = models.CharField("Rôle du refuseur", max_length=20, blank=True, null=True)
    budget_project = models.ForeignKey(
        'BudgetProject',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='purchase_requests',
    )
    budget_locked_amount = models.DecimalField(
        max_digits=12, decimal_places=2, null=True, blank=True
    )
    budget_deducted = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']
        verbose_name = "Demande d'achat"
        verbose_name_plural = "Demandes d'achat"

    def __str__(self):
        return f"Demande #{self.id} - {self.item_description[:50]}..."
    
    @property
    def current_step(self):
        """Retourne l'étape actuelle du workflow"""
        steps_order = {
            'pending': 'Moyens Généraux',
            'mg_approved': 'Comptabilité', 
            'accounting_reviewed': 'Direction',
            'director_approved': 'Terminé',
            'rejected': 'Refusée'
        }
        return steps_order.get(self.status, 'Inconnu')

class RequestStep(models.Model):
    ACTION_CHOICES = [
        ('submitted', 'Soumise'),
        ('approved', 'Approuvée'),
        ('rejected', 'Refusée'),
        ('reviewed', 'Étudiée'),
    ]
    
    request = models.ForeignKey(PurchaseRequest, on_delete=models.CASCADE, related_name='steps')
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    comment = models.TextField("Commentaire", blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    budget_check = models.BooleanField("Vérification budgétaire", null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Étape de validation"
        verbose_name_plural = "Étapes de validation"

    def __str__(self):
        return f"{self.request.id} - {self.get_action_display()} par {self.user.username}"

class Attachment(models.Model):
    ATTACHMENT_TYPES = [
        ('quote', 'Devis'),
        ('invoice', 'Facture'),
        ('justification', 'Justificatif'),
        ('pdf', 'PDF'),
        ('jpeg', 'Image JPEG'),
        ('png', 'Image PNG'),
        ('other', 'Autre')
    ]
    
    request = models.ForeignKey(PurchaseRequest, on_delete=models.CASCADE, related_name='attachments')
    file_url = models.URLField(max_length=500, blank=True, null=True)
    file_type = models.CharField(max_length=20, choices=ATTACHMENT_TYPES, default='other')
    description = models.CharField("Description", max_length=200, blank=True)
    uploaded_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    storage_public_id = models.CharField(max_length=255, blank=True, null=True)
    storage_resource_type = models.CharField(max_length=20, blank=True, null=True)
    file_size = models.BigIntegerField(blank=True, null=True)
    mime_type = models.CharField(max_length=120, blank=True, null=True)
    
    class Meta:
        verbose_name = "Pièce jointe"
        verbose_name_plural = "Pièces jointes"

    def __str__(self):
        return f"{self.get_file_type_display()} - Demande #{self.request.id}"

    @property
    def file_size_mb(self):
        """Retourne la taille du fichier en MB"""
        if self.file_size is not None:
            return round(self.file_size / (1024 * 1024), 2)
        return None


class BudgetProject(models.Model):
    STATUS_CHOICES = [
        ('active', 'Actif'),
        ('on_hold', 'Suspendu'),
        ('closed', 'Clôturé'),
    ]

    name = models.CharField(max_length=150)
    code = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True)
    allocated_amount = models.DecimalField(max_digits=14, decimal_places=2, default=0)
    committed_amount = models.DecimalField(max_digits=14, decimal_places=2, default=0)
    spent_amount = models.DecimalField(max_digits=14, decimal_places=2, default=0)
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    created_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_budget_projects',
        limit_choices_to={'role': 'accounting'},
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = "Projet budgétaire"
        verbose_name_plural = "Projets budgétaires"

    def __str__(self):
        return f"{self.code} - {self.name}"

    @property
    def available_amount(self):
        return (
            (self.allocated_amount or Decimal('0')) -
            (self.committed_amount or Decimal('0')) -
            (self.spent_amount or Decimal('0'))
        )

    def _clean_amount(self, amount):
        if amount is None:
            return Decimal('0')
        if not isinstance(amount, Decimal):
            amount = Decimal(str(amount))
        return amount.quantize(Decimal('0.01'))

    def reserve_amount(self, amount):
        amount = self._clean_amount(amount)
        if amount <= 0:
            raise ValueError("Le montant réservé doit être positif.")
        if amount > self.available_amount:
            raise ValueError("Budget insuffisant sur ce projet.")
        self.committed_amount = (self.committed_amount or Decimal('0')) + amount
        self.save(update_fields=['committed_amount', 'updated_at'])

    def release_amount(self, amount):
        amount = self._clean_amount(amount)
        if amount <= 0:
            return
        current_committed = self.committed_amount or Decimal('0')
        self.committed_amount = max(Decimal('0'), current_committed - amount)
        self.save(update_fields=['committed_amount', 'updated_at'])

    def spend_amount(self, amount):
        amount = self._clean_amount(amount)
        if amount <= 0:
            return
        current_committed = self.committed_amount or Decimal('0')
        if amount > current_committed + self.available_amount:
            raise ValueError("Montant supérieur au budget disponible.")
        committed_after = max(Decimal('0'), current_committed - amount)
        self.committed_amount = committed_after
        self.spent_amount = (self.spent_amount or Decimal('0')) + amount
        self.save(update_fields=['committed_amount', 'spent_amount', 'updated_at'])


class ProvisionRequest(models.Model):
    PRIORITY_CHOICES = [
        ('low', 'Basse'),
        ('normal', 'Normale'),
        ('high', 'Haute'),
    ]

    STATUS_CHOICES = [
        ('pending', 'En attente'),
        ('in_progress', 'En cours de traitement'),
        ('completed', 'Distribuée'),
        ('rejected', 'Refusée'),
    ]

    title = models.CharField(max_length=150)
    description = models.TextField()
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default='normal')
    expected_date = models.DateField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='provision_requests')
    handled_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='handled_provision_requests',
        limit_choices_to={'role': 'mg'},
    )
    manager_note = models.TextField(blank=True)
    rejection_reason = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = "Mise à disposition"
        verbose_name_plural = "Mises à disposition"

    def __str__(self):
        return f"MAD #{self.id} - {self.title}"


class IncidentReport(models.Model):
    CATEGORY_CHOICES = [
        ('logistics', 'Logistique / Moyens'),
        ('it', 'Informatique'),
        ('hr', 'Ressources Humaines'),
        ('security', 'Sécurité'),
        ('other', 'Autre'),
    ]

    STATUS_CHOICES = [
        ('open', 'Ouvert'),
        ('acknowledged', 'Pris en charge'),
        ('resolved', 'Résolu'),
    ]

    title = models.CharField(max_length=180)
    category = models.CharField(max_length=40, choices=CATEGORY_CHOICES, default='other')
    description = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    resolution_note = models.TextField(blank=True)

    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='incident_reports')
    acknowledged_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='acknowledged_incidents',
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_activity_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-last_activity_at']
        verbose_name = "Signalement"
        verbose_name_plural = "Signalements"

    def __str__(self):
        return f"Signalement #{self.id} - {self.title}"


class IncidentComment(models.Model):
    report = models.ForeignKey(IncidentReport, on_delete=models.CASCADE, related_name='comments')
    author = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']
        verbose_name = "Commentaire de signalement"
        verbose_name_plural = "Commentaires de signalement"

    def __str__(self):
        return f"Commentaire #{self.id} sur signalement #{self.report_id}"
    
