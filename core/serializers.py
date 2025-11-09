# core/serializers.py
import logging
import secrets
import string

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from rest_framework import serializers

from services.email_service import EmailService
from services.supabase_storage_service import (
    SupabaseStorageError,
    SupabaseStorageService,
)

from .models import Attachment, PasswordResetCode, PurchaseRequest, RequestStep, UserActivity


logger = logging.getLogger(__name__)

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'role', 'department', 'phone']
        read_only_fields = ['id']
        


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()
    
    def validate_email(self, value):
        try:
            user = User.objects.get(email__iexact=value)
            if not user.is_active:
                raise serializers.ValidationError("Ce compte est désactivé.")
        except User.DoesNotExist:
            raise serializers.ValidationError("Aucun compte associé à cet email.")
        return value.lower()


class PasswordResetVerifySerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(max_length=5, min_length=5)
    
    def validate(self, attrs):
        email = attrs.get('email')
        code = attrs.get('code')
        
        try:
            user = User.objects.get(email__iexact=email)
            reset_code = PasswordResetCode.objects.filter(
                user=user, 
                code=code,
                is_used=False
            ).order_by('-created_at').first()
            
            if not reset_code:
                raise serializers.ValidationError("Code incorrect.")
            
            if reset_code.is_expired():
                raise serializers.ValidationError("Code expiré.")
                
            attrs['user'] = user
            attrs['reset_code'] = reset_code
            
        except User.DoesNotExist:
            raise serializers.ValidationError("Email non trouvé.")
            
        return attrs


class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField(min_length=8)
    confirm_password = serializers.CharField(min_length=8)
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError("Les mots de passe ne correspondent pas.")
        return attrs


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer pour l'inscription d'un utilisateur avec mot de passe auto-généré"""
    generated_password = serializers.CharField(read_only=True)
    created_by_name = serializers.CharField(source='created_by.username', read_only=True)
    created_by_role = serializers.CharField(source='created_by.get_role_display', read_only=True)
    email_sent = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name', 
            'role', 'department', 'phone', 'generated_password',
            'created_by_name', 'created_by_role', 'created_at', 'is_active',
            'email_sent'
        ]
        extra_kwargs = {
            'email': {'required': True},
            'first_name': {'required': True},
            'last_name': {'required': True},
        }

    def validate_email(self, value):
        """Vérifier que l'email n'existe pas déjà"""
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("Un utilisateur avec cet email existe déjà.")
        return value.lower()

    def validate_username(self, value):
        """Vérifier que le username n'existe pas déjà"""
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError("Un utilisateur avec ce nom d'utilisateur existe déjà.")
        return value.lower()

    def generate_password(self, length=12):
        """Générer un mot de passe sécurisé"""
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special_chars = "!@#$%&*"
        
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special_chars)
        ]
        
        all_chars = lowercase + uppercase + digits + special_chars
        for _ in range(length - 4):
            password.append(secrets.choice(all_chars))
        
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)

    def create(self, validated_data):
        """Créer l'utilisateur avec un mot de passe généré automatiquement"""
        created_by = self.context.get('created_by')
        
        generated_password = self.generate_password()
        
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            password=generated_password,
            role=validated_data.get('role', 'employee'),
            department=validated_data.get('department', ''),
            phone=validated_data.get('phone', ''),
            created_by=created_by
        )
        
        UserActivity.objects.create(
            user=user,
            performed_by=created_by,
            action='created',
            details={
                'role': user.role,
                'department': user.department,
                'email': user.email
            },
            ip_address=self.context.get('ip_address')
        )
        
        user.generated_password = generated_password
        
        email_service = EmailService()
        email_sent = False
        
        try:
            welcome_sent = email_service.send_welcome_email(
                user=user,
                created_by=created_by,
                generated_password=generated_password
            )
            
            notification_sent = email_service.send_notification_to_creator(
                creator=created_by,
                new_user=user
            )
            
            email_sent = welcome_sent  
            
        except Exception as e:
            logger.error("Erreur lors de l'envoi des emails de bienvenue: %s", e, exc_info=True)
            email_sent = False
        
        user.email_sent = email_sent
        
        return user

    def to_representation(self, instance):
        """Personnaliser la réponse"""
        data = super().to_representation(instance)
        if hasattr(instance, 'generated_password'):
            data['generated_password'] = instance.generated_password
            email_status = "envoyé" if getattr(instance, 'email_sent', False) else "non envoyé"
            data['message'] = (
                f"Utilisateur créé avec succès. "
                f"Mot de passe généré : {instance.generated_password}. "
                f"Email de bienvenue : {email_status}."
            )
        return data


class UserListSerializer(serializers.ModelSerializer):
    """Serializer pour la liste des utilisateurs"""
    created_by_name = serializers.CharField(source='created_by.username', read_only=True)
    created_by_role = serializers.CharField(source='created_by.get_role_display', read_only=True)
    role_display = serializers.CharField(source='get_role_display', read_only=True)
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name', 'full_name',
            'role', 'role_display', 'department', 'phone', 'is_active',
            'created_by_name', 'created_by_role', 'created_at', 'updated_at'
        ]
    
    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip()


class UserUpdateSerializer(serializers.ModelSerializer):
    """Serializer pour la mise à jour des utilisateurs"""
    
    class Meta:
        model = User
        fields = ['role', 'department', 'phone', 'is_active']
    
    def update(self, instance, validated_data):
        old_values = {
            'role': instance.role,
            'department': instance.department,
            'phone': instance.phone,
            'is_active': instance.is_active
        }
        
        updated_instance = super().update(instance, validated_data)
        
        performed_by = self.context.get('performed_by')
        changes = {}
        
        for field, new_value in validated_data.items():
            if old_values.get(field) != new_value:
                changes[field] = {
                    'old': old_values.get(field),
                    'new': new_value
                }
        
        if changes:
            UserActivity.objects.create(
                user=updated_instance,
                performed_by=performed_by,
                action='role_changed' if 'role' in changes else 'updated',
                details=changes,
                ip_address=self.context.get('ip_address')
            )
        
        return updated_instance


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    """Serializer pour que les utilisateurs mettent à jour leur propre profil"""
    
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'phone', 'username']
        extra_kwargs = {
            'email': {'required': True}
        }
    
    def validate_email(self, value):
        """Vérifier que l'email n'est pas déjà utilisé par un autre utilisateur"""
        if User.objects.exclude(pk=self.instance.pk).filter(email__iexact=value).exists():
            raise serializers.ValidationError("Un autre utilisateur utilise déjà cet email.")
        return value.lower()
    

class PasswordChangeSerializer(serializers.Serializer):
    """Serializer pour le changement de mot de passe"""
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, min_length=8)
    
    def validate_old_password(self, value):
        """Vérifier l'ancien mot de passe"""
        user = self.context['request'].user
        if not check_password(value, user.password):
            raise serializers.ValidationError("Ancien mot de passe incorrect.")
        return value
    
    def validate_new_password(self, value):
        """Validation du nouveau mot de passe"""
        if len(value) < 8:
            raise serializers.ValidationError(
                "Le nouveau mot de passe doit contenir au moins 8 caractères."
            )
        return value
    
    def save(self):
        """Changer le mot de passe"""
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        
        UserActivity.objects.create(
            user=user,
            performed_by=user,
            action='updated',
            details={'action': 'password_changed'},
            ip_address=self.context.get('ip_address')
        )
        
        return user


class UserActivitySerializer(serializers.ModelSerializer):
    """Serializer pour les activités des utilisateurs"""
    performed_by_name = serializers.CharField(source='performed_by.username', read_only=True)
    performed_by_role = serializers.CharField(source='performed_by.get_role_display', read_only=True)
    action_display = serializers.CharField(source='get_action_display', read_only=True)
    
    class Meta:
        model = UserActivity
        fields = [
            'id', 'action', 'action_display', 'details', 'timestamp',
            'performed_by_name', 'performed_by_role'
        ]


class AttachmentSerializer(serializers.ModelSerializer):
    uploaded_by_name = serializers.CharField(source='uploaded_by.username', read_only=True)
    file_size_mb = serializers.ReadOnlyField()
    file_url = serializers.SerializerMethodField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._supabase_service = None
        self._supabase_service_attempted = False

    class Meta:
        model = Attachment
        fields = [
            'id',
            'file_url',
            'file_type',
            'description',
            'request',
            'uploaded_by',
            'uploaded_by_name',
            'file_size',
            'file_size_mb',
            'mime_type',
            'storage_public_id',
            'storage_resource_type',
            'created_at',
        ]
        read_only_fields = ['id', 'uploaded_by', 'file_size', 'mime_type', 'storage_public_id', 'storage_resource_type', 'created_at']

    def get_file_url(self, obj):
        if obj.storage_resource_type == 'supabase' and obj.storage_public_id:
            service = self._get_supabase_service()
            if service:
                try:
                    return service.get_file_url(obj.storage_public_id)
                except SupabaseStorageError as exc:
                    logger.warning("Impossible de générer l'URL Supabase pour l'attachement %s: %s", obj.id, exc)
        return obj.file_url

    def _get_supabase_service(self):
        if self._supabase_service_attempted:
            return self._supabase_service
        self._supabase_service_attempted = True
        try:
            self._supabase_service = SupabaseStorageService()
        except SupabaseStorageError as exc:
            logger.debug("Supabase Storage non disponible pour la sérialisation: %s", exc)
            self._supabase_service = None
        return self._supabase_service

class RequestStepSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.username', read_only=True)
    user_role = serializers.CharField(source='user.get_role_display', read_only=True)
    
    class Meta:
        model = RequestStep
        fields = ['id', 'user', 'user_name', 'user_role', 'action', 'comment', 'budget_check', 'created_at']
        read_only_fields = ['id', 'user', 'created_at']


class PurchaseRequestListSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.username', read_only=True)
    user_id = serializers.IntegerField(source='user.id', read_only=True)
    department = serializers.CharField(source='user.department', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    urgency_display = serializers.CharField(source='get_urgency_display', read_only=True)
    current_step = serializers.ReadOnlyField()

    rejected_by_name = serializers.CharField(source='rejected_by.username', read_only=True)

    accounting_validated_by = serializers.IntegerField(source='accounting_validated_by.id', read_only=True)
    accounting_validated_by_name = serializers.CharField(source='accounting_validated_by.username', read_only=True)

    approved_by = serializers.IntegerField(source='approved_by.id', read_only=True)
    approved_by_name = serializers.CharField(source='approved_by.username', read_only=True)

    created_by = serializers.IntegerField(source='user.id', read_only=True)

    class Meta:
        model = PurchaseRequest
        fields = [
            'id', 'user', 'user_id', 'user_name','department', 'created_by',
            'item_description', 'quantity', 
            'estimated_cost', 'final_cost', 'urgency', 'urgency_display', 'status', 
            'status_display', 'current_step', 'created_at', 'updated_at',
            'justification',
            'rejected_by', 'rejected_by_name', 'rejected_by_role',
            'accounting_validated_by', 'accounting_validated_by_name',
            'approved_by', 'approved_by_name'
        ]

        
       
class PurchaseRequestDetailSerializer(serializers.ModelSerializer):
    """Serializer pour le détail d'une demande (avec steps et attachments)"""
    user_name = serializers.CharField(source='user.username', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    urgency_display = serializers.CharField(source='get_urgency_display', read_only=True)
    current_step = serializers.ReadOnlyField()
    steps = RequestStepSerializer(many=True, read_only=True)
    attachments = AttachmentSerializer(many=True, read_only=True)
    rejected_by_name = serializers.CharField(source='rejected_by.username', read_only=True)
    
    class Meta:
        model = PurchaseRequest
        fields = [
            'id', 'user', 'user_name', 'item_description', 'quantity', 
            'estimated_cost', 'urgency', 'urgency_display', 'justification',
            'status', 'status_display', 'current_step', 'budget_available', 
            'final_cost', 'created_at', 'updated_at', 'steps', 'attachments',
            'rejection_reason', 'rejected_by', 'rejected_by_name', 
            'rejected_at', 'rejected_by_role'
        ] 



class PurchaseRequestCreateSerializer(serializers.ModelSerializer):
    """Serializer pour créer une demande"""
    auto_validate_mg = serializers.BooleanField(required=False, write_only=True)
    
    class Meta:
        model = PurchaseRequest
        fields = [
            'item_description', 'quantity', 'estimated_cost', 
            'urgency', 'justification', 'auto_validate_mg'
        ]
    
    def create(self, validated_data):
        validated_data.pop('auto_validate_mg', None)
        return PurchaseRequest.objects.create(**validated_data)


class ValidateRequestSerializer(serializers.Serializer):
    """Serializer pour valider/rejeter une demande"""
    action = serializers.ChoiceField(choices=['approve', 'reject'])
    comment = serializers.CharField(required=False, allow_blank=True)
    budget_available = serializers.BooleanField(required=False)
    final_cost = serializers.DecimalField(max_digits=12, decimal_places=2, required=False)
    
    def validate(self, data):
        action = data.get('action')
        user_role = self.context['request'].user.role
        
        logger.debug(
            "ValidateRequestSerializer - action=%s, user_role=%s, data=%s",
            action,
            user_role,
            data,
        )
        
        if user_role == 'accounting' and action == 'approve':
            if 'budget_available' not in data:
                raise serializers.ValidationError({
                    'budget_available': "La vérification budgétaire est obligatoire pour la comptabilité"
                })
        
        if action == 'reject':
            comment = data.get('comment', '').strip()
            if not comment:
                raise serializers.ValidationError({
                    'comment': "Un commentaire est obligatoire pour refuser une demande"
                })
        
        return data
    


class DashboardSerializer(serializers.Serializer):
    total_requests = serializers.IntegerField()
    pending_requests = serializers.IntegerField()
    in_progress_requests = serializers.IntegerField()
    approved_requests = serializers.IntegerField()
    rejected_requests = serializers.IntegerField()
    recent_requests = PurchaseRequestListSerializer(many=True)
    all_requests = PurchaseRequestListSerializer(many=True)
    monthly_stats = serializers.ListField()
    requests_by_status = serializers.DictField()
    user_requests_count = serializers.IntegerField()
    
    accounting_total = serializers.IntegerField(required=False)
    accounting_pending = serializers.IntegerField(required=False)
    accounting_approved = serializers.IntegerField(required=False)
    accounting_rejected = serializers.IntegerField(required=False)
    
    director_total = serializers.IntegerField(required=False)
    director_pending = serializers.IntegerField(required=False)
    director_approved = serializers.IntegerField(required=False)
    director_rejected = serializers.IntegerField(required=False)
    
    validation_rate = serializers.IntegerField(required=False)
    processing_delays = serializers.DictField(required=False)
    department_stats = serializers.ListField(required=False)
    monthly_trends = serializers.ListField(required=False)
    trends = serializers.DictField(required=False)
    current_period_stats = serializers.DictField(required=False)
    previous_period_stats = serializers.DictField(required=False)
    
    def to_representation(self, instance):
        """Permet de dire à DRF que l'instance est déjà un dict"""
        return instance
