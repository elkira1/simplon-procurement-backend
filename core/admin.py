from django.contrib import admin

# Register your models here.

from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from .models import CustomUser, PasswordResetCode, PurchaseRequest, RequestStep, Attachment, UserActivity

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'role', 'department', 'is_staff', 'is_active')
    list_filter = ('role', 'is_staff', 'is_active', 'department')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    
    fieldsets = UserAdmin.fieldsets + (
        ('Informations supplémentaires', {
            'fields': ('role', 'department', 'phone')
        }),
    )
    
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Informations supplémentaires', {
            'fields': ('role', 'department', 'phone')
        }),
    )
    
@admin.register(UserActivity)
class UserActivityAdmin(admin.ModelAdmin):
    list_display = ('user', 'action', 'performed_by', 'timestamp', 'ip_address')
    list_filter = ('action', 'timestamp', 'performed_by__role')
    search_fields = ('user__username', 'performed_by__username', 'details')
    readonly_fields = ('timestamp',)

    def has_add_permission(self, request):
        return False  
    def has_change_permission(self, request, obj=None):
        return False  
    

@admin.register(PasswordResetCode)
class PasswordResetCodeAdmin(admin.ModelAdmin):
    list_display = ('user', 'code', 'created_at', 'expires_at', 'is_used', 'ip_address')
    list_filter = ('is_used', 'created_at')
    search_fields = ('user__username', 'code')
    readonly_fields = ('created_at', 'expires_at', 'code')

    def has_add_permission(self, request):
        return False  

    def has_change_permission(self, request, obj=None):
        return False



class RequestStepInline(admin.TabularInline):
    model = RequestStep
    extra = 0
    readonly_fields = ('created_at',)
    fields = ('user', 'action', 'comment', 'budget_check', 'created_at')

class AttachmentInline(admin.TabularInline):
    model = Attachment
    extra = 0
    readonly_fields = ('created_at', 'file_size_mb')
    fields = ('file_url', 'file_type', 'description', 'uploaded_by', 'created_at')

@admin.register(PurchaseRequest)
class PurchaseRequestAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'user', 'item_description_short', 'estimated_cost', 
        'status_badge', 'urgency_badge', 'created_at'
    )
    list_filter = ('status', 'urgency', 'created_at', 'user__role')
    search_fields = ('item_description', 'user__username', 'justification')
    readonly_fields = ('created_at', 'updated_at', 'current_step')
    
    fieldsets = (
        ('Informations de base', {
            'fields': ('user', 'item_description', 'quantity', 'estimated_cost', 'urgency')
        }),
        ('Justification', {
            'fields': ('justification',)
        }),
        ('Workflow', {
            'fields': ('status', 'current_step', 'budget_available', 'final_cost')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    inlines = [RequestStepInline, AttachmentInline]
    
    def item_description_short(self, obj):
        return obj.item_description[:50] + "..." if len(obj.item_description) > 50 else obj.item_description
    item_description_short.short_description = "Description"
    
    def status_badge(self, obj):
        colors = {
            'pending': '#fbbf24',  # yellow
            'mg_approved': '#3b82f6',  # blue
            'accounting_reviewed': '#8b5cf6',  # purple
            'director_approved': '#10b981',  # green
            'rejected': '#ef4444'  # red
        }
        color = colors.get(obj.status, '#6b7280')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; border-radius: 12px; font-size: 11px;">{}</span>',
            color,
            obj.get_status_display()
        )
    status_badge.short_description = "Statut"
    
    def urgency_badge(self, obj):
        colors = {
            'low': '#10b981',  # green
            'medium': '#f59e0b',  # amber
            'high': '#f97316',  # orange
            'critical': '#ef4444'  # red
        }
        color = colors.get(obj.urgency, '#6b7280')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; border-radius: 12px; font-size: 11px;">{}</span>',
            color,
            obj.get_urgency_display()
        )
    urgency_badge.short_description = "Urgence"
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')

@admin.register(RequestStep)
class RequestStepAdmin(admin.ModelAdmin):
    list_display = ('request_id', 'user', 'action', 'comment_short', 'created_at')
    list_filter = ('action', 'created_at', 'user__role')
    search_fields = ('request__item_description', 'user__username', 'comment')
    readonly_fields = ('created_at',)
    
    def request_id(self, obj):
        return f"Demande #{obj.request.id}"
    request_id.short_description = "Demande"
    
    def comment_short(self, obj):
        return obj.comment[:50] + "..." if len(obj.comment) > 50 else obj.comment
    comment_short.short_description = "Commentaire"

@admin.register(Attachment)
class AttachmentAdmin(admin.ModelAdmin):
    list_display = ('request_id', 'file_url', 'file_type', 'description', 'uploaded_by', 'file_size_mb', 'created_at')
    list_filter = ('file_type', 'created_at', 'uploaded_by__role')
    search_fields = ('request__item_description', 'description', 'uploaded_by__username')
    readonly_fields = ('created_at', 'file_size_mb')
    
    def request_id(self, obj):
        return f"Demande #{obj.request.id}"
    request_id.short_description = "Demande"

admin.site.site_header = "Administration - Gestion Moyens Généraux"
admin.site.site_title = "Gestion MG"
admin.site.index_title = "Tableau de bord administrateur"