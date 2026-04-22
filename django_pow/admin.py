from django.contrib import admin

from .models import DummyItem


@admin.register(DummyItem)
class DummyItemAdmin(admin.ModelAdmin):
    list_display = ("name", "is_active")
