from django.contrib import admin
from .models import *

# Register your models here.
admin.site.register(Site)
admin.site.register(Correction)
admin.site.register(Log)