from django.db import models


# Create your models here.
class Site(models.Model):
    url = models.CharField(max_length=500)
    status = models.CharField(max_length=10)


class Log(models.Model):
    url = models.CharField(max_length=500)
    source = models.CharField(max_length=10)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=10)

    def __str__(self):
        return self.url + ' ' + self.source + ' ' + self.status

class Correction(models.Model):
    url = models.CharField(max_length=500)
    source = models.CharField(max_length=10)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=10)


