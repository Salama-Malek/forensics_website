from django.db import models
from django.contrib.auth.models import User  # Import User model
from django.contrib.auth.models import User


class Evidence(models.Model):
    file = models.FileField(upload_to='evidence_files/')
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, default=1)  # Assign default user

    def __str__(self):
        return f"Evidence {self.id} - {self.file.name}"

class MalwareAnalysis(models.Model):
    evidence = models.ForeignKey(Evidence, on_delete=models.CASCADE)
    analysis_result = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"MalwareAnalysis {self.id} - Evidence {self.evidence.id}"



class LogFile(models.Model):
    file = models.FileField(upload_to='logs/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)  # Allow null values for now

    def __str__(self):
        return self.file.name