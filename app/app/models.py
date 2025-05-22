from django.db import models
from django.contrib.auth.models import User

# Create your models here.


class Note(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    text = models.TextField(max_length=200)


class UserRelationship(models.Model):
    FRIEND = "FRIEND"
    relationship_types = dict(FRIEND="Friend")

    user1 = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="%(class)s_first_user"
    )
    user2 = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="%(class)s_second_user"
    )
    relationship_type = models.CharField(choices=relationship_types, default=FRIEND)

    class Meta:

        constraints = [
            models.UniqueConstraint(
                fields=["user1", "user2", "relationship_type"],
                name="unique_relationship",
            ),
            models.CheckConstraint(
                condition=~(models.Q(user1=models.F("user2"))), name="not_same_user"
            ),
        ]
