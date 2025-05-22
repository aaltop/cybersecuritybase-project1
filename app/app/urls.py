from django.urls import path
import django.contrib.auth.views as auth_views

from . import views

app_name = "app"
urlpatterns = [
    path("", views.index, name="index"),
    path(
        "login/",
        views.login,
        name="login",
    ),
    path("signup/", views.signup, name="signup"),
    path("logout/", views.logout, name="logout"),
    path("create_note/", views.create_note, name="create_note"),
    path("delete_note/<int:pk>", views.delete_note, name="delete_note"),
    path("shared/", views.shared, name="shared"),
    path("add_friend/", views.add_friend, name="add_friend"),
]
