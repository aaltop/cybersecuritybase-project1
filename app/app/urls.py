from django.urls import path
import django.contrib.auth.views as auth_views

from . import views

app_name = "app"
urlpatterns = [
    path("", views.index, name="index"),
    path(
        "login/",
        auth_views.LoginView.as_view(template_name="app/login.html"),
        name="login",
    ),
    path("signup/", views.signup, name="signup"),
]
