from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse

from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

# Create your views here.


@login_required
def index(request):
    return render(request, "app/index.html")


# TODO: see FormView?
def signup(request):
    match request.method:
        case "GET":
            context = dict(form=UserCreationForm())
            return render(request, "app/signup.html", context)
        case "POST":
            username = request.POST.get("username", None)
            password1 = request.POST.get("password1", None)
            password2 = request.POST.get("password2", None)
            if username is None or password1 is None or password2 is None:
                return HttpResponse(status=400, reason="username and password required")

            user_data = dict(
                username=username, password1=password1, password2=password2
            )
            form = UserCreationForm(user_data)
            form.full_clean()
            if form.errors:
                return render(request, "app/signup.html", dict(form=form))
            form.save()
            return HttpResponseRedirect(reverse("app:index"))
