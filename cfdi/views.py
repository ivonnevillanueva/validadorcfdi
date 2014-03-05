#from cfdi.models import Cfdi
from django.http import HttpResponse
from django.http import Http404
from django.shortcuts import get_object_or_404, render_to_response, render
from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse
from django.views.generic import TemplateView


def validador(request):
    return  render(request,'validador.html', {'validador':validador})

class validadorcfdi(TemplateView):
	"""docstring for validadorcfdi"""
	template_name = 'validadorcfdi.html'

class cadena(TemplateView):
	"""docstring for cadena"""
	template_name = 'cadena.html'

class sellodigital(TemplateView):
	"""docstring for sellodigital"""
	template_name = 'sellodigital.html' 