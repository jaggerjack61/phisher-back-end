from django.shortcuts import render
from django.views import View
from django.http import JsonResponse
import json
from .models import *
import ssl
import urllib.request


# from django.http import HttpResponse
# Create your views here.

class SiteClassifier(View):
    def add_url(self, url, status):
        site = Site(url=url, status=status)
        site.save()

    def update_url(self, url, status):
        site = Site.objects.filter(url=url).first()
        site.status = status
        site.save()

    def search_url(self, url):
        site = Site.objects.filter(url=url).first()
        if site:
            if site.status == "phishing":
                return True
            else:
                return False
        else:
            return None

    def classify_url(self, url):
        import urllib
        import numpy as np
        import tensorflow as tf
        parsed_url = urllib.parse.urlparse(url)

        length_url = len(url)
        length_hostname = len(parsed_url.hostname)
        nb_dots = url.count('.')
        nb_hyphens = url.count('-')
        nb_at = url.count('@')
        nb_qm = url.count('?')
        nb_and = url.count('&')
        nb_eq = url.count('=')

        features = [length_url, length_hostname, nb_dots, nb_hyphens, nb_at, nb_qm, nb_and, nb_eq]

        features = np.reshape(features, (1, 8))

        model = tf.keras.models.load_model('phishing_model.h5')

        probs = model.predict(features)

        if probs >= 0.5:
            return True
        else:
            return False

    def check_ssl(self, url):
        context = ssl.create_default_context()
        try:
            response = urllib.request.urlopen(url, context=context)
            return True
        except Exception as e:
            return False

    def add_log(self, url, status, source):
        log = Log(url=url, status=status, source=source)
        log.save()

    def add_correction(self, url, status, source):
        correction = Correction(url=url, status=status, source=source)
        correction.save()


class Home(SiteClassifier):
    def get(self, request):
        return render(request, 'home.html')

    def post(self, request):
        data = json.loads(request.body)
        self.search_url(data['url'])
        return JsonResponse({"message": "done"})



class Status(SiteClassifier):
    def get(self, request):
        all_sites = Site.objects.all()
        return render(request, 'status.html', {'sites': all_sites})

    def post(self, request):
        data = json.loads(request.body)
        self.update_url(data['url'], data['status'])
        self.add_correction(data['url'], data['status'], data['source'])
        data['message'] = 'success'
        return JsonResponse(data)


class CheckUrl(SiteClassifier):
    def get(self, request):
        return JsonResponse({"status": "running"})

    def post(self, request):
        data = json.loads(request.body)
        print(data)

        if not data['check_ssl']:
            check = self.search_url(data['url'])
            if check:
                data['status'] = 'phishing'
            elif check == None:
                classify = self.classify_url(data['url'])
                if classify:
                    self.add_url(data['url'], 'phishing')
                    self.add_log(data['url'], 'phishing', data['source'])
                    data['status'] = 'phishing'
                else:
                    self.add_url(data['url'], 'legitimate')
                    self.add_log(data['url'], 'legitimate', data['source'])
                    data['status'] = 'legitimate'
            else:
                data['status'] = 'legitimate'

            return JsonResponse(data)
        elif data['check_ssl']:
            if self.check_ssl(data['url']):
                check = self.search_url(data['url'])
                if check:
                    data['status'] = 'phishing'
                elif check == None:
                    classify = self.classify_url(data['url'])
                    if classify:
                        self.add_url(data['url'], 'phishing')
                        self.add_log(data['url'], 'phishing', data['source'])
                        data['status'] = 'phishing'
                    else:
                        self.add_url(data['url'], 'legitimate')
                        self.add_log(data['url'], 'legitimate', data['source'])
                        data['status'] = 'legitimate'
                else:
                    data['status'] = 'legitimate'

                return JsonResponse(data)
            else:
                check = self.search_url(data['url'])
                if check == None:
                    self.add_url(data['url'], 'phishing')
                    data['status'] = 'phishing'
                    return JsonResponse(data)


