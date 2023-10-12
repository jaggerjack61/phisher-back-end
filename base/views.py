from django.shortcuts import render
from django.views import View
from django.http import JsonResponse,HttpResponse
import json
from .models import *
import ssl
import urllib.request
from datetime import datetime, timedelta
from django.utils import timezone


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
        websites = ["google.com", "google.co.zw", "localhost","youtube.com", "facebook.com", "amazon.com", "wikipedia.org", "twitter.com",
                    "netflix.com", "reddit.com", "instagram.com", "zoom.us", "linkedin.com", "yahoo.com", "ebay.com",
                    "bing.com", "microsoft.com", "apple.com", "cnn.com", "bbc.com", "nytimes.com", "walmart.com",
                    "spotify.com", "paypal.com", "quora.com", "pinterest.com", "wordpress.com", "twitch.tv", "imdb.com",
                    "stackoverflow.com", "github.com", "medium.com", "nasa.gov", "ted.com", "khanacademy.org",
                    "coursera.org", "udemy.com", "codecademy.com", "duolingo.com", "tripadvisor.com", "booking.com",
                    "airbnb.com", "skyscanner.net", "uber.com", "lyft.com", "tesla.com", "nike.com", "adidas.com",
                    "starbucks.com", "mcdonalds.com", "cocacola.com", "msn.com"]
        print(parsed_url.netloc.replace("www.", "").replace(":8080","").replace("8000",""))
        if parsed_url.netloc.replace("www.", "").replace(":8080","").replace(":8000","") in websites:
            return False

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
                self.add_log(data['url'], 'phishing', data['source'])
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
                self.add_log(data['url'], 'legitimate', data['source'])

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

class Reports(View):
    def get(self, request):
        now = timezone.now()
        yesterday = now - timedelta(hours=24)
        logs = list(Log.objects.filter(created_at__gte=yesterday).values())
        corrections = list(Correction.objects.filter(created_at__gte=yesterday).values())
        data = {"logs": logs, "corrections": corrections}
        print(data)
        return JsonResponse(data)

class Pie(View):
    def get(self, request):
        now = timezone.now()
        yesterday = now - timedelta(hours=24)
        logs = list(Log.objects.filter(created_at__gte=yesterday).values())
        T = Log.objects.filter(created_at__gte=yesterday).count()
        corrections = list(Correction.objects.filter(created_at__gte=yesterday).values())
        logs_phishing = [item["status"] == "phishing" for item in logs]
        logs_legitimate = [item["status"] == "legitimate" for item in logs]
        corrections_phishing = [item["status"] == "phishing" for item in corrections]
        corrections_legitimate = [item["status"] == "legitimate" for item in corrections]
        print(sum(logs_phishing))
        print(sum(corrections_phishing))
        print(sum(logs_legitimate))
        print(sum(corrections_legitimate))
        TP = sum(logs_phishing) - sum(corrections_legitimate)
        TN = sum(logs_legitimate) - sum(corrections_phishing)
        FP = sum(corrections_legitimate)
        FN = sum(corrections_phishing)
        PA = sum(logs_phishing) - sum(corrections_legitimate) + sum(corrections_phishing)
        data = {'true_positives': TP,
                'true_negatives': TN,
                'false_positives': FP,
                'false_negatives': FN,
                'total_visits': T,
                'phishing_attempts':PA
                }
        # print(data)
        return JsonResponse(data)



