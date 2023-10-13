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
        print(data)
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

def is_number(obj):
    try:
        float(obj)
        return True
    except ValueError:
        return False

# Define a helper function to calculate the statistics from logs and corrections
def calculate_stats(logs, corrections):
    # Use list comprehensions to filter the logs and corrections by status
    logs_phishing = [log for log in logs if log["status"] == "phishing"]
    logs_legitimate = [log for log in logs if log["status"] == "legitimate"]
    corrections_phishing = [correction for correction in corrections if correction["status"] == "phishing"]
    corrections_legitimate = [correction for correction in corrections if correction["status"] == "legitimate"]

    # Use built-in functions to count the number of elements in each list
    TP = len(logs_phishing) - len(corrections_legitimate)
    TN = len(logs_legitimate) - len(corrections_phishing)
    FP = len(corrections_legitimate)
    FN = len(corrections_phishing)
    PA = TP + FN
    T = len(logs)

    # Return a dictionary with the calculated statistics
    return {
        'true_positives': TP,
        'true_negatives': TN,
        'false_positives': FP,
        'false_negatives': FN,
        'total_visits': T,
        'phishing_attempts': PA,
        'logs':logs
    }

# Define a class-based view for the Pie endpoint
class Pie(View):
    def get(self, request):
        # Get the current and previous time using timezone-aware objects
        now = timezone.now()
        yesterday = now - timedelta(hours=24)

        # Query the Log and Correction models using the time range filter
        logs = list(Log.objects.filter(created_at__gte=yesterday).values())
        corrections = list(Correction.objects.filter(created_at__gte=yesterday).values())

        # Calculate the statistics from the logs and corrections
        data = calculate_stats(logs, corrections)

        # Generate a list of date ranges for the last 24 hours with 3-hour intervals
        date_ranges = [(now - timedelta(hours=i + 3), now - timedelta(hours=i)) for i in range(0, 24, 3)]

        # Generate a list of dictionaries with the data count and the start and end times for each date range
        coordinates = []
        for start, end in date_ranges:
            # Query the Log model using the date range filter and count the number of results
            count = Log.objects.filter(created_at__range=(start, end)).count()
            # Append a dictionary with the data count and the ISO-formatted start and end times to the coordinates list
            coordinates.append({"data_count": count, "start": start.isoformat(), "end": end.isoformat()})
        data['coordinates'] = coordinates
        return JsonResponse(data)

    def post(self, request):
        # Get the start and stop dates from the request data as strings
        data = json.loads(request.body)
        print(data)
        start = data['start']
        stop = data['stop']

        # Import the datetime module
        import datetime

        # Parse the start and stop dates as datetime objects using strptime
        start = datetime.datetime.strptime(start, '%Y-%m-%d')
        stop = datetime.datetime.strptime(stop, '%Y-%m-%d')

        # Query the Log and Correction models using the start and stop dates as filters
        logs = list(Log.objects.filter(created_at__range=(start, stop)).values())
        corrections = list(Correction.objects.filter(created_at__range=(start, stop)).values())

        # Calculate the statistics from the logs and corrections using the helper function
        data = calculate_stats(logs, corrections)

        return JsonResponse(data)

