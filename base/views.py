from django.shortcuts import render
from django.views import View
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
import json


# from django.http import HttpResponse
# Create your views here.

class SiteClassifier(View):
    def add_url(self, url, status, file_name='sites.csv'):
        import csv
        if self.search_url(url) != None:
            self.delete_url(url)

        with open(file_name, "r") as csv_file:
            # Create a csv reader object
            csv_reader = csv.reader(csv_file)
            # Get the number of rows in the csv file
            row_count = sum(1 for row in csv_reader)
            # Calculate the next id value by adding one to the row count
            next_id = row_count - 1

        # Open the csv file in append mode
        with open(file_name, "a") as csv_file:
            # Create a csv writer object
            csv_writer = csv.writer(csv_file, lineterminator="\n")
            # Write the url and status as a new row
            csv_writer.writerow([next_id, url, status])


    def delete_url(self, url, file_name='sites.csv'):
        import csv
        # Create an empty list to store the rows that are not deleted
        rows = []
        # Open the csv file in read mode
        with open(file_name, "r") as csv_file:
            # Create a csv reader object
            csv_reader = csv.reader(csv_file)
            # Loop through the rows of the csv file
            for row in csv_reader:
                # Check if the url does not match the first column of the row
                if url != row[1]:
                    # Append the row to the list
                    rows.append(row)
        # Open the csv file in write mode
        with open(file_name, "w") as csv_file:
            # Create a csv writer object
            csv_writer = csv.writer(csv_file, lineterminator="\n")
            # Write the rows that are not deleted to the csv file
            csv_writer.writerows(rows)

    def search_url(self, url, file_name='sites.csv'):
        import csv
        with open(file_name, "r") as csv_file:
            # Create a csv reader object
            csv_reader = csv.reader(csv_file)
            # Skip the header row
            next(csv_reader)
            # Loop through the rows of the csv file
            for row in csv_reader:
                # Check if the url matches the first column of the row
                if url == row[1]:
                    # Return the status from the second column of the row
                    if row[2] == 'phishing':
                        return True
                    else:
                        return False
            # If no match is found, return None
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

        model = tf.keras.models.load_model('phishing_model.keras')

        probs = model.predict(features)

        if probs >= 0.5:
            return True
        else:
            return False


class Home(View):
    def get(self, request):
        return render(request, 'home.html')


class Status(SiteClassifier):
    def get(self, request):
        return render(request, 'status.html')

    def post(self, request):
        data = json.loads(request.body)
        self.add_url(data['url'], data['status'])
        data['message'] = 'success'
        return JsonResponse(data)


class CheckUrl(SiteClassifier):
    def get(self, request):
        return JsonResponse({"status": "running"})

    def post(self, request):
        data = json.loads(request.body)
        # data["status"] = "received"
        print(data)
        check = self.search_url(data['url'])
        if check:
            data['status'] = 'phishing'
        elif check == None:
            classify = self.classify_url(data['url'])
            if classify:
                data['status'] = 'phishing'
            else:
                data['status'] = 'legitimate'
        else:
            data['status'] = 'legitimate'

        return JsonResponse(data)
